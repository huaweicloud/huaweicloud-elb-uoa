#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright 2023 Huawei Cloud Computing Technology Co., Ltd.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""

import sys
import argparse
import random
import struct
import time
import unittest
from socket import AF_INET, htons, inet_pton, IPPROTO_UDP

from scapy.all import Raw, raw, AsyncSniffer, send, sr1
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, HBHOptUnknown, IPv6ExtHdrDestOpt, in6_chksum

SNIFF_THREAD_WAIT_TIME = 0.1
TIMEOUT = 0.5


class Util(object):
    @staticmethod
    def rand_port():
        return int(random.random() * 50000 + 10000)

    @staticmethod
    def parse_ipv4_arg(arg):
        """parse ipv4 arg - ip:port"""
        if arg is None:
            return None, None
        try:
            ip, port = arg.split(':')
            port = int(port)
        except Exception as e:
            raise Exception('invalid ipv4 arg: arg=%s, e=%s' % (arg, e))
        return ip, port

    @staticmethod
    def parse_ipv6_arg(arg):
        """parse ipv6 arg - [ip]:port"""
        if arg is None:
            return None, None
        try:
            ip, port = arg.strip('[').split(']:')
            port = int(port)
        except Exception as e:
            raise Exception('invalid ipv6 arg: arg=%s, e=%s' % (arg, e))
        return ip, port

    @staticmethod
    def parse_args(argv=None):
        parser = argparse.ArgumentParser()
        parser.add_argument('-k', metavar='<CASE>', default=None,
                            help='Only run test methods and classes that match the pattern or substring')
        parser.add_argument('--serv-ipv4', metavar='<SERVER IPV4>', default=None,
                            help='UDP Server IPv4 Address (e.g. 10.2.3.3:8082)')
        parser.add_argument('--serv-ipv6', metavar='<SERVER IPV4>', default=None,
                            help='UDP Server IPv6 Address (e.g. [fe80::2333]:8082)')
        parser.add_argument('--lb-ipv4', metavar='<LB IPV4>', default=None,
                            help='Load Balancer IPv4 Address (e.g. 10.2.3.3:8082)')
        parser.add_argument('--lb-ipv6', metavar='<LB IPV6>', default=None,
                            help='Load Balancer IPv6 Address (e.g. [fe80::2333]:8082)')
        parser.add_argument('--self-ipv4', metavar='<SELF IPV4>', default=None,
                            help='Self IPv4 Address (e.g. 10.2.3.3)')
        parser.add_argument('--self-ipv6', metavar='<SELF IPV6>', default=None,
                            help='Self IPv6 Address (e.g. [fe80::2333]:8082)')
        parser.add_argument('--nat46-lb-ipv4', metavar='<NAT46 LB IPV4>', default=None,
                            help='NAT46 Load Balancer IPv4 Address (e.g. 10.2.3.3:8082)')
        parser.add_argument('--nat64-lb-ipv6', metavar='<NAT64 LB IPV6>', default=None,
                            help='NAT64 Load Balancer IPv6 Address (e.g. [fe80::2333]:8082)')
        argv = argv or sys.argv
        return parser.parse_args(argv[1:])


class PktGen(object):
    UOA_TYPE = 0x1f
    UNK_TYPE = 0x2f

    def __init__(self, dip, dport, sport=None, payload=None):
        self.dip = dip
        self.dport = dport
        self.sport = sport or Util.rand_port()
        self.payload = payload or 'Hello, UOA!'

    def udp4(self, pkt_len=None):
        """Simple UDP Packet"""
        payload = self.payload if pkt_len is None else 'v' * (pkt_len - 20 - 8)
        return IP(dst=self.dip) / UDP(sport=self.sport, dport=self.dport) / Raw(load=payload)

    def udp6(self, pkt_len=None):
        """Simple UDP6 Packet"""
        payload = self.payload if pkt_len is None else 'v' * (pkt_len - 40 - 8)
        return IPv6(dst=self.dip) / UDP(sport=self.sport, dport=self.dport) / Raw(load=payload)

    def udp4_uoa_opt(self, real_af, real_ip, real_port):
        """UDP Packet With UOA Option

        :param real_af: AF_INET | AF_INET6
        :param real_ip: ip address in uoa option
        :param real_port: port in uoa option
        :return: scapy.all.Packet
        """
        fmt = 'bbh4s' if real_af == AF_INET else 'bbh16s'
        length = 8 if real_af == AF_INET else 20
        opt = Raw(struct.pack(fmt, self.UOA_TYPE, length, htons(real_port), inet_pton(real_af, real_ip)))
        return IP(dst=self.dip, options=opt) / UDP(sport=self.sport, dport=self.dport) / Raw(load=self.payload)

    def udp4_unknown_opt(self):
        """UDP Packet With Unknown Option"""
        opt = Raw(struct.pack('bb6s', self.UNK_TYPE, 8, b'123456'))
        return IP(dst=self.dip, options=opt) / UDP(sport=self.sport, dport=self.dport) / Raw(load=self.payload)

    def udp4_opt_end(self):
        """UDP Packet With Option End"""
        opt = Raw(struct.pack('bb6sb', self.UNK_TYPE, 8, b'123456', 0))
        return IP(dst=self.dip, options=opt) / UDP(sport=self.sport, dport=self.dport) / Raw(load=self.payload)

    def udp4_full_opt(self):
        """UDP Packet Filled With Options"""
        opt = Raw(struct.pack('bb38s', self.UNK_TYPE, 40, b'\xee' * 38))
        return IP(dst=self.dip, options=opt) / UDP(sport=self.sport, dport=self.dport) / Raw(load=self.payload)

    def udp6_ext_hdr_with_uoa_opt(self, real_af, real_ip, real_port):
        """UDP6 Packet With Destination Extension Header UOA Option

        :param real_af: AF_INET | AF_INET6
        :param real_ip: ip address in uoa option
        :param real_port: port in uoa option
        :return: scapy.all.Packet
        """
        fmt = 'h4s' if real_af == AF_INET else 'h16s'
        length = 6 if real_af == AF_INET else 18

        uoa_data = struct.pack(fmt, htons(real_port), inet_pton(real_af, real_ip))
        opt = HBHOptUnknown(otype=self.UOA_TYPE, optlen=length, optdata=uoa_data)

        pkt = (IPv6(dst=self.dip) / IPv6ExtHdrDestOpt(options=opt) /
               UDP(sport=self.sport, dport=self.dport, chksum=0) / Raw(load=self.payload))
        pkt[UDP].chksum = in6_chksum(IPPROTO_UDP, pkt[IPv6], raw(pkt[UDP]))
        return pkt

    def udp6_ext_hdr_with_unknown_opt(self):
        """UDP6 Packet With Destination Extension Header Unknown Option"""
        unknown_data = struct.pack('18s', b'123456789012345678')
        opt = HBHOptUnknown(otype=self.UNK_TYPE, optlen=18, optdata=unknown_data)

        pkt = (IPv6(dst=self.dip) / IPv6ExtHdrDestOpt(options=opt) /
               UDP(sport=self.sport, dport=self.dport, chksum=0) / Raw(load=self.payload))
        pkt[UDP].chksum = in6_chksum(IPPROTO_UDP, pkt[IPv6], raw(pkt[UDP]))
        return pkt


class BaseTest(unittest.TestCase):
    def send_sniff_and_assert(self, pkt, expect_real_addr, sniff_dst_port):
        snif = AsyncSniffer(filter='dst port %s' % sniff_dst_port, count=1, timeout=TIMEOUT)
        snif.start()
        time.sleep(SNIFF_THREAD_WAIT_TIME)  # sleep to wait for snif thread to actually start running
        send(pkt, verbose=False)
        snif.join()
        if len(snif.results) <= 0:
            raise Exception('no pkt recv')
        recv_pkt = snif.results[0]

        self.assert_payload(recv_pkt[Raw].load, expect_real_addr)

    def sr1_and_assert(self, pkt, expect_real_addr):
        recv_pkt = sr1(pkt, timeout=TIMEOUT, verbose=False)
        if recv_pkt is None:
            raise Exception('no pkt recv')

        self.assert_payload(recv_pkt[Raw].load, expect_real_addr)

    def assert_payload(self, payload, expect_real_addr):
        # payload is str in py2 and bytes in py3
        if type(payload) is bytes:
            payload = payload.decode('utf-8')

        recv_msg_splits = payload.split('RealAddr=')
        if len(recv_msg_splits) < 2:
            raise Exception('real addr not found: %s' % payload)
        real_addr = recv_msg_splits[-1]

        self.assertEqual(real_addr, expect_real_addr)


class BaseTestServ(BaseTest):
    def __init__(self, *args, **kwargs):
        super(BaseTestServ, self).__init__(*args, **kwargs)
        self.dip = None
        self.dport = None

    def setUp(self):
        if self.dip is None or self.dport is None:
            self.skipTest('dip or dport is not specific')
        self.pkt_gen = PktGen(dip=self.dip, dport=self.dport)


class BaseTestLb(BaseTest):
    def __init__(self, *args, **kwargs):
        super(BaseTestLb, self).__init__(*args, **kwargs)
        self.dip = None
        self.dport = None
        self.sip = None

    def setUp(self):
        if self.dip is None or self.dport is None or self.sip is None:
            self.skipTest('dip or dport is not specific')
        self.pkt_gen = PktGen(dip=self.dip, dport=self.dport)
        self.expect_read_addr = '%s:%s' % (self.sip, self.pkt_gen.sport)


class BaseTestMulLb(BaseTestServ):
    pass
