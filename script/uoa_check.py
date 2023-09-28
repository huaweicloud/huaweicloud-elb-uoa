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

----

These are UOA automated cases used to test the UOA capability.
They need to work with the Python example UDP server (examples/python/udp_serv.py).

For a case, the client should send an udp packet to serv/lb. If the client could:

- recv a reply udp packet
- the udp packet carries real source address
- the real source address equals the expected source address

Then we think this case is passed.
"""
import sys
import traceback
import unittest
from socket import AF_INET, AF_INET6

from util import Util, BaseTestLb, BaseTestServ, BaseTestMulLb

MOCK_REAL_IPV4 = '10.2.3.3'
MOCK_REAL_IPV6 = 'fe80::2333'
MOCK_REAL_PORT = 23333
UOA_MAX_TRAIL = 3

ARGS = Util.parse_args()


class TestIpv4Serv(BaseTestServ):
    def setUp(self):
        self.dip, self.dport = Util.parse_ipv4_arg(ARGS.serv_ipv4)
        super(TestIpv4Serv, self).setUp()

    def test_send_udp4_uoa_opt_to_serv(self):
        expect_read_addr = '%s:%s' % (MOCK_REAL_IPV4, MOCK_REAL_PORT)
        pkt = self.pkt_gen.udp4_uoa_opt(AF_INET, MOCK_REAL_IPV4, MOCK_REAL_PORT)
        self.sr1_and_assert(pkt, expect_read_addr)

    def test_send_udp4_uoa6_opt_to_serv(self):
        expect_read_addr = '%s:%s' % (MOCK_REAL_IPV6, MOCK_REAL_PORT)
        pkt = self.pkt_gen.udp4_uoa_opt(AF_INET6, MOCK_REAL_IPV6, MOCK_REAL_PORT)
        self.sr1_and_assert(pkt, expect_read_addr)


class TestIpv6Serv(BaseTestServ):
    def setUp(self):
        self.dip, self.dport = Util.parse_ipv6_arg(ARGS.serv_ipv6)
        super(TestIpv6Serv, self).setUp()

    def test_send_udp6_ext_hdr_with_uoa4_opt_to_serv(self):
        expect_read_addr = '%s:%s' % (MOCK_REAL_IPV4, MOCK_REAL_PORT)
        pkt = self.pkt_gen.udp6_ext_hdr_with_uoa_opt(AF_INET, MOCK_REAL_IPV4, MOCK_REAL_PORT)
        self.send_sniff_and_assert(pkt, expect_read_addr, self.pkt_gen.sport)

    def test_send_udp6_ext_hdr_with_uoa6_opt_to_serv(self):
        expect_read_addr = '%s:%s' % (MOCK_REAL_IPV6, MOCK_REAL_PORT)
        pkt = self.pkt_gen.udp6_ext_hdr_with_uoa_opt(AF_INET6, MOCK_REAL_IPV6, MOCK_REAL_PORT)
        self.send_sniff_and_assert(pkt, expect_read_addr, self.pkt_gen.sport)


class TestIpv4Lb(BaseTestLb):
    def setUp(self):
        self.dip, self.dport = Util.parse_ipv4_arg(ARGS.lb_ipv4)
        self.sip = ARGS.self_ipv4
        super(TestIpv4Lb, self).setUp()

    def test_send_udp4_to_lb(self):
        pkt = self.pkt_gen.udp4()
        self.sr1_and_assert(pkt, self.expect_read_addr)

    def test_send_udp4_unknown_opt_to_lb(self):
        pkt = self.pkt_gen.udp4_unknown_opt()
        self.sr1_and_assert(pkt, self.expect_read_addr)

    def test_send_udp4_opt_end_to_lb(self):
        pkt = self.pkt_gen.udp4_opt_end()
        self.sr1_and_assert(pkt, self.expect_read_addr)

    def test_send_udp4_full_opt_to_lb(self):
        pkt = self.pkt_gen.udp4_full_opt()
        self.sr1_and_assert(pkt, self.expect_read_addr)


class TestIpv6Lb(BaseTestLb):
    def setUp(self):
        self.dip, self.dport = Util.parse_ipv6_arg(ARGS.lb_ipv6)
        self.sip = ARGS.self_ipv6
        super(TestIpv6Lb, self).setUp()

    def test_send_udp6_to_lb(self):
        pkt = self.pkt_gen.udp6()
        self.sr1_and_assert(pkt, self.expect_read_addr)

    def test_send_udp6_ext_hdr_with_unknown_opt_to_lb(self):
        pkt = self.pkt_gen.udp6_ext_hdr_with_unknown_opt()
        self.send_sniff_and_assert(pkt, self.expect_read_addr, self.pkt_gen.sport)


class TestNat46Lb(BaseTestLb):
    def setUp(self):
        self.dip, self.dport = Util.parse_ipv4_arg(ARGS.nat46_lb_ipv4)
        self.sip = ARGS.self_ipv4
        super(TestNat46Lb, self).setUp()

    def test_send_udp4_to_lb(self):
        pkt = self.pkt_gen.udp4()
        self.sr1_and_assert(pkt, self.expect_read_addr)


class TestNat64Lb(BaseTestLb):
    def setUp(self):
        self.dip, self.dport = Util.parse_ipv6_arg(ARGS.nat64_lb_ipv6)
        self.sip = ARGS.self_ipv6
        super(TestNat64Lb, self).setUp()

    def test_send_udp6_to_lb(self):
        pkt = self.pkt_gen.udp6()
        self.sr1_and_assert(pkt, self.expect_read_addr)


class TestMultipleIpv4Lb(BaseTestMulLb):
    def setUp(self):
        self.dip, self.dport = Util.parse_ipv4_arg(ARGS.lb_ipv4)
        super(TestMultipleIpv4Lb, self).setUp()

    def test_send_udp4_to_mul_lb(self):
        expect_read_addr = '%s:%s' % (MOCK_REAL_IPV4, MOCK_REAL_PORT)

        uoa_pkt = self.pkt_gen.udp4_uoa_opt(AF_INET, MOCK_REAL_IPV4, MOCK_REAL_PORT)
        pkt = self.pkt_gen.udp4()

        for _ in range(UOA_MAX_TRAIL):
            self.sr1_and_assert(uoa_pkt, expect_read_addr)
        self.sr1_and_assert(pkt, expect_read_addr)

    def test_send_udp4_with_standalone_uoa_pkt_to_mul_lb(self):
        expect_read_addr = '%s:%s' % (MOCK_REAL_IPV4, MOCK_REAL_PORT)

        standalone_uoa_pkt = self.pkt_gen.udp4_uoa_opt(AF_INET, MOCK_REAL_IPV4, MOCK_REAL_PORT)
        full_opt_pkt = self.pkt_gen.udp4_full_opt()

        for _ in range(UOA_MAX_TRAIL):
            self.sr1_and_assert(standalone_uoa_pkt, expect_read_addr)
            self.sr1_and_assert(full_opt_pkt, expect_read_addr)
        self.sr1_and_assert(full_opt_pkt, expect_read_addr)


class TestMultipleIpv6Lb(BaseTestMulLb):
    def setUp(self):
        self.dip, self.dport = Util.parse_ipv6_arg(ARGS.lb_ipv6)
        super(TestMultipleIpv6Lb, self).setUp()

    def test_send_udp6_to_mul_lb(self):
        expect_read_addr = '%s:%s' % (MOCK_REAL_IPV6, MOCK_REAL_PORT)

        uoa_pkt = self.pkt_gen.udp6_ext_hdr_with_uoa_opt(AF_INET6, MOCK_REAL_IPV6, MOCK_REAL_PORT)
        pkt = self.pkt_gen.udp6()

        for _ in range(UOA_MAX_TRAIL):
            self.send_sniff_and_assert(uoa_pkt, expect_read_addr, self.pkt_gen.sport)
        self.send_sniff_and_assert(pkt, expect_read_addr, self.pkt_gen.sport)

    def test_send_udp6_with_standalone_uoa_pkt_to_mul_lb(self):
        expect_read_addr = '%s:%s' % (MOCK_REAL_IPV6, MOCK_REAL_PORT)

        standalone_uoa_pkt = self.pkt_gen.udp6_ext_hdr_with_uoa_opt(AF_INET6, MOCK_REAL_IPV6, MOCK_REAL_PORT)
        unknown_opt_pkt = self.pkt_gen.udp6_ext_hdr_with_unknown_opt()

        for _ in range(UOA_MAX_TRAIL):
            self.send_sniff_and_assert(standalone_uoa_pkt, expect_read_addr, self.pkt_gen.sport)
            self.send_sniff_and_assert(unknown_opt_pkt, expect_read_addr, self.pkt_gen.sport)
        self.send_sniff_and_assert(unknown_opt_pkt, expect_read_addr, self.pkt_gen.sport)


if __name__ == '__main__':
    try:
        unittest_argv = sys.argv[:1]
        if ARGS.k is not None:
            unittest_argv.extend(['-k', ARGS.k])
        unittest.main(argv=unittest_argv)
    except Exception as exc:
        sys.stderr.write('run failed: %s\n%s' % (exc, traceback.format_exc()))
        sys.stderr.flush()
        sys.exit(1)
