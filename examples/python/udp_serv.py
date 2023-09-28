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
import socket
import threading
from uoa_module.uoa import get_real_address


def run_udp_serv(af, listen_addr):
    s = socket.socket(af, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(listen_addr)
    sys.stdout.write(f'UDP server listening on {listen_addr[0]}:{listen_addr[1]}\n')
    sys.stdout.flush()

    while True:
        msg, caddr = s.recvfrom(1024)

        # UOA syscall
        try:
            res = get_real_address(s.fileno(), af, caddr[0], caddr[1], listen_addr[1])
        except Exception as e:
            sys.stderr.write(f'get_real_address failed: {e}')
            sys.stderr.flush()
            continue

        reply_msg = f'Msg={msg.decode("utf-8")}'
        print_msg = f'Recv {len(msg)} bytes from {caddr[0]}:{caddr[1]}: {msg.decode("utf-8")}'
        if res is not None:
            _, real_addr, real_port = res
            reply_msg += f', RealAddr={real_addr}:{real_port}'
            print_msg += f' --> RealAddr: {real_addr}:{real_port}'

        s.sendto(reply_msg.encode('utf-8'), caddr)
        sys.stdout.write(f'{print_msg}\n')
        sys.stdout.flush()


def main():
    local_port = int(sys.argv[1])
    threading.Thread(target=run_udp_serv, args=(socket.AF_INET6, ('::', local_port)), daemon=True).start()
    run_udp_serv(socket.AF_INET, ('0.0.0.0', local_port))


if __name__ == '__main__':
    main()
