# -*- coding: utf-8 -*-
#  Copyright (C) 2016- BOUFFALO LAB (NANJING) CO., LTD.
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.

import re
import sys
import time
import socket
import threading
import binascii

try:
    import bflb_path
except ImportError:
    from libs import bflb_path
import config as gol
from libs import bflb_eflash_loader
from libs import bflb_version
from libs import bflb_ecdh
from libs import bflb_utils
from libs.bflb_utils import eflash_loader_parser_init


def eflash_loader_worker(client_addr, client_data, count_total, count_success):
    with count_total.get_lock():
        count_total.value += 1
    bflb_utils.enable_udp_send_log(True)
    tid = threading.get_ident()
    request = client_data.decode("utf-8")
    bflb_utils.printf("Worker ID: {0} deal request: {1}".format(tid, request))
    bflb_utils.add_udp_client(str(tid), client_addr)
    ret = False
    try:
        parser = eflash_loader_parser_init()
        args = parser.parse_args(request.split(" "))
        eflash_loader_t = bflb_eflash_loader.BflbEflashLoader(args.chipname, gol.dict_chip_cmd[args.chipname])
        ret = eflash_loader_t.efuse_flash_loader(args, None, None)
    finally:
        udp_socket_result = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bflb_utils.remove_udp_client(str(tid))
        if ret is True:
            udp_socket_result.sendto(
                bytearray.fromhex(binascii.hexlify(b"Finished with success").decode("utf-8")),
                client_addr,
            )
            bflb_utils.printf("Worker ID: {} finished with success".format(tid))
            udp_socket_result.close()
            del eflash_loader_t
            with count_success.get_lock():
                count_success.value += 1
            bflb_utils.printf("State: {0}/{1}".format(count_success.value, count_total.value))
            return True
        else:
            udp_socket_result.sendto(
                bytearray.fromhex(binascii.hexlify(b"Finished with fail").decode("utf-8")),
                client_addr,
            )
            bflb_utils.printf("Worker ID: {} finished unsuccessfully".format(tid))
            udp_socket_result.close()
            del eflash_loader_t
            bflb_utils.printf("State: {0}/{1}".format(count_success.value, count_total.value))

            return False
