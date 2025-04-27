# -*- coding:utf-8 -*-
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

import os
import sys
import binascii

from libs import bflb_utils
from libs.bflb_configobj import BFConfigParser


def load_sec_eng_key_slot(cmd, cfgfile, write_callback, ack_callback):
    cfg = BFConfigParser()
    cfg.read(cfgfile)
    aeskey = bflb_utils.hexstr_to_bytearray(cfg.get("Img_Cfg", "aes_key_org"))
    aeslen = len(aeskey)

    bflb_utils.printf("load sec eng key: ")
    tmp = bflb_utils.int_to_2bytearray_l(aeslen * 2)
    cmd_id = bflb_utils.hexstr_to_bytearray(cmd)
    data = cmd_id + bytearray(1) + tmp
    i = 0
    while i < aeslen:
        start_addr = bflb_utils.int_to_4bytearray_l(0x400070B0 + i)
        write_data = aeskey[i : i + 4]
        data += start_addr + write_data
        i += 4
    # bflb_utils.printf(binascii.hexlify(data))
    write_callback(data)
    res = ack_callback(dmy_data=False)
    if res.startswith("OK") is False:
        bflb_utils.printf("failed to load sec eng key")
        return False

    tmp = bflb_utils.int_to_2bytearray_l(8)
    start_addr = bflb_utils.int_to_4bytearray_l(0x400700E0)
    write_data = bflb_utils.int_to_4bytearray_l(0x30003000)
    data = cmd_id + bytearray(1) + tmp + start_addr + write_data
    write_callback(data)
    res = ack_callback(dmy_data=False)
    if res.startswith("OK") is False:
        bflb_utils.printf("failed to load rd/wr lock key slot")
        return False
    return True
