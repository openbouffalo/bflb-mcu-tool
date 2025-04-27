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
import random
import binascii
import argparse

try:
    import bflb_path
except ImportError:
    from libs import bflb_path

import config as gol
from libs import bflb_utils
from libs import bflb_img_create


class BflbImgEncryptSign(object):
    def __init__(self, chipname="bl60x", chiptype="bl60x", image_type="all"):
        self.chipname = chipname
        self.chiptype = chiptype
        self.image_type = image_type

    @staticmethod
    def random_hex(length):
        result = hex(random.randint(0, 16**length)).replace("0x", "").upper()
        if len(result) < length:
            result = "0" * (length - len(result)) + result
        return result

    def encrypt_sign_iot_data(self, dir, whole_flash_file, key, iv, publickey, privatekey, **kwargs):
        with open(whole_flash_file, "rb") as fp:
            whole_flash_data = bytearray(fp.read())

        encrypt_ota_data = bytearray(0)
        sub_module = __import__("libs." + self.chiptype, fromlist=[self.chiptype])
        if sub_module.partition_cfg_do.bootheader_magic_code != bflb_utils.bytearray_to_int(whole_flash_data[0:4]):
            bflb_utils.printf("bootheader bin magic check failed", binascii.hexlify(whole_flash_data[0:4]))
            return False
        efuse_data = bytearray(128)
        img_start_offset = 128
        img_len_offset = 120
        if self.chiptype == "bl808":
            img_start_offset = 132
            img_len_offset = 140
        elif self.chiptype == "bl616":
            img_start_offset = 124
            img_len_offset = 132
        elif self.chiptype == "bl628":
            img_start_offset = 128
            img_len_offset = 136
        else:
            img_start_offset = 128
            img_len_offset = 120
        boot2_addr = (
            bflb_utils.bytearray_to_int(whole_flash_data[img_start_offset + 0 : img_start_offset + 1])
            + (bflb_utils.bytearray_to_int(whole_flash_data[img_start_offset + 1 : img_start_offset + 2]) << 8)
            + (bflb_utils.bytearray_to_int(whole_flash_data[img_start_offset + 2 : img_start_offset + 3]) << 16)
            + (bflb_utils.bytearray_to_int(whole_flash_data[img_start_offset + 3 : img_start_offset + 4]) << 24)
        )
        boot2_len = (
            bflb_utils.bytearray_to_int(whole_flash_data[img_len_offset + 0 : img_len_offset + 1])
            + (bflb_utils.bytearray_to_int(whole_flash_data[img_len_offset + 1 : img_len_offset + 2]) << 8)
            + (bflb_utils.bytearray_to_int(whole_flash_data[img_len_offset + 2 : img_len_offset + 3]) << 16)
            + (bflb_utils.bytearray_to_int(whole_flash_data[img_len_offset + 3 : img_len_offset + 4]) << 24)
        )
        pt_data = whole_flash_data[0xE000:0xF000]
        entry_type, entry_addr, entry_len = sub_module.partition_cfg_do.parse_pt_data(pt_data)
        bflb_utils.printf(entry_type, entry_addr, entry_len)
        (
            whole_flash_data[: boot2_len + boot2_addr],
            efuse_data,
            img_len,
        ) = sub_module.img_create_do.create_encryptandsign_flash_data(
            whole_flash_data[0 : boot2_len + boot2_addr], boot2_addr, key, iv, publickey, privatekey, **kwargs
        )
        for i, val in enumerate(entry_type):
            if entry_addr[i] > len(whole_flash_data):
                continue
            if sub_module.partition_cfg_do.bootheader_magic_code != bflb_utils.bytearray_to_int(
                whole_flash_data[entry_addr[i] : entry_addr[i] + 4]
            ):
                continue
            if val == sub_module.partition_cfg_do.fireware_name:
                (
                    whole_flash_data[entry_addr[i] : entry_addr[i] + entry_len[i]],
                    efuse_data,
                    img_len,
                ) = sub_module.img_create_do.create_encryptandsign_flash_data(
                    whole_flash_data[entry_addr[i] : entry_addr[i] + entry_len[i]],
                    0x1000,
                    key,
                    iv,
                    publickey,
                    privatekey,
                    **kwargs,
                )
                encrypt_ota_data = whole_flash_data[entry_addr[i] : entry_addr[i] + 0x1000 + img_len]
            if val == sub_module.partition_cfg_do.mfg_name:
                (
                    whole_flash_data[entry_addr[i] : entry_addr[i] + entry_len[i]],
                    efuse_data,
                    img_len,
                ) = sub_module.img_create_do.create_encryptandsign_flash_data(
                    whole_flash_data[entry_addr[i] : entry_addr[i] + entry_len[i]],
                    0x1000,
                    key,
                    iv,
                    publickey,
                    privatekey,
                    **kwargs,
                )
        if self.image_type == "all" or self.image_type == "ota":
            with open(os.path.join(dir, "FW_OTA.bin"), "wb+") as fp:
                fp.write(encrypt_ota_data)
        if self.image_type == "all" or self.image_type == "image":
            with open(os.path.join(dir, "output.bin"), "wb+") as fp:
                fp.write(whole_flash_data)


def flasher_encrypt_sign(args):
    chipname = args.chipname
    chiptype = gol.dict_chip_cmd.get(chipname, "unkown chip type")
    if chiptype not in ["bl60x", "bl602", "bl702", "bl702l", "bl808", "bl616", "bl628"]:
        bflb_utils.printf("chip type is not in bl602/bl702/bl702l/bl808/bl616/bl628")
        return

    key = ""
    iv = ""
    publickey = ""
    privatekey = ""

    dir = args.output_dir
    whole_flash_file = args.file
    if args.aeskey and args.aesiv:
        key = args.aeskey
        iv = args.aesiv
    if args.publickey and args.privatekey:
        publickey = args.publickey
        privatekey = args.privatekey
    if key == "" and iv == "" and publickey == "" and privatekey == "":
        bflb_utils.printf("please selete encrypt key/iv or sign publickey/privatekey")
        return
    bflb_utils.printf(dir, whole_flash_file, key, iv, publickey, privatekey)
    obj_iot = BflbImgEncryptSign(chipname, chiptype, "all")
    obj_iot.encrypt_sign_iot_data(dir, whole_flash_file, key, iv, publickey, privatekey)


def run():
    parser = argparse.ArgumentParser(description="iot-encrypt-sign-tool")
    parser.add_argument("--chipname", required=True, help="chip name")
    parser.add_argument("--output_dir", dest="output_dir", help="output files directory")
    parser.add_argument("--file", dest="file", help="whole flash data file")
    parser.add_argument("--aeskey", dest="aeskey", help="aes key data")
    parser.add_argument("--aesiv", dest="aesiv", help="aes iv data")
    parser.add_argument("--publickey", dest="publickey", help="public key file")
    parser.add_argument("--privatekey", dest="privatekey", help="private key file")
    args = parser.parse_args()
    bflb_utils.printf("==================================================")
    parser.set_defaults(func=flasher_encrypt_sign)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    print(sys.argv)
    run()
