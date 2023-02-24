# -*- coding:utf-8 -*-

import os
import sys
import random
import binascii
import argparse
import traceback

from libs import bflb_utils


# Get app path
if getattr(sys, "frozen", False):
    app_path = os.path.dirname(sys.executable)
else:
    app_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(app_path)
chip_path = os.path.join(app_path, "chips")

try:
    import changeconf as cgc
    conf_sign = True
except ImportError:
    conf_sign = False

if conf_sign:
    chip_dict = {cgc.lower_name: "bl602"}
    chip_xtal = cgc.choice_xtal
    chip_brd = cgc.choice_board
    bl_factory_params_file_prefix = cgc.show_text_first_value
    boot2bin = "chipsp_boot2.bin"  
else:
    chip_dict = {
        "bl56x": "bl60x",
        "bl60x": "bl60x",
        "bl562": "bl602",
        "bl602": "bl602",
        "bl702": "bl702",
        "bl808": "bl808",
    }
    chip_xtal = 'bl60x_xtal'
    chip_brd = 'bl60x_brd'
    bl_factory_params_file_prefix = 'bl_factory_params_'
    boot2bin = "blsp_boot2.bin"


class BflbFlashEncryptSign(object):

    def __init__(self, chipname="bl602", chiptype="bl602"):
        self.chipname = chipname
        self.chiptype = chiptype


    def random_hex(self, length):
        result = hex(random.randint(0,16**length)).replace('0x','').upper()
        if(len(result) < length):
            result = '0'*(length-len(result))+result
        return result


    def create_security_efuse(self, key, sel):
        efuse_data = bytearray(128)
        mask_data = bytearray(128)
        sub_module = __import__("libs." + self.chiptype, fromlist=[self.chiptype])
        efuse_data = sub_module.img_create_do.img_update_efuse(None, 0, None, 0, None, sel, key, False)

        for num in range(0, len(efuse_data)):
            if efuse_data[num] != 0:
                mask_data[num] |= 0xff
        return efuse_data, mask_data


    def encrypt_sign_flash_data(self, whole_flash_file, key, iv, publickey, privatekey):
        fp = open(whole_flash_file, 'rb')
        whole_flash_data = bytearray(fp.read())
        fp.close()
        efuse_data = bytearray(128)
        mask_data = bytearray(128)

        try:
            sub_module = __import__("libs." + self.chiptype, fromlist=[self.chiptype])
            if sub_module.partition_cfg_do.bootheader_magic_code != \
                bflb_utils.bytearray_to_int(whole_flash_data[0:4]):
                bflb_utils.printf("bootheader bin magic check fail ", binascii.hexlify(whole_flash_data[0:4]))
                return False
            boot2_addr = bflb_utils.bytearray_to_int(whole_flash_data[128+0 : 128+1]) + \
                        (bflb_utils.bytearray_to_int(whole_flash_data[128+1 : 128+2]) << 8) + \
                        (bflb_utils.bytearray_to_int(whole_flash_data[128+2 : 128+3]) << 16) + \
                        (bflb_utils.bytearray_to_int(whole_flash_data[128+3 : 128+4]) << 24)
            boot2_len  = bflb_utils.bytearray_to_int(whole_flash_data[120+0 : 120+1]) + \
                        (bflb_utils.bytearray_to_int(whole_flash_data[120+1 : 120+2]) << 8) + \
                        (bflb_utils.bytearray_to_int(whole_flash_data[120+2 : 120+3]) << 16) + \
                        (bflb_utils.bytearray_to_int(whole_flash_data[120+3 : 120+4]) << 24)
            pt_data = whole_flash_data[0xE000:0xF000]
            entry_type, entry_addr, entry_len = sub_module.partition_cfg_do.parse_pt_data(pt_data)
            bflb_utils.printf(entry_type, entry_addr, entry_len)
            whole_flash_data[:boot2_len+boot2_addr], efuse_data, img_len = \
                sub_module.img_create_do.create_encryptandsign_flash_data(
                whole_flash_data[0:boot2_len+boot2_addr], boot2_addr, key, iv, publickey, privatekey)
            for i, val in enumerate(entry_type):
                if entry_addr[i] > len(whole_flash_data):
                    continue
                if sub_module.partition_cfg_do.bootheader_magic_code != \
                    bflb_utils.bytearray_to_int(whole_flash_data[entry_addr[i]:entry_addr[i]+4]):
                    continue
                if val == sub_module.partition_cfg_do.fireware_name:
                    whole_flash_data[entry_addr[i]:entry_addr[i]+entry_len[i]], efuse_data, img_len = \
                        sub_module.img_create_do.create_encryptandsign_flash_data(
                        whole_flash_data[entry_addr[i]:entry_addr[i]+entry_len[i]], 0x1000, key, iv, publickey, privatekey)
                if val == sub_module.partition_cfg_do.mfg_name:
                    whole_flash_data[entry_addr[i]:entry_addr[i]+entry_len[i]], efuse_data, img_len = \
                        sub_module.img_create_do.create_encryptandsign_flash_data(
                        whole_flash_data[entry_addr[i]:entry_addr[i]+entry_len[i]], 0x1000, key, iv, publickey, privatekey)

            for num in range(0, len(efuse_data)):
                if efuse_data[num] != 0:
                    mask_data[num] |= 0xff
        except Exception as e:
            error = str(e)
            bflb_utils.printf(error)
            traceback.print_exc(limit=5, file=sys.stdout)
        return whole_flash_data, efuse_data, mask_data


def flasher_encrypt_sign(args):
    chipname = args.chipname
    chiptype = chip_dict.get(chipname, "unkown chip type") 
    if chiptype not in ["bl60x", "bl602", "bl702"]: 
        bflb_utils.printf("Chip type is not in bl60x/bl602/bl702")
        return
    whole_flash_file = args.file
    key = args.aeskey
    iv = args.aesiv
    publickey = args.publickey
    privatekey = args.privatekey
    bflb_utils.printf(whole_flash_file, key, iv, publickey, privatekey)
    obj_iot = BflbFlashEncryptSign(chipname, chiptype)
    obj_iot.encrypt_sign_flash_data(whole_flash_file, key, iv, publickey, privatekey)


def run():
    parser = argparse.ArgumentParser(description='iot-encrypt-sign-tool')
    parser.add_argument('--chipname', required=True, help='chip name')
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


if __name__ == '__main__':
    print(sys.argv)
    run()

