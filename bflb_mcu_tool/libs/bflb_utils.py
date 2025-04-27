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
import re
import time
import shutil
import binascii
import struct
import random
import socket
import threading
import datetime
import hashlib
import argparse
import traceback
import platform
import codecs
from glob import glob

import pylink
from serial import Serial
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization

try:
    from PySide2 import QtCore

    qt_sign = True
except ImportError:
    qt_sign = False

try:
    from serial.tools.list_ports import comports
except ImportError:
    pass

# Get app path
if getattr(sys, "frozen", False):
    app_path = os.path.dirname(sys.executable)
else:
    app_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
chip_path = os.path.join(app_path, "chips")

python_version = struct.calcsize("P") * 8
if python_version == 64:
    path_dll = os.path.join(app_path, "utils/jlink", "JLink_x64.dll")
else:
    path_dll = os.path.join(app_path, "utils/jlink", "JLinkARM.dll")

path_dylib = os.path.join(app_path, "utils/jlink", "libjlinkarm.dylib")

try:
    import changeconf as cgc

    conf_sign = True
except ImportError:
    cgc = None
    conf_sign = False

PY2 = sys.version_info[0] == 2

udp_clinet_dict = {}
udp_send_log = False
udp_log_local_echo = False
udp_socket_server = None
error_code_num = "FFFF"
error_code_num_task = ["FFFF"] * 66
local_log_en = True
local_log_data = ""

# all in hex mode
if conf_sign:
    bflb_error_code = {
        "0000": "SUCCESS",
        "0001": "FLASH_INIT_ERROR",
        "0002": "FLASH_ERASE_PARA_ERROR",
        "0003": "FLASH_ERASE_ERROR",
        "0004": "FLASH_WRITE_PARA_ERROR",
        "0005": "FLASH_WRITE_ADDR_ERROR",
        "0006": "FLASH_WRITE_ERROR",
        "0007": "FLASH_BOOT_PARA_ERROR",
        "0008": "FLASH_SET_PARA_ERROR",
        "0009": "FLASH_READ_STATUS_REG_ERROR",
        "000a": "FLASH_WRITE_STATUS_REG_ERROR",
        "000b": "FLASH_DECOMPRESS_WRITE_ERROR",
        "000c": "FLASH_WRITE_XZ_ERROR",
        "000d": "FLASH_SWITCH_BANK_ERROR",
        "0101": "CMD_ID_ERROR",
        "0102": "CMD_LEN_ERROR",
        "0103": "CMD_CRC_ERROR",
        "0104": "CMD_SEQ_ERROR",
        "0201": "IMG_BOOTHEADER_LEN_ERROR",
        "0202": "IMG_BOOTHEADER_NOT_LOAD_ERROR",
        "0203": "IMG_BOOTHEADER_MAGIC_ERROR",
        "0204": "IMG_BOOTHEADER_CRC_ERROR",
        "0205": "IMG_BOOTHEADER_ENCRYPT_NOTFIT",
        "0206": "IMG_BOOTHEADER_SIGN_NOTFIT",
        "0207": "IMG_SEGMENT_CNT_ERROR",
        "0208": "IMG_AES_IV_LEN_ERROR",
        "0209": "IMG_AES_IV_CRC_ERROR",
        "020a": "IMG_PK_LEN_ERROR",
        "020b": "IMG_PK_CRC_ERROR",
        "020c": "IMG_PK_HASH_ERROR",
        "020d": "IMG_SIGNATURE_LEN_ERROR",
        "020e": "IMG_SIGNATURE_CRC_ERROR",
        "020f": "IMG_SECTIONHEADER_LEN_ERROR",
        "0210": "IMG_SECTIONHEADER_CRC_ERROR",
        "0211": "IMG_SECTIONHEADER_DST_ERROR",
        "0212": "IMG_SECTIONDATA_LEN_ERROR",
        "0213": "IMG_SECTIONDATA_DEC_ERROR",
        "0214": "IMG_SECTIONDATA_TLEN_ERROR",
        "0215": "IMG_SECTIONDATA_CRC_ERROR",
        "0216": "IMG_HALFBAKED_ERROR",
        "0217": "IMG_HASH_ERROR",
        "0218": "IMG_SIGN_PARSE_ERROR",
        "0219": "IMG_SIGN_ERROR",
        "021a": "IMG_DEC_ERROR",
        "021b": "IMG_ALL_INVALID_ERROR",
        "0301": "IF_RATE_LEN_ERROR",
        "0302": "IF_RATE_PARA_ERROR",
        "0303": "IF_PASSWORDERROR",
        "0304": "IF_PASSWORDCLOSE",
        "0401": "EFUSE_WRITE_PARA_ERROR",
        "0402": "EFUSE_WRITE_ADDR_ERROR",
        "0403": "EFUSE_WRITE_ERROR",
        "0404": "EFUSE_READ_PARA_ERROR",
        "0405": "EFUSE_READ_ADDR_ERROR",
        "0406": "EFUSE_READ_ERROR",
        "0407": "EFUSE_READ_MAC_ERROR",
        "0408": "EFUSE_WRITE_MAC_ERROR",
        "0501": "MEMORY_WRITE_PARA_ERROR",
        "0502": "MEMORY_WRITE_ADDR_ERROR",
        "0503": "MEMORY_WRITE_ERROR",
        "0504": "MEMORY_READ_PARA_ERROR",
        "0505": "MEMORY_READ_ADDR_ERROR",
        "0506": "MEMORY_READ_ERROR",
        "0508": "REG_WRITE_PARA_ERROR",
        "0509": "REG_WRITE_ADDR_ERROR",
        "050a": "REG_WRITE_ERROR",
        "050b": "REG_READ_PARA_ERROR",
        "050c": "REG_READ_ADDR_ERROR",
        "050d": "REG_READ_ERROR",
        "0601": "ECDH_PARA_ERROR",
        "0602": "ECDH_PRIVATE_KEY_ERROR",
        "0603": "ECDH_SHARED_KEY_ERROR",
        "0604": "ECDH_RANDOM_VAL_ERROR",
        "0605": "ECDH_DECRYPT_ERROR",
        "0606": "ECDH_ENCRYPT_ERROR",
        "fffc": "PLL_ERROR",
        "fffd": "INVASION_ERROR",
        "fffe": "POLLING",
        "ffff": "FAIL",
    }

    eflash_loader_error_code = {
        "0000": "SUCCESS",
        "0001": "EFLASH LOADER HANDSHAKE FAIL",
        "0002": "OPTION SET UNSUPPORTED",
        "0003": "LOAD HELP BIN FAIL",
        "0004": "RESET CPU FAIL",
        "0005": "BURN RETRY FAIL",
        "0006": "LOG READ FAIL",
        "0009": "CONNECT OPENOCD SERVER FAIL",
        "000A": "REPEAT BURN",
        "000B": "CONFIG FILE NOT FOUND",
        "000C": "SET CLOCK PLL FAIL",
        "000D": "SET OPT FINISH FAIL",
        "000E": "IMPORT PACKET FAIL",
        "0020": "EFUSE READ FAIL",
        "0021": "EFUSE WRITE FAIL",
        "0022": "EFUSE COMPARE FAIL",
        "0023": "EFUSE READ MAC ADDR FAIL",
        "0024": "EFUSE WRITE MAC ADDR FAIL",
        "0025": "EFUSE MAC ADDR CRC FAIL",
        "0030": "READ FLASH JEDEC ID FAIL",
        "0031": "READ FLASH STATUS REGISTER FAIL",
        "0032": "WRITE FLASH STATUS REGISTER FAIL",
        "0033": "FLASH CHIP ERASE FAIL",
        "0034": "FLASH ERASE FAIL",
        "0035": "FLASH READ FAIL",
        "0036": "FLASH WRITE FAIL",
        "0037": "FLASH WRITE CHECK FAIL",
        "0038": "FLASH READ SHA FAIL",
        "0039": "FLASH XIP MODE ENTER FAIL",
        "003A": "FLASH XIP MODE EXIT FAIL",
        "003B": "FLASH SET PARA FAIL",
        "003C": "FLASH LOAD FIRMWARE BIN FAIL",
        "003D": "FLASH MATCH TYPE FAIL",
        "003E": "FLASH LOAD VERIFY FAIL",
        "003F": "FLASH BOOT FAIL",
        "0040": "FLASH CFG NOT FIT WITH BOOTHEADER",
        "0041": "FLASH LOAD ROMFS FAIL",
        "0042": "FLASH SWITCH BANK FAIL",
        "0043": "FLASH IDENTIFY FAIL",
        "0044": "FLASH CHIPERASE CONFLICT WITH SKIP MODE",
        "0045": "FLASH SIZE OVER FLOW",
        "0050": "IMG LOAD HANDSHAKE FAIL",
        "0051": "IMG LOAD BOOT CHECK FAIL",
        "0060": "IMG CREATE FAIL",
        "0061": "IMG FILE NOT SET",
        "0062": "IMG ADDR NOT SET",
        "0063": "BOOTINFO ADDR NOT SET",
        "0064": "AES KEY NOT SET",
        "0065": "AES IV  NOT SET",
        "0066": "PUBLIC KEY NOT SET",
        "0067": "PRIVATE KEY NOT SET",
        "0068": "RAW DATA NOT NEED CREATE",
        "0069": "FLASH ID NOT SUPPORT",
        "0070": "FLASH ID NOT FOUND",
        "0071": "ENCRYPT KEY LEN ERROR",
        "0072": "AES IV LEN ERROR",
        "0073": "AES IV SHOULD END WITH 00000000",
        "0074": "IMG TYPE NOT FIT",
        "0075": "IMG CREATE ENTER EXCEPT",
        "0076": "PT NOT SET",
        "0077": "AES KEY DATA OR LEN ERROR",
        "0078": "AES IV DATA OR LEN ERROR",
        "0079": "FACTORY IMG NOT FOUND",
        "007A": "GENERATE ROMFS FAIL",
        "007B": "PT PARCEL IS NULL",
        "007C": "PT TABLE NOT SET",
        "007D": "BOOT2 BIN NOT SET",
        "007E": "FW BIN NOT SET",
        "007F": "MEDIA NOT SET",
        "0080": "ROMFS NOT SET",
        "0081": "MFG BIN NOT SET",
        "0082": "PT CHECK FAIL",
        "0083": "D0 FW BIN NOT SET",
        "0084": "IMTB BIN NOT SET",
        "0085": "IMG LOADER BIN NOT SET",
        "0086": "SBI BIN NOT SET",
        "0087": "KERNEL BIN NOT SET",
        "0088": "ROOTFS BIN NOT SET",
        "0089": "KV BIN NOT SET",
        "0090": "YOCBOOT BIN NOT SET",
        "0091": "DTB BIN NOT SET",
        "FFFF": "BURN RETRY FAIL",
    }
else:
    bflb_error_code = {
        "0000": "BFLB_SUCCESS",
        "0001": "BFLB_FLASH_INIT_ERROR",
        "0002": "BFLB_FLASH_ERASE_PARA_ERROR",
        "0003": "BFLB_FLASH_ERASE_ERROR",
        "0004": "BFLB_FLASH_WRITE_PARA_ERROR",
        "0005": "BFLB_FLASH_WRITE_ADDR_ERROR",
        "0006": "BFLB_FLASH_WRITE_ERROR",
        "0007": "BFLB_FLASH_BOOT_PARA_ERROR",
        "0008": "BFLB_FLASH_SET_PARA_ERROR",
        "0009": "BFLB_FLASH_READ_STATUS_REG_ERROR",
        "000a": "BFLB_FLASH_WRITE_STATUS_REG_ERROR",
        "000b": "BFLB_FLASH_DECOMPRESS_WRITE_ERROR",
        "000c": "BFLB_FLASH_WRITE_XZ_ERROR",
        "000d": "BFLB_FLASH_SWITCH_BANK_ERROR",
        "0101": "BFLB_CMD_ID_ERROR",
        "0102": "BFLB_CMD_LEN_ERROR",
        "0103": "BFLB_CMD_CRC_ERROR",
        "0104": "BFLB_CMD_SEQ_ERROR",
        "0201": "BFLB_IMG_BOOTHEADER_LEN_ERROR",
        "0202": "BFLB_IMG_BOOTHEADER_NOT_LOAD_ERROR",
        "0203": "BFLB_IMG_BOOTHEADER_MAGIC_ERROR",
        "0204": "BFLB_IMG_BOOTHEADER_CRC_ERROR",
        "0205": "BFLB_IMG_BOOTHEADER_ENCRYPT_NOTFIT",
        "0206": "BFLB_IMG_BOOTHEADER_SIGN_NOTFIT",
        "0207": "BFLB_IMG_SEGMENT_CNT_ERROR",
        "0208": "BFLB_IMG_AES_IV_LEN_ERROR",
        "0209": "BFLB_IMG_AES_IV_CRC_ERROR",
        "020a": "BFLB_IMG_PK_LEN_ERROR",
        "020b": "BFLB_IMG_PK_CRC_ERROR",
        "020c": "BFLB_IMG_PK_HASH_ERROR",
        "020d": "BFLB_IMG_SIGNATURE_LEN_ERROR",
        "020e": "BFLB_IMG_SIGNATURE_CRC_ERROR",
        "020f": "BFLB_IMG_SECTIONHEADER_LEN_ERROR",
        "0210": "BFLB_IMG_SECTIONHEADER_CRC_ERROR",
        "0211": "BFLB_IMG_SECTIONHEADER_DST_ERROR",
        "0212": "BFLB_IMG_SECTIONDATA_LEN_ERROR",
        "0213": "BFLB_IMG_SECTIONDATA_DEC_ERROR",
        "0214": "BFLB_IMG_SECTIONDATA_TLEN_ERROR",
        "0215": "BFLB_IMG_SECTIONDATA_CRC_ERROR",
        "0216": "BFLB_IMG_HALFBAKED_ERROR",
        "0217": "BFLB_IMG_HASH_ERROR",
        "0218": "BFLB_IMG_SIGN_PARSE_ERROR",
        "0219": "BFLB_IMG_SIGN_ERROR",
        "021a": "BFLB_IMG_DEC_ERROR",
        "021b": "BFLB_IMG_ALL_INVALID_ERROR",
        "0301": "BFLB_IF_RATE_LEN_ERROR",
        "0302": "BFLB_IF_RATE_PARA_ERROR",
        "0303": "BFLB_IF_PASSWORDERROR",
        "0304": "BFLB_IF_PASSWORDCLOSE",
        "0401": "BFLB_EFUSE_WRITE_PARA_ERROR",
        "0402": "BFLB_EFUSE_WRITE_ADDR_ERROR",
        "0403": "BFLB_EFUSE_WRITE_ERROR",
        "0404": "BFLB_EFUSE_READ_PARA_ERROR",
        "0405": "BFLB_EFUSE_READ_ADDR_ERROR",
        "0406": "BFLB_EFUSE_READ_ERROR",
        "0407": "BFLB_EFUSE_READ_MAC_ERROR",
        "0408": "BFLB_EFUSE_WRITE_MAC_ERROR",
        "0501": "BFLB_MEMORY_WRITE_PARA_ERROR",
        "0502": "BFLB_MEMORY_WRITE_ADDR_ERROR",
        "0503": "BFLB_MEMORY_WRITE_ERROR",
        "0504": "BFLB_MEMORY_READ_PARA_ERROR",
        "0505": "BFLB_MEMORY_READ_ADDR_ERROR",
        "0506": "BFLB_MEMORY_READ_ERROR",
        "0508": "BFLB_REG_WRITE_PARA_ERROR",
        "0509": "BFLB_REG_WRITE_ADDR_ERROR",
        "050a": "BFLB_REG_WRITE_ERROR",
        "050b": "BFLB_REG_READ_PARA_ERROR",
        "050c": "BFLB_REG_READ_ADDR_ERROR",
        "050d": "BFLB_REG_READ_ERROR",
        "0601": "BFLB_ECDH_PARA_ERROR",
        "0602": "BFLB_ECDH_PRIVATE_KEY_ERROR",
        "0603": "BFLB_ECDH_SHARED_KEY_ERROR",
        "0604": "BFLB_ECDH_RANDOM_VAL_ERROR",
        "0605": "BFLB_ECDH_DECRYPT_ERROR",
        "0606": "BFLB_ECDH_ENCRYPT_ERROR",
        "0701": "BFLB_SDCARD_MOUNT_ERROR",
        "0702": "BFLB_SDCARD_FILE_NOT_FOUND_ERROR",
        "0703": "BFLB_SDCARD_READ_LEN_ERROR",
        "0704": "BFLB_SDCARD_READ_ERROR",
        "0901": "BFLB_CODEPATH_CHECK_ERROR",
        "0a01": "BFLB_PASSWORD_LEN_CHECKERROR",
        "0a02": "BFLB_PASSWORD_MODE_NEED_PSW",
        "0a03": "BFLB_PASSWORD_MODE_CLOSE",
        "0b01": "BFLB_MODE_LEN_CHECK_ERROR",
        "0c01": "BFLB_BOOT2_VERSION_CHECK_ERROR",
        "fffc": "BFLB_PLL_ERROR",
        "fffd": "BFLB_INVASION_ERROR",
        "fffe": "BFLB_POLLING",
        "ffff": "BFLB_FAIL",
    }

    eflash_loader_error_code = {
        "0000": "BFLB SUCCESS",
        "0001": "BFLB EFLASH LOADER HANDSHAKE FAIL",
        "0002": "BFLB OPTION SET UNSUPPORTED",
        "0003": "BFLB LOAD HELP BIN FAIL",
        "0004": "BFLB RESET CPU FAIL",
        "0005": "BFLB BURN RETRY FAIL",
        "0006": "BFLB LOG READ FAIL",
        "0009": "BFLB CONNECT OPENOCD SERVER FAIL",
        "000A": "BFLB REPEAT BURN",
        "000B": "BFLB CONFIG FILE NOT FOUND",
        "000C": "BFLB SET CLOCK PLL FAIL",
        "000D": "BFLB SET OPT FINISH FAIL",
        "000E": "BFLB IMPORT PACKET FAIL",
        "0020": "BFLB EFUSE READ FAIL",
        "0021": "BFLB EFUSE WRITE FAIL",
        "0022": "BFLB EFUSE COMPARE FAIL",
        "0023": "BFLB EFUSE READ MAC ADDR FAIL",
        "0024": "BFLB EFUSE WRITE MAC ADDR FAIL",
        "0025": "BFLB EFUSE MAC ADDR CRC FAIL",
        "0030": "BFLB READ FLASH JEDEC ID FAIL",
        "0031": "BFLB READ FLASH STATUS REGISTER FAIL",
        "0032": "BFLB WRITE FLASH STATUS REGISTER FAIL",
        "0033": "BFLB FLASH CHIP ERASE FAIL",
        "0034": "BFLB FLASH ERASE FAIL",
        "0035": "BFLB FLASH READ FAIL",
        "0036": "BFLB FLASH WRITE FAIL",
        "0037": "BFLB FLASH WRITE CHECK FAIL",
        "0038": "BFLB FLASH READ SHA FAIL",
        "0039": "BFLB FLASH XIP MODE ENTER FAIL",
        "003A": "BFLB FLASH XIP MODE EXIT FAIL",
        "003B": "BFLB FLASH SET PARA FAIL",
        "003C": "BFLB FLASH LOAD FIRMWARE BIN FAIL",
        "003D": "BFLB FLASH MATCH TYPE FAIL",
        "003E": "BFLB FLASH LOAD VERIFY FAIL",
        "003F": "BFLB FLASH BOOT FAIL",
        "0040": "BFLB FLASH CFG NOT FIT WITH BOOTHEADER",
        "0041": "BFLB FLASH LOAD ROMFS FAIL",
        "0042": "BFLB FLASH SWITCH BANK FAIL",
        "0043": "BFLB FLASH IDENTIFY FAIL",
        "0044": "BFLB FLASH CHIPERASE CONFLICT WITH SKIP MODE",
        "0045": "BFLB FLASH SIZE OVER FLOW",
        "0050": "BFLB IMG LOAD HANDSHAKE FAIL",
        "0051": "BFLB IMG LOAD BOOT CHECK FAIL",
        "0060": "BFLB IMG CREATE FAIL",
        "0061": "BFLB IMG FILE NOT SET",
        "0062": "BFLB IMG ADDR NOT SET",
        "0063": "BFLB BOOTINFO ADDR NOT SET",
        "0064": "BFLB AES KEY NOT SET",
        "0065": "BFLB AES IV NOT SET",
        "0066": "BFLB PUBLIC KEY NOT SET",
        "0067": "BFLB PRIVATE KEY NOT SET",
        "0068": "BFLB RAW DATA NOT NEED CREATE",
        "0069": "BFLB FLASH ID NOT SUPPORT",
        "0070": "BFLB FLASH ID NOT FOUND",
        "0071": "BFLB ENCRYPT KEY LEN ERROR",
        "0072": "BFLB AES IV LEN ERROR",
        "0073": "BFLB AES IV SHOULD END WITH 00000000",
        "0074": "BFLB IMG TYPE NOT FIT",
        "0075": "BFLB IMG CREATE ENTER EXCEPT",
        "0076": "BFLB PT NOT SET",
        "0077": "BFLB AES KEY DATA OR LEN ERROR",
        "0078": "BFLB AES IV DATA OR LEN ERROR",
        "0079": "BFLB FACTORY IMG NOT FOUND",
        "007A": "BFLB GENERATE ROMFS FAIL",
        "007B": "BFLB PT PARCEL IS NULL",
        "007C": "BFLB PT TABLE NOT SET",
        "007D": "BFLB BOOT2 BIN NOT SET",
        "007E": "BFLB FW BIN NOT SET",
        "007F": "BFLB MEDIA NOT SET",
        "0080": "BFLB ROMFS NOT SET",
        "0081": "BFLB MFG BIN NOT SET",
        "0082": "BFLB PT CHECK FAIL",
        "0083": "D0 FW BIN NOT SET",
        "0084": "IMTB BIN NOT SET",
        "0085": "IMG LOADER BIN NOT SET",
        "0086": "SBI BIN NOT SET",
        "0087": "KERNEL BIN NOT SET",
        "0088": "ROOTFS BIN NOT SET",
        "0089": "KV BIN NOT SET",
        "0090": "YOCBOOT BIN NOT SET",
        "FFFF": "BFLB BURN RETRY FAIL",
    }


def swap_rd_rs2(inst):
    rd = (inst >> 7) & 0x1F
    rs2 = (inst >> 20) & 0x1F
    inst &= 0xFE0FF07F
    inst |= rd << 20
    inst |= rs2 << 7
    return inst


def write32le(buf, index, num):
    buf[0 + index] = num & 0xFF
    buf[1 + index] = (num >> 8) & 0xFF
    buf[2 + index] = (num >> 16) & 0xFF
    buf[3 + index] = (num >> 24) & 0xFF


def read32le(buf, index):
    num = buf[0 + index]
    num |= buf[1 + index] << 8
    num |= buf[2 + index] << 16
    num |= buf[3 + index] << 24
    return num


def riscv_code(buffer, size, now_pos, is_encoder):
    i = 0
    while i + 8 <= size:
        pc = now_pos + i
        inst = read32le(buffer, i)
        if (inst & 0xDFF) == 0x0EF:
            addr = (
                ((inst & 0x80000000) >> 11)
                | ((inst & 0x7FE00000) >> 20)
                | ((inst & 0x00100000) >> 9)
                | (inst & 0x000FF000)
            )
            if not is_encoder:
                pc = 0 - pc
            addr += pc
            inst &= 0xFFF
            inst |= ((addr & 0x100000) << 11) | ((addr & 0x0007FE) << 20) | ((addr & 0x000800) << 9) | (addr & 0x0FF000)
            write32le(buffer, i, inst)
            i += 2
        elif (inst & 0x7F) == 0x17:
            inst2 = read32le(buffer, i + 4)
            if not ((inst2 & 0x5B) == 0x03 or (inst2 & 0x707F) == 0x67 or (inst2 & 0x707F) == 0x13):
                i += 8
                continue
            auipc_rd = (inst >> 7) & 0x1F
            inst2_rs1 = (inst2 >> 15) & 0x1F
            if auipc_rd != inst2_rs1:
                i += 8
                continue
            is_s_type = (inst2 & 0x7B) == 0x23
            if is_encoder and is_s_type:
                inst2 = swap_rd_rs2(inst2)
            if not is_s_type:
                inst2_rd = (inst2 >> 7) & 0x1F
                inst ^= inst2_rd << 7
                inst2 ^= inst2_rd << 15
            addr = (inst & 0xFFFFF000) + (inst2 >> 20) - ((inst2 >> 19) & 0x1000)
            if not is_encoder:
                pc = 0 - pc
            addr += pc
            inst &= 0xFFF
            inst |= (addr + ((addr << 1) & 0x1000)) & 0xFFFFF000
            inst2 &= 0x000FFFFF
            inst2 |= addr << 20
            if not is_encoder and is_s_type:
                inst2 = swap_rd_rs2(inst2)
            write32le(buffer, i, inst)
            write32le(buffer, i + 4, inst2)
            i += 6
        i += 2
    return i


def riscv_encode(bytedata):
    buffer = bytearray()
    buffer.extend(bytedata)
    riscv_code(buffer, len(buffer), 0, True)
    return buffer


def riscv_decode(bytedata):
    buffer = bytearray()
    buffer.extend(bytedata)
    riscv_code(buffer, len(buffer), 0, False)
    return buffer


def convert_path(path: str) -> str:
    return path.replace(r"\/".replace(os.sep, ""), os.sep)


def printf(*args):
    data = ""
    for arg in args:
        data += str(arg)
    # print(data.title())
    # print(data.capitalize())
    if data:
        if conf_sign:
            for key, value in cgc.replace_name_list.items():
                data = data.replace(key, value)
        now_time = datetime.datetime.now().strftime("[%H:%M:%S.%f")[:-3] + "] - "
        data = now_time + data

        # save log
        global local_log_en
        global local_log_data
        if local_log_en is True:
            local_log_data += data + "\n"
        else:
            local_log_data = ""

        if udp_send_log:
            tid = str(threading.get_ident())
            if udp_log_local_echo:
                print("[{0}]{1}".format(tid, data.strip()))
            try:
                if tid in udp_clinet_dict:
                    udp_socket_server.sendto((data.strip() + "\r\n").encode("utf-8"), udp_clinet_dict[tid])  # .lower()
            except Exception as e:
                print(e)
        else:
            if qt_sign and QtCore.QThread.currentThread().objectName():
                print("[Task{0}]{1}".format(QtCore.QThread.currentThread().objectName(), data.strip()))
            else:
                print(data.strip())
    sys.stdout.flush()


def local_log_enable(en=False):
    global local_log_en
    global local_log_data
    if en is True:
        local_log_en = True
    else:
        local_log_en = False


def local_log_save(local_path="log", key_word=""):
    global local_log_en
    global local_log_data
    log_dir = os.path.join(app_path, local_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    if local_log_en is True:
        try:
            rq = time.strftime("%Y%m%d%H%M%S", time.localtime(time.time()))
            log_name = rq + "_" + key_word + ".log"
            log_path = os.path.join(log_dir, log_name)
            with codecs.open(log_path, "w", encoding="utf-8") as fp:
                fp.write(local_log_data)
        except Exception as e:
            printf(e)
            traceback.print_exc(limit=5, file=sys.stdout)
    local_log_data = ""


def set_error_code(num_str, task=None):
    global error_code_num
    global error_code_num_task
    if task is not None:
        if len(error_code_num_task) == 0:
            for _ in range(66):
                error_code_num_task.append("FFFF")
        if error_code_num_task[task] == "FFFF":
            error_code_num_task[task] = num_str
        if num_str == "FFFF":
            error_code_num_task[task] = num_str
    else:
        if error_code_num == "FFFF":
            error_code_num = num_str
        if num_str == "FFFF":
            error_code_num = num_str


def get_error_code(task=None):
    global error_code_num
    global error_code_num_task
    if task is not None:
        return error_code_num_task[task]
    return error_code_num


def get_error_code_bflb(code):
    global bflb_error_code
    return bflb_error_code[code]


def get_error_code_msg(task=None):
    global error_code_num
    global error_code_num_task
    global eflash_loader_error_code
    """
    if task is not None:
        return '{"ErrorCode": "' + error_code_num_task[task] + \
            '", "ErrorMsg":"' + eflash_loader_error_code[error_code_num_task[task]] + '"}'
    return '{"ErrorCode": "' + error_code_num + \
        '", "ErrorMsg":"' + eflash_loader_error_code[error_code_num] + '"}'
    """
    if task is not None:
        return (
            "ErrorCode: "
            + error_code_num_task[task]
            + " ErrorMsg: "
            + eflash_loader_error_code[error_code_num_task[task]]
        )
    return "ErrorCode: " + error_code_num + ", ErrorMsg: " + eflash_loader_error_code[error_code_num]


def enable_udp_send_log(local_echo):
    global udp_send_log, udp_socket_server, udp_log_local_echo
    udp_send_log = True
    udp_log_local_echo = local_echo
    udp_socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def add_udp_client(tid, upd_client):
    udp_clinet_dict[tid] = upd_client


def remove_udp_client(tid):
    del udp_clinet_dict[tid]


def str_endian_switch(string):
    s = string[6:8] + string[4:6] + string[2:4] + string[0:2]
    return s


def verify_hex_num(string):
    length = len(string)
    i = 0
    while True:
        if re.match("\A[0-9a-fA-F]+\Z", string[i : i + 1]) is None:
            return False
        i += 1
        if i >= length:
            break
    return True


def hexstr_to_bytearray(hexstring):
    return bytearray.fromhex(hexstring)


def hexstr_to_bytearray_l(hexstring):
    b = bytearray.fromhex(hexstring)
    b.reverse()
    return b


# 12345678->0x12,0x34,0x56,0x78
def hexstr_to_bytearray_b(hexstring):
    return bytearray.fromhex(hexstring)


def int_to_2bytearray_l(intvalue):
    return struct.pack("<H", intvalue)


def int_to_2bytearray_b(intvalue):
    return struct.pack(">H", intvalue)


def int_to_4bytearray_l(intvalue):
    src = bytearray(4)
    src[3] = (intvalue >> 24) & 0xFF
    src[2] = (intvalue >> 16) & 0xFF
    src[1] = (intvalue >> 8) & 0xFF
    src[0] = (intvalue >> 0) & 0xFF
    return src


def int_to_4bytearray_b(intvalue):
    val = int_to_4bytearray_l(intvalue)
    val.reverse()
    return val


def bytearray_reverse(a):
    length = len(a)
    b = bytearray(length)
    i = 0
    while i < length:
        b[i] = a[length - i - 1]
        i = i + 1
    return b


def bytearray_to_int(b):
    return int(binascii.hexlify(b), 16)


def bytearray_to_string(bytesarray):
    return str(bytesarray)


def string_to_bytearray(string):
    return bytes(string, encoding="utf8")


def string_number_reverse(str_number):
    """
    high position low data
    data unit number:00000280
    storage format:  80020000
    """
    reverse_str = ""
    if len(str_number) == 8:
        str_part1 = str_number[0:2]
        str_part2 = str_number[2:4]
        str_part3 = str_number[4:6]
        str_part4 = str_number[6:8]
        reverse_str = str_part4 + str_part3 + str_part2 + str_part1
    return reverse_str


def get_random_hexstr(n_bytes):
    hextring = ""
    i = 0
    while i < n_bytes:
        hextring = hextring + "%02X" % random.randint(0, 255)
        i = i + 1
    return hextring


def get_crc32_bytearray(data):
    crc = binascii.crc32(data)
    return int_to_4bytearray_l(crc)


def fill_to_16(par):
    while len(par) % 16 != 0:
        par += b"\x00"
    return par


# do hash of image
def img_create_sha256_data(data_bytearray):
    hashfun = hashlib.sha256()
    hashfun.update(data_bytearray)
    return hexstr_to_bytearray(hashfun.hexdigest())


# encrypt image, mainly segdata
def img_create_encrypt_data(data_bytearray, key_bytearray, iv_bytearray, flash_img):
    if flash_img == 0:
        # 创建 AES-CBC加密器
        cipher = Cipher(algorithms.AES(key_bytearray), modes.CBC(iv_bytearray))
        encryptor = cipher.encryptor()
        # 加密数据
        ciphertext = encryptor.update(data_bytearray) + encryptor.finalize()
    else:
        # 创建 AES-CTR加密器
        cipher = Cipher(algorithms.AES(key_bytearray), modes.CTR(iv_bytearray))
        encryptor = cipher.encryptor()
        # 加密数据
        ciphertext = encryptor.update(data_bytearray) + encryptor.finalize()
    return ciphertext


# decrypt image, mainly segdata
def img_create_decrypt_data(data_bytearray, key_bytearray, iv_bytearray, flash_img):
    if flash_img == 0:
        # 创建 AES-CBC解密器
        cipher = Cipher(algorithms.AES(key_bytearray), modes.CBC(iv_bytearray))
        decryptor = cipher.decryptor()
        # 解密数据
        plaintext = decryptor.update(data_bytearray) + decryptor.finalize()
    else:
        # 创建 AES-CTR解密器
        cipher = Cipher(algorithms.AES(key_bytearray), modes.CTR(iv_bytearray))
        decryptor = cipher.decryptor()
        # 解密数据
        plaintext = decryptor.update(data_bytearray) + decryptor.finalize()
    return plaintext


def img_create_encrypt_data_xts(data_bytearray, key_bytearray, iv_bytearray, encrypt):
    counter = binascii.hexlify(iv_bytearray[4:16]).decode()
    # data unit number default value is 0
    data_unit_number = 0

    key = (key_bytearray[0:16], key_bytearray[16:32])
    if encrypt == 2 or encrypt == 3:
        key = (key_bytearray, key_bytearray)
    total_len = len(data_bytearray)
    ciphertext = bytearray(0)
    deal_len = 0

    while deal_len < total_len:
        data_unit_number = str(hex(data_unit_number)).replace("0x", "")
        data_unit_number_to_str = str(data_unit_number)
        right_justify_str = data_unit_number_to_str.rjust(8, "0")
        reverse_data_unit_number_str = string_number_reverse(right_justify_str)
        tweak = reverse_data_unit_number_str + counter
        tweak = hexstr_to_bytearray("0" * (32 - len(tweak)) + tweak)
        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
        encryptor = cipher.encryptor()
        if 32 + deal_len <= total_len:
            cur_block = data_bytearray[0 + deal_len : 32 + deal_len]
            ciphertext += encryptor.update(cur_block) + encryptor.finalize()
        else:
            cur_block = data_bytearray[0 + deal_len : 16 + deal_len] + bytearray(16)
            ciphertext += (encryptor.update(cur_block) + encryptor.finalize())[0:16]
        deal_len += 32
        data_unit_number = int(data_unit_number, 16)
        data_unit_number += 1

    return ciphertext


def get_security_key():
    # b'BOUFFALOLABKEYIV'
    key_hex = "424F554646414C4F4C41424B45594956"
    # b'BOUFFALOLABK\x00\x00\x00\x00'
    iv_hex = "424F554646414C4F4C41424B00000000"
    return hexstr_to_bytearray(key_hex), hexstr_to_bytearray(iv_hex)


def get_aes_encrypted_security_key(cfg):
    # b"BOUFFALOLABKEY\x00\x00"
    key_hex = "424f554646414c4f4c41424b45590000"
    # b"BOUFFALOLABIV\x00\x00\x00"
    iv_hex = "424f554646414c4f4c41424956000000"
    try:
        key_bytearray = hexstr_to_bytearray(key_hex)
        iv_bytearray = hexstr_to_bytearray(iv_hex)
        with open(cfg, mode="rb") as fp:
            data_bytearray = fp.read()
        # 创建 AES-CBC解密器
        cipher = Cipher(algorithms.AES(key_bytearray), modes.CBC(iv_bytearray))
        decryptor = cipher.decryptor()
        # 解密数据
        plaintext = decryptor.update(data_bytearray) + decryptor.finalize()
        if len(plaintext) == 32:
            return True, plaintext[0:16], plaintext[16:32]
        else:
            return False, None, None
    except Exception:
        return False, None, None


def get_eflash_loader(xtal):
    xtal_suffix = str(xtal).lower().replace(".", "p").replace("M", "m").replace("RC", "rc")
    return "eflash_loader_" + xtal_suffix + ".bin"


def open_file(file, mode="rb"):
    fp = open(os.path.join(app_path, file), mode)
    return fp


def copy_file(srcfile, dstfile):
    if os.path.isfile(srcfile):
        fpath, fname = os.path.split(dstfile)
        if not os.path.exists(fpath):
            os.makedirs(fpath)
        shutil.copyfile(srcfile, dstfile)
    else:
        printf("Src file does not exist")
        # sys.exit()


def update_cfg(cfg, section, key, value):
    if cfg.has_option(section, key):
        cfg.set(section, key, str(value))


def get_systype():
    type_ = platform.system().lower()
    arch = platform.machine().lower()
    if type_ == "windows":
        arch = "amd64" if platform.architecture()[0] == "64bit" else "x86"
    return "%s_%s" % (type_, arch) if arch else type_


def get_serial_ports():
    try:
        # pylint: disable=import-outside-toplevel
        from serial.tools.list_ports import comports
    except ImportError:
        return None

    WINDOWS = sys.platform.startswith("win")
    result = []
    for p, d, h in comports():
        if not p:
            continue
        if WINDOWS and PY2:
            try:
                # pylint: disable=undefined-variable
                d = unicode(d, errors="ignore")
            except TypeError:
                pass
        if "VID:PID" in h:
            result.append({"port": p, "description": d, "hwid": h})

    # fix for PySerial
    if not result and "darwin" in get_systype():
        for p in glob("/dev/tty.*"):
            result.append({"port": p, "description": "n/a", "hwid": "n/a"})
    return result


def serial_enumerate():
    prog_ports = []
    sdio_ports = []
    sdio_file_ser_dict = {}
    uart_ports = []
    file_dict = {}
    ports = []
    if sys.platform.startswith("win"):
        for p, d, h in comports():
            if "Virtual" in d or not p:
                if "STM" not in d:
                    continue
            if "PID=1D6B" in h.upper():
                ser_value = h.split(" ")[2][4:]
                if ser_value not in sdio_file_ser_dict:
                    # sdio_ports.append(p+" (SDIO)")
                    sdio_file_ser_dict[ser_value] = p
                else:
                    if "LOCATION" in h.upper():
                        file_dict[sdio_file_ser_dict[ser_value]] = p
                        sdio_ports.append(sdio_file_ser_dict[ser_value] + " (SDIO)")
                    else:
                        file_dict[p] = sdio_file_ser_dict[ser_value]
                        sdio_ports.append(p + " (SDIO)")
            else:
                if "FACTORYAIOT_PROG" in h.upper() or "PID=42BF:B210" in h.upper():
                    prog_ports.append(p + " (PROG)")
                else:
                    uart_ports.append(p)
        try:
            uart_ports = sorted(uart_ports, key=lambda x: int(re.match("COM(\d+)", x).group(1)))
        except Exception:
            uart_ports = sorted(uart_ports)
        ports = sorted(prog_ports) + sorted(sdio_ports) + uart_ports
    elif sys.platform.startswith("linux"):
        for p, d, h in comports():
            if not p:
                continue
            if "PID=1D6B" in h.upper():
                ser_value = h.split(" ")[2][4:]
                if ser_value not in sdio_file_ser_dict:
                    sdio_file_ser_dict[ser_value] = p
                else:
                    if sdio_file_ser_dict[ser_value] > p:
                        file_dict[p] = sdio_file_ser_dict[ser_value]
                        sdio_ports.append(p + " (SDIO)")
                    else:
                        file_dict[sdio_file_ser_dict[ser_value]] = p
                        sdio_ports.append(sdio_file_ser_dict[ser_value] + " (SDIO)")
            else:
                if "FACTORYAIOT PROG" in h.upper():
                    prog_ports.append(p + " (PROG)")
                else:
                    uart_ports.append(p)
        ports = sorted(prog_ports) + sorted(sdio_ports) + sorted(uart_ports)
    elif sys.platform.startswith("darwin"):
        for dev in glob("/dev/tty.usb*"):
            ports.append(dev)
    return ports


def pylink_enumerate():
    try:
        if sys.platform == "win32":
            obj_dll = pylink.Library(dllpath=path_dll)
            obj = pylink.JLink(lib=obj_dll)
        elif sys.platform.startswith("darwin"):
            obj_dylib = pylink.Library(dllpath=path_dylib)
            obj = pylink.JLink(lib=obj_dylib)
        else:
            obj = pylink.JLink()
    except Exception:
        return []
    else:
        return obj.connected_emulators()


def cklink_openocd_enumerate():
    ports_cklink = []
    ports_openocd = []
    if sys.platform.startswith("win"):
        for p, d, h in comports():
            if not p:
                continue
            elif "FACTORYAIOT_PROG" in h.upper():
                match1 = re.search("FACTORYAIOT_PROG_([a-zA-Z0-9]{6}) LOCATION", h.upper(), re.I)
                match2 = re.search("FACTORYAIOT_PROG_([a-zA-Z0-9]{6})$", h.upper(), re.I)
                if match1 is not None:
                    ports_cklink.append(match1.group(1))
                if match2 is not None:
                    ports_openocd.append(match2.group(1))
            else:
                match = re.search("SER=([A-Z0-9]{1,23}) LOCATION", h.upper(), re.I)
                if match is not None:
                    ports_cklink.append(match.group(1))
    elif sys.platform.startswith("linux"):
        for p, d, h in comports():
            if not p:
                continue
            elif "FactoryAIOT Prog" in h:
                match1 = re.search("FactoryAIOT Prog ([a-zA-Z0-9]{6}) LOCATION", h, re.I)
                if match1 is not None:
                    ports_cklink.append(match1.group(1))
    ports_openocd.sort()
    ports_cklink.sort()
    return ports_cklink, ports_openocd


def firmware_auxiliary_parser_init():
    parser = argparse.ArgumentParser(description="bouffalolab image auxiliary command")
    parser.add_argument("--wdir", dest="wdir", help="sdk work directory")
    parser.add_argument("--imgfile", dest="imgfile", help="image file")
    return parser


def image_create_parser_init():
    parser = argparse.ArgumentParser(description="bouffalolab image create command")
    parser.add_argument("--chipname", dest="chipname", help="chip name")
    parser.add_argument("--imgfile", dest="imgfile", help="image file")
    parser.add_argument("--security", dest="security", help="security save efusedata")
    parser.add_argument("-i", "--image", dest="image", help="image type: media or if")
    parser.add_argument("-c", "--cpu", dest="cpu", help="cpu type: cpu0 cpu1 or all")
    parser.add_argument("-g", "--group", dest="group", help="group type")
    parser.add_argument("-s", "--signer", dest="signer", help="signer")
    return parser


def eflash_loader_parser_init():
    parser = argparse.ArgumentParser(description="bouffalolab eflash loader command")
    parser.add_argument("--chipname", dest="chipname", help="chip name")
    parser.add_argument("--chipid", dest="chipid", action="store_true", help="chip id")
    parser.add_argument("--usage", dest="usage", action="store_true", help="display usage")
    parser.add_argument("--flash", dest="flash", action="store_true", help="target is flash")
    parser.add_argument("--efuse", dest="efuse", action="store_true", help="target is efuse")
    parser.add_argument("--ram", dest="ram", action="store_true", help="target is ram")
    parser.add_argument("--efusecheck", dest="efusecheck", action="store_true", help="efuse check data")
    parser.add_argument("-w", "--write", dest="write", action="store_true", help="write to flash/efuse")
    parser.add_argument("-e", "--erase", dest="erase", action="store_true", help="erase flash")
    parser.add_argument("-r", "--read", dest="read", action="store_true", help="read from flash/efuse")
    parser.add_argument("-n", "--none", dest="none", action="store_true", help="eflash loader environment init")
    parser.add_argument("-p", "--port", dest="port", help="serial port to use")
    parser.add_argument("-b", "--baudrate", dest="baudrate", type=int, help="the speed at which to communicate")
    parser.add_argument("-c", "--config", dest="config", help="eflash loader config file")
    parser.add_argument("-i", "--interface", dest="interface", help="interface type: uart/jlink/openocd")
    parser.add_argument("--xtal", dest="xtal", help="xtal type")
    parser.add_argument("--start", dest="start", help="start address")
    parser.add_argument("--end", dest="end", help="end address")
    parser.add_argument("--addr", dest="addr", help="address to write")
    parser.add_argument("--mac", dest="mac", nargs="?", const=True, default=False)
    parser.add_argument("--file", dest="file", help="file to store read data or file to write")
    parser.add_argument("--skip", dest="skip", help="skip write file to flash")
    parser.add_argument("--packet", dest="packet", help=" import packet to replace burn file")
    parser.add_argument("--efusefile", dest="efusefile", help="efuse file to write efuse")
    parser.add_argument("--data", dest="data", help="data to write")
    parser.add_argument("--data_encrypted", dest="data_encrypted", help="encrypted data to write")
    parser.add_argument("--mass", dest="mass", help="load mass bin")
    parser.add_argument("--loadstr", dest="loadstr", help="")
    parser.add_argument("--loadfile", dest="loadfile", help="")
    parser.add_argument("--userarea", dest="userarea", help="user area")
    parser.add_argument("--romfs", dest="romfs", help="romfs data to write")
    parser.add_argument("--csvfile", dest="csvfile", help="csv file contains 3/5 tuples")
    parser.add_argument("--csvaddr", dest="csvaddr", help="address to write for csv file")
    parser.add_argument("--para", dest="para", action="store_true", help="efuse para")
    parser.add_argument("--isp", dest="isp", action="store_true", help="isp config")
    parser.add_argument("--createcfg", dest="createcfg", help="img create cfg file")
    parser.add_argument("--key", dest="key", help="encrypt aes key")
    parser.add_argument("--iv", dest="iv", help="encrypt aes iv")
    parser.add_argument("--publickey", dest="publickey", help="signature public key")
    parser.add_argument("--privatekey", dest="privatekey", help="signature private key")
    parser.add_argument("--ecdh", dest="ecdh", action="store_true", help="open ecdh function")
    parser.add_argument("--echo", dest="echo", action="store_true", help="open local log echo")
    parser.add_argument("-a", "--auto", dest="auto", action="store_true", help="auto flash")
    parser.add_argument("--dac_value", dest="dac_value", help="dac value")
    parser.add_argument("--dac_addr", dest="dac_addr", help="dac address")
    parser.add_argument("--dac_key", dest="dac_key", help="dac encrpt key")
    parser.add_argument("--dac_iv", dest="dac_iv", help="dac encrypt iv")
    parser.add_argument("--auth", dest="auth", help="auth port")
    parser.add_argument(
        "--auto_efuse_verify",
        action="store_true",
        dest="auto_efuse_verify",
        help="auto efuse verify",
    )
    parser.add_argument("-v", "--version", dest="version", action="store_true", help="display version")
    return parser
