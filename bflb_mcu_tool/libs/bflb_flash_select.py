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

import os
import re

import config as gol
from libs import bflb_utils
from libs.bflb_utils import app_path, chip_path, conf_sign
from libs.bflb_configobj import BFConfigParser


def get_int_mask(pos, length):
    ones = "1" * 32
    zeros = "0" * 32
    mask = ones[0 : 32 - pos - length] + zeros[0:length] + ones[0:pos]
    return int(mask, 2)


def get_suitable_file_name(cfg_dir, flash_id):
    conf_files = []
    for home, dirs, files in os.walk(cfg_dir):
        for filename in files:
            if filename.split("_")[-1] == flash_id + ".conf":
                conf_files.append(filename)

    if len(conf_files) > 1:
        bflb_utils.printf("Flash id duplicate and alternative is:")
        for i in range(len(conf_files)):
            tmp = conf_files[i].split(".")[0]
            bflb_utils.printf("%d:%s" % (i + 1, tmp))
        return conf_files[i]
    elif len(conf_files) == 1:
        return conf_files[0]
    else:
        return ""


def get_supported_flash(chiptype):
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])
    return sub_module.flash_select_do.get_supported_flash_do()


def check_basic_flash_cfg(cfg_file, section):
    if os.path.isfile(cfg_file) is False:
        return False
    cfg = BFConfigParser()
    cfg.read(cfg_file)
    if cfg.has_option(section, "mfg_id"):
        if cfg.get(section, "mfg_id") == "0xff" or cfg.get(section, "mfg_id") == "0xFF":
            cfg.set(section, "io_mode", "0x11")
            cfg.set(section, "cont_read_support", "0")
            cfg.set(section, "cont_read_code", "0xff")
            cfg.write(cfg_file, "w+")
            return True
        if cfg.get(section, "mfg_id") == "0x00":
            return True
    return False


def update_flash_para_from_cfg(config_keys, config_file):
    section = "FLASH_CFG"
    cfg = BFConfigParser()
    cfg.read(config_file)
    # get finally data len
    filelen = 0
    offset = 0
    min_offset = 0xFFFFFFFF
    max_offset = 0
    flash_crc_offset = 0
    crc_offset = 0
    if config_keys.get("crc32") is not None:
        crc_offset = int(config_keys.get("crc32")["offset"], 10)
    if config_keys.get("flashcfg_crc32") is not None:
        flash_crc_offset = int(config_keys.get("flashcfg_crc32")["offset"], 10)
    for key in cfg.options(section):
        if config_keys.get(key) is None:
            continue
        offset = int(config_keys.get(key)["offset"], 10)
        if offset < min_offset:
            min_offset = offset
        if offset > max_offset:
            max_offset = offset
    filelen = max_offset - min_offset + 4
    data = bytearray(filelen)
    # bflb_utils.printf(binascii.hexlify(data))
    for key in cfg.options(section):
        if config_keys.get(key) is None:
            bflb_utils.printf(key, " does not exist")
            continue
        # bflb_utils.printf(key)
        val = cfg.get(section, key)
        if val.startswith("0x"):
            val = int(val, 16)
        else:
            val = int(val, 10)
        # bflb_utils.printf(val)
        offset = int(config_keys.get(key)["offset"], 10) - min_offset
        pos = int(config_keys.get(key)["pos"], 10)
        bitlen = int(config_keys.get(key)["bitlen"], 10)

        oldval = bflb_utils.bytearray_to_int(bflb_utils.bytearray_reverse(data[offset : offset + 4]))
        newval = (oldval & get_int_mask(pos, bitlen)) + (val << pos)
        # bflb_utils.printf(newval, binascii.hexlify(bflb_utils.int_to_4bytearray_l(newval)))
        data[offset : offset + 4] = bflb_utils.int_to_4bytearray_l(newval)
    # bflb_utils.printf(binascii.hexlify(data))
    return min_offset, filelen, data, flash_crc_offset, crc_offset


def update_flash_cfg_data_do(chipname, chiptype, flash_id):
    if conf_sign:
        cfg_dir = app_path + "/utils/flash/" + chipname + "/"
    else:
        cfg_dir = app_path + "/utils/flash/" + gol.flash_dict[chipname] + "/"
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])
    # conf_name = sub_module.flash_select_do.get_suitable_file_name(cfg_dir, flash_id)
    conf_name = get_suitable_file_name(cfg_dir, flash_id)
    if os.path.isfile(cfg_dir + conf_name) is False:
        return None, None, None, None, None
    return update_flash_para_from_cfg(sub_module.bootheader_cfg_keys.bootheader_cfg_keys, cfg_dir + conf_name)


def update_flash_cfg_data(chipname, chiptype, flash_id, cfg, bh_cfg_file, cfg_key):
    cfg2 = BFConfigParser()
    cfg2.read(bh_cfg_file)
    magic_code = cfg2.get(cfg_key, "magic_code")
    magic_code = int(magic_code, 16)
    flash_magic_code = cfg2.get(cfg_key, "flashcfg_magic_code")
    flash_magic_code = int(flash_magic_code, 16)
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])
    offset, flash_cfg_len, data, flash_crc_offset, crc_offset = update_flash_cfg_data_do(chipname, chiptype, flash_id)

    para_file = cfg.get("FLASH_CFG", "flash_para")
    if para_file != "":
        with open(os.path.join(app_path, para_file), "wb") as fp:
            fp.write(data)

    flash_file = re.compile("\\s+").split(cfg.get("FLASH_CFG", "file"))
    for f in flash_file:
        with open(os.path.join(app_path, f), "rb") as fp:
            rdata = bytearray(fp.read())
            i = 0
            length = len(rdata)
            while i < length:
                if rdata[i : i + 4] == bflb_utils.int_to_4bytearray_l(magic_code):
                    if rdata[i + 8 : i + 12] == bflb_utils.int_to_4bytearray_l(flash_magic_code):
                        data[2:4] = rdata[i + 14 : i + 16]
                        flash_cfg = rdata[i + offset : i + offset + flash_cfg_len]
                        if data != flash_cfg:
                            return False
                i += 4
    return True


def update_flash_cfg(chipname, chiptype, flash_id, file=None, create=False, section=None):
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])
    if check_basic_flash_cfg(file, section):
        return True
    if sub_module.flash_select_do.update_flash_cfg_do(chipname, chiptype, flash_id, file, create, section) is False:
        return False
    return True


def flash_bootheader_config_check(chipname, chiptype, flashid, file, parafile):
    magic_code = 0x504E4642
    flash_magic_code = 0x47464346
    offset, flash_cfg_len, data, flash_crc_offset, crc_offset = update_flash_cfg_data_do(chipname, chiptype, flashid)
    if data is None:
        offset = 12
        flash_cfg_len = 84

    if parafile != "" and data is not None:
        with open(os.path.join(app_path, parafile), "wb") as fp:
            fp.write(data)

    with open(os.path.join(app_path, file), "rb") as fp:
        rdata = bytearray(fp.read())
    i = 0
    length = 128
    flash_cfg = bytearray(256)
    while i < length:
        if rdata[i : i + 4] == bflb_utils.int_to_4bytearray_l(magic_code):
            if rdata[i + 8 : i + 12] == bflb_utils.int_to_4bytearray_l(flash_magic_code):
                if data is not None:
                    data[2:4] = rdata[i + 14 : i + 16]
                flash_cfg = rdata[i + offset : i + offset + flash_cfg_len]
                if data is not None:
                    if data != flash_cfg:
                        if flash_cfg[13:14] != b"\xff" and flash_cfg[13:14] != b"\x00":
                            return False
                else:
                    if flash_cfg[13:14] != b"\xff" and flash_cfg[13:14] != b"\x00":
                        return False
        i += 4
    return True
