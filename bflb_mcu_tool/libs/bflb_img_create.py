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
import os
import sys
import time
import shutil
import zipfile

try:
    import bflb_path
except ImportError:
    from libs import bflb_path
from libs import bflb_utils
from libs import bflb_efuse_boothd_create
from libs.bflb_utils import app_path, chip_path, set_error_code, convert_path
from libs.bflb_configobj import BFConfigParser


def take_second(elem):
    return elem[1]


def factory_mode_set(file, value):
    cfg = BFConfigParser()
    cfg.read(file)
    if cfg.has_option("EFUSE_CFG", "factory_mode"):
        cfg.set("EFUSE_CFG", "factory_mode", value)
        cfg.write(file, "w")


def check_pt_file(file, addr):
    if len(file) > 0:
        i = 0
        L = []
        if len(file) > len(addr):
            bflb_utils.printf("error: tool path contains spaces")
            return False
        while i < len(file):
            L.append([convert_path(file[i]), int(addr[i], 16)])
            i += 1
        L.sort(key=take_second)
        i = 0
        try:
            while i < len(L) - 1:
                address = L[i][1]
                address_next = L[i + 1][1]
                file_size = os.path.getsize(os.path.join(app_path, L[i][0]))
                if address_next < address + file_size:
                    bflb_utils.printf(
                        "pt check fail, %s is overlayed with %s in flash layout, please check your partition table to fix this issue"
                        % (L[i][0], L[i + 1][0])
                    )
                    return False
                i += 1
        except Exception as e:
            bflb_utils.printf(e)
            return False
    return True


def compress_dir(chipname, zippath, efuse_load=False):
    zip_file = os.path.join(chip_path, chipname, zippath, "whole_img.pack")
    dir_path = os.path.join(chip_path, chipname, chipname)
    cfg_file = os.path.join(chip_path, chipname, "eflash_loader/eflash_loader_cfg.ini")
    cfg = BFConfigParser()
    cfg.read(cfg_file)
    flash_file = re.compile("\\s+").split(cfg.get("FLASH_CFG", "file"))
    address = re.compile("\\s+").split(cfg.get("FLASH_CFG", "address"))
    if check_pt_file(flash_file, address) is not True:
        bflb_utils.printf("partition table check failed")
        set_error_code("0082")
        return False
    flash_file.append(os.path.join(chip_path, chipname, "eflash_loader", "eflash_loader_cfg.ini"))
    if efuse_load:
        flash_file.append(cfg.get("EFUSE_CFG", "file"))
        flash_file.append(cfg.get("EFUSE_CFG", "maskfile"))
    if len(flash_file) > 0:
        i = 0
        try:
            while i < len(flash_file):
                relpath = os.path.relpath(os.path.join(app_path, convert_path(flash_file[i])), chip_path)
                dir = os.path.join(chip_path, chipname, relpath)
                if os.path.isdir(os.path.dirname(dir)) is False:
                    os.makedirs(os.path.dirname(dir))
                shutil.copyfile(os.path.join(app_path, convert_path(flash_file[i])), dir)
                i += 1
            verfile = os.path.join(chip_path, chipname, chipname, "version.txt")
            with open(verfile, mode="w") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        except Exception as e:
            bflb_utils.printf(e)
            factory_mode_set(os.path.join(chipname, "eflash_loader/eflash_loader_cfg.ini"), "false")
            return False

    try:
        z = zipfile.ZipFile(zip_file, "w")
        for dirpath, dirnames, filenames in os.walk(dir_path):
            for file in filenames:
                z.write(
                    os.path.join(dirpath, file),
                    os.path.relpath(os.path.join(dirpath, file), os.path.join(chip_path, chipname)),
                )
        z.close()
        shutil.rmtree(dir_path)
    except Exception as e:
        bflb_utils.printf(e)
        factory_mode_set(os.path.join(chipname, "eflash_loader/eflash_loader_cfg.ini"), "false")
        return False
    factory_mode_set(os.path.join(chipname, "eflash_loader/eflash_loader_cfg.ini"), "false")
    return True


def compress_dir_iot(chipname, outdir, efuse_load=False):
    zip_file = os.path.join(outdir, "whole_img.pack")
    dir_path = os.path.join(outdir, chipname)
    cfg_file = os.path.join(chip_path, chipname, "eflash_loader/eflash_loader_cfg.ini")
    cfg = BFConfigParser()
    cfg.read(cfg_file)
    flash_file = re.compile("\\s+").split(cfg.get("FLASH_CFG", "file"))
    address = re.compile("\\s+").split(cfg.get("FLASH_CFG", "address"))
    if check_pt_file(flash_file, address) is not True:
        bflb_utils.printf("partition table check failed")
        set_error_code("0082")
        return False
    flash_file.append(os.path.join(chip_path, chipname, "eflash_loader", "eflash_loader_cfg.ini"))
    if efuse_load:
        flash_file.append(cfg.get("EFUSE_CFG", "file"))
        flash_file.append(cfg.get("EFUSE_CFG", "maskfile"))
    if len(flash_file) > 0:
        i = 0
        try:
            while i < len(flash_file):
                if os.path.exists(flash_file[i]):
                    filedir = convert_path(flash_file[i])
                    filename = os.path.basename(filedir)
                    suffix = filedir.split(".")[-1]
                    if suffix == "bin" and filename not in [
                        "partition.bin",
                        "efusedata.bin",
                        "efusedata_mask.bin",
                    ]:
                        dir = os.path.join(outdir, chipname, "img_create_iot", filename)
                    else:
                        relpath = os.path.relpath(os.path.join(app_path, convert_path(flash_file[i])), chip_path)
                        dir = os.path.join(outdir, relpath)
                    if os.path.isdir(os.path.dirname(dir)) is False:
                        os.makedirs(os.path.dirname(dir))
                    shutil.copyfile(os.path.join(app_path, convert_path(flash_file[i])), dir)
                    if filename in ["efusedata.bin", "efusedata_mask.bin"]:
                        shutil.copyfile(
                            os.path.join(app_path, convert_path(flash_file[i])),
                            os.path.join(outdir, filename),
                        )
                i += 1
            ver_file = os.path.join(dir_path, "version.txt")
            with open(ver_file, mode="w") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        except Exception as e:
            bflb_utils.printf(e)
            factory_mode_set(os.path.join(chipname, "eflash_loader/eflash_loader_cfg.ini"), "false")
            return False

    try:
        z = zipfile.ZipFile(zip_file, "w")
        for dirpath, dirnames, filenames in os.walk(dir_path):
            for file in filenames:
                if file == "eflash_loader_cfg.ini":
                    cfg_file = os.path.join(dirpath, file)
                    cfg = BFConfigParser()
                    cfg.read(cfg_file)
                    flash_file = re.compile("\\s+").split(cfg.get("FLASH_CFG", "file"))
                    list_file = []
                    for item in flash_file:
                        filedir = convert_path(item)
                        filename = os.path.basename(filedir)
                        suffix = filedir.split(".")[-1]
                        if suffix == "bin" and filename != "partition.bin":
                            item = "chips/" + chipname + "/img_create_iot/" + filename
                        list_file.append(item)
                    files_str = " ".join(list_file)
                    cfg.set("FLASH_CFG", "file", files_str)
                    cfg.write(cfg_file, "w")
                z.write(
                    os.path.join(dirpath, file),
                    os.path.relpath(os.path.join(dirpath, file), outdir),
                )
        z.close()
        shutil.rmtree(dir_path)
    except Exception as e:
        bflb_utils.printf(e)
        factory_mode_set(os.path.join(chipname, "eflash_loader", "eflash_loader_cfg.ini"), "false")
        return False
    factory_mode_set(os.path.join(chipname, "eflash_loader", "eflash_loader_cfg.ini"), "false")
    return True


def get_img_offset(chiptype="bl60x", bootheader_data=None):
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])
    return sub_module.img_create_do.img_create_get_img_offset(bootheader_data)


def encrypt_loader_bin(chiptype, file, sign, encrypt, key, iv, publickey, privatekey, **kwargs):
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])
    return sub_module.img_create_do.encrypt_loader_bin_do(file, sign, encrypt, key, iv, publickey, privatekey, **kwargs)


def create_sp_media_image_file(config, chiptype="bl60x", cpu_type=None, security=False, **kwargs):
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])
    sub_module.img_create_do.create_sp_media_image(config, cpu_type, security, **kwargs)


def create_security_efuse(chiptype, key, sel):
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])

    if chiptype == "bl808" or chiptype == "bl616" or chiptype == "bl628":
        efuse_data = bytearray(256)
        mask_data = bytearray(256)
        img_update_efuse_fun = sub_module.img_create_do.img_update_efuse_group0
    else:
        efuse_data = bytearray(128)
        mask_data = bytearray(128)
        img_update_efuse_fun = sub_module.img_create_do.img_update_efuse

    efuse_data, mask_data = img_update_efuse_fun(None, 0, None, 0, None, sel, key, True)
    for num in range(0, len(efuse_data)):
        if efuse_data[num] != 0:
            mask_data[num] |= 0xFF

    return efuse_data, mask_data


def img_create(args, chipname="bl60x", chiptype="bl60x", img_dir=None, config_file=None, **kwargs):
    sub_module = __import__("libs." + chiptype, fromlist=[chiptype])
    img_dir_path = os.path.join(chip_path, chipname, "img_create_iot")
    if img_dir is None:
        res = sub_module.img_create_do.img_create_do(args, img_dir_path, config_file, **kwargs)
    else:
        res = sub_module.img_create_do.img_create_do(args, img_dir, config_file, **kwargs)
    return res


def run():
    parser_image = bflb_utils.image_create_parser_init()
    args = parser_image.parse_args()
    bflb_utils.printf("chipname: {}".format(args.chipname))
    if args.chipname:
        chip_dict = {
            "bl56x": "bl60x",
            "bl60x": "bl60x",
            "bl562": "bl602",
            "bl602": "bl602",
            "bl702": "bl702",
            "bl702l": "bl702l",
            "bl808": "bl808",
            "bl628": "bl628",
            "bl606p": "bl808",
            "bl616": "bl616",
            "wb03": "wb03",
        }
        chipname = args.chipname
        chiptype = chip_dict[chipname]
        img_create_path = os.path.join(chip_path, chipname, "img_create_mcu")
        img_create_cfg = os.path.join(chip_path, chipname, "img_create_mcu") + "/img_create_cfg.ini"
        bh_cfg_file = img_create_path + "/efuse_bootheader_cfg.ini"
        bh_file = img_create_path + "/bootheader.bin"
        if args.imgfile:
            imgbin = args.imgfile
            cfg = BFConfigParser()
            cfg.read(img_create_cfg)
            cfg.set("Img_Cfg", "segdata_file", imgbin)
            cfg.write(img_create_cfg, "w")
        bflb_efuse_boothd_create.bootheader_create_process(
            chipname, chiptype, bh_cfg_file, bh_file, img_create_path + "/bootheader_dummy.bin"
        )
        img_create(args, chipname, chiptype, img_create_path, img_create_cfg)
    else:
        bflb_utils.printf("please set chipname config, exit")


if __name__ == "__main__":
    run()
