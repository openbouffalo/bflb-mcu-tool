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
import sys
import re
import time
import hashlib
import binascii
import subprocess
import traceback
import shutil
import lzma
import csv
import zipfile
from importlib import reload

import portalocker
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

try:
    import bflb_path
except ImportError:
    from libs import bflb_path

import config as gol
from libs import bflb_version
from libs import bflb_interface_uart
from libs import bflb_interface_sdio
from libs import bflb_interface_jlink
from libs import bflb_interface_cklink
from libs import bflb_interface_openocd
from libs import bflb_efuse_boothd_create
from libs import bflb_img_loader
from libs import bflb_flash_select
from libs import bflb_utils
from libs import bflb_ecdh
from libs import bflb_img_create
from libs.bflb_utils import app_path, chip_path, open_file, eflash_loader_parser_init, convert_path
from libs.bflb_configobj import BFConfigParser
from libs.bflb_private_driver_auth import BflbAuthBase

try:
    import changeconf as cgc

    conf_sign = True
except ImportError:
    conf_sign = False

try:
    from config import mutex

    th_sign = True
except ImportError:
    th_sign = False

try:
    from PySide2 import QtCore, QtWidgets

    qt_sign = True
    TRANSLATOR = QtCore.QTranslator()
    trans = QtWidgets.QApplication.translate
except ImportError:
    try:
        from PySide6 import QtCore, QtWidgets

        qt_sign = True
        TRANSLATOR = QtCore.QTranslator()
        trans = QtWidgets.QApplication.translate
    except ImportError:
        qt_sign = False

import threading

mutex = threading.Lock()

FLASH_LOAD_HANDKE = "Flash load handshake"
FLASH_ERASE_HANDKE = "Flash erase handshake"
PRIVATE_KEY_RSA_HEX = """
2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d49
49435851494241414b426751436b62486e492f62337849384a4951665276434f6378
5146346e6c3541395470326b396a6a6154622b7947412b572b6857790a6c6f516b35
6f33543852574f796e4e30513562656f536a354e665430706e33574964643074792f
7159652f42495a724966576e724c736251584974325a4c55680a6a354a38486b5955
7247584c54497150774e6b4a65454863593235567a5336787764593036742f49376c
44654b70676e46466469326b6d694b774944415141420a416f47414e744874397476
57364e2b31786e617241787779544f4c376f584b7768696841656b41587133315270
52544e6d645a4f78716a5662534972646c63430a6934576e59634f704f5266396537
32494b73755a312f75586845734e7471384f43472b30562b4f4e63624a3967567854
52673636343465343932577470676e470a7a484d656c486e35796e69686541667151
574139463534747266364c53706b64344a6e584d5937335851767664723043515144
434f474b352b5a3943662b62470a426e587877524a454d4d6d74334b764479794548
555445494c3378676f554743535a644d75637375724a47736752492b735847776349
6c434b3646596174696e0a574935474c5a4366416b4541324c6d344c3766444c4b42
5a5776554f4c48576a5248795a67763943716f70673743745873656a33374f796e77
506b2f624662530a732b4f317378486133377a4467623853366147576f35572b5a37
78694543574739514a42414a2b7976587375526b586e35566e75396778544e544863
362f694a0a2b724b4431435377486945633671694a37394f78727a626e6a7170534f
3359637132506868426f5162737836453745674b6756775334786f36774543514466
310a72474e563161562b4f64524d6c6a35516d626d6a5770674368526f33354e4c57
566978763953524e37767261344d392b6b36557a564d564b4250506b623637650a77
576c6c2b646c2f58737932546250526e4d6b435151434c517a704d4d7a485477376d
626c376e497857786c6a39744c393433446158645731415956445542790a72313366
777256646341546542343156617463396d4274584c543366376842484f7338773372
4152513857590a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d
2d2d"""

try:
    from config import NUM_ERR
except ImportError:
    NUM_ERR = 5


class BflbEflashLoader(object):
    def __init__(self, chipname="bl60x", chiptype="bl60x", outdir="img_create_iot"):
        self._bflb_auto_download = False
        # img loader class
        self._bflb_com_img_loader = None
        # communicate interface
        self._bflb_com_if = None
        # communicate device name
        self._bflb_com_device = ""
        # bootrom device speed
        self._bflb_boot_speed = 500000
        # communicate device speed
        self._bflb_com_speed = 2000000
        # communicate device speed
        self._bflb_com_tx_size = 2056
        # erase timeout
        self._erase_time_out = 10000
        self._host_rx_timeout = None
        # default rx timeout is 2s
        self._default_time_out = 2.0
        # handshake
        self._need_handshake = True
        # retry limit when checksum error occurred
        self._checksum_err_retry_limit = 2
        self._csv_burn_en = False
        self._task_num = None
        self._cpu_reset = False
        self._retry_delay_after_cpu_reset = 0
        self._input_macaddr = ""
        self._macaddr_check = bytearray(0)
        self._decompress_write = False
        self._chip_type = chiptype
        self._chip_name = chipname
        self._mass_opt = False
        self._efuse_bootheader_file = ""
        self._img_create_file = ""
        self._csv_data = ""
        self._csv_file = ""
        self._skip_addr = 0
        self._skip_len = 0
        self._loader_checksum_err_str = "FL0103"
        self._bootinfo = None
        self._isp_shakehand_timeout = 0
        self._isp_en = False
        self._macaddr_check_status = False
        self._efuse_data = bytearray(0)
        self._efuse_mask_data = bytearray(0)
        self._ecdh_shared_key = None
        self._ecdh_public_key = None
        self._ecdh_private_key = None
        self._flash_size = 64 * 1024 * 1024
        # flash2 cfg
        self._flash2_en = False
        self._flash2_select = False
        self._flash2_size = 64 * 1024 * 1024
        self._outdir = outdir

        self._com_cmds = {
            "change_rate": {"cmd_id": "20", "data_len": "0008", "callback": None},
            "reset": {"cmd_id": "21", "data_len": "0000", "callback": None},
            "clk_set": {"cmd_id": "22", "data_len": "0000", "callback": None},
            "opt_finish": {"cmd_id": "23", "data_len": "0000", "callback": None},
            "flash_erase": {"cmd_id": "30", "data_len": "0000", "callback": None},
            "flash_write": {"cmd_id": "31", "data_len": "0100", "callback": None},
            "flash_read": {"cmd_id": "32", "data_len": "0100", "callback": None},
            "flash_boot": {"cmd_id": "33", "data_len": "0000", "callback": None},
            "flash_xip_read": {"cmd_id": "34", "data_len": "0100", "callback": None},
            "flash_switch_bank": {"cmd_id": "35", "data_len": "0100", "callback": None},
            "flash_read_jid": {"cmd_id": "36", "data_len": "0000", "callback": None},
            "flash_read_status_reg": {"cmd_id": "37", "data_len": "0000", "callback": None},
            "flash_write_status_reg": {"cmd_id": "38", "data_len": "0000", "callback": None},
            "flash_write_check": {"cmd_id": "3a", "data_len": "0000", "callback": None},
            "flash_set_para": {"cmd_id": "3b", "data_len": "0000", "callback": None},
            "flash_chiperase": {"cmd_id": "3c", "data_len": "0000", "callback": None},
            "flash_readSha": {"cmd_id": "3d", "data_len": "0100", "callback": None},
            "flash_xip_readSha": {"cmd_id": "3e", "data_len": "0100", "callback": None},
            "flash_decompress_write": {"cmd_id": "3f", "data_len": "0100", "callback": None},
            "efuse_write": {"cmd_id": "40", "data_len": "0080", "callback": None},
            "efuse_read": {"cmd_id": "41", "data_len": "0000", "callback": None},
            "efuse_read_mac": {"cmd_id": "42", "data_len": "0000", "callback": None},
            "efuse_write_mac": {"cmd_id": "43", "data_len": "0006", "callback": None},
            "flash_xip_read_start": {"cmd_id": "60", "data_len": "0080", "callback": None},
            "flash_xip_read_finish": {"cmd_id": "61", "data_len": "0000", "callback": None},
            "log_read": {"cmd_id": "71", "data_len": "0000", "callback": None},
            "efuse_security_write": {"cmd_id": "80", "data_len": "0080", "callback": None},
            "efuse_security_read": {"cmd_id": "81", "data_len": "0000", "callback": None},
            "ecdh_get_pk": {"cmd_id": "90", "data_len": "0000", "callback": None},
            "ecdh_challenge": {"cmd_id": "91", "data_len": "0000", "callback": None},
        }
        self._resp_cmds = [
            "flash_read",
            "flash_xip_read",
            "efuse_read",
            "efuse_read_mac",
            "flash_readSha",
            "flash_xip_readSha",
            "flash_read_jid",
            "flash_read_status_reg",
            "log_read",
            "ecdh_get_pk",
            "ecdh_challenge",
            "efuse_security_read",
        ]

    def com_process_one_cmd(self, section, cmd_id, data_send):
        data_read = bytearray(0)
        data_len = bflb_utils.int_to_2bytearray_l(len(data_send))
        checksum = 0
        checksum += bflb_utils.bytearray_to_int(data_len[0:1]) + bflb_utils.bytearray_to_int(data_len[1:2])
        for char in data_send:
            checksum += char
        data = cmd_id + bflb_utils.int_to_2bytearray_l(checksum & 0xFF)[0:1] + data_len + data_send
        self._bflb_com_if.if_write(data)
        if section in self._resp_cmds:
            res, data_read = self._bflb_com_if.if_deal_response()
            if res != "OK":
                self._bflb_com_if.if_write(data)
                res, data_read = self._bflb_com_if.if_deal_response()
        else:
            res = self._bflb_com_if.if_deal_ack()
        return res, data_read

    def com_inf_change_rate(self, section, newrate):
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get(section)["cmd_id"])
        cmd_len = bflb_utils.hexstr_to_bytearray(self._com_cmds.get(section)["data_len"])
        bflb_utils.printf(
            "Process ",
            section,
            ", cmd=",
            binascii.hexlify(cmd_id).decode("utf-8"),
            ",data len=",
            binascii.hexlify(cmd_len).decode("utf-8"),
        )
        baudrate = self._bflb_com_if.if_get_rate()
        oldv = bflb_utils.int_to_4bytearray_l(baudrate)
        newv = bflb_utils.int_to_4bytearray_l(newrate)
        tmp = bytearray(3)
        tmp[1] = cmd_len[1]
        tmp[2] = cmd_len[0]
        data = cmd_id + tmp + oldv + newv
        self._bflb_com_if.if_write(data)
        # wait for data send done
        stime = (11 * 10) / float(baudrate) * 2
        if stime < 0.003:
            stime = 0.003
        time.sleep(stime)
        self._bflb_com_speed = newrate
        self._bflb_com_if.if_init(self._bflb_com_device, self._bflb_com_speed, self._chip_type, self._chip_name)
        return self._bflb_com_if.if_deal_ack()

    def is_conf_exist(self, flash_id):
        if conf_sign:
            cfg_dir = app_path + "/utils/flash/" + cgc.lower_name + "/"
        else:
            cfg_dir = app_path + "/utils/flash/" + self._chip_type + "/"
        conf_name = self.get_suitable_conf_name(cfg_dir, flash_id)
        if os.path.isfile(cfg_dir + conf_name) is False:
            return False
        else:
            return True

    def read_log_process(self, shakehand=1, callback=None):
        readdata = bytearray(0)
        try:
            # handshake
            if shakehand:
                bflb_utils.printf(FLASH_LOAD_HANDKE)
                if self._handshake() is False:
                    bflb_utils.printf("handshake retry")
            cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("log_read")["cmd_id"])
            ret, data_read = self.com_process_one_cmd("log_read", cmd_id, bytearray(0))
            bflb_utils.printf("read log")
            if ret.startswith("OK") is False:
                bflb_utils.printf("read failed")
                return False, None
            readdata += data_read
            bflb_utils.printf("log: ")
            bflb_utils.printf("========================================================")
            bflb_utils.printf(readdata.decode("utf-8"))
            bflb_utils.printf("========================================================")
        except Exception as e:
            bflb_utils.printf(e)
            self.print_error_code("0006")
            traceback.print_exc(limit=NUM_ERR, file=sys.stdout)
            return False, None
        return True, readdata

    def print_error_code(self, code):
        bflb_utils.set_error_code(code, self._task_num)
        bflb_utils.printf("ErrorCode: {0}, ErrorMsg: {1}".format(code, bflb_utils.eflash_loader_error_code[code]))

    @staticmethod
    def print_usage():
        bflb_utils.printf("-e --start=00000000 --end=0000FFFF -c config.ini")
        bflb_utils.printf("-w --flash -c config.ini")
        bflb_utils.printf("-w --flash --file=1.bin,2.bin --addr=00000000,00001000 -c config.ini")
        bflb_utils.printf("-r --flash --start=00000000 --end=0000FFFF --file=flash.bin -c config.ini")

    @staticmethod
    def save_csv_file(csv_data, csv_file, state):
        if csv_data and csv_file:
            lock_file = open("lock.txt", "w+")
            portalocker.lock(lock_file, portalocker.LOCK_EX)
            with open(csv_file, "r") as csvf:
                reader = csv.DictReader(csvf)
                list_csv = []
                for row in reader:
                    if row.get("DeviceName", "") == csv_data:
                        if row.get("Burned", "") == "P":
                            if state is True:
                                row["Burned"] = "Y"
                            else:
                                row["Burned"] = ""
                        else:
                            bflb_utils.printf(csv_data, "status not programing")
                    list_csv.append(row)
                with open(csv_file, "w", newline="") as f:
                    headers = [
                        "ProductKey",
                        "DeviceName",
                        "DeviceSecret",
                        "ProductSecret",
                        "ProductID",
                        "Burned",
                    ]
                    f_csv = csv.DictWriter(f, headers)
                    f_csv.writeheader()
                    f_csv.writerows(list_csv)
            lock_file.close()
            os.remove("lock.txt")

    @staticmethod
    def unpack_file_zip(packet_file):
        bflb_utils.printf("unpack file")
        filename = packet_file
        try:
            if filename:
                efuse_burn = "false"
                eflash_loader_file = ""
                zip_file = zipfile.ZipFile(filename)
                zip_list = zip_file.namelist()
                for f in zip_list:
                    if f.find("efusedata.bin") != -1:
                        efuse_burn = "true"
                    if f.find("eflash_loader_cfg") != -1:
                        eflash_loader_file = os.path.join(app_path, "chips", f)
                    zip_file.extract(f, os.path.join(app_path, "chips"))
                zip_file.close()
                cfg = BFConfigParser()
                cfg.read(eflash_loader_file)
                if cfg.has_option("EFUSE_CFG", "burn_en"):
                    cfg.set("EFUSE_CFG", "burn_en", efuse_burn)
                    cfg.write(eflash_loader_file, "w")
                # os.remove(latest_zip_file)
                bflb_utils.printf("unpack successfully")
            return True
        except Exception as err:
            error = str(err)
            bflb_utils.printf("unpack failed: ", error)
            return False

    def operate_finish(self, shakehand=0):
        bflb_utils.printf("boot from flash")
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_ERASE_HANDKE)
            if self._handshake() is False:
                return False
        else:
            if self._bflb_com_if is not None:
                self._bflb_com_if.if_close()
            self._bflb_com_if.if_init(self._bflb_com_device, self._bflb_com_speed, self._chip_type, self._chip_name)
        # send command
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("opt_finish")["cmd_id"])
        ret, dmy = self.com_process_one_cmd("opt_finish", cmd_id, bytearray(0))
        if ret.startswith("OK"):
            return True
        else:
            self.print_error_code("000D")
            return False

    def boot_from_flash(self, shakehand=0):
        bflb_utils.printf("boot from flash")
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_ERASE_HANDKE)
            if self._handshake() is False:
                return False
        else:
            if self._bflb_com_if is not None:
                self._bflb_com_if.if_close()
            self._bflb_com_if.if_init(self._bflb_com_device, self._bflb_com_speed, self._chip_type, self._chip_name)
        # send command
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_boot")["cmd_id"])
        ret, dmy = self.com_process_one_cmd("flash_boot", cmd_id, bytearray(0))
        if ret.startswith("OK"):
            return True
        else:
            self.print_error_code("003F")
            return False

    def clear_boot_status(self, shakehand=0):
        # bflb_utils.printf("clear boot status at hbn rsvd register")
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_ERASE_HANDKE)
            if self._handshake() is False:
                return False
        # write memory, 0x2000F108=0x00000000
        data = bytearray(12)
        data[0] = 0x50
        data[1] = 0x00
        data[2] = 0x08
        data[3] = 0x00
        data[4] = 0x08
        data[5] = 0xF1
        data[6] = 0x00
        data[7] = 0x20
        data[8] = 0x00
        data[9] = 0x00
        data[10] = 0x00
        data[11] = 0x00
        self._bflb_com_if.if_write(data)
        self._bflb_com_if.if_deal_ack(dmy_data=False)
        return True

    def clear_object_status(self):
        self._bootinfo = None
        self._macaddr_check = bytearray(0)
        self._macaddr_check_status = False

    def reset_cpu(self, shakehand=0):
        bflb_utils.printf("reset cpu")
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_ERASE_HANDKE)
            if self._handshake() is False:
                return False
        # send command
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("reset")["cmd_id"])
        ret, dmy = self.com_process_one_cmd("reset", cmd_id, bytearray(0))
        if ret.startswith("OK"):
            return True
        else:
            self.print_error_code("0004")
            return False

    def close_port(self):
        if self._bflb_com_if is not None:
            self._bflb_com_if.if_close()

    def set_config_file(self, bootheader_file, img_create_file):
        self._efuse_bootheader_file = bootheader_file
        self._img_create_file = img_create_file

    def set_mass_opt_flag(self, flag):
        self._mass_opt = flag

    def set_clock_pll(self, shakehand, irq_en, speed, clk_para):
        bflb_utils.printf("set clock pll")
        # handshake
        if shakehand:
            bflb_utils.printf("clock set handshake")
            if self._handshake() is False:
                return False
        start_time = time.time() * 1000
        # send command
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("clk_set")["cmd_id"])
        irq_enable = bytearray(4)
        # load_speed = bytearray(4)
        if irq_en:
            irq_enable = b"\x01\x00\x00\x00"
        load_speed = bflb_utils.int_to_4bytearray_l(int(speed))
        data_send = irq_enable + load_speed + clk_para
        if len(clk_para) > 0:
            bflb_utils.printf("clock para: ")
            bflb_utils.printf(binascii.hexlify(clk_para).decode("utf-8"))
        try_cnt = 0
        while True:
            ret, dmy = self.com_process_one_cmd("clk_set", cmd_id, data_send)
            if ret.startswith("OK"):
                break
            if try_cnt < self._checksum_err_retry_limit:
                bflb_utils.printf("retry")
                try_cnt += 1
            else:
                self.print_error_code("000C")
                return False
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("set clock time cost(ms): ", round(time_cost, 3))
        self._bflb_com_if.if_init(self._bflb_com_device, speed, self._chip_type, self._chip_name)
        self._bflb_com_if.if_clear_buf()
        time.sleep(0.01)
        return True

    def update_clock_para(self, file):
        if os.path.isfile(file) is False:
            efuse_bootheader_path = os.path.join(chip_path, self._chip_name, "efuse_bootheader")
            efuse_bh_cfg = efuse_bootheader_path + "/efuse_bootheader_cfg.conf"
            sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
            section = "BOOTHEADER_GROUP0_CFG"
            with open(efuse_bh_cfg, "r") as fp:
                data = fp.read()
            if "BOOTHEADER_CFG" in data:
                section = "BOOTHEADER_CFG"
            elif "BOOTHEADER_CPU0_CFG" in data:
                section = "BOOTHEADER_CPU0_CFG"
            elif "BOOTHEADER_GROUP0_CFG" in data:
                section = "BOOTHEADER_GROUP0_CFG"
            bh_data, tmp = bflb_efuse_boothd_create.update_data_from_cfg(
                sub_module.bootheader_cfg_keys.bootheader_cfg_keys, efuse_bh_cfg, section
            )
            bh_data = bflb_efuse_boothd_create.bootheader_update_flash_pll_crc(bh_data, self._chip_type)
            with open(file, "wb+") as fp:
                if self._chip_type == "bl808":
                    if section == "BOOTHEADER_GROUP0_CFG":
                        fp.write(bh_data[100 : 100 + 28])
                elif self._chip_type == "bl628":
                    if section == "BOOTHEADER_GROUP0_CFG":
                        fp.write(bh_data[100 : 100 + 24])
                elif self._chip_type == "bl616" or self._chip_type == "bl616l" or self._chip_type == "bl616d":
                    if section == "BOOTHEADER_GROUP0_CFG":
                        fp.write(bh_data[100 : 100 + 20])
                elif self._chip_type == "wb03":
                    if section == "BOOTHEADER_GROUP0_CFG":
                        fp.write(bh_data[208 + 100 : 208 + 100 + 20])
                elif self._chip_type == "bl702l":
                    if section == "BOOTHEADER_CFG":
                        fp.write(bh_data[100 : 100 + 16])
            # os.remove(efuse_bh_cfg)

        fp = open_file(file, "rb")
        clock_para = bytearray(fp.read())
        fp.close()
        return clock_para

    def get_boot_info(
        self,
        interface,
        helper_file,
        do_reset=False,
        reset_hold_time=100,
        shake_hand_delay=100,
        reset_revert=True,
        cutoff_time=0,
        shake_hand_retry=2,
        isp_timeout=0,
    ):
        bflb_utils.printf("========= get boot info =========")
        bootinfo = ""
        if interface == "uart":
            ret = True
            start_time = time.time() * 1000
            ret, bootinfo = self._bflb_com_img_loader.img_get_bootinfo(
                self._bflb_com_device,
                self._bflb_boot_speed,
                self._bflb_boot_speed,
                helper_file,
                "",
                None,
                do_reset,
                reset_hold_time,
                shake_hand_delay,
                reset_revert,
                cutoff_time,
                shake_hand_retry,
                isp_timeout,
                boot_baudrate=self._bflb_boot_speed,
            )
            chipid = None
            if ret is True:
                bootinfo = bootinfo.decode("utf-8")
                if self._chip_type == "bl702" or self._chip_type == "bl702l":
                    chipid = (
                        bootinfo[32:34]
                        + bootinfo[34:36]
                        + bootinfo[36:38]
                        + bootinfo[38:40]
                        + bootinfo[40:42]
                        + bootinfo[42:44]
                        + bootinfo[44:46]
                        + bootinfo[46:48]
                    )
                else:
                    chipid = (
                        bootinfo[34:36]
                        + bootinfo[32:34]
                        + bootinfo[30:32]
                        + bootinfo[28:30]
                        + bootinfo[26:28]
                        + bootinfo[24:26]
                    )
                bflb_utils.printf("========= chip id: ", chipid, " =========")
                time_cost = (time.time() * 1000) - start_time
                bflb_utils.printf("get bootinfo time cost(ms): ", round(time_cost, 3))
            if qt_sign and th_sign and QtCore.QThread.currentThread().objectName():
                with mutex:
                    num = str(QtCore.QThread.currentThread().objectName())
                    gol.list_chipid[int(num) - 1] = chipid
                    if chipid is not None:
                        gol.list_chipid_check[int(num) - 1] = chipid
                    for i, j in gol.list_download_check_last:
                        if (chipid is not None) and (chipid == i) and (j is True):
                            return True, bootinfo, "repeat_burn"
                    if chipid is not None:
                        return True, bootinfo, "OK"
                    else:
                        return False, bootinfo, "chipid_is_none"
            return ret, bootinfo, "OK"
        else:
            bflb_utils.printf("interface is not supported")
            return False, bootinfo, ""

    def get_active_fwbin_addr(self, ptaddr1, ptaddr2, entry_name, shakehand=1, callback=None):
        fwaddr = 0
        maxlen = 0
        ptdata = bytearray(0)
        table_count = 0
        try:
            # handshake
            if shakehand:
                bflb_utils.printf(FLASH_LOAD_HANDKE)
                if self._handshake() is False:
                    return False, 0
            bflb_utils.printf("read partition 1 0x", ptaddr1)
            ret, ptdata1 = self.flash_read_main_process(int(ptaddr1, 16), 0x300, 0, None, callback)
            if ret is False:
                bflb_utils.printf("read pt 1 data failed")
            bflb_utils.printf("read partition 2 0x", ptaddr2)
            ret, ptdata2 = self.flash_read_main_process(int(ptaddr2, 16), 0x300, 0, None, callback)
            if ret is False:
                bflb_utils.printf("read pt 2 data failed")
            sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
            ret1, table_count1, age1 = sub_module.partition_cfg_do.check_pt_data(ptdata1)
            if ret1 is False:
                if self._chip_type == "bl702" or self._chip_type == "bl702l":
                    ret, ptdata1 = self.flash_read_main_process(0x1000, 0x300, 0, None, callback)
                    ret1, table_count1, age1 = sub_module.partition_cfg_do.check_pt_data(ptdata1)
                    if ret1 is False:
                        bflb_utils.printf("pt table 1 check failed")
                else:
                    bflb_utils.printf("pt table 1 check failed")
            ret2, table_count2, age2 = sub_module.partition_cfg_do.check_pt_data(ptdata2)
            if ret2 is False:
                if self._chip_type == "bl702" or self._chip_type == "bl702l":
                    ret, ptdata2 = self.flash_read_main_process(0x2000, 0x300, 0, None, callback)
                    ret2, table_count2, age2 = sub_module.partition_cfg_do.check_pt_data(ptdata2)
                    if ret2 is False:
                        bflb_utils.printf("pt table 2 check failed")
                else:
                    bflb_utils.printf("pt table 2 check failed")
            if ret1 is not False and ret2 is not False:
                if age1 >= age2:
                    ptdata = ptdata1[16:]
                    table_count = table_count1
                else:
                    ptdata = ptdata2[16:]
                    table_count = table_count2
            elif ret1 is not False:
                ptdata = ptdata1[16:]
                table_count = table_count1
            elif ret2 is not False:
                ptdata = ptdata2[16:]
                table_count = table_count2
            else:
                bflb_utils.printf("pt table all check failed")
                return False, 0, 0
            for i in range(table_count):
                if entry_name == ptdata[i * 36 + 3 : i * 36 + 3 + len(entry_name)].decode(encoding="utf-8"):
                    addr_start = 0
                    if bflb_utils.bytearray_to_int(ptdata[i * 36 + 2 : i * 36 + 3]) != 0:
                        addr_start = i * 36 + 16
                    else:
                        addr_start = i * 36 + 12
                    fwaddr = (
                        bflb_utils.bytearray_to_int(ptdata[addr_start + 0 : addr_start + 1])
                        + (bflb_utils.bytearray_to_int(ptdata[addr_start + 1 : addr_start + 2]) << 8)
                        + (bflb_utils.bytearray_to_int(ptdata[addr_start + 2 : addr_start + 3]) << 16)
                        + (bflb_utils.bytearray_to_int(ptdata[addr_start + 3 : addr_start + 4]) << 24)
                    )
                    maxlen = (
                        bflb_utils.bytearray_to_int(ptdata[addr_start + 0 + 8 : addr_start + 1 + 8])
                        + (bflb_utils.bytearray_to_int(ptdata[addr_start + 1 + 8 : addr_start + 2 + 8]) << 8)
                        + (bflb_utils.bytearray_to_int(ptdata[addr_start + 2 + 8 : addr_start + 3 + 8]) << 16)
                        + (bflb_utils.bytearray_to_int(ptdata[addr_start + 3 + 8 : addr_start + 4 + 8]) << 24)
                    )
        except Exception as e:
            bflb_utils.printf(e)
            traceback.print_exc(limit=NUM_ERR, file=sys.stdout)
            return False, 0, 0
        return True, fwaddr, maxlen

    @staticmethod
    def get_suitable_conf_name(cfg_dir, flash_id):
        conf_files = []
        for home, dirs, files in os.walk(cfg_dir):
            for filename in files:
                if filename.split("_")[-1] == flash_id + ".conf":
                    conf_files.append(filename)
        if len(conf_files) > 1:
            bflb_utils.printf("flash id duplicate and alternative is: ")
            for i in range(len(conf_files)):
                tmp = conf_files[i].split(".")[0]
                bflb_utils.printf("%d:%s" % (i + 1, tmp))
            return conf_files[i]
        elif len(conf_files) == 1:
            return conf_files[0]
        else:
            return ""

    def get_factory_config_info(self, file, output_file):
        version = "ver0.0.1"
        csv_mac = ""
        info_dict = {
            "ProductKey": "",
            "DeviceName": "",
            "DeviceSecret": "",
            "ProductSecret": "",
            "ProductID": "",
        }
        lock_file = open("lock.txt", "w+")
        portalocker.lock(lock_file, portalocker.LOCK_EX)
        try:
            with open(file, "r") as csv_file:
                reader = csv.DictReader(csv_file)
                list_csv = []
                list_product_secret = []
                list_product_id = []
                for row in reader:
                    if (
                        "ProductKey" in row
                        and "DeviceName" in row
                        and "DeviceSecret" in row
                        and "ProductSecret" in row
                        and "ProductID" in row
                    ):
                        if "Burned" in row:
                            if len(row) == 6:
                                pass
                            else:
                                bflb_utils.printf("csv file format error")
                                self._csv_data = None
                                self._csv_file = None
                                return False, None
                        else:
                            if len(row) == 5:
                                pass
                            else:
                                bflb_utils.printf("csv file format error")
                                self._csv_data = None
                                self._csv_file = None
                                return False, None
                    else:
                        bflb_utils.printf("csv file format error")
                        self._csv_data = None
                        self._csv_file = None
                        return False, None
                    list_product_secret.append(info_dict["ProductSecret"])
                    list_product_id.append(info_dict["ProductID"])
                    if "Burned" not in row:
                        if csv_mac == "":
                            burnkey = {"Burned": "P"}
                            row.update(burnkey)
                        list_csv.append(row)
                    elif row.get("Burned", "") != "Y" and row.get("Burned", "") != "P":
                        if csv_mac == "":
                            row["Burned"] = "P"
                        list_csv.append(row)
                    else:
                        list_csv.append(row)
                        continue
                    if csv_mac == "":
                        info_dict["ProductKey"] = row.get("ProductKey", "")
                        csv_mac = info_dict["DeviceName"] = row.get("DeviceName", "")
                        info_dict["DeviceSecret"] = row.get("DeviceSecret", "")
                        info_dict["ProductSecret"] = row.get("ProductSecret", "")
                        info_dict["ProductID"] = row.get("ProductID", "")
                        if len(set(list_product_secret)) > 1:
                            print("error: ProductSecret is not the same")
                            return False, csv_mac
                        if len(set(list_product_id)) > 1:
                            print("error: ProductID is not the same")
                            return False, csv_mac
                        if re.match(r"^([0-9a-fA-F]{2,2}){6,8}$", csv_mac) is None:
                            print("error: {} is not a valid mac address".format(csv_mac))
                            return False, csv_mac
                        self._csv_data = csv_mac
                        self._csv_file = file
                if csv_mac == "":
                    bflb_utils.printf("all factory info used up")
                    lock_file.close()
                    os.remove("lock.txt")
                    return False, csv_mac
                else:
                    ret, efusedata = self.efuse_read_main_process(
                        0, 128, self._need_handshake, file=None, security_read=False
                    )
                    if ret is False:
                        return False, csv_mac
                    efusedata = bytearray(efusedata)
                    data_efuse = (
                        csv_mac[10:12] + csv_mac[8:10] + csv_mac[6:8] + csv_mac[4:6] + csv_mac[2:4] + csv_mac[0:2]
                    )
                    mac_bytearray = bflb_utils.hexstr_to_bytearray(data_efuse)
                    sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
                    slot0_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot0"]
                    slot1_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot1"]
                    slot2_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot2"]
                    bflb_utils.printf(mac_bytearray)
                    bflb_utils.printf(efusedata[int(slot0_addr, 10) : int(slot0_addr, 10) + 6])
                    bflb_utils.printf(efusedata[int(slot1_addr, 10) : int(slot1_addr, 10) + 6])
                    bflb_utils.printf(efusedata[int(slot2_addr, 10) : int(slot2_addr, 10) + 6])
                    if efusedata[int(slot2_addr, 10) : int(slot2_addr, 10) + 6] == mac_bytearray:
                        bflb_utils.printf("DeviceName was already written at efuse mac slot 2")
                        return False, csv_mac
                    elif efusedata[int(slot1_addr, 10) : int(slot1_addr, 10) + 6] == mac_bytearray:
                        bflb_utils.printf("DeviceName was already written at efuse mac slot 1")
                        return False, csv_mac
                    elif efusedata[int(slot0_addr, 10) : int(slot0_addr, 10) + 6] == mac_bytearray:
                        bflb_utils.printf("DeviceName was already written at efuse mac slot 0")
                        return False, csv_mac
            with open(file, "w", newline="") as f:
                headers = [
                    "ProductKey",
                    "DeviceName",
                    "DeviceSecret",
                    "ProductSecret",
                    "ProductID",
                    "Burned",
                ]
                f_csv = csv.DictWriter(f, headers)
                f_csv.writeheader()
                f_csv.writerows(list_csv)
            lock_file.close()
            os.remove("lock.txt")
        except Exception as e:
            bflb_utils.printf(e)
            lock_file.close()
            os.remove("lock.txt")
            return False, csv_mac
        try:
            data_value = bytearray()
            data_len = 0
            temp = bflb_utils.int_to_4bytearray_l(0x01)
            for b in temp:
                data_value.append(b)
            temp = bflb_utils.int_to_4bytearray_l(len(version) + 1)
            for b in temp:
                data_value.append(b)
            ver = bflb_utils.string_to_bytearray(version)
            for b in ver:
                data_value.append(b)
            data_value.append(0x00)
            data_len += 4 + 4 + len(version) + 1
            for key, value in info_dict.items():
                if value != "":
                    temp = bflb_utils.int_to_4bytearray_l(0x0101)
                    for b in temp:
                        data_value.append(b)
                    temp = bflb_utils.int_to_4bytearray_l(len(key) + 1)
                    for b in temp:
                        data_value.append(b)
                    temp = bflb_utils.string_to_bytearray(key)
                    for b in temp:
                        data_value.append(b)
                    data_value.append(0x00)
                    data_len += 4 + 4 + len(key) + 1
                    temp = bflb_utils.int_to_4bytearray_l(0x0102)
                    for b in temp:
                        data_value.append(b)
                    temp = bflb_utils.int_to_4bytearray_l(len(value) + 1)
                    for b in temp:
                        data_value.append(b)
                    temp = bflb_utils.string_to_bytearray(value)
                    for b in temp:
                        data_value.append(b)
                    data_value.append(0x00)
                    data_len += 4 + 4 + len(value) + 1
            info = bytearray()
            info.append(0xA5)
            info.append(0xA5)
            info.append(0xA5)
            info.append(0xA5)
            temp = bflb_utils.int_to_4bytearray_l(data_len)
            for b in temp:
                info.append(b)
            for _ in range(40):
                info.append(0xFF)
            sh = hashlib.sha256()
            sh.update(data_value)
            data_sha256 = sh.hexdigest()
            data_sha256 = bflb_utils.hexstr_to_bytearray(data_sha256)
            temp = data_sha256[-16:]
            for b in temp:
                info.append(b)
            for b in data_value:
                info.append(b)
            with open(output_file, mode="wb") as f:
                f.write(info)
        except Exception as e:
            bflb_utils.printf(e)
            return False, csv_mac
        return True, csv_mac

    def get_ecdh_shared_key(self, shakehand=0):
        bflb_utils.printf("========= get ecdh shared key =========")
        # publickey_file = "utils/pem/publickey_uecc.pem"
        if shakehand:
            bflb_utils.printf("handshake")
            ret = self._handshake()
            if ret is False:
                return
        tmp_ecdh = bflb_ecdh.BflbEcdh()
        self._ecdh_public_key = tmp_ecdh.create_public_key()
        self._ecdh_private_key = binascii.hexlify(
            tmp_ecdh.private_key.private_numbers().private_value.to_bytes(32, "big")
        ).decode("utf-8")
        # bflb_utils.printf("ecdh public key")
        # bflb_utils.printf(self._ecdh_public_key)
        # bflb_utils.printf("ecdh private key")
        # bflb_utils.printf(self._ecdh_private_key)
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("ecdh_get_pk")["cmd_id"])
        data_send = bytearray.fromhex(self._ecdh_public_key)
        ret, data_read = self.com_process_one_cmd("ecdh_get_pk", cmd_id, data_send)
        if ret.startswith("OK") is True:
            self._ecdh_peer_public_key = binascii.hexlify(data_read).decode("utf-8")
            bflb_utils.printf("ecdh peer key")
            bflb_utils.printf(self._ecdh_peer_public_key)
            self._ecdh_shared_key = tmp_ecdh.create_shared_key(self._ecdh_peer_public_key[0:128])
            # bflb_utils.printf("ecdh shared key")
            # bflb_utils.printf(self._ecdh_shared_key)
            # challenge
            cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("ecdh_challenge")["cmd_id"])
            data_send = bytearray(0)
            ret, data_read = self.com_process_one_cmd("ecdh_challenge", cmd_id, data_send)
            if ret.startswith("OK") is True:
                bflb_utils.printf("challenge data")
                bflb_utils.printf(binascii.hexlify(data_read).decode("utf-8"))
                encrypted_data = data_read[0:32]
                signature = data_read[32:96]
                signature_r = data_read[32:64]
                signature_s = data_read[64:96]
                signature = encode_dss_signature(int.from_bytes(signature_r, "big"), int.from_bytes(signature_s, "big"))
                ret = False
                try:
                    with open(os.path.join(app_path, "utils/pem/room_root_publickey_ecc.pem"), "rb") as fp:
                        key = fp.read()
                    public_key = serialization.load_pem_public_key(key)
                    public_key.verify(signature, self.ecdh_decrypt_data(encrypted_data), ec.ECDSA(hashes.SHA256()))
                    ret = True
                except Exception as err:
                    bflb_utils.printf(err)
                if ret is True:
                    return True
                else:
                    bflb_utils.printf("challenge verification failed")
                    return False
            else:
                bflb_utils.printf("challenge ack failed")
                return False
        else:
            bflb_utils.printf("get shared key failed")
            return False

    def ecdh_encrypt_data(self, data):
        # 创建 AES-CBC加密器
        cipher = Cipher(algorithms.AES(bytearray.fromhex(self._ecdh_shared_key[0:32])), modes.CBC(bytearray(16)))
        encryptor = cipher.encryptor()
        # 加密数据
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext

    def ecdh_decrypt_data(self, data):
        # 创建 AES-CBC解密器
        cipher = Cipher(algorithms.AES(bytearray.fromhex(self._ecdh_shared_key[0:32])), modes.CBC(bytearray(16)))
        decryptor = cipher.decryptor()
        # 解密数据
        plaintext = decryptor.update(data) + decryptor.finalize()
        return plaintext

    def efuse_read_mac_addr_process(self, shakehand=1, callback=None):
        readdata = bytearray(0)
        mac_length = 6
        if self._chip_type == "bl702" or self._chip_type == "bl702l":
            mac_length = 8
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("efuse_read_mac")["cmd_id"])
        bflb_utils.printf("read mac addr")
        ret, data_read = self.com_process_one_cmd("efuse_read_mac", cmd_id, bytearray(0))
        if ret.startswith("OK") is False:
            self.print_error_code("0023")
            return False, None
        # bflb_utils.printf(binascii.hexlify(data_read))
        readdata += data_read
        crcarray = bflb_utils.get_crc32_bytearray(readdata[:mac_length])
        if crcarray != readdata[mac_length : mac_length + 4]:
            bflb_utils.printf(binascii.hexlify(crcarray))
            bflb_utils.printf(binascii.hexlify(readdata[mac_length : mac_length + 4]))
            self.print_error_code("0025")
            return False, None
        return True, readdata[:mac_length]

    def efuse_read_main_process(self, start_addr, data_len, shakehand=0, file=None, security_read=False):
        readdata = bytearray(0)
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None
        if security_read:
            cmd_name = "efuse_security_read"
        else:
            cmd_name = "efuse_read"
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get(cmd_name)["cmd_id"])
        data_send = bflb_utils.int_to_4bytearray_l(start_addr) + bflb_utils.int_to_4bytearray_l(data_len)
        ret, data_read = self.com_process_one_cmd(cmd_name, cmd_id, data_send)
        bflb_utils.printf("read efuse")
        if ret.startswith("OK") is False:
            self.print_error_code("0020")
            return False, None
        readdata += data_read
        if security_read:
            readdata = self.ecdh_decrypt_data(readdata)
        if file is not None:
            fp = open_file(file, "wb+")
            fp.write(readdata)
            fp.close()
        return True, readdata

    def efuse_write_mac_addr_process(self, macaddr, shakehand=1, callback=None):
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("efuse_write_mac")["cmd_id"])
        ret, data_read = self.com_process_one_cmd("efuse_write_mac", cmd_id, macaddr)
        bflb_utils.printf("write mac addr")
        if ret.startswith("OK") is False:
            self.print_error_code("0024")
            return False, None
        return True, None

    def efuse_get_macaddr(self, verify=0, shakehand=0, security_write=False, file="macaddr.txt"):
        bflb_utils.printf("========= efuse macaddr get =========")

        if security_write and (self.get_ecdh_shared_key() is not True):
            return False

        zeromac = bytearray(6)
        ret, efusedata = self.efuse_read_main_process(0, 128, shakehand, file=None, security_read=security_write)
        if ret is False:
            return False
        efusedata = bytearray(efusedata)
        sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
        slot0_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot0"]
        slot1_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot1"]
        slot2_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot2"]
        if efusedata[int(slot2_addr, 10) : int(slot2_addr, 10) + 6] != zeromac:
            bflb_utils.printf("Efuse get mac at slot 2")
            efuseaddrstr = slot2_addr
        elif efusedata[int(slot1_addr, 10) : int(slot1_addr, 10) + 6] != zeromac:
            bflb_utils.printf("Efuse get mac at slot 1")
            efuseaddrstr = slot1_addr
        elif efusedata[int(slot0_addr, 10) : int(slot0_addr, 10) + 6] != zeromac:
            bflb_utils.printf("Efuse get mac at slot 0")
            efuseaddrstr = slot0_addr
        else:
            bflb_utils.printf("Efuse mac slot 0/1/2 are all empty")
            return False
        getmacaddr = efusedata[int(efuseaddrstr, 10) : int(efuseaddrstr, 10) + 6]
        macaddr = binascii.hexlify(getmacaddr).decode("utf-8")
        bflb_utils.printf("get mac addr: ", macaddr)
        if file is not None:
            fp = open_file(file, "w+")
            fp.write(macaddr)
            fp.close()
        return ret

    def efuse_get_macaddr_bl702(self, verify=0, shakehand=0, security_write=False, file="macaddr.txt"):
        bflb_utils.printf("========= efuse 702 macaddr get =========")

        if security_write and (self.get_ecdh_shared_key() is not True):
            return False

        zeromac = bytearray(8)
        ret, efusedata = self.efuse_read_main_process(0, 128, shakehand, file=None, security_read=security_write)
        if ret is False:
            return False
        efusedata = bytearray(efusedata)
        sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
        slot0_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot0"]
        slot1_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot1"]
        slot2_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot2"]
        if efusedata[int(slot2_addr, 10) : int(slot2_addr, 10) + 8] != zeromac:
            bflb_utils.printf("efuse get mac at slot 2")
            efuseaddrstr = slot2_addr
        elif efusedata[int(slot1_addr, 10) : int(slot1_addr, 10) + 8] != zeromac:
            bflb_utils.printf("efuse get mac at slot 1")
            efuseaddrstr = slot1_addr
        elif efusedata[int(slot0_addr, 10) : int(slot0_addr, 10) + 8] != zeromac:
            bflb_utils.printf("efuse get mac at slot 0")
            efuseaddrstr = slot0_addr
        else:
            bflb_utils.printf("efuse mac slot 0/1/2 are all empty")
            return False
        getmacaddr = efusedata[int(efuseaddrstr, 10) : int(efuseaddrstr, 10) + 8]
        macaddr = binascii.hexlify(getmacaddr).decode("utf-8")
        bflb_utils.printf("get mac addr: ", macaddr)
        if file is not None:
            fp = open_file(file, "w+")
            fp.write(macaddr)
            fp.close()
        return ret

    def efuse_load_main_process(self, file, maskfile, efusedata, efusedatamask, verify=0, security_write=False):
        if self._chip_type == "bl616":
            if self._bflb_com_img_loader.bl616_a0:
                # write memory, set bl616 a0 bootrom uart timeout to 2s
                tmp = bflb_utils.int_to_2bytearray_l(8)
                start_addr_tmp = bflb_utils.int_to_4bytearray_l(0x6102DF04)
                write_data = bflb_utils.int_to_4bytearray_l(0x07D01200)
                cmd_id = bflb_utils.hexstr_to_bytearray("50")
                data = cmd_id + bytearray(1) + tmp + start_addr_tmp + write_data
                self._bflb_com_if.if_write(data)
                ret, data_read_ack = self._bflb_com_if.if_deal_ack(dmy_data=False)
            else:
                # 03 command to set bl616 ax bootrom uart timeout to 2s
                tmp = bflb_utils.int_to_2bytearray_l(4)
                timeout = bflb_utils.int_to_4bytearray_l(2000)
                cmd_id = bflb_utils.hexstr_to_bytearray("23")
                data = cmd_id + bytearray(1) + tmp + timeout
                self._bflb_com_if.if_write(data)
                ret, data_read_ack = self._bflb_com_if.if_deal_ack(dmy_data=False)
        if efusedata != bytearray(0):
            bflb_utils.printf("load data")
            efuse_data = efusedata
            mask_data = efusedatamask
        elif file is not None:
            bflb_utils.printf("load file: ", os.path.normpath(file))
            fp = open_file(file, "rb")
            efuse_data = bytearray(fp.read()) + bytearray(0)
            fp.close()
            if len(efuse_data) > 4096:
                bflb_utils.printf("decrypt efuse data")
                efuse_save_crc = efuse_data[0:4]
                efuse_data = efuse_data[4096:]
                cfg_key = os.path.join(app_path, "cfg.bin")
                # bflb_utils.printf(cfg_key)
                if os.path.exists(cfg_key):
                    res, security_key, security_iv = bflb_utils.get_aes_encrypted_security_key(cfg_key)
                    if res is False:
                        bflb_utils.printf("get encrypted aes key and iv failed")
                        return False
                else:
                    security_key, security_iv = bflb_utils.get_security_key()
                efuse_data = bflb_utils.img_create_decrypt_data(efuse_data, security_key, security_iv, 0)
                efuse_crc = bflb_utils.get_crc32_bytearray(efuse_data)
                if efuse_crc != efuse_save_crc:
                    bflb_utils.printf("efuse crc check failed")
                    self.print_error_code("0021")
                    return False
            try:
                bflb_utils.printf("open ", os.path.normpath(maskfile))
                fp = open_file(maskfile, "rb")
                mask_data = bytearray(fp.read()) + bytearray(0)
                fp.close()
            except:
                bflb_utils.printf(maskfile, " does not exist")
                bflb_utils.printf("create efuse mask data")
                mask_data = self.efuse_create_mask_data(efuse_data)
        else:
            efuse_data = self._efuse_data
            mask_data = self._efuse_mask_data
        if security_write and (self.get_ecdh_shared_key() is not True):
            return False
        if security_write:
            cmd_name = "efuse_security_write"
        else:
            cmd_name = "efuse_write"
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get(cmd_name)["cmd_id"])

        # parameter end_idx: end - 4
        def write_and_verify_except_protect_data(start_idx, end_idx):
            # load normal data
            data_send = efuse_data[start_idx:end_idx]
            if len(data_send) % 16 != 0:
                data_send += bytearray(16 - len(data_send) % 16)
            if security_write:
                data_send = self.ecdh_encrypt_data(data_send)
            data_send = bflb_utils.int_to_4bytearray_l(start_idx) + data_send
            ret, dmy = self.com_process_one_cmd(cmd_name, cmd_id, data_send)
            if ret.startswith("OK") is False:
                bflb_utils.printf("write failed")
                self.print_error_code("0021")
                return False
            # verify
            if verify >= 1:
                ret, read_data = self.efuse_read_main_process(
                    start_idx,
                    end_idx - start_idx + 4,
                    shakehand=0,
                    file=None,
                    security_read=security_write,
                )
                if ret is True and self.efuse_compare_data(
                    read_data,
                    mask_data[start_idx:end_idx] + bytearray(4),
                    efuse_data[start_idx:end_idx] + bytearray(4),
                ):
                    bflb_utils.printf("verification succeeded")
                else:
                    bflb_utils.printf("verification failed")
                    self.print_error_code("0022")
                    return False
            return True

        def write_and_verify_protect_data(start_idx, end_idx):
            # load read write protect data
            data_send = efuse_data[start_idx:end_idx]
            if len(data_send) % 16 != 0:
                data_send = bytearray(12) + data_send + bytearray(16 - len(data_send) - 12)
            if security_write:
                data_send = self.ecdh_encrypt_data(data_send)
            data_send = bflb_utils.int_to_4bytearray_l(start_idx - 12) + data_send
            ret, dmy = self.com_process_one_cmd(cmd_name, cmd_id, data_send)
            if ret.startswith("OK") is False:
                bflb_utils.printf("write failed")
                self.print_error_code("0021")
                return False
            # verify
            if verify >= 1:
                ret, read_data = self.efuse_read_main_process(
                    start_idx - 12, 16, shakehand=0, file=None, security_read=security_write
                )
                if ret is True and self.efuse_compare_data(
                    read_data,
                    bytearray(12) + mask_data[start_idx:end_idx],
                    bytearray(12) + efuse_data[start_idx:end_idx],
                ):
                    bflb_utils.printf("verification succeeded")
                else:
                    # bflb_utils.printf("Read: ")
                    # bflb_utils.printf(binascii.hexlify(read_data[12:16]))
                    # bflb_utils.printf("Expected: ")
                    # bflb_utils.printf(binascii.hexlify(efuse_data[start_idx:end_idx]))
                    bflb_utils.printf("verification failed")
                    self.print_error_code("0022")
                    return False
            return True

        def write_and_verify_all_data(start_idx, end_idx):
            # load normal data
            data_send = efuse_data[start_idx:end_idx]
            if len(data_send) % 16 != 0:
                data_send += bytearray(16 - len(data_send) % 16)
            if security_write:
                data_send = self.ecdh_encrypt_data(data_send)
            data_send = bflb_utils.int_to_4bytearray_l(start_idx) + data_send
            ret, dmy = self.com_process_one_cmd(cmd_name, cmd_id, data_send)
            if ret.startswith("OK") is False:
                bflb_utils.printf("write failed")
                self.print_error_code("0021")
                return False
            # verify
            if verify >= 1:
                ret, read_data = self.efuse_read_main_process(
                    start_idx,
                    end_idx - start_idx,
                    shakehand=0,
                    file=None,
                    security_read=security_write,
                )
                if ret is True and self.efuse_compare_data(
                    read_data, mask_data[start_idx:end_idx], efuse_data[start_idx:end_idx]
                ):
                    bflb_utils.printf("verification succeeded")
                else:
                    bflb_utils.printf("verification failed")
                    self.print_error_code("0022")
                    return False
            return True

        if self._chip_type == "bl616" or self._chip_type == "bl616l" or self._chip_type == "bl616d":
            if len(efuse_data) > 256:
                bflb_utils.printf("load efuse remainder")
                if not write_and_verify_all_data(256, 512):
                    return False
            if len(efuse_data) > 128:
                bflb_utils.printf("load efuse 1")
                if not write_and_verify_all_data(128, 256):
                    return False
            bflb_utils.printf("load efuse 0")
            if not write_and_verify_all_data(0, 128):
                return False
        else:
            bflb_utils.printf("load efuse 0")
            if not write_and_verify_except_protect_data(0, 124):
                return False
            if len(efuse_data) > 124:
                if not write_and_verify_protect_data(124, 128):
                    return False

            if len(efuse_data) > 128:
                bflb_utils.printf("load efuse 1")
                if not write_and_verify_except_protect_data(128, 252):
                    return False
            if len(efuse_data) > 252:
                if not write_and_verify_protect_data(252, 256):
                    return False

            if len(efuse_data) > 256:
                bflb_utils.printf("load efuse remainder")
                if not write_and_verify_except_protect_data(256, 508):
                    return False
            if len(efuse_data) > 508:
                if not write_and_verify_protect_data(508, 512):
                    return False
        return True

    def efuse_load_specified(
        self, file, maskfile, efusedata, efusedatamask, verify=0, shakehand=0, security_write=False
    ):
        bflb_utils.printf("========= efuse load =========")
        if shakehand:
            bflb_utils.printf("efuse load handshake")
            ret = self._handshake()
            if ret is False:
                return False
        ret = self.efuse_load_main_process(file, maskfile, efusedata, efusedatamask, verify, security_write)
        return ret

    def efuse_load_macaddr(self, macaddr, verify=0, shakehand=0, security_write=False):
        bflb_utils.printf("========= efuse macaddr load =========")
        cnt = 0
        mac = macaddr[:12]

        if security_write and (self.get_ecdh_shared_key() is not True):
            return False

        for i in range(0, 12):
            temp = int(mac[i : i + 1], 16)
            for j in range(0, 4):
                if temp & (1 << j) == 0:
                    cnt += 1
        bflb_utils.printf("mac check cnt: 0x%02X" % (cnt))
        data_efuse = mac[10:12] + mac[8:10] + mac[6:8] + mac[4:6] + mac[2:4] + mac[0:2] + "%02X" % (cnt)
        efusedatastr = data_efuse
        efusemaskdata = bytearray(128)
        zeromac = bytearray(6)
        ret, efusedata = self.efuse_read_main_process(0, 128, shakehand, file=None, security_read=security_write)
        if ret is False:
            return False
        efusedata = bytearray(efusedata)
        sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
        slot0_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot0"]
        slot1_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot1"]
        slot2_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot2"]
        if efusedata[int(slot0_addr, 10) : int(slot0_addr, 10) + 6] == zeromac:
            bflb_utils.printf("efuse load mac to slot 0")
            efuseaddrstr = slot0_addr
        elif efusedata[int(slot1_addr, 10) : int(slot1_addr, 10) + 6] == zeromac:
            bflb_utils.printf("efuse load mac to slot 1")
            efuseaddrstr = slot1_addr
        elif efusedata[int(slot2_addr, 10) : int(slot2_addr, 10) + 6] == zeromac:
            bflb_utils.printf("efuse load mac to slot 2")
            efuseaddrstr = slot2_addr
        else:
            bflb_utils.printf("none of efuse mac slot 0/1/2 are empty")
            return False
        for num in range(int(efuseaddrstr), int(efuseaddrstr) + int((len(efusedatastr) / 2))):
            efusedata[num] |= bytearray.fromhex(efusedatastr)[num - int(efuseaddrstr)]
            efusemaskdata[num] |= 0xFF
        for num in range(0, 128):
            if efusedata[num] != 0:
                efusemaskdata[num] |= 0xFF
        ret = self.efuse_load_specified(None, None, efusedata, efusemaskdata, verify, 0, security_write)
        if ret is False:
            return False
        return ret

    def efuse_load_macaddr_bl702(self, macaddr, verify=0, shakehand=0, security_write=False):
        bflb_utils.printf("========= efuse 702 macaddr load =========")
        cnt = 0
        if len(macaddr) != 16:
            bflb_utils.printf("mac addr length is not 16")
            return False
        mac = macaddr[:16]

        if security_write and (self.get_ecdh_shared_key() is not True):
            return False

        for i in range(0, 16):
            temp = int(mac[i : i + 1], 16)
            for j in range(0, 4):
                if temp & (1 << j) == 0:
                    cnt += 1
        bflb_utils.printf("mac check cnt: 0x%02X" % (cnt))
        # data_efuse = mac[10:12] + mac[8:10] + mac[6:8] + mac[4:6] + mac[2:4] + mac[0:2]
        efusedatastr = mac
        efusemaskdata = bytearray(128)
        zeromac = bytearray(8)
        ret, efusedata = self.efuse_read_main_process(0, 128, shakehand, file=None, security_read=security_write)
        if ret is False:
            return False
        efusedata = bytearray(efusedata)
        sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
        slot0_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot0"]
        slot1_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot1"]
        slot2_addr = sub_module.efuse_cfg_keys.efuse_mac_slot_offset["slot2"]
        if efusedata[int(slot0_addr, 10) : int(slot0_addr, 10) + 8] == zeromac:
            bflb_utils.printf("efuse load mac to slot 0")
            efuseaddrstr = slot0_addr
            data_cnt = cnt
        elif efusedata[int(slot1_addr, 10) : int(slot1_addr, 10) + 8] == zeromac:
            bflb_utils.printf("efuse load mac to slot 1")
            efuseaddrstr = slot1_addr
            data_cnt = cnt << 6
        elif efusedata[int(slot2_addr, 10) : int(slot2_addr, 10) + 8] == zeromac:
            bflb_utils.printf("efuse load mac to slot 2")
            efuseaddrstr = slot2_addr
            data_cnt = cnt << 12
        else:
            bflb_utils.printf("none of efuse mac slot 0/1/2 are empty")
            return False
        efusedata[116:120] = bflb_utils.int_to_4bytearray_l(data_cnt)
        for num in range(int(efuseaddrstr), int(efuseaddrstr) + int((len(efusedatastr) / 2))):
            efusedata[num] |= bytearray.fromhex(efusedatastr)[num - int(efuseaddrstr)]
            efusemaskdata[num] |= 0xFF
        for num in range(0, 128):
            if efusedata[num] != 0:
                efusemaskdata[num] |= 0xFF

        # bflb_utils.printf(binascii.hexlify(efusedata))
        # bflb_utils.printf(binascii.hexlify(efusemaskdata))
        ret = self.efuse_load_specified(None, None, efusedata, efusemaskdata, verify, 0, security_write)
        if ret is False:
            return False
        return ret

    def efuse_load_data_process(self, data, addr, func=0, verify=0, shakehand=0, security_write=False):
        bflb_utils.printf("========= efuse data load =========")
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False

        if int(addr) > 512 or (int(addr) + len(data) // 2) > 512:
            bflb_utils.printf("efuse data is out of range")
            return False

        start_addr = 0x0
        efuse_data = bytearray(int(addr)) + bytearray.fromhex(data)
        if (int(addr) + len(data) // 2) % 16 != 0:
            efuse_data += bytearray(16 - (int(addr) + len(data) // 2) % 16)
        efuse_maskdata = bytearray(len(efuse_data))
        for num in range(0, len(efuse_data)):
            if efuse_data[num] != 0:
                efuse_maskdata[num] |= 0xFF

        bflb_utils.printf("load efuse data")
        try:
            if func > 0:
                bflb_utils.printf("read and check efuse data")
                if security_write and (self.get_ecdh_shared_key() is not True):
                    return False
                ret, read_data = self.efuse_read_main_process(
                    start_addr, len(efuse_data), 0, file=None, security_read=security_write
                )
                if self._chip_type == "bl808":
                    if len(efuse_data) > 128:
                        ret, read_data2 = self.efuse_read_main_process(
                            128, len(efuse_data) - 128, 0, file=None, security_read=security_write
                        )
                        read_data += read_data2
                i = int(addr) - start_addr
                for i in range(int(addr) - start_addr, int(addr) - start_addr + int(len(data) / 2)):
                    compare_data = read_data[i] | efuse_data[i]
                    if compare_data != efuse_data[i]:
                        bflb_utils.printf(
                            "The efuse data to be written can't overwrite the efuse area at ",
                            i + start_addr,
                        )
                        bflb_utils.printf("read data is {0}, write data is {1}".format(read_data[i], efuse_data[i]))
                        return False
        except Exception as e:
            bflb_utils.printf(e)
            return False

        ret = self.efuse_load_specified(None, None, efuse_data, efuse_maskdata, verify, 0, security_write)

        if ret is True and func > 0:
            tmp, read_data = self.efuse_read_main_process(
                start_addr, len(efuse_data), 0, file=None, security_read=security_write
            )
            if self._chip_type == "bl808":
                if len(efuse_data) > 128:
                    ret, read_data2 = self.efuse_read_main_process(
                        128, len(efuse_data) - 128, 0, file=None, security_read=security_write
                    )
                    read_data += read_data2
            i = int(addr) - start_addr
            for i in range(int(addr) - start_addr, int(addr) - start_addr + int(len(data) / 2)):
                if read_data[i] != efuse_data[i]:
                    bflb_utils.printf(
                        "after efuse loading, verification failed at ",
                        i + start_addr,
                    )
                    bflb_utils.printf("read data is {0}, write data is {1}".format(read_data[i], efuse_data[i]))
                    return False

        return ret

    def efuse_create_encrypt_sign_data(
        self,
        cfg,
        sign,
        pk_hash,
        flash_encryp_type,
        flash_key,
        sec_eng_key_sel,
        sec_eng_key,
        security=False,
    ):
        try:
            img_update_efuse_fun = None
            if self._chip_type == "bl602" or self._chip_type == "bl702" or self._chip_type == "bl702l":
                sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
                img_update_efuse_fun = sub_module.img_create_do.img_update_efuse
            elif self._chip_type == "bl808" or self._chip_type == "bl628":
                sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
                img_update_efuse_fun = sub_module.img_create_do.img_update_efuse_group0
            elif self._chip_type == "bl616" or self._chip_type == "bl616l" or self._chip_type == "bl616d":
                sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
                img_update_efuse_fun = sub_module.img_create_do.img_update_efuse_group0
            else:
                bflb_utils.printf("unrecognized chiptype")
                return bytearray(0), bytearray(0)
            efuse_data, mask_data = img_update_efuse_fun(
                cfg,
                sign,
                pk_hash,
                flash_encryp_type,
                flash_key,
                sec_eng_key_sel,
                sec_eng_key,
                security,
            )
        except Exception as e:
            bflb_utils.printf(e)
            traceback.print_exc(limit=NUM_ERR, file=sys.stdout)
        return efuse_data, mask_data

    @staticmethod
    def efuse_create_mask_data(efuse_data):
        efuse_len = len(efuse_data)
        mask_data = bytearray(efuse_len)
        for i in range(0, efuse_len):
            if efuse_data[i] != 0:
                mask_data[i] |= 0xFF
        return mask_data

    @staticmethod
    def efuse_compare_data(read_data, maskdata, write_data):
        bflb_utils.printf("========= efuse verify =========")
        i = 0
        for i in range(len(read_data)):
            compare_data = read_data[i] & maskdata[i]
            if (compare_data & write_data[i]) != write_data[i]:
                bflb_utils.printf("compare fail: ", i)
                bflb_utils.printf(read_data[i], write_data[i])
                return False
        return True

    # debug for bl616l and bl616d
    """
    def flash_get_size(self, jedec_id):
        flash_size = 64 * 1024 * 1024
        flash_cfg_csv = app_path + "/utils/flash/" + self._chip_type + "/flashcfg_list.csv"
        if conf_sign:
            flash_cfg_csv = app_path + "/utils/flash/" + cgc.lower_name + "/flashcfg_list.csv"
        with open(flash_cfg_csv, "r", encoding="utf-8-sig") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                if row.get("flashJedecID", "") == jedec_id:
                    if row.get("flashSize", "") == "0.5":
                        flash_size = 512 * 1024
                    else:
                        flash_size = int(row.get("flashSize", ""), 10) * 1024 * 1024
                    return flash_size
        return flash_size
    """

    @staticmethod
    def flash_get_size(jedec_id):
        bflb_utils.printf("jedec id is {}".format(jedec_id))
        capacity_id = int(jedec_id[-2:], 16)
        bflb_utils.printf("capacity id is {}".format(capacity_id))
        if capacity_id == 0:
            return 0
        flash_size_level = capacity_id & 0x1F
        flash_size_level -= 0x13
        flash_size = (1 << flash_size_level) * 512 * 1024
        # bflb_utils.printf("The capacity is {}M".format(flash_size / 1024 / 1024))
        return flash_size

    def flash_read_jedec_id_process(self, callback=None):
        bflb_utils.printf("========= flash read jedec id =========")
        readdata = bytearray(0)
        # handshake
        if self._need_handshake:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_read_jid")["cmd_id"])
        ret, data_read = self.com_process_one_cmd("flash_read_jid", cmd_id, bytearray(0))
        # bflb_utils.printf("read flash jedec id")
        if ret.startswith("OK") is False:
            self.print_error_code("0030")
            return False, None
        readdata += data_read
        bflb_utils.printf("flash jedec id: ", binascii.hexlify(readdata).decode("utf-8"))
        return True, readdata[:4]

    def flash_read_status_reg_process(self, cmd, len, callback=None):
        bflb_utils.printf("========= flash read status register =========")
        readdata = bytearray(0)
        # handshake
        if self._need_handshake:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None

        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_read_status_reg")["cmd_id"])
        data_send = bflb_utils.int_to_4bytearray_l(int(cmd, 16)) + bflb_utils.int_to_4bytearray_l(len)
        ret, data_read = self.com_process_one_cmd("flash_read_status_reg", cmd_id, data_send)
        bflb_utils.printf("read flash status register")
        if ret.startswith("OK") is False:
            self.print_error_code("0031")
            return False, None
        readdata += data_read
        bflb_utils.printf("readdata:")
        bflb_utils.printf(binascii.hexlify(readdata))
        return True, readdata

    def flash_read_main_process(self, start_addr, flash_data_len, shakehand=0, file=None, callback=None):
        bflb_utils.printf("========= flash read =========")
        i = 0
        cur_len = 0
        readdata = bytearray(0)
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None
        start_time = time.time() * 1000
        log = ""
        while i < flash_data_len:
            cur_len = flash_data_len - i
            if cur_len > self._bflb_com_tx_size - 8:
                cur_len = self._bflb_com_tx_size - 8
            cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_read")["cmd_id"])
            data_send = bflb_utils.int_to_4bytearray_l(i + start_addr) + bflb_utils.int_to_4bytearray_l(cur_len)
            try_cnt = 0
            while True:
                ret, data_read = self.com_process_one_cmd("flash_read", cmd_id, data_send)
                if ret.startswith("OK"):
                    break
                if try_cnt < self._checksum_err_retry_limit:
                    bflb_utils.printf("Retry")
                    try_cnt += 1
                else:
                    self.print_error_code("0035")
                    return False, None
            i += cur_len
            log += "Read " + str(i) + "/" + str(flash_data_len)
            if len(log) > 50:
                bflb_utils.printf(log)
                log = ""
            else:
                log += "\n"
            if callback is not None:
                callback(i, flash_data_len, "flash")
            readdata += data_read
        bflb_utils.printf(log)
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("flash read time cost(ms): ", round(time_cost, 3))
        if file is not None:
            fp = open_file(file, "wb+")
            fp.write(readdata)
            fp.close()
        return True, readdata

    def flash_read_sha_main_process(self, start_addr, flash_data_len, shakehand=0, file=None, callback=None):
        readdata = bytearray(0)
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None
        start_time = time.time() * 1000
        log = ""
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_readSha")["cmd_id"])
        data_send = bflb_utils.int_to_4bytearray_l(start_addr) + bflb_utils.int_to_4bytearray_l(flash_data_len)
        try_cnt = 0
        while True:
            ret, data_read = self.com_process_one_cmd("flash_readSha", cmd_id, data_send)
            if ret.startswith("OK"):
                break
            if try_cnt < self._checksum_err_retry_limit:
                bflb_utils.printf("Retry")
                try_cnt += 1
            else:
                self.print_error_code("0038")
                return False, None
        log += "read " + "256" + "/" + str(flash_data_len)
        if callback is not None:
            callback(flash_data_len, flash_data_len, "APP_VR")
        readdata += data_read
        bflb_utils.printf(log)
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("flash readsha time cost(ms):", round(time_cost, 3))
        if file is not None:
            fp = open_file(file, "wb+")
            fp.write(readdata)
            fp.close()
        return True, readdata

    def flash_write_status_reg_process(self, cmd, len, write_data, callback=None):
        bflb_utils.printf("========= flash write status register =========")
        # handshake
        if self._need_handshake:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, "flash load handshake failed"

        bflb_utils.printf("write_data ", write_data)
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_write_status_reg")["cmd_id"])
        data_send = (
            bflb_utils.int_to_4bytearray_l(int(cmd, 16))
            + bflb_utils.int_to_4bytearray_l(len)
            + bflb_utils.int_to_4bytearray_l(int(write_data, 16))
        )
        ret, data_read = self.com_process_one_cmd("flash_write_status_reg", cmd_id, data_send)
        bflb_utils.printf("write flash status register")
        if ret.startswith("OK") is False:
            self.print_error_code("0032")
            return False, "write failed"
        return True, None

    def flash_write_check_main_process(self, shakehand=0):
        bflb_utils.printf("flash write check")
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False
        # send command
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_write_check")["cmd_id"])
        try_cnt = 0
        while True:
            ret, dmy = self.com_process_one_cmd("flash_write_check", cmd_id, bytearray(0))
            if ret.startswith("OK"):
                break
            if try_cnt < self._checksum_err_retry_limit:
                bflb_utils.printf("retry")
                try_cnt += 1
            else:
                self.print_error_code("0037")
                return False
        return True

    def flash_erase_main_process(self, start_addr, end_addr, shakehand=0):
        bflb_utils.printf("========= flash erase =========")
        bflb_utils.printf("erase flash from {0} to {1}".format(hex(start_addr), hex(end_addr)))
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_ERASE_HANDKE)
            if self._handshake() is False:
                bflb_utils.printf("handshake failed")
                return False
        start_time = time.time() * 1000
        # send command
        if self._chip_type == "bl602" or self._chip_type == "bl702" or self._chip_type == "bl702l":
            self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
        else:
            self._bflb_com_if.if_set_rx_timeout(self._erase_time_out / 1000)
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_erase")["cmd_id"])
        data_send = bflb_utils.int_to_4bytearray_l(start_addr) + bflb_utils.int_to_4bytearray_l(end_addr)
        try_cnt = 0
        while True:
            ret, dmy = self.com_process_one_cmd("flash_erase", cmd_id, data_send)
            if ret.startswith("OK"):
                break
            elif ret.startswith("PD"):
                bflb_utils.printf("erase pending")
                while True:
                    ret = self._bflb_com_if.if_deal_ack()
                    if ret.startswith("PD"):
                        bflb_utils.printf("erase pending")
                    else:
                        # clear uart fifo 'PD' data
                        self._bflb_com_if.if_set_rx_timeout(0.02)
                        self._bflb_com_if.if_read(1000)
                        break
                    if (time.time() * 1000) - start_time > self._erase_time_out:
                        bflb_utils.printf("erase timeout")
                        break
            if ret.startswith("OK"):
                break

            if try_cnt < self._checksum_err_retry_limit:
                bflb_utils.printf("retry")
                try_cnt += 1
            else:
                bflb_utils.printf("erase failed")
                self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
                self.print_error_code("0034")
                return False
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("erase time cost(ms): ", round(time_cost, 3))
        self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
        return True

    def flash_chiperase_main_process(self, shakehand=0):
        bflb_utils.printf("========= flash chip erase all =========")
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_ERASE_HANDKE)
            if self._handshake() is False:
                bflb_utils.printf("handshake failed")
                return False
        start_time = time.time() * 1000
        # send command
        if self._chip_type == "bl602" or self._chip_type == "bl702" or self._chip_type == "bl702l":
            self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
        else:
            self._bflb_com_if.if_set_rx_timeout(self._erase_time_out / 1000)
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_chiperase")["cmd_id"])
        try_cnt = 0
        while True:
            ret, dmy = self.com_process_one_cmd("flash_chiperase", cmd_id, bytearray(0))
            if ret.startswith("OK"):
                break
            elif ret.startswith("PD"):
                bflb_utils.printf("erase pending")
                while True:
                    ret = self._bflb_com_if.if_deal_ack()
                    if ret.startswith("PD"):
                        bflb_utils.printf("erase pending")
                    else:
                        # clear uart fifo 'PD' data
                        self._bflb_com_if.if_set_rx_timeout(0.02)
                        self._bflb_com_if.if_read(1000)
                        break
                    if (time.time() * 1000) - start_time > self._erase_time_out:
                        bflb_utils.printf("erase timeout")
                        break
            if ret.startswith("OK"):
                break

            if try_cnt < self._checksum_err_retry_limit:
                bflb_utils.printf("Retry")
                try_cnt += 1
            else:
                bflb_utils.printf("erase failed")
                self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
                self.print_error_code("0033")
                return False
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("chip erase time cost(ms): ", round(time_cost, 3))
        self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
        return True

    def flash_loader_cut_flash_bin(self, file, addr, flash1_size):
        flash1_bin = "flash1.bin"
        flash2_bin = "flash2.bin"

        fp = open_file(file, "rb")
        flash_data = bytearray(fp.read())
        fp.close()
        flash_data_len = len(flash_data)
        if flash1_size < addr + flash_data_len and flash1_size > addr:
            flash1_data = flash_data[0 : flash1_size - addr]
            flash2_data = flash_data[flash1_size - addr : flash_data_len]
            fp = open_file(flash1_bin, "wb+")
            fp.write(flash1_data)
            fp.close()
            fp = open_file(flash2_bin, "wb+")
            fp.write(flash2_data)
            fp.close()
            return flash1_bin, len(flash1_data), flash2_bin, len(flash2_data)
        return "", 0, "", 0

    def flash_switch_bank_process(self, bank, shakehand=0):
        bflb_utils.printf("flash switch bank")
        # handshake
        if shakehand:
            bflb_utils.printf("Flash switch bank handshake")
            if self._handshake() is False:
                bflb_utils.printf("handshake failed")
                return False
        start_time = time.time() * 1000
        # send command
        self._bflb_com_if.if_set_rx_timeout(self._erase_time_out / 1000)
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_switch_bank")["cmd_id"])
        data_send = bflb_utils.int_to_4bytearray_l(bank)
        ret, dmy = self.com_process_one_cmd("flash_switch_bank", cmd_id, data_send)
        if ret.startswith("OK") is False:
            bflb_utils.printf("switch failed")
            self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
            self.print_error_code("0042")
            return False
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("switch bank time cost(ms): ", round(time_cost, 3))
        self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
        if bank == 0:
            self._flash2_select = False
        else:
            self._flash2_select = True
        return True

    @staticmethod
    def flash_get_pin_from_bootinfo(chiptype, bootinfo):
        if chiptype == "bl808":
            sw_usage_data = bootinfo[22:24] + bootinfo[20:22] + bootinfo[18:20] + bootinfo[16:18]
            sw_usage_data = int(sw_usage_data, 16)
            return (sw_usage_data >> 14) & 0x1F
        elif chiptype == "bl616" or chiptype == "wb03":
            sw_usage_data = bootinfo[22:24] + bootinfo[20:22] + bootinfo[18:20] + bootinfo[16:18]
            sw_usage_data = int(sw_usage_data, 16)
            return (sw_usage_data >> 14) & 0x3F
        elif chiptype == "bl702l":
            dev_info_data = bootinfo[30:32] + bootinfo[28:30] + bootinfo[26:28] + bootinfo[24:26]
            dev_info_data = int(dev_info_data, 16)
            flash_cfg = (dev_info_data >> 26) & 7
            sf_reverse = (dev_info_data >> 29) & 1
            sf_swap_cfg = (dev_info_data >> 22) & 3
            if flash_cfg == 0:
                return 0
            else:
                if sf_reverse == 0:
                    return sf_swap_cfg + 1
                else:
                    return sf_swap_cfg + 5
        return 0x80

    def flash_set_para_main_process(self, flash_pin, flash_para, shakehand=0):
        bflb_utils.printf("========= flash set config =========")
        if flash_para != bytearray(0):
            if flash_para[13:14] == b"\xff":
                bflb_utils.printf("skip set flash para due to flash id is 0xFF")
                # manufacturer id is 0xff, do not need set flash para
                return True
        # handshake
        if shakehand:
            bflb_utils.printf("flash set para handshake")
            if self._handshake() is False:
                return False
        start_time = time.time() * 1000
        # send command
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_set_para")["cmd_id"])
        data_send = bflb_utils.int_to_4bytearray_l(flash_pin) + flash_para
        try_cnt = 0
        while True:
            ret, dmy = self.com_process_one_cmd("flash_set_para", cmd_id, data_send)
            if ret.startswith("OK"):
                break
            if try_cnt < self._checksum_err_retry_limit:
                bflb_utils.printf("Retry")
                try_cnt += 1
            else:
                self.print_error_code("003B")
                return False
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("set para time cost(ms): ", round(time_cost, 3))
        return True

    def flash_xip_read_main_process(self, start_addr, flash_data_len, shakehand=0, file=None, callback=None):
        bflb_utils.printf("========= flash xip read =========")
        i = 0
        cur_len = 0
        readdata = bytearray(0)
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None
        start_time = time.time() * 1000
        log = ""
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_xip_read_start")["cmd_id"])
        ret, dmy = self.com_process_one_cmd("flash_xip_read_start", cmd_id, bytearray(0))
        if ret.startswith("OK") is False:
            self.print_error_code("0039")
            return False, None
        while i < flash_data_len:
            cur_len = flash_data_len - i
            if cur_len > self._bflb_com_tx_size - 8:
                cur_len = self._bflb_com_tx_size - 8
            cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_xip_read")["cmd_id"])
            data_send = bflb_utils.int_to_4bytearray_l(i + start_addr) + bflb_utils.int_to_4bytearray_l(cur_len)
            try_cnt = 0
            while True:
                ret, data_read = self.com_process_one_cmd("flash_xip_read", cmd_id, data_send)
                if ret.startswith("OK"):
                    break
                if try_cnt < self._checksum_err_retry_limit:
                    bflb_utils.printf("Retry")
                    try_cnt += 1
                else:
                    self.print_error_code("0035")
                    return False, None
            i += cur_len
            log += "Read " + str(i) + "/" + str(flash_data_len)
            if len(log) > 50:
                bflb_utils.printf(log)
                log = ""
            else:
                log += "\n"
            if callback is not None:
                callback(i, flash_data_len, "APP_VR")
            readdata += data_read
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_xip_read_finish")["cmd_id"])
        ret, dmy = self.com_process_one_cmd("flash_xip_read_finish", cmd_id, bytearray(0))
        if ret.startswith("OK") is False:
            self.print_error_code("0039")
            return False, None
        bflb_utils.printf(log)
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("flash read time cost(ms): ", round(time_cost, 3))
        if file is not None:
            fp = open_file(file, "wb+")
            fp.write(readdata)
            fp.close()
        return True, readdata

    def flash_xip_read_sha_main_process(self, start_addr, flash_data_len, shakehand=0, file=None, callback=None):
        readdata = bytearray(0)
        # handshake
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False, None
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_xip_read_start")["cmd_id"])
        ret, dmy = self.com_process_one_cmd("flash_xip_read_start", cmd_id, bytearray(0))
        if ret.startswith("OK") is False:
            self.print_error_code("0039")
            return False, None
        start_time = time.time() * 1000
        log = ""
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_xip_readSha")["cmd_id"])
        data_send = bflb_utils.int_to_4bytearray_l(start_addr) + bflb_utils.int_to_4bytearray_l(flash_data_len)
        try_cnt = 0
        while True:
            ret, data_read = self.com_process_one_cmd("flash_xip_readSha", cmd_id, data_send)
            if ret.startswith("OK"):
                break
            if try_cnt < self._checksum_err_retry_limit:
                bflb_utils.printf("retry")
                try_cnt += 1
            else:
                bflb_utils.printf("read failed")
                # exit xip mode
                cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_xip_read_finish")["cmd_id"])
                ret, dmy = self.com_process_one_cmd("flash_xip_read_finish", cmd_id, bytearray(0))
                if ret.startswith("OK") is False:
                    self.print_error_code("0039")
                    return False, None
                return False, None
        log += "read " + "256" + "/" + str(flash_data_len)
        if callback is not None:
            callback(flash_data_len, flash_data_len, "APP_VR")
        readdata += data_read
        bflb_utils.printf(log)
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("flash xip readsha time cost(ms): ", round(time_cost, 3))
        if file is not None:
            fp = open_file(file, "wb+")
            fp.write(readdata)
            fp.close()
        # exit xip mode
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("flash_xip_read_finish")["cmd_id"])
        ret, dmy = self.com_process_one_cmd("flash_xip_read_finish", cmd_id, bytearray(0))
        if ret.startswith("OK") is False:
            self.print_error_code("0039")
            return False, None
        return True, readdata

    def flash_create_efuse_dac_encrypt_data(self, value, key, iv):
        if (
            self._chip_type == "bl616"
            or self._chip_type == "bl616d"
            or self._chip_type == "bl628"
            or self._chip_type == "bl808"
        ):
            length = 256
        else:
            length = 128
        dac_file = os.path.join(app_path, "dacfile.bin")
        tlv_data = bytearray(0)
        unencrypt_data = bytearray(0)
        efuse_data = bytearray(length)
        mask_data = bytearray(length)
        dac_value = value.split(":")
        encrypt_dac_data = dac_value[0].split(",")
        unencrypt_dac_data = dac_value[1].split(",")
        encrypt_dac_count = len(encrypt_dac_data)
        unencrypt_dac_count = len(unencrypt_dac_data)

        # create encrypt dac data
        for i in range(encrypt_dac_count):
            data = encrypt_dac_data[i]
            data_len = int(len(data) / 2)
            tlv_data += bflb_utils.int_to_2bytearray_l(i + 1)
            tlv_data += bflb_utils.int_to_2bytearray_l(data_len)
            tlv_data += bflb_utils.hexstr_to_bytearray(data)

        tlv_data = bflb_utils.fill_to_16(tlv_data)
        tlv_len = len(tlv_data)
        bflb_utils.printf("tlv data length is ", tlv_len)
        bflb_utils.printf(binascii.hexlify(tlv_data).decode("utf-8"))
        encrypt_key = bflb_utils.hexstr_to_bytearray(key)
        encrypt_iv = bflb_utils.hexstr_to_bytearray(iv)
        tlv_data = bflb_utils.img_create_encrypt_data(tlv_data, encrypt_key, encrypt_iv, 0)
        crcarray = bflb_utils.get_crc32_bytearray(tlv_data)

        tlv_data = bflb_utils.int_to_4bytearray_l(tlv_len) + tlv_data + crcarray

        # create unencrypt dac data
        for i in range(unencrypt_dac_count):
            data = unencrypt_dac_data[i]
            data_len = int(len(data) / 2)
            unencrypt_data += bflb_utils.int_to_2bytearray_l(i + 1 + 0x8000)
            unencrypt_data += bflb_utils.int_to_2bytearray_l(data_len)
            unencrypt_data += bflb_utils.hexstr_to_bytearray(data)
        tlv_len = len(unencrypt_data)
        crcarray = bflb_utils.get_crc32_bytearray(unencrypt_data)

        tlv_data = tlv_data + bflb_utils.int_to_4bytearray_l(tlv_len) + unencrypt_data + crcarray

        efuse_data_sec, mask_data_sec = bflb_img_create.create_security_efuse(self._chip_type, encrypt_key, 1)
        for i in range(length):
            efuse_data[i] |= efuse_data_sec[i]
            mask_data[i] |= mask_data_sec[i]

        with open(dac_file, "wb+") as fp:
            fp.write(tlv_data)

        return dac_file, efuse_data, mask_data

    def flash_cfg_option(
        self,
        read_flash_id,
        flash_para_file,
        flash_set,
        id_valid_flag,
        binfile,
        cfgfile,
        cfg,
        create_img_callback=None,
        create_simple_callback=None,
    ):
        ret = bflb_flash_select.flash_bootheader_config_check(
            self._chip_name, self._chip_type, read_flash_id, convert_path(binfile), flash_para_file
        )
        if ret is False:
            bflb_utils.printf("flashcfg does not match firstly")
            # recreate bootinfo.bin
            if self.is_conf_exist(read_flash_id) is True:
                bflb_utils.update_cfg(cfg, "FLASH_CFG", "flash_id", read_flash_id)
                if isinstance(cfgfile, BFConfigParser) is False:
                    cfg.write(cfgfile, "w+")
                if create_img_callback is not None:
                    create_img_callback()
                elif create_simple_callback is not None:
                    create_simple_callback()
            else:
                self.print_error_code("003D")
                return False
            ret = bflb_flash_select.flash_bootheader_config_check(
                self._chip_name,
                self._chip_type,
                read_flash_id,
                convert_path(binfile),
                flash_para_file,
            )
            if ret is False:
                bflb_utils.printf("flashcfg does not match again")
                self.print_error_code("0040")
                return False
        # set flash config
        if flash_para_file and id_valid_flag != "80":
            bflb_utils.printf("flash para file: ", os.path.normpath(flash_para_file))
            fp = open_file(flash_para_file, "rb")
            flash_para = bytearray(fp.read())
            fp.close()
            ret = self.flash_set_para_main_process(flash_set, flash_para, self._need_handshake)
            self._need_handshake = False
            if ret is False:
                return False
        return True

    def flash_load_opt(self, file, start_addr, erase=1, verify=0, shakehand=0, callback=None):
        bflb_utils.printf("========= flash load =========")
        if shakehand:
            bflb_utils.printf(FLASH_LOAD_HANDKE)
            if self._handshake() is False:
                return False
        if self._flash2_select is True:
            start_addr -= self._flash_size
        if self._chip_type == "bl808":
            if self._mass_opt is False:
                fp = open_file(file, "rb")
                flash_data = bytearray(fp.read())
                fp.close()
                flash_data_len = len(flash_data)
                end_addr = start_addr + flash_data_len - 1
                if start_addr <= 0x1000 and end_addr > 0x1000:
                    ret, flash_read_data = self.flash_read_main_process(0x1000, 0x1000, 0, None, callback)
                    if flash_read_data[0:4] == bflb_utils.int_to_4bytearray_b(0x424C5246):
                        bflb_utils.printf("RF para already written at flash 0x1000 addr, replace it")
                        flash_data[0x1000:0x2000] = flash_read_data[0x0:0x1000]
                        fp = open_file(file, "wb")
                        fp.write(flash_data)
                        fp.close()
        ret = self.flash_load_main_process(file, start_addr, erase, callback)
        if ret is False:
            bflb_utils.printf("flash load failed")
            return ret
        # temp var to store imgage sha-256
        fw_sha256 = ""
        fp = open_file(file, "rb")
        flash_data = fp.read()
        fp.close()
        flash_data_len = len(flash_data)
        if flash_data_len > (2 * 1024 * 1024):
            # if program file size is greater than 2*1024*1024, xip read sha will use more time
            self._bflb_com_if.if_set_rx_timeout(2.0 * (flash_data_len / (2 * 1024 * 1024) + 1))
        sh = hashlib.sha256()
        sh.update(flash_data)
        fw_sha256 = sh.hexdigest()
        fw_sha256 = bflb_utils.hexstr_to_bytearray(fw_sha256)
        bflb_utils.printf("sha256 caled by host: ", binascii.hexlify(fw_sha256).decode("utf-8"))
        del sh
        # xip mode verify
        bflb_utils.printf("xip mode verify")
        ret, read_data = self.flash_xip_read_sha_main_process(start_addr, flash_data_len, 0, None, callback)
        bflb_utils.printf("sha256 caled by dev: ", binascii.hexlify(read_data).decode("utf-8"))
        if ret is True and read_data == fw_sha256:
            bflb_utils.printf("verification succeeded")
        else:
            bflb_utils.printf("verification failed, retry")
            ret, read_data = self.flash_xip_read_sha_main_process(start_addr, flash_data_len, 0, None, callback)
            bflb_utils.printf("sha256 caled by dev: ", binascii.hexlify(read_data).decode("utf-8"))
            if ret is True and read_data == fw_sha256:
                bflb_utils.printf("verification succeeded")
            else:
                bflb_utils.printf("verification failed")
                self.flash_load_tips()
                self.print_error_code("003E")
                ret = False
        if verify > 0:
            fp = open_file(file, "rb")
            flash_data = bytearray(fp.read())
            fp.close()
            flash_data_len = len(flash_data)
            ret, read_data = self.flash_read_main_process(start_addr, flash_data_len, 0, None, callback)
            if ret is True and read_data == flash_data:
                bflb_utils.printf("verify successfully")
            else:
                bflb_utils.printf("verification failed, retry")
                ret, read_data = self.flash_read_main_process(start_addr, flash_data_len, 0, None, callback)
                if ret is True and read_data == flash_data:
                    bflb_utils.printf("verification succeeded")
                else:
                    bflb_utils.printf("verification failed")
                    self.flash_load_tips()
                    self.print_error_code("003E")
                    ret = False
            # sbus mode verify
            bflb_utils.printf("sbus mode verify")
            ret, read_data = self.flash_read_sha_main_process(start_addr, flash_data_len, 0, None, callback)
            bflb_utils.printf(" caled by dev: ", binascii.hexlify(read_data).decode("utf-8"))
            if ret is True and read_data == fw_sha256:
                bflb_utils.printf("verification succeeded")
            else:
                bflb_utils.printf("verify fail, retry")
                ret, read_data = self.flash_read_sha_main_process(start_addr, flash_data_len, 0, None, callback)
                bflb_utils.printf(" caled by dev: ", binascii.hexlify(read_data).decode("utf-8"))
                if ret is True and read_data == fw_sha256:
                    bflb_utils.printf("verification succeeded")
                else:
                    bflb_utils.printf("verification failed")
                    self.flash_load_tips()
                    self.print_error_code("003E")
                    ret = False
        self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
        return ret

    def flash_load_specified(self, file, start_addr, erase=1, verify=0, shakehand=0, callback=None):
        ret = False
        if self._skip_len > 0:
            bflb_utils.printf("skip flash file, skip addr 0x%08X, skip len 0x%08X" % (self._skip_addr, self._skip_len))
            fp = open_file(file, "rb")
            flash_data = fp.read()
            fp.close()
            flash_data_len = len(flash_data)
            if (
                self._skip_addr <= start_addr
                and self._skip_addr + self._skip_len > start_addr
                and self._skip_addr + self._skip_len < start_addr + flash_data_len
            ):
                addr = self._skip_addr + self._skip_len
                data = flash_data[self._skip_addr + self._skip_len - start_addr :]
                filename, ext = os.path.splitext(file)
                file_temp = os.path.join(app_path, filename + "_skip_" + self._bflb_com_device.replace("/", "_") + ext)
                with open(file_temp, "wb") as fp:
                    fp.write(data)
                ret = self.flash_load_opt(file_temp, addr, erase, verify, shakehand, callback)
                os.remove(file_temp)
            elif self._skip_addr > start_addr and self._skip_addr + self._skip_len < start_addr + flash_data_len:
                addr = start_addr
                data = flash_data[: self._skip_addr - start_addr]
                filename, ext = os.path.splitext(file)
                file_temp = os.path.join(app_path, filename + "_skip1_" + self._bflb_com_device.replace("/", "_") + ext)
                with open(file_temp, "wb") as fp:
                    fp.write(data)
                self.flash_load_opt(file_temp, addr, erase, verify, shakehand, callback)
                os.remove(file_temp)
                addr = self._skip_addr + self._skip_len
                data = flash_data[self._skip_addr + self._skip_len - start_addr :]
                filename, ext = os.path.splitext(file)
                file_temp = os.path.join(app_path, filename + "_skip2_" + self._bflb_com_device.replace("/", "_") + ext)
                with open(file_temp, "wb") as fp:
                    fp.write(data)
                ret = self.flash_load_opt(file_temp, addr, erase, verify, shakehand, callback)
                os.remove(file_temp)
            elif (
                self._skip_addr > start_addr
                and self._skip_addr < start_addr + flash_data_len
                and self._skip_addr + self._skip_len >= start_addr + flash_data_len
            ):
                addr = start_addr
                data = flash_data[: self._skip_addr - start_addr]
                filename, ext = os.path.splitext(file)
                file_temp = os.path.join(app_path, filename + "_skip_" + self._bflb_com_device.replace("/", "_") + ext)
                with open(file_temp, "wb") as fp:
                    fp.write(data)
                ret = self.flash_load_opt(file_temp, addr, erase, verify, shakehand, callback)
                os.remove(file_temp)
            elif self._skip_addr <= start_addr and self._skip_addr + self._skip_len >= start_addr + flash_data_len:
                return True
            else:
                ret = self.flash_load_opt(file, start_addr, erase, verify, shakehand, callback)
        else:
            ret = self.flash_load_opt(file, start_addr, erase, verify, shakehand, callback)
        return ret

    def flash_load_main_process(self, file, start_addr, erase=1, callback=None):
        fp = open_file(file, "rb")
        flash_data = bytearray(fp.read())
        fp.close()
        flash_data_len = len(flash_data)
        flash_size = self._flash_size
        if self._flash2_select is True:
            flash_size = self._flash2_size
        if flash_size < start_addr + flash_data_len:
            bflb_utils.printf(
                "program %s file to 0x%08X, but it exceeds flash size 0x%08X" % (file, start_addr, flash_size)
            )
            self.print_error_code("0045")
            return False
        i = 0
        cur_len = 0
        if erase == 1:
            if flash_data_len == 0:
                bflb_utils.printf("file size is 0")
                return False
            ret = self.flash_erase_main_process(start_addr, start_addr + flash_data_len - 1)
            if ret is False:
                return False
        start_time = time.time() * 1000
        log = ""
        decompressor = None
        if self._decompress_write and flash_data_len > 4 * 1024:
            decompressor = lzma.LZMADecompressor()
            flash_data_len_origin = flash_data_len
            ret, flash_data, flash_data_len = self.flash_load_xz_compress(file)
            if ret is False:
                bflb_utils.printf("flash write data xz failed")
                self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
                return False
            # set rx timeout to avoid chip decompress data cause timeout
            # flash page program timeout = 3ms
            # rx_timeout = flash_size / 256 * 3 / 1000
            if self._host_rx_timeout:
                rx_timeout = int(self._host_rx_timeout)
            else:
                rx_timeout = 2000 + 16 * flash_data_len_origin / flash_data_len
                if rx_timeout > 10000:
                    rx_timeout = 10000
            bflb_utils.printf("decompress write rx timeout(ms): ", round(rx_timeout, 3))
            self._bflb_com_if.if_set_rx_timeout(rx_timeout / 1000)
            start_addr |= 0x80000000
            cmd_name = "flash_decompress_write"
            chip_isp_timeout = 2000
            if self._chip_type == "bl616" or self._chip_type == "bl602":
                # bl616 has set isp timeout to 10s in bflb_img_loader.py: img_get_bootinfo
                chip_isp_timeout = 10000
            # if compress take time > 2.2s, chip timeout, reshakehand
            if (time.time() * 1000) - start_time > chip_isp_timeout * 1.1:
                bflb_utils.printf(FLASH_LOAD_HANDKE)
                if self._handshake() is False:
                    return False
            # if compress take time > 1.8s, delay 0.6s make sure chip timeout, and reshakehand
            # if compress take time <= 1.8s, no need reshakehand
            elif (time.time() * 1000) - start_time > chip_isp_timeout * 0.9:
                time.sleep(chip_isp_timeout * 0.001 * 0.3)
                bflb_utils.printf(FLASH_LOAD_HANDKE)
                if self._handshake() is False:
                    return False
            bflb_utils.printf("decompress flash load ", flash_data_len)
        else:
            cmd_name = "flash_write"

        if self._chip_type == "bl616":
            if self._bflb_com_img_loader.bl616_a0:
                # write memory, set bl616 a0 bootrom uart timeout to 2s
                tmp = bflb_utils.int_to_2bytearray_l(8)
                start_addr_tmp = bflb_utils.int_to_4bytearray_l(0x6102DF04)
                write_data = bflb_utils.int_to_4bytearray_l(0x07D01200)
                cmd_id = bflb_utils.hexstr_to_bytearray("50")
                data = cmd_id + bytearray(1) + tmp + start_addr_tmp + write_data
                self._bflb_com_if.if_write(data)
                ret, data_read_ack = self._bflb_com_if.if_deal_ack(dmy_data=False)
            else:
                # 03 command to set bl616 ax bootrom uart timeout to 2s
                tmp = bflb_utils.int_to_2bytearray_l(4)
                timeout = bflb_utils.int_to_4bytearray_l(2000)
                cmd_id = bflb_utils.hexstr_to_bytearray("23")
                data = cmd_id + bytearray(1) + tmp + timeout
                self._bflb_com_if.if_write(data)
                ret, data_read_ack = self._bflb_com_if.if_deal_ack(dmy_data=False)

        while i < flash_data_len:
            cur_len = flash_data_len - i
            if cur_len > self._bflb_com_tx_size - 8:
                cur_len = self._bflb_com_tx_size - 8
            cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get(cmd_name)["cmd_id"])
            data_send = bflb_utils.int_to_4bytearray_l(i + start_addr) + flash_data[i : i + cur_len]
            start_addr &= 0x7FFFFFFF
            try_cnt = 0
            last_rx_time_out = self._bflb_com_if.if_get_rx_timeout()
            if self._decompress_write and decompressor:
                decompress_data = decompressor.decompress(flash_data[i : i + cur_len])
                # print(f"decompress_data:{str(len(decompress_data))}")
                current_rx_timeout = len(decompress_data) / 256 * 0.5 * 2 + 2000
                current_rx_timeout = round(current_rx_timeout)
                # aligin to 4s times
                current_rx_timeout = (current_rx_timeout + 3999) // 4000 * 4000
                if current_rx_timeout != last_rx_time_out:
                    # print(f"TO:{str(current_rx_timeout)}")
                    self._bflb_com_if.if_set_rx_timeout(current_rx_timeout / 1000)
                    # last_rx_time_out = current_rx_timeout
            while True:
                ret, dmy = self.com_process_one_cmd(cmd_name, cmd_id, data_send)
                if ret.startswith("OK"):
                    break
                elif ret.find("FL000c") != -1:
                    self.print_error_code("0036")
                    self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
                    return False
                if try_cnt < self._checksum_err_retry_limit:
                    bflb_utils.printf("retry")
                    try_cnt += 1
                else:
                    self.print_error_code("0036")
                    self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
                    return False
            i += cur_len
            length = len(str(flash_data_len)) + 1
            log = (
                # "load{:>8}/{:<8}[{}%]".format(i, flash_data_len, (i*100)//flash_data_len)
                "load{0}/{1}[{2}%]".format(
                    str(i).rjust(length), str(flash_data_len).ljust(length), (i * 100) // flash_data_len
                )
            )
            bflb_utils.printf(log)
            if callback is not None and flash_data_len > 200:
                callback(i, flash_data_len, "APP_WR")
        bflb_utils.printf(log)
        if self.flash_write_check_main_process() is False:
            bflb_utils.printf("flash write check failed")
            self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
            return False
        self._bflb_com_if.if_set_rx_timeout(self._default_time_out)
        time_cost = (time.time() * 1000) - start_time
        bflb_utils.printf("flash load time cost(ms): ", round(time_cost, 3))
        return True

    @staticmethod
    def flash_load_xz_compress(file):
        try:
            xz_filters = [
                {"id": lzma.FILTER_LZMA2, "dict_size": 32768},
            ]
            fp = open_file(file, "rb")
            data = bytearray(fp.read())
            fp.close()
            flash_data = lzma.compress(data, check=lzma.CHECK_CRC32, filters=xz_filters)
            flash_data_len = len(flash_data)
        except Exception as e:
            bflb_utils.printf(e)
            return False, None, None
        return True, flash_data, flash_data_len

    @staticmethod
    def flash_load_tips():
        bflb_utils.printf("########################################################################")
        bflb_utils.printf("请按照以下描述排查问题：")
        bflb_utils.printf("是否降低烧录波特率到500K测试过")
        bflb_utils.printf("烧写文件的大小是否超过Flash所能存储的最大空间")
        bflb_utils.printf("Flash是否被写保护")
        bflb_utils.printf("########################################################################")

    def flash_update_para(self, file, jedec_id):
        flash_para = bytearray(0)
        if self.is_conf_exist(jedec_id) is True:
            sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
            if conf_sign:
                cfg_dir = app_path + "/utils/flash/" + self._chip_name + "/"
            else:
                cfg_dir = app_path + "/utils/flash/" + self._chip_type + "/"
            conf_name = sub_module.flash_select_do.get_suitable_file_name(cfg_dir, jedec_id)
            (
                offset,
                flash_cfg_length,
                flash_para,
                flash_crc_offset,
                crc_offset,
            ) = bflb_flash_select.update_flash_para_from_cfg(
                sub_module.bootheader_cfg_keys.bootheader_cfg_keys, cfg_dir + conf_name
            )
            with open(os.path.join(app_path, file), "wb+") as fp:
                fp.write(flash_para)
        return flash_para

    def _handshake(self):
        isp_sh_time = 0
        if self._chip_type == "bl702" or self._chip_type == "bl702l":
            isp_sh_time = self._isp_shakehand_timeout
        self._bflb_com_if.if_init(self._bflb_com_device, self._bflb_com_speed, self._chip_type, self._chip_name)
        if (
            self._bflb_com_if.if_shakehand(
                do_reset=False,
                reset_hold_time=100,
                shake_hand_delay=100,
                reset_revert=True,
                cutoff_time=0,
                shake_hand_retry=2,
                isp_timeout=isp_sh_time,
                boot_load=False,
            )
            != "OK"
        ):
            self.print_error_code("0001")
            return False
        self._need_handshake = False
        return True

    def load_shake_hand(
        self,
        interface,
        do_reset=False,
        reset_hold_time=100,
        shake_hand_delay=100,
        reset_revert=True,
        cutoff_time=0,
        shake_hand_retry=2,
        isp_timeout=0,
    ):
        bflb_utils.printf("========= handshake with bootrom =========")
        if interface == "jlink":
            bflb_utils.printf("handshake via jlink")
            self._bflb_com_if.if_init(self._bflb_com_device, self._bflb_com_speed, self._chip_type, self._chip_name)
            return "OK", None
        elif interface == "openocd":
            bflb_utils.printf("handshake via openocd")
            self._bflb_com_if.if_init(
                self._bflb_com_device,
                self._bflb_sn_device,
                self._bflb_com_speed,
                self._chip_type,
                self._chip_name,
            )
            return "OK", None
        elif interface == "cklink":
            bflb_utils.printf("handshake via cklink")
            self._bflb_com_if.if_init(
                self._bflb_com_device,
                self._bflb_sn_device,
                self._bflb_com_speed,
                self._chip_type,
                self._chip_name,
            )
            return "OK", None
        elif interface == "uart":
            ret = True
            bflb_utils.printf("handshake via uart")
            self._bflb_com_img_loader.img_load_interface_init(self._bflb_com_device, self._bflb_boot_speed)
            ret = self._bflb_com_img_loader.img_load_shake_hand(
                self._bflb_com_device,
                self._bflb_boot_speed,
                self._bflb_boot_speed,
                do_reset,
                reset_hold_time,
                shake_hand_delay,
                reset_revert,
                cutoff_time,
                shake_hand_retry,
                isp_timeout,
            )
            return ret, None

    def load_romfs_data(self, data, addr, verify, shakehand=1, callback=None):
        romfs_path = os.path.join(chip_path, self._chip_name, "romfs")
        dst_img_name = os.path.join(chip_path, self._chip_name, self._outdir, "media.bin")
        if not os.path.exists(romfs_path):
            os.makedirs(romfs_path)
        private_key_file = os.path.join(romfs_path, "private_key")
        with open(private_key_file, "w+") as f:
            f.write(data)
        exe = None
        if os.name == "nt":
            exe = os.path.join(app_path, "utils/genromfs", "genromfs.exe")
        elif os.name == "posix":
            machine = os.uname().machine
            if machine == "x86_64":
                exe = os.path.join(app_path, "utils/genromfs", "genromfs_amd64")
            elif machine == "armv7l":
                exe = os.path.join(app_path, "utils/genromfs", "genromfs_armel")
        if exe is None:
            bflb_utils.printf("no supported genromfs exe for your platform!")
            return -1
        dirname = os.path.abspath(romfs_path)
        dst = os.path.abspath(dst_img_name)
        if os.name == "nt":
            CREATE_NO_WINDOW = 0x08000000
            subprocess.call([exe, "-d", dirname, "-f", dst], creationflags=CREATE_NO_WINDOW)
        else:
            subprocess.call([exe, "-d", dirname, "-f", dst])
        bflb_utils.printf("========= programming romfs {0} to {1}".format(dst_img_name, hex(addr)))
        ret = self.flash_load_specified(dst_img_name, addr, 1, verify, 0, callback)
        return ret

    def load_firmware_bin(self, file, verify, shakehand=1, callback=None):
        entry_name = ""
        sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
        pt_addr1 = sub_module.partition_cfg_do.partition1_addr
        pt_addr2 = sub_module.partition_cfg_do.partition2_addr
        entry_name = sub_module.partition_cfg_do.fireware_name
        ret, fwaddr, max_len = self.get_active_fwbin_addr(pt_addr1, pt_addr2, entry_name, shakehand, callback)
        if ret is False:
            bflb_utils.printf("get active fwbin addr failed")
            return False
        if os.path.getsize(file) > max_len:
            bflb_utils.printf("fwbin size > max len", os.path.getsize(file))
            return False
        bflb_utils.printf("========= programming firmare {0} to {1}".format(file, hex(fwaddr)))
        ret = self.flash_load_specified(file, fwaddr, 1, verify, 0, callback)
        return ret

    def load_helper_bin(
        self,
        interface,
        helper_file,
        do_reset=False,
        reset_hold_time=100,
        shake_hand_delay=100,
        reset_revert=True,
        cutoff_time=0,
        shake_hand_retry=2,
        isp_timeout=0,
        **kwargs,
    ):
        bflb_utils.printf("========= load eflash_loader.bin =========")
        bootinfo = None
        if interface == "jlink":
            bflb_utils.printf("load eflash_loader.bin via jlink")
            self._bflb_com_if.if_init(self._bflb_com_device, self._bflb_com_speed, self._chip_type, self._chip_name)
            self._bflb_com_if.reset_cpu()
            imge_fp = open_file(helper_file, "rb")
            # eflash_loader.bin has 192 bytes bootheader and seg header
            fw_data = bytearray(imge_fp.read())[192:] + bytearray(0)
            imge_fp.close()
            sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
            load_addr = sub_module.jlink_load_cfg.jlink_load_addr
            self._bflb_com_if.if_raw_write(load_addr, fw_data)
            pc = fw_data[4:8]
            pc = bytes([pc[3], pc[2], pc[1], pc[0]])
            # c.reverse()
            msp = fw_data[0:4]
            msp = bytes([msp[3], msp[2], msp[1], msp[0]])
            # msp.reverse()
            self._bflb_com_if.set_pc_msp(binascii.hexlify(pc), binascii.hexlify(msp).decode("utf-8"))
            time.sleep(0.01)
            self._bflb_com_if.if_close()
            return True, bootinfo, ""
        elif interface == "openocd":
            bflb_utils.printf("load eflash_loader.bin via openocd")
            self._bflb_com_if.if_init(
                self._bflb_com_device,
                self._bflb_sn_device,
                self._bflb_com_speed,
                self._chip_type,
                self._chip_name,
            )
            self._bflb_com_if.halt_cpu()
            imge_fp = open_file(helper_file, "rb")
            # eflash_loader.bin has 192 bytes bootheader and seg header
            fw_data = bytearray(imge_fp.read())[192:] + bytearray(0)
            imge_fp.close()
            sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
            load_addr = sub_module.openocd_load_cfg.openocd_load_addr
            self._bflb_com_if.if_raw_write(load_addr, fw_data)
            pc = fw_data[4:8]
            pc = bytes([pc[3], pc[2], pc[1], pc[0]])
            # c.reverse()
            msp = fw_data[0:4]
            msp = bytes([msp[3], msp[2], msp[1], msp[0]])
            # msp.reverse()
            self._bflb_com_if.set_pc_msp(binascii.hexlify(pc), binascii.hexlify(msp).decode("utf-8"))
            return True, bootinfo, ""
        elif interface == "cklink":
            bflb_utils.printf("load eflash_loader.bin via cklink")
            self._bflb_com_if.if_init(
                self._bflb_com_device,
                self._bflb_sn_device,
                self._bflb_com_speed,
                self._chip_type,
                self._chip_name,
            )
            # self._bflb_com_if.reset_cpu()
            self._bflb_com_if.halt_cpu()
            imge_fp = open_file(helper_file, "rb")
            # eflash_loader.bin has 192 bytes bootheader and seg header
            fw_data = bytearray(imge_fp.read())[192:] + bytearray(0)
            imge_fp.close()
            sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
            load_addr = sub_module.openocd_load_cfg.openocd_load_addr
            self._bflb_com_if.if_raw_write(load_addr, fw_data)
            pc = fw_data[4:8]
            pc = bytes([pc[3], pc[2], pc[1], pc[0]])
            # c.reverse()
            msp = fw_data[0:4]
            msp = bytes([msp[3], msp[2], msp[1], msp[0]])
            # msp.reverse()
            self._bflb_com_if.set_pc_msp(binascii.hexlify(pc), binascii.hexlify(msp).decode("utf-8"))
            self._bflb_com_if.resume_cpu()
            return True, bootinfo, ""
        elif interface == "uart" or interface == "sdio":
            ret = True
            bflb_utils.printf("load eflash_loader.bin via {}".format(interface))
            start_time = time.time() * 1000
            ret, bootinfo, res = self._bflb_com_img_loader.img_load_process(
                self._bflb_com_device,
                self._bflb_boot_speed,
                self._bflb_boot_speed,
                helper_file,
                "",
                None,
                do_reset,
                reset_hold_time,
                shake_hand_delay,
                reset_revert,
                cutoff_time,
                shake_hand_retry,
                isp_timeout,
                True,
                self._bootinfo,
                **kwargs,
            )
            time_cost = (time.time() * 1000) - start_time
            bflb_utils.printf("load helper bin time cost(ms): ", round(time_cost, 3))
            return ret, bootinfo, res

    def efuse_flash_loader(
        self,
        args,
        eflash_loader_cfg,
        eflash_loader_bin,
        callback=None,
        create_simple_callback=None,
        create_img_callback=None,
        macaddr_callback=None,
        task_num=None,
        **kwargs,
    ):
        ret = None
        if task_num is None:
            bflb_utils.local_log_enable(True)
        bflb_utils.printf("eflash loader version: ", bflb_version.version_text.replace("(", "").replace(")", ""))
        start_time = time.time() * 1000
        try:
            retry = -1
            update_cutoff_time = True
            if task_num is not None:
                if task_num > 256:
                    self._csv_burn_en = False
                    self._task_num = task_num - 256
                else:
                    self._csv_burn_en = True
                    self._task_num = task_num
            else:
                self._csv_burn_en = False
                self._task_num = None
            while True:
                if self._bflb_com_if is not None:
                    self._bflb_com_if.if_close()
                bflb_utils.printf("program start")
                ret, flash_burn_retry = self.efuse_flash_loader_do(
                    args,
                    eflash_loader_cfg,
                    eflash_loader_bin,
                    callback,
                    update_cutoff_time,
                    create_simple_callback,
                    create_img_callback,
                    macaddr_callback,
                    task_num,
                    **kwargs,
                )
                self._skip_len = 0
                if ret == "repeat_burn":
                    if self._bflb_com_if is not None:
                        self._bflb_com_if.if_close()
                    return "repeat_burn"
                if self._cpu_reset is True:
                    # bflb_utils.printf("reset cpu")
                    self.reset_cpu()
                if self._retry_delay_after_cpu_reset > 0:
                    bflb_utils.printf("delay for uart timeout:", self._retry_delay_after_cpu_reset)
                    time.sleep(self._retry_delay_after_cpu_reset)
                if retry == -1:
                    retry = flash_burn_retry
                if ret is True:
                    if not args.none:
                        time_cost = (time.time() * 1000) - start_time
                        bflb_utils.printf("all time cost(ms): ", round(time_cost, 3))
                        time.sleep(0.1)
                        if self._bflb_com_if is not None:
                            bflb_utils.printf("close interface")
                            self._bflb_com_if.if_close()
                        self.save_csv_file(self._csv_data, self._csv_file, True)
                        bflb_utils.printf("[All Successful]")
                        bflb_utils.local_log_save("log", self._input_macaddr)
                    return True
                else:
                    retry -= 1
                    bflb_utils.printf("burn retry")
                    # bflb_utils.printf(retry)
                    if retry <= 0:
                        break
            bflb_utils.printf("burn return with retry failed")
            self.save_csv_file(self._csv_data, self._csv_file, False)
            bflb_utils.local_log_save("log", self._input_macaddr)
            if self._bflb_com_if is not None:
                self._bflb_com_if.if_close()
            return bflb_utils.get_error_code_msg(self._task_num)
        except Exception as e:
            print(e)
            bflb_utils.printf("efuse_flash_loader failed")
            # bflb_utils.printf(e)
            # traceback.print_exc(limit=NUM_ERR, file=sys.stdout)
            self.save_csv_file(self._csv_data, self._csv_file, False)
            bflb_utils.local_log_save("log", self._input_macaddr)
            if self._bflb_com_if is not None:
                self._bflb_com_if.if_close()
            return bflb_utils.get_error_code_msg(self._task_num)

    def efuse_flash_loader2(self, options, eflash_loader_cfg, eflash_loader_bin, callback=None, port=""):
        if port is not None and port:
            import socket

            bflb_utils.printf("Listen on port: ", port)
            ip_port = ("127.0.0.1", int(port))
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.bind(ip_port)
            while True:
                data, client_addr = server.recvfrom(1024)
            server.close()
        else:
            self.efuse_flash_loader(options, eflash_loader_cfg, eflash_loader_bin, callback)

    def efuse_flash_loader_do(
        self,
        args,
        eflash_loader_cfg,
        eflash_loader_bin,
        callback=None,
        update_cutoff_time=True,
        create_simple_callback=None,
        create_img_callback=None,
        macaddr_callback=None,
        task_num=None,
        **kwargs,
    ):
        bflb_utils.printf("========= eflash loader cmd arguments =========")
        # bflb_utils.printf(eflash_loader_cfg)
        config_file = None
        eflash_loader_file = None
        bootinfo = None
        try:
            start = ""
            end = ""
            packet_file = ""
            img_file = ""
            efuse_file = ""
            massbin = ""
            fwbin = ""
            address = ""
            load_str = ""
            load_data = ""
            load_data_encrypted = ""
            interface = ""
            port = ""
            load_speed = ""
            aeskey = ""
            aesiv = ""
            publickey = ""
            privatekey = ""
            chip_type = ""
            xtal_type = ""
            load_file = ""
            macaddr = ""
            romfs_data = ""
            csv_file = ""
            csvaddr = ""
            efuse_para = ""
            create_cfg = ""
            flash_set = 0
            read_flash_id = 0
            id_valid_flag = "80"
            read_flash2_id = 0
            id2_valid_flag = "80"
            efuse_load_func = 0
            dacvalue = ""
            dacaddr = ""
            dackey = ""
            daciv = ""
            if args.config and config_file is None:
                config_file = args.config
            if args.interface:
                interface = args.interface
            if args.port:
                port = args.port
            if args.baudrate:
                load_speed = args.baudrate
            if args.mass:
                massbin = args.mass
            if args.userarea:
                fwbin = args.userarea
            if args.start:
                start = args.start
            if args.end:
                end = args.end
            if args.packet:
                packet_file = args.packet
            if args.file:
                img_file = args.file
            if args.efusefile:
                efuse_file = args.efusefile
            if args.efusecheck:
                efuse_load_func = 1
            else:
                efuse_load_func = 0
            if args.data:
                load_data = args.data
            if args.data_encrypted:
                load_data_encrypted = args.data_encrypted
            if args.addr:
                address = args.addr
            if args.skip:
                skip_str = args.skip
                skip_para = skip_str.split(",")
                if skip_para[0][0:2] == "0x":
                    self._skip_addr = int(skip_para[0][2:], 16)
                else:
                    self._skip_addr = int(skip_para[0], 10)
                if skip_para[1][0:2] == "0x":
                    self._skip_len = int(skip_para[1][2:], 16)
                else:
                    self._skip_len = int(skip_para[1], 10)
            if args.key:
                aeskey = args.key
            if args.iv:
                aesiv = args.iv
            if args.publickey:
                publickey = args.publickey
            if args.privatekey:
                privatekey = args.privatekey
            if args.createcfg:
                create_cfg = args.createcfg
            if args.chipname:
                chip_type = gol.dict_chip_cmd[args.chipname]
            if args.xtal:
                xtal_type = args.xtal.replace("m", "M").replace("rc", "RC").replace("none", "None")
            if args.loadstr:
                load_str = args.loadstr
            if args.loadfile:
                load_file = args.loadfile
            if args.mac:
                macaddr = args.mac
            if args.isp:
                self._isp_en = True
            else:
                self._isp_en = False
            if args.romfs:
                romfs_data = args.romfs
            if args.csvfile:
                csv_file = args.csvfile
            if args.csvaddr:
                csvaddr = args.csvaddr
            if args.auto:
                bflb_utils.printf("auto burn")
                self._bflb_auto_download = True
            else:
                self._bflb_auto_download = False
            if args.para:
                efuse_para = args.para
            if args.dac_value:
                dacvalue = args.dac_value
            if args.dac_addr:
                dacaddr = args.dac_addr
            if args.dac_key:
                dackey = args.dac_key
            if args.dac_iv:
                daciv = args.dac_iv
        except Exception as e:
            bflb_utils.printf(e)
            self.print_error_code("0002")
            return False, 0

        if packet_file != "":
            if self.unpack_file_zip(packet_file) is True:
                return True, 0
            else:
                return False, 0
        if chip_type:
            self._chip_type = chip_type
        if config_file is None:
            if self._chip_name:
                config_file = os.path.join(
                    app_path,
                    "chips",
                    self._chip_name.lower(),
                    "eflash_loader",
                    "eflash_loader_cfg.ini",
                )
            else:
                config_file = "eflash_loader_cfg.ini"
        if args.usage:
            self.print_usage()
        load_str = load_str.replace("*", "\n").replace("%", " ")
        # get interface
        if config_file is None and load_str is None and eflash_loader_cfg is None:
            return False, 0
        if not load_str:
            if eflash_loader_cfg is not None:
                config_file = eflash_loader_cfg
            else:
                config_file = os.path.abspath(config_file)
            if isinstance(config_file, BFConfigParser):
                cfg = config_file
            else:
                bflb_utils.printf("config file: ", os.path.normpath(config_file))
                if os.path.exists(config_file):
                    cfg = BFConfigParser()
                    cfg.read(config_file)
                else:
                    bflb_utils.printf("config file not found, copy and use default config file")
                    default_cfg = os.path.join(
                        app_path,
                        "chips",
                        self._chip_name.lower(),
                        "eflash_loader",
                        "eflash_loader_cfg.conf",
                    )
                    shutil.copyfile(default_cfg, config_file)
                    cfg = BFConfigParser()
                    cfg.read(config_file)
        else:
            cfg = BFConfigParser()
            bflb_utils.printf("config str: ", load_str)
        if cfg.has_option("LOAD_CFG", "local_log"):
            if cfg.get("LOAD_CFG", "local_log") == "true":
                bflb_utils.printf("local log enable")
                bflb_utils.local_log_enable(True)
                if isinstance(macaddr, str):
                    self._input_macaddr = macaddr
                else:
                    self._input_macaddr = ""
            else:
                bflb_utils.local_log_enable(False)
                self._input_macaddr = ""
        # get interface and device
        if not interface:
            if cfg.has_option("LOAD_CFG", "interface"):
                interface = cfg.get("LOAD_CFG", "interface")
            else:
                interface = "uart"
        if not port:
            if interface == "openocd":
                self._bflb_com_device = cfg.get("LOAD_CFG", "openocd_config")
                self._bflb_sn_device = cfg.get("LOAD_CFG", "device")
            elif interface == "cklink":
                self._bflb_com_device = cfg.get("LOAD_CFG", "cklink_vidpid")
                self._bflb_sn_device = cfg.get("LOAD_CFG", "cklink_type") + " " + cfg.get("LOAD_CFG", "device")
            else:
                self._bflb_com_device = cfg.get("LOAD_CFG", "device")
        else:
            self._bflb_com_device = port
        bflb_utils.printf("serial port is ", self._bflb_com_device)
        verify = 0
        erase = 1
        if cfg.has_option("LOAD_CFG", "verify"):
            verify = int(cfg.get("LOAD_CFG", "verify"))
        if cfg.has_option("LOAD_CFG", "erase"):
            erase = int(cfg.get("LOAD_CFG", "erase"))
        if interface == "cklink":
            self._bflb_com_tx_size = 14344
        else:
            if cfg.has_option("LOAD_CFG", "tx_size"):
                self._bflb_com_tx_size = int(cfg.get("LOAD_CFG", "tx_size"))
        do_reset = False
        reset_hold_time = 100
        shake_hand_delay = 100
        reset_revert = True
        cutoff_time = 0
        shake_hand_retry = 2
        flash_burn_retry = 1
        if cfg.has_option("LOAD_CFG", "host_rx_timeout"):
            self._host_rx_timeout = cfg.get("LOAD_CFG", "host_rx_timeout")
        if cfg.has_option("LOAD_CFG", "erase_time_out"):
            self._erase_time_out = int(cfg.get("LOAD_CFG", "erase_time_out"))
        if cfg.has_option("LOAD_CFG", "shake_hand_retry"):
            shake_hand_retry = int(cfg.get("LOAD_CFG", "shake_hand_retry"))
        if cfg.has_option("LOAD_CFG", "flash_burn_retry"):
            flash_burn_retry = int(cfg.get("LOAD_CFG", "flash_burn_retry"))
        if cfg.has_option("LOAD_CFG", "checksum_err_retry"):
            self._checksum_err_retry_limit = int(cfg.get("LOAD_CFG", "checksum_err_retry"))
        if cfg.has_option("LOAD_CFG", "chiptype"):
            self._chip_type = cfg.get("LOAD_CFG", "chiptype")
        if cfg.has_option("LOAD_CFG", "cpu_reset_after_load"):
            self._cpu_reset = cfg.get("LOAD_CFG", "cpu_reset_after_load") == "true"
        if cfg.has_option("LOAD_CFG", "retry_delay_after_cpu_reset"):
            self._retry_delay_after_cpu_reset = int(cfg.get("LOAD_CFG", "retry_delay_after_cpu_reset"))
            bflb_utils.printf("retry delay: ", self._retry_delay_after_cpu_reset)
        if cfg.has_option("LOAD_CFG", "eflash_loader_file") and eflash_loader_file is None:
            eflash_loader_file = cfg.get("LOAD_CFG", "eflash_loader_file")
        if cfg.has_option("LOAD_CFG", "skip_mode") and self._skip_len == 0:
            skip_para = cfg.get("LOAD_CFG", "skip_mode")
            if skip_para[0][0:2] == "0x":
                self._skip_addr = int(skip_para[0][2:], 16)
            else:
                self._skip_addr = int(skip_para[0], 10)
            if skip_para[1][0:2] == "0x":
                self._skip_len = int(skip_para[1][2:], 16)
            else:
                self._skip_len = int(skip_para[1], 10)
            if self._skip_len > 0:
                if erase == 2:
                    bflb_utils.printf("error: skip mode can not set flash chiperase")
                    self.print_error_code("0044")
                    return False, 0
        if self._bflb_auto_download is False and cfg.has_option("LOAD_CFG", "auto_burn"):
            if "true" == cfg.get("LOAD_CFG", "auto_burn"):
                self._bflb_auto_download = True
            else:
                self._bflb_auto_download = False
        bflb_utils.printf("cpu reset flag is ", self._cpu_reset)
        if xtal_type != "":
            eflash_loader_file = (
                "chips/"
                + self._chip_name.lower()
                + "/eflash_loader/eflash_loader_"
                + xtal_type.replace(".", "p").lower()
                + ".bin"
            )
        if load_file and not eflash_loader_file:
            eflash_loader_file = load_file
        if eflash_loader_bin is not None:
            eflash_loader_file = eflash_loader_bin
        elif eflash_loader_file is not None:
            eflash_loader_file = os.path.join(app_path, eflash_loader_file)
        bflb_utils.printf("chip type: ", self._chip_type)
        if interface == "uart" or interface == "sdio":
            bflb_utils.printf("========= interface is {} =========".format(interface))
            self._bflb_com_img_loader = bflb_img_loader.BflbImgLoader(
                self._chip_type, self._chip_name, interface, create_cfg
            )
            self._bflb_com_if = self._bflb_com_img_loader.bflb_boot_if
            if load_speed:
                self._bflb_com_speed = load_speed
            else:
                if cfg.has_option("LOAD_CFG", "speed_uart_load"):
                    self._bflb_com_speed = int(cfg.get("LOAD_CFG", "speed_uart_load"))
            bflb_utils.printf("uart speed: ", self._bflb_com_speed)
            if cfg.has_option("LOAD_CFG", "speed_uart_boot"):
                self._bflb_boot_speed = int(cfg.get("LOAD_CFG", "speed_uart_boot"))
            if load_speed and (
                self._chip_type == "bl616" or self._chip_type == "bl616l" or self._chip_type == "bl616d"
            ):
                self._bflb_boot_speed = load_speed
            if self._isp_en is True and self._chip_type == "bl602":
                self._bflb_boot_speed = self._bflb_com_speed
            if cfg.has_option("LOAD_CFG", "reset_hold_time"):
                reset_hold_time = int(cfg.get("LOAD_CFG", "reset_hold_time"))
            if cfg.has_option("LOAD_CFG", "shake_hand_delay"):
                shake_hand_delay = int(cfg.get("LOAD_CFG", "shake_hand_delay"))
            if cfg.has_option("LOAD_CFG", "do_reset"):
                do_reset = cfg.get("LOAD_CFG", "do_reset") == "true"
            if cfg.has_option("LOAD_CFG", "reset_revert"):
                reset_revert = cfg.get("LOAD_CFG", "reset_revert") == "true"
            if update_cutoff_time and cfg.has_option("LOAD_CFG", "cutoff_time"):
                cutoff_time = int(cfg.get("LOAD_CFG", "cutoff_time"))
            if cfg.has_option("LOAD_CFG", "isp_mode_speed") and self._isp_en is True:
                isp_mode_speed = int(cfg.get("LOAD_CFG", "isp_mode_speed"))
                self._bflb_com_if.if_set_isp_baudrate(isp_mode_speed)
        elif interface == "jlink":
            bflb_utils.printf("========= interface is JLink =========")
            self._bflb_com_if = bflb_interface_jlink.BflbJLinkPort()
            if load_speed:
                self._bflb_com_speed = load_speed // 1000
                bflb_utils.printf("jlink speed: %dk" % (self._bflb_com_speed))
            else:
                if cfg.has_option("LOAD_CFG", "speed_jlink"):
                    self._bflb_com_speed = int(cfg.get("LOAD_CFG", "speed_jlink"))
                else:
                    self._bflb_com_speed = 2000
            self._bflb_boot_speed = self._bflb_com_speed
        elif interface == "openocd":
            bflb_utils.printf("========= interface is Openocd =========")
            self._bflb_com_if = bflb_interface_openocd.BflbOpenocdPort()
            if load_speed:
                self._bflb_com_speed = load_speed // 1000
                bflb_utils.printf("openocd speed: %dk" % (self._bflb_com_speed))
            else:
                if cfg.has_option("LOAD_CFG", "speed_jlink"):
                    self._bflb_com_speed = int(cfg.get("LOAD_CFG", "speed_jlink"))
                else:
                    self._bflb_com_speed = 2000
            self._bflb_boot_speed = self._bflb_com_speed
        elif interface == "cklink":
            bflb_utils.printf("========= interface is CKLink =========")
            self._bflb_com_if = bflb_interface_cklink.BflbCKLinkPort()
            if load_speed:
                self._bflb_com_speed = load_speed // 1000
                bflb_utils.printf("cklink speed: %dk" % (self._bflb_com_speed))
            else:
                if cfg.has_option("LOAD_CFG", "speed_jlink"):
                    self._bflb_com_speed = int(cfg.get("LOAD_CFG", "speed_jlink"))
                else:
                    self._bflb_com_speed = 2000
            self._bflb_boot_speed = self._bflb_com_speed
        else:
            bflb_utils.printf(interface, " is not supported")
            return False, flash_burn_retry
        # add common config
        if cfg.has_option("LOAD_CFG", "password"):
            self._bflb_com_if.set_password(cfg.get("LOAD_CFG", "password"))
        self._need_handshake = True
        ram_load = False
        load_function = 1
        if args.ram and args.file:
            ram_load = True
            eflash_loader_file = img_file

        if (aeskey != "" and aesiv != "") or (publickey != "" and privatekey != ""):
            self._bflb_com_img_loader.img_load_set_sec_cfg(aeskey, aesiv, publickey, privatekey)

        try:
            if args.chipid:
                ret, bootinfo, res = self.get_boot_info(
                    interface,
                    eflash_loader_file,
                    do_reset,
                    reset_hold_time,
                    shake_hand_delay,
                    reset_revert,
                    cutoff_time,
                    shake_hand_retry,
                )
                if ret is False:
                    self.print_error_code("0003")
                    return False, flash_burn_retry
                else:
                    return True, flash_burn_retry

            if cfg.has_option("LOAD_CFG", "load_function"):
                load_function = int(cfg.get("LOAD_CFG", "load_function"))
            if cfg.has_option("LOAD_CFG", "isp_shakehand_timeout"):
                self._isp_shakehand_timeout = int(cfg.get("LOAD_CFG", "isp_shakehand_timeout"))
            if self._isp_en is True:
                if self._isp_shakehand_timeout == 0:
                    self._isp_shakehand_timeout = 5
                if self._chip_type == "bl702":
                    load_function = 0
                elif self._chip_type == "bl602":
                    load_function = 1
                else:
                    load_function = 2
            if ram_load:
                load_function = 1
                ram = True
            else:
                ram = False
            if load_function == 0:
                bflb_utils.printf("no need to load eflash_loader.bin")
            elif load_function == 1:
                load_bin_pass = False
                bflb_utils.printf("eflash load helper file: ", os.path.normpath(eflash_loader_file))
                ret, bootinfo, res = self.load_helper_bin(
                    interface,
                    eflash_loader_file,
                    do_reset,
                    reset_hold_time,
                    shake_hand_delay,
                    reset_revert,
                    cutoff_time,
                    shake_hand_retry,
                    self._isp_shakehand_timeout,
                    ram=ram,
                    **kwargs,
                )
                if res == "shake hand fail":
                    self.print_error_code("0050")
                if res.startswith("repeat_burn") is True:
                    # self.print_error_code("000A")
                    return "repeat_burn", flash_burn_retry
                if res.startswith("error_shakehand") is True:
                    if self._cpu_reset is True:
                        self.print_error_code("0003")
                        return False, flash_burn_retry
                    else:
                        load_bin_pass = True
                        time.sleep(4.5)
                if ret is False and load_bin_pass is False:
                    self.print_error_code("0003")
                    return False, flash_burn_retry
                if ram_load:
                    return True, flash_burn_retry
            elif load_function == 2:
                load_bin_pass = False
                bflb_utils.printf("bootrom load")
                ret, bootinfo, res = self.get_boot_info(
                    interface,
                    eflash_loader_file,
                    do_reset,
                    reset_hold_time,
                    shake_hand_delay,
                    reset_revert,
                    cutoff_time,
                    shake_hand_retry,
                    self._isp_shakehand_timeout,
                )
                if res == "shake hand fail":
                    self.print_error_code("0050")
                if res.startswith("repeat_burn") is True:
                    # self.print_error_code("000A")
                    return "repeat_burn", flash_burn_retry
                if res.startswith("error_shakehand") is True:
                    if self._cpu_reset is True:
                        self.print_error_code("0003")
                        return False, flash_burn_retry
                    else:
                        load_bin_pass = True
                        time.sleep(4.5)
                if ret is False and load_bin_pass is False:
                    self.print_error_code("0050")
                    return False, flash_burn_retry
                self._need_handshake = False
                clock_para = bytearray(0)
                if cfg.has_option("LOAD_CFG", "clock_para"):
                    clock_para_str = cfg.get("LOAD_CFG", "clock_para")
                    if clock_para_str != "":
                        clock_para_file = os.path.join(app_path, clock_para_str)
                        bflb_utils.printf("clock para file: ", clock_para_file)
                        clock_para = self.update_clock_para(os.path.join(app_path, clock_para_file))
                bflb_utils.printf("change baudrate to ", self._bflb_com_speed)
                ret = self.set_clock_pll(self._need_handshake, True, self._bflb_com_speed, clock_para)
                if ret is False:
                    bflb_utils.printf("pll set failed")
                    return False, flash_burn_retry
            sign = 0
            encrypt = 0
            if bootinfo:
                if self._chip_type == "bl808" or self._chip_type == "bl628":
                    sign = int(bootinfo.encode("utf-8")[8:10], 16)
                    encrypt = int(bootinfo.encode("utf-8")[12:14], 16)
                else:
                    sign = int(bootinfo.encode("utf-8")[8:10], 16)
                    encrypt = int(bootinfo.encode("utf-8")[10:12], 16)
                if args.auto_efuse_verify:
                    if sign == 1 or encrypt == 1:
                        bflb_utils.printf("skip efuse verify")
                        cfg.set("EFUSE_CFG", "factory_mode", "false")
                    else:
                        cfg.set("EFUSE_CFG", "factory_mode", "true")
        except Exception as e:
            bflb_utils.printf(e)
            self.print_error_code("0003")
            return False, flash_burn_retry
        time.sleep(0.1)

        if self._isp_en is True and self._cpu_reset is True:
            if (
                self._chip_type == "bl808"
                or self._chip_type == "bl628"
                or self._chip_type == "bl616"
                or self._chip_type == "wb03"
            ):
                # clear boot status for boot from media after isp mode
                self.clear_boot_status(self._need_handshake)

        macaddr_check = False
        mac_addr = bytearray(0)
        if cfg.has_option("LOAD_CFG", "check_mac"):
            macaddr_check = cfg.get("LOAD_CFG", "check_mac") == "true"
        if macaddr_check and self._isp_en is False:
            # check mac addr
            # isp mode don't support read macaddr
            check_macaddr_cnt = 5
            while True:
                ret, mac_addr = self.efuse_read_mac_addr_process(self._need_handshake)
                if ret is False:
                    bflb_utils.printf("read mac addr failed")
                else:
                    break
                check_macaddr_cnt -= 1
                if check_macaddr_cnt == 0:
                    return False, flash_burn_retry
            bflb_utils.printf("mac addr: ", binascii.hexlify(mac_addr).decode("utf-8"))
            if mac_addr == self._macaddr_check:
                self.print_error_code("000A")
                return False, flash_burn_retry
            self._need_handshake = False
            self._macaddr_check_status = True

        # for mass_production tool
        if macaddr_callback is not None:
            ret, self._efuse_data, self._efuse_mask_data, macaddr = macaddr_callback(
                binascii.hexlify(mac_addr).decode("utf-8")
            )
            if ret is False:
                return False, flash_burn_retry
            if (self._efuse_data != bytearray(0) and self._efuse_mask_data != bytearray(0)) or macaddr != "":
                args.efuse = True
        if callback:
            callback(0, 100, trans("MainWindow", "进行", None, -1), "blue")

        if args.flash:
            # set flash parameter
            flash_pin = 0
            flash_clock_cfg = 0
            flash_io_mode = 0
            flash_clk_delay = 0
            if cfg.has_option("FLASH_CFG", "decompress_write"):
                self._decompress_write = cfg.get("FLASH_CFG", "decompress_write") == "true"
            if self._chip_type == "bl60x" or self._chip_type == "bl702":
                self._decompress_write = False
            bflb_utils.printf("flash set para")
            if cfg.get("FLASH_CFG", "flash_pin"):
                flash_pin_cfg = cfg.get("FLASH_CFG", "flash_pin")
                if flash_pin_cfg.startswith("0x"):
                    flash_pin = int(flash_pin_cfg, 16)
                else:
                    flash_pin = int(flash_pin_cfg, 10)
                if flash_pin == 0x80:
                    flash_pin = self.flash_get_pin_from_bootinfo(self._chip_type, bootinfo)
                    bflb_utils.printf("get flash pin cfg from bootinfo: 0x%02X" % (flash_pin))
            else:
                if self._chip_type == "bl602" or self._chip_type == "bl702":
                    flash_pin = 0xFF
            if self._chip_type != "bl60x":
                if cfg.has_option("FLASH_CFG", "flash_clock_cfg"):
                    clock_div_cfg = cfg.get("FLASH_CFG", "flash_clock_cfg")
                    if clock_div_cfg.startswith("0x"):
                        flash_clock_cfg = int(clock_div_cfg, 16)
                    else:
                        flash_clock_cfg = int(clock_div_cfg, 10)
                if cfg.has_option("FLASH_CFG", "flash_io_mode"):
                    io_mode_cfg = cfg.get("FLASH_CFG", "flash_io_mode")
                    if io_mode_cfg.startswith("0x"):
                        flash_io_mode = int(io_mode_cfg, 16)
                    else:
                        flash_io_mode = int(io_mode_cfg, 10)
                if cfg.has_option("FLASH_CFG", "flash_clock_delay"):
                    clk_delay_cfg = cfg.get("FLASH_CFG", "flash_clock_delay")
                    if clk_delay_cfg.startswith("0x"):
                        flash_clk_delay = int(clk_delay_cfg, 16)
                    else:
                        flash_clk_delay = int(clk_delay_cfg, 10)
            # 0x0101ff is default set: flash_io_mode=1, flash_clock_cfg=1, flash_pin=0xff
            flash_set = (flash_pin << 0) + (flash_clock_cfg << 8) + (flash_io_mode << 16) + (flash_clk_delay << 24)
            if (
                (flash_set != 0x0101FF and self._chip_type != "bl60x")
                or (flash_pin != 0 and self._chip_type == "bl60x")
                or load_function == 2
            ):
                bflb_utils.printf("set flash config: %X" % (flash_set))
                ret = self.flash_set_para_main_process(flash_set, bytearray(0), self._need_handshake)
                self._need_handshake = False
                if ret is False:
                    return False, flash_burn_retry
            # recreate bootinfo.bin
            ret, data = self.flash_read_jedec_id_process(self._need_handshake)
            if ret:
                self._need_handshake = False
                data = binascii.hexlify(data).decode("utf-8")
                id_valid_flag = data[6:]
                read_id = data[0:6]
                read_flash_id = read_id
                if cfg.has_option("FLASH_CFG", "flash_para"):
                    flash_para_file = os.path.join(app_path, cfg.get("FLASH_CFG", "flash_para"))
                    self.flash_update_para(flash_para_file, read_id)
                if id_valid_flag != "80":
                    if self._chip_type == "bl602" or self._chip_type == "bl702":
                        bflb_utils.printf("eflash loader identify flash failed")
                        self.print_error_code("0043")
                        return False, flash_burn_retry
                # debug for bl616l and bl616d
                self._flash_size = self.flash_get_size(read_flash_id)
                bflb_utils.printf("get flash size: 0x%08X" % (self._flash_size))
                """
                if self.is_conf_exist(read_flash_id) is False:
                    self.print_error_code("003D")
                    return False, flash_burn_retry
                else:
                    self._flash_size = self.flash_get_size(read_flash_id)
                    bflb_utils.printf("get flash size: 0x%08X" % (self._flash_size))
                """
            else:
                self.print_error_code("0030")
                return False, flash_burn_retry
            # flash2 init
            if self._chip_type == "bl616" or self._chip_type == "wb03":
                if cfg.has_option("FLASH2_CFG", "flash2_en"):
                    self._flash2_en = cfg.get("FLASH2_CFG", "flash2_en") == "true"
                    if self._flash2_en is True:
                        bflb_utils.printf("flash2 set para")
                        flash2_pin = 0
                        flash2_clock_cfg = 0
                        flash2_io_mode = 0
                        flash2_clk_delay = 0
                        if cfg.get("FLASH2_CFG", "flash2_pin"):
                            flash_pin_cfg = cfg.get("FLASH2_CFG", "flash2_pin")
                            if flash_pin_cfg.startswith("0x"):
                                flash2_pin = int(flash_pin_cfg, 16)
                            else:
                                flash2_pin = int(flash_pin_cfg, 10)
                        if cfg.has_option("FLASH2_CFG", "flash2_clock_cfg"):
                            clock_div_cfg = cfg.get("FLASH2_CFG", "flash2_clock_cfg")
                            if clock_div_cfg.startswith("0x"):
                                flash2_clock_cfg = int(clock_div_cfg, 16)
                            else:
                                flash2_clock_cfg = int(clock_div_cfg, 10)
                        if cfg.has_option("FLASH2_CFG", "flash2_io_mode"):
                            io_mode_cfg = cfg.get("FLASH2_CFG", "flash2_io_mode")
                            if io_mode_cfg.startswith("0x"):
                                flash2_io_mode = int(io_mode_cfg, 16)
                            else:
                                flash2_io_mode = int(io_mode_cfg, 10)
                        if cfg.has_option("FLASH2_CFG", "flash2_clock_delay"):
                            clk_delay_cfg = cfg.get("FLASH2_CFG", "flash2_clock_delay")
                            if clk_delay_cfg.startswith("0x"):
                                flash2_clk_delay = int(clk_delay_cfg, 16)
                            else:
                                flash2_clk_delay = int(clk_delay_cfg, 10)
                        flash2_set = (
                            (flash2_pin << 0)
                            + (flash2_clock_cfg << 8)
                            + (flash2_io_mode << 16)
                            + (flash2_clk_delay << 24)
                        )
                        if load_function == 2:
                            bflb_utils.printf("set flash2 cfg: %X" % (flash2_set))
                            ret = self.flash_set_para_main_process(flash2_set, bytearray(0), self._need_handshake)
                            self._need_handshake = False
                            if ret is False:
                                return False, flash_burn_retry
                        # switch to flash2 ctrl
                        ret = self.flash_switch_bank_process(1, self._need_handshake)
                        self._need_handshake = False
                        if ret is False:
                            return False, flash_burn_retry
                        # recreate bootinfo.bin
                        ret, data = self.flash_read_jedec_id_process(self._need_handshake)
                        if ret:
                            self._need_handshake = False
                            data = binascii.hexlify(data).decode("utf-8")
                            id2_valid_flag = data[6:]
                            read_id2 = data[0:6]
                            read_flash2_id = read_id2
                            if cfg.has_option("FLASH2_CFG", "flash2_para"):
                                flash2_para_file = os.path.join(app_path, cfg.get("FLASH2_CFG", "flash2_para"))
                                self.flash_update_para(flash2_para_file, read_id2)

                                # flash2 set flash para iomode=0x11
                                fp = open_file(flash2_para_file, "rb")
                                para_data = bytearray(fp.read())
                                fp.close()
                                para_data[0:1] = b"\x11"
                                fp = open_file(flash2_para_file, "wb+")
                                fp.write(para_data)
                                fp.close()
                            if self.is_conf_exist(read_flash2_id) is False:
                                self.print_error_code("003D")
                                return False, flash_burn_retry
                            else:
                                self._flash2_size = self.flash_get_size(read_flash2_id)
                                bflb_utils.printf("get flash2 size: 0x%08X" % (self._flash2_size))
                        else:
                            self.print_error_code("0030")
                            return False, flash_burn_retry
                        # switch to default flash1 ctrl
                        ret = self.flash_switch_bank_process(0, self._need_handshake)
                        self._need_handshake = False
                        if ret is False:
                            return False, flash_burn_retry

        # '--none' for eflash loader environment init
        if args.none:
            return True, flash_burn_retry

        # erase
        if args.erase:
            # set flash parameter
            flash_pin = 0
            flash_clock_cfg = 0
            flash_io_mode = 0
            flash_clk_delay = 0
            if cfg.has_option("FLASH_CFG", "decompress_write"):
                self._decompress_write = cfg.get("FLASH_CFG", "decompress_write") == "true"
            if self._chip_type == "bl60x" or self._chip_type == "bl702":
                self._decompress_write = False
            bflb_utils.printf("flash set para")
            if cfg.get("FLASH_CFG", "flash_pin"):
                flash_pin_cfg = cfg.get("FLASH_CFG", "flash_pin")
                if flash_pin_cfg.startswith("0x"):
                    flash_pin = int(flash_pin_cfg, 16)
                else:
                    flash_pin = int(flash_pin_cfg, 10)
                if flash_pin == 0x80:
                    flash_pin = self.flash_get_pin_from_bootinfo(self._chip_type, bootinfo)
                    bflb_utils.printf("get flash pin cfg from bootinfo: 0x%02X" % (flash_pin))
            else:
                if self._chip_type == "bl602" or self._chip_type == "bl702":
                    flash_pin = 0xFF
            if self._chip_type != "bl60x":
                if cfg.has_option("FLASH_CFG", "flash_clock_cfg"):
                    clock_div_cfg = cfg.get("FLASH_CFG", "flash_clock_cfg")
                    if clock_div_cfg.startswith("0x"):
                        flash_clock_cfg = int(clock_div_cfg, 16)
                    else:
                        flash_clock_cfg = int(clock_div_cfg, 10)
                if cfg.has_option("FLASH_CFG", "flash_io_mode"):
                    io_mode_cfg = cfg.get("FLASH_CFG", "flash_io_mode")
                    if io_mode_cfg.startswith("0x"):
                        flash_io_mode = int(io_mode_cfg, 16)
                    else:
                        flash_io_mode = int(io_mode_cfg, 10)
                if cfg.has_option("FLASH_CFG", "flash_clock_delay"):
                    clk_delay_cfg = cfg.get("FLASH_CFG", "flash_clock_delay")
                    if clk_delay_cfg.startswith("0x"):
                        flash_clk_delay = int(clk_delay_cfg, 16)
                    else:
                        flash_clk_delay = int(clk_delay_cfg, 10)
            # 0x0101ff is default set: flash_io_mode=1, flash_clock_cfg=1, flash_pin=0xff
            flash_set = (flash_pin << 0) + (flash_clock_cfg << 8) + (flash_io_mode << 16) + (flash_clk_delay << 24)
            if (
                (flash_set != 0x0101FF and self._chip_type != "bl60x")
                or (flash_pin != 0 and self._chip_type == "bl60x")
                or load_function == 2
            ):
                bflb_utils.printf("set flash config: %X" % (flash_set))
                ret = self.flash_set_para_main_process(flash_set, bytearray(0), self._need_handshake)
                self._need_handshake = False
                if ret is False:
                    return False, flash_burn_retry
            bflb_utils.printf("erase flash operation")
            if self._skip_len:
                bflb_utils.printf("error: skip mode can not set flash chiperase")
                return False, 0
            if int(end, 16) == 0:
                erase = 0
                ret = self.flash_chiperase_main_process(self._need_handshake)
                if ret is False:
                    return False, flash_burn_retry
            else:
                erase = 1
                ret = self.flash_erase_main_process(int(start, 16), int(end, 16), self._need_handshake)
                if ret is False:
                    return False, flash_burn_retry
            bflb_utils.printf("erase flash ok")
        # write
        if args.write:
            if not args.flash and not args.efuse:
                bflb_utils.printf("no target selected")
                return False, flash_burn_retry
            bflb_utils.printf("program operation")
            # get program type
            if args.flash:
                flash_para_file = ""
                flash2_para_file = ""
                if cfg.has_option("FLASH_CFG", "flash_para"):
                    flash_para_file = os.path.join(app_path, cfg.get("FLASH_CFG", "flash_para"))
                if cfg.has_option("FLASH2_CFG", "flash2_para"):
                    flash2_para_file = os.path.join(app_path, cfg.get("FLASH2_CFG", "flash2_para"))
                if romfs_data != "":
                    if address == "":
                        bflb_utils.printf("please set romfs load address")
                        self.print_error_code("0041")
                        return False, flash_burn_retry
                    bflb_utils.printf("load romfs ", romfs_data)
                    ret = self.load_romfs_data(romfs_data, int(address, 16), verify, self._need_handshake, callback)
                    if ret is False:
                        self.print_error_code("0041")
                        return False, flash_burn_retry
                    self._need_handshake = False
                    bflb_utils.printf("program romfs finished")
                elif fwbin:
                    bflb_utils.printf("load firmware bin", fwbin)
                    fwbin = os.path.abspath(fwbin)
                    ret = self.flash_cfg_option(
                        read_flash_id,
                        flash_para_file,
                        flash_set,
                        id_valid_flag,
                        fwbin,
                        config_file,
                        cfg,
                        create_img_callback,
                        create_simple_callback,
                    )
                    if ret is False:
                        return False, flash_burn_retry
                    ret = self.load_firmware_bin(fwbin, verify, self._need_handshake, callback)
                    if ret is False:
                        self.print_error_code("003C")
                        return False, flash_burn_retry
                    self._need_handshake = False
                    bflb_utils.printf("program fwbin finished")
                elif massbin:
                    bflb_utils.printf("load mass bin ", massbin)
                    bflb_utils.printf("========= programming mass {0} to {1}".format(massbin, hex(0)))
                    massbin = os.path.abspath(massbin)
                    ret = self.flash_cfg_option(
                        read_flash_id,
                        flash_para_file,
                        flash_set,
                        id_valid_flag,
                        massbin,
                        config_file,
                        cfg,
                        create_img_callback,
                        create_simple_callback,
                    )
                    if ret is False:
                        return False, flash_burn_retry
                    ret = self.flash_load_specified(massbin, 0x0, 1, verify, self._need_handshake, callback)
                    if ret is False:
                        return False, flash_burn_retry
                    self._need_handshake = False
                    bflb_utils.printf("program massbin finished")
                else:
                    if img_file:
                        flash_file = img_file.split(",")
                        address = address.split(",")
                        erase = 1
                    else:
                        flash_file = re.compile("\\s+").split(cfg.get("FLASH_CFG", "file"))
                        address = re.compile("\\s+").split(cfg.get("FLASH_CFG", "address"))
                        if len(flash_file) > len(address):
                            bflb_utils.printf("error: tool path contains spaces")
                            return False, 0
                    if csv_file and csvaddr:
                        bflb_utils.printf("factory info burn")
                        csvbin = os.path.join(chip_path, self._chip_name, self._outdir, "media.bin")
                        ret, csv_mac = self.get_factory_config_info(csv_file, csvbin)
                        if ret is not False:
                            flash_file.append(csvbin)
                            address.append(csvaddr)
                            if csv_mac:
                                macaddr = csv_mac
                                args.efuse = True
                        else:
                            bflb_utils.printf("create media.bin failed")
                            return False, flash_burn_retry
                    # do chip erase first
                    if erase == 2:
                        ret = self.flash_chiperase_main_process(self._need_handshake)
                        if ret is False:
                            return False, flash_burn_retry
                        self._need_handshake = False
                        erase = 0
                    # program flash
                    if len(flash_file) > 0:
                        size_before = 0
                        size_all = 0
                        i = 0
                        for item in flash_file:
                            if task_num is not None and self._csv_burn_en is True:
                                size_all += os.path.getsize(
                                    os.path.join(app_path, convert_path("task" + str(task_num) + "/" + item))
                                )
                            else:
                                size_all += os.path.getsize(os.path.join(app_path, convert_path(item)))
                        try:
                            ret = False
                            while i < len(flash_file):
                                write_addr = int(address[i], 16)
                                if task_num is not None and self._csv_burn_en is True:
                                    flash_file[i] = "task" + str(task_num) + "/" + flash_file[i]
                                    size_current = os.path.getsize(os.path.join(app_path, convert_path(flash_file[i])))
                                else:
                                    size_current = os.path.getsize(os.path.join(app_path, convert_path(flash_file[i])))
                                if callback:
                                    callback(size_before, size_all, "program1")
                                if callback:
                                    callback(size_current, size_all, "program2")
                                # if task_num is not None and self._csv_burn_en is True:
                                #     flash_file[i] = "task" + str(task_num) + "/" + flash_file[i]
                                bflb_utils.printf("processing index ", i)
                                if self._isp_en is True:
                                    bflb_utils.printf("========= programming ", convert_path(flash_file[i]))
                                else:
                                    bflb_utils.printf(
                                        "========= programming ",
                                        convert_path(flash_file[i]),
                                        " to 0x%08X" % (write_addr),
                                    )
                                flash1_bin = ""
                                flash1_bin_len = 0
                                flash2_bin = ""
                                # flash2_bin_len = 0
                                if self._chip_type == "bl616" or self._chip_type == "wb03":
                                    if (
                                        self._flash_size != 0
                                        and self._flash_size < write_addr + size_current
                                        and self._flash_size > write_addr
                                        and self._flash2_select is False
                                        and self._flash2_en is True
                                    ):
                                        bflb_utils.printf("{} file exceeds flash1".format(flash_file[i]))
                                        (
                                            flash1_bin,
                                            flash1_bin_len,
                                            flash2_bin,
                                            flash2_bin_len,
                                        ) = self.flash_loader_cut_flash_bin(flash_file[i], write_addr, self._flash_size)
                                if flash1_bin != "" and flash2_bin != "":
                                    ret = self.flash_cfg_option(
                                        read_flash_id,
                                        flash_para_file,
                                        flash_set,
                                        id_valid_flag,
                                        flash1_bin,
                                        config_file,
                                        cfg,
                                        create_img_callback,
                                        create_simple_callback,
                                    )
                                    if ret is False:
                                        return False, flash_burn_retry
                                    bflb_utils.printf(
                                        "========= programming ",
                                        convert_path(flash1_bin),
                                        " to 0x%08X" % (write_addr),
                                    )
                                    ret = self.flash_load_specified(
                                        convert_path(flash1_bin),
                                        write_addr,
                                        erase,
                                        verify,
                                        self._need_handshake,
                                        callback,
                                    )
                                    if ret is False:
                                        return False, flash_burn_retry
                                    ret = self.flash_switch_bank_process(1, self._need_handshake)
                                    self._need_handshake = False
                                    if ret is False:
                                        return False, flash_burn_retry
                                    ret = self.flash_cfg_option(
                                        read_flash2_id,
                                        flash2_para_file,
                                        flash2_set,
                                        id2_valid_flag,
                                        flash_file[i],
                                        config_file,
                                        cfg,
                                        create_img_callback,
                                        create_simple_callback,
                                    )
                                    if ret is False:
                                        return False, flash_burn_retry
                                    bflb_utils.printf(
                                        "========= programming ",
                                        convert_path(flash2_bin),
                                        " to 0x%08X" % (write_addr + flash1_bin_len),
                                    )
                                    ret = self.flash_load_specified(
                                        convert_path(flash2_bin),
                                        write_addr + flash1_bin_len,
                                        erase,
                                        verify,
                                        self._need_handshake,
                                        callback,
                                    )
                                    if ret is False:
                                        return False, flash_burn_retry
                                else:
                                    if self._flash2_en is False or (
                                        self._flash2_select is False and write_addr < self._flash_size
                                    ):
                                        ret = self.flash_cfg_option(
                                            read_flash_id,
                                            flash_para_file,
                                            flash_set,
                                            id_valid_flag,
                                            flash_file[i],
                                            config_file,
                                            cfg,
                                            create_img_callback,
                                            create_simple_callback,
                                        )
                                        if ret is False:
                                            return False, flash_burn_retry
                                    else:
                                        if self._flash2_select is False and write_addr >= self._flash_size:
                                            ret = self.flash_switch_bank_process(1, self._need_handshake)
                                            self._need_handshake = False
                                            if ret is False:
                                                return False, flash_burn_retry
                                        ret = self.flash_cfg_option(
                                            read_flash2_id,
                                            flash2_para_file,
                                            flash2_set,
                                            id2_valid_flag,
                                            flash_file[i],
                                            config_file,
                                            cfg,
                                            create_img_callback,
                                            create_simple_callback,
                                        )
                                        if ret is False:
                                            return False, flash_burn_retry
                                    ret = self.flash_load_specified(
                                        convert_path(flash_file[i]),
                                        write_addr,
                                        erase,
                                        verify,
                                        self._need_handshake,
                                        callback,
                                    )
                                    if ret is False:
                                        return False, flash_burn_retry
                                size_before += os.path.getsize(os.path.join(app_path, convert_path(flash_file[i])))
                                i += 1
                                if callback:
                                    callback(i, len(flash_file), "program")
                                self._need_handshake = False
                            if self._flash2_select is True:
                                ret = self.flash_switch_bank_process(0, self._need_handshake)
                                self._need_handshake = False
                                if ret is False:
                                    return False, flash_burn_retry
                            bflb_utils.printf("program finished")
                        except Exception as e:
                            bflb_utils.printf(e)
                            traceback.print_exc(limit=NUM_ERR, file=sys.stdout)
                            return False, flash_burn_retry
                    else:
                        bflb_utils.printf("no input file to program to flash")
            # get program type
            if args.efuse:
                loadflag = True
                efuse_load = True
                if cfg.has_option("EFUSE_CFG", "burn_en"):
                    efuse_load = cfg.get("EFUSE_CFG", "burn_en") == "true"
                efuse_verify = 1
                if cfg.has_option("EFUSE_CFG", "factory_mode"):
                    if cfg.get("EFUSE_CFG", "factory_mode") != "true":
                        efuse_verify = 0
                if macaddr:
                    # loadflag = False
                    bflb_utils.printf("write efuse macaddr ", macaddr)
                    if gol.ENABLE_AQARA:
                        security_write = True
                    elif gol.ENABLE_XIAOMI:
                        security_write = False
                    elif self._chip_type == "bl602" or self._chip_type == "bl702":
                        security_write = False
                    else:
                        security_write = True
                        # security_write = (cfg.get("EFUSE_CFG", "security_write") == "true")
                    if self._chip_type == "bl702" or self._chip_type == "bl702l":
                        ret = self.efuse_load_macaddr_bl702(
                            macaddr,
                            verify=1,
                            shakehand=self._need_handshake,
                            security_write=security_write,
                        )
                    else:
                        ret = self.efuse_load_macaddr(
                            macaddr,
                            verify=1,
                            shakehand=self._need_handshake,
                            security_write=security_write,
                        )
                    if ret is False:
                        bflb_utils.printf("load macaddr failed")
                        return False, flash_burn_retry
                    self._need_handshake = False
                if publickey:
                    loadflag = False
                    bflb_utils.printf("write efuse publickey hash")
                    with open(publickey, "rb") as fp:
                        key = fp.read()
                    public_key = serialization.load_pem_public_key(key, backend=default_backend())
                    public_numbers = public_key.public_numbers()
                    x = public_numbers.x
                    y = public_numbers.y
                    x_bytes = x.to_bytes(32, "big")
                    y_bytes = y.to_bytes(32, "big")
                    pk_data = x_bytes + y_bytes
                    pk_hash = bflb_utils.img_create_sha256_data(pk_data)
                    bflb_utils.printf("public key hash=", binascii.hexlify(pk_hash))
                    efuse_data, mask_data = self.efuse_create_encrypt_sign_data(
                        None, 1, pk_hash, 0, None, 0, None, False
                    )
                    if gol.ENABLE_AQARA:
                        security_write = True
                    elif gol.ENABLE_XIAOMI:
                        security_write = False
                    elif self._chip_type == "bl602" or self._chip_type == "bl702":
                        security_write = False
                    else:
                        security_write = True
                        # security_write = (cfg.get("EFUSE_CFG", "security_write") == "true")
                    ret = self.efuse_load_specified(
                        None,
                        None,
                        efuse_data,
                        mask_data,
                        efuse_verify,
                        self._need_handshake,
                        security_write,
                    )
                    if ret is False:
                        return False, flash_burn_retry
                if aeskey:
                    loadflag = False
                    aeskey_bytearray = bflb_utils.hexstr_to_bytearray(aeskey)
                    flash_encrypt_type = 0
                    if len(aeskey_bytearray) == 16:
                        # AES 128
                        flash_encrypt_type = 1
                    elif len(aeskey_bytearray) == 24:
                        # AES 192
                        flash_encrypt_type = 2
                    elif len(aeskey_bytearray) == 32:
                        # AES 256
                        flash_encrypt_type = 3
                    else:
                        bflb_utils.printf("key length error")
                        return False, flash_burn_retry

                    efuse_data, mask_data = self.efuse_create_encrypt_sign_data(
                        None, 0, None, flash_encrypt_type, aeskey_bytearray, 0, None, False
                    )
                    if gol.ENABLE_AQARA:
                        security_write = True
                    elif gol.ENABLE_XIAOMI:
                        security_write = False
                    elif self._chip_type == "bl602" or self._chip_type == "bl702":
                        security_write = False
                    else:
                        security_write = True
                        # security_write = (cfg.get("EFUSE_CFG", "security_write") == "true")
                    ret = self.efuse_load_specified(
                        None,
                        None,
                        efuse_data,
                        mask_data,
                        efuse_verify,
                        self._need_handshake,
                        security_write,
                    )
                    if ret is False:
                        bflb_utils.printf("load aes key failed")
                        return False, flash_burn_retry

                if load_data and args.addr:
                    address = args.addr
                    loadflag = False
                    write_addr = 0
                    if address[0:2] == "0x":
                        write_addr = int(address, 16)
                    else:
                        write_addr = int(address, 10)
                    bflb_utils.printf("write efuse data to ", address)
                    if gol.ENABLE_AQARA:
                        security_write = True
                    elif gol.ENABLE_XIAOMI:
                        security_write = False
                    elif self._chip_type == "bl602" or self._chip_type == "bl702":
                        security_write = False
                    else:
                        security_write = True
                        # security_write = (cfg.get("EFUSE_CFG", "security_write") == "true")
                    ret = self.efuse_load_data_process(
                        load_data,
                        write_addr,
                        efuse_load_func,
                        verify,
                        self._need_handshake,
                        security_write,
                    )
                    if ret is False:
                        bflb_utils.printf("write efuse data failed")
                        return False, flash_burn_retry

                if load_data_encrypted and args.addr:
                    address = args.addr
                    loadflag = False
                    write_addr = 0
                    if address[0:2] == "0x":
                        write_addr = int(address, 16)
                    else:
                        write_addr = int(address, 10)
                    bflb_utils.printf("write encrypted efuse data {0} to {1}".format(load_data_encrypted, address))
                    if gol.ENABLE_AQARA:
                        security_write = True
                    elif gol.ENABLE_XIAOMI:
                        security_write = False
                    elif self._chip_type == "bl602" or self._chip_type == "bl702":
                        security_write = False
                    else:
                        security_write = True
                        # security_write = (cfg.get("EFUSE_CFG", "security_write") == "true")
                    sk = bytearray.fromhex(PRIVATE_KEY_RSA_HEX)
                    privatekey = serialization.load_pem_private_key(sk, password=None)
                    data = []
                    load_data_encrypted = bytearray.fromhex(load_data_encrypted)
                    for i in range(0, len(load_data_encrypted), 128):
                        cont = load_data_encrypted[i : i + 128]
                        data.append(privatekey.decrypt(bytes(cont), asymmetric_padding.PKCS1v15()))
                    data_decrypted = b"".join(data)
                    load_data = binascii.hexlify(data_decrypted).decode("utf-8")
                    ret = self.efuse_load_data_process(
                        load_data,
                        write_addr,
                        efuse_load_func,
                        verify,
                        self._need_handshake,
                        security_write,
                    )
                    if ret is False:
                        bflb_utils.printf("write encrypted efuse data failed")
                        return False, flash_burn_retry

                if efuse_para:
                    loadflag = False
                    bflb_utils.printf("write efuse para")
                    cfgfile_org = os.path.join(
                        chip_path,
                        self._chip_name.lower(),
                        "efuse_bootheader",
                        "efuse_bootheader_cfg.conf",
                    )
                    cfgfile = os.path.join(chip_path, self._chip_name, self._outdir, "efuse_bootheader_cfg.ini")
                    if os.path.isfile(cfgfile) is False:
                        shutil.copyfile(cfgfile_org, cfgfile)
                    sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
                    efuse_data, mask = bflb_efuse_boothd_create.update_data_from_cfg(
                        sub_module.efuse_cfg_keys.efuse_cfg_keys, cfgfile, "EFUSE_CFG"
                    )
                    if gol.ENABLE_AQARA:
                        security_write = True
                    elif gol.ENABLE_XIAOMI:
                        security_write = False
                    elif self._chip_type == "bl602" or self._chip_type == "bl702":
                        security_write = False
                    else:
                        security_write = True
                        # security_write = (cfg.get("EFUSE_CFG", "security_write") == "true")
                    if efuse_load:
                        ret = self.efuse_load_specified(
                            None,
                            None,
                            efuse_data,
                            mask,
                            efuse_verify,
                            self._need_handshake,
                            security_write,
                        )
                        if callback:
                            callback(1, 1, "APP_WR")
                        if ret is False:
                            return False, flash_burn_retry
                    else:
                        bflb_utils.printf("efuse load disalbe")
                if loadflag is True:
                    if efuse_file:
                        mask_file = efuse_file.replace(".bin", "_mask.bin")
                    else:
                        efuse_file = cfg.get("EFUSE_CFG", "file")
                        mask_file = cfg.get("EFUSE_CFG", "maskfile")
                    if task_num is not None and self._csv_burn_en is True:
                        efuse_file = "task" + str(task_num) + "/" + efuse_file
                    if gol.ENABLE_AQARA:
                        security_write = True
                    elif gol.ENABLE_XIAOMI:
                        security_write = False
                    elif self._chip_type == "bl602" or self._chip_type == "bl702":
                        security_write = False
                    else:
                        security_write = True
                        # security_write = cfg.get("EFUSE_CFG", "security_write") == "true"
                    if efuse_load and self._isp_en is False:
                        ret = self.efuse_load_specified(
                            efuse_file,
                            mask_file,
                            bytearray(0),
                            bytearray(0),
                            efuse_verify,
                            self._need_handshake,
                            security_write,
                        )
                        if callback:
                            callback(1, 1, "APP_WR")
                        if ret is False:
                            return False, flash_burn_retry
                    else:
                        bflb_utils.printf("efuse load disalbe")
                self._need_handshake = False
        if args.dac_value:
            bflb_utils.printf("========= encrypt and write dac =========")
            dac_file, efuse_data, mask_data = self.flash_create_efuse_dac_encrypt_data(dacvalue, dackey, daciv)
            bflb_utils.printf("========= programming {0} to {1}".format(dac_file, dacaddr))
            dac_file = os.path.abspath(dac_file)
            ret = self.flash_load_specified(dac_file, int(dacaddr, 16), 1, verify, self._need_handshake, callback)
            if ret is False:
                return False, flash_burn_retry
            bflb_utils.printf("program dac file finished")
            bflb_utils.printf("write efuse data")
            if gol.ENABLE_AQARA:
                security_write = True
            elif gol.ENABLE_XIAOMI:
                security_write = False
            elif self._chip_type == "bl602" or self._chip_type == "bl702":
                security_write = False
            else:
                security_write = True
                # security_write = (cfg.get("EFUSE_CFG", "security_write") == "true")
            ret = self.efuse_load_specified(None, None, efuse_data, mask_data, 0, self._need_handshake, security_write)
            if ret is False:
                bflb_utils.printf("write efuse data failed")
                return False, flash_burn_retry
        # read
        if args.read:
            bflb_utils.printf("read operation")
            if not args.flash and not args.efuse:
                bflb_utils.printf("no target selected")
                return False, flash_burn_retry
            if args.flash:
                if not start or not end:
                    self.flash_read_jedec_id_process(callback)
                else:
                    start_addr = int(start, 16)
                    end_addr = int(end, 16)
                    if end_addr >= self._flash_size:
                        bflb_utils.printf(
                            "read flash end addr 0x%08X exceeds flash size 0x%08X" % (end_addr, self._flash_size)
                        )
                        self.print_error_code("0045")
                        return False, flash_burn_retry
                    ret, readdata = self.flash_read_main_process(
                        start_addr,
                        end_addr - start_addr + 1,
                        self._need_handshake,
                        img_file,
                        callback,
                    )
                    if ret is False:
                        return False, flash_burn_retry
            if args.efuse:
                if macaddr:
                    if gol.ENABLE_AQARA:
                        security_write = True
                    elif gol.ENABLE_XIAOMI:
                        security_write = False
                    elif self._chip_type == "bl602" or self._chip_type == "bl702":
                        security_write = False
                    else:
                        security_write = True
                    if self._chip_type == "bl702" or self._chip_type == "bl702l":
                        if (
                            self.efuse_get_macaddr_bl702(
                                verify=1, shakehand=self._need_handshake, security_write=security_write
                            )
                            is False
                        ):
                            return False, flash_burn_retry
                    else:
                        if (
                            self.efuse_get_macaddr(
                                verify=1, shakehand=self._need_handshake, security_write=security_write
                            )
                            is False
                        ):
                            return False, flash_burn_retry
                else:
                    start_addr = int(start, 16)
                    end_addr = int(end, 16)
                    ret, efusedata = self.efuse_read_main_process(
                        start_addr, end_addr - start_addr + 1, self._need_handshake, img_file
                    )
                    if ret is False:
                        return False, flash_burn_retry

        if args.auth:
            res = True
            if self._bflb_com_if is not None:
                self._bflb_com_if.if_close()
            bflb_utils.printf("========= Start to authorize =========")
            rate_uart = self._bflb_com_speed
            port_auth = args.auth
            if port:
                port_dev = port
            elif self._bflb_com_device:
                # port_dev = re.match("(COM\\d+)", self._bflb_com_device).group(1)
                port_dev = self._bflb_com_device
            with mutex:
                efuse_data = bytearray(128)

                bflb_auth_obj = BflbAuthBase(port_auth, port_dev, rate_uart)
                if bflb_auth_obj.efuse_load_shakehand():
                    res = bflb_auth_obj.efuse_load_main_process(efuse_data, security_write=True)
                else:
                    res = False
            if not res:
                bflb_utils.printf("authorization failed")
            return res, flash_burn_retry

        if self._isp_en is True and (self._chip_type == "bl702" or self._chip_type == "bl702l"):
            self.reset_cpu()
        if macaddr_check is True:
            self._bootinfo = bootinfo
        self._macaddr_check = mac_addr
        self._macaddr_check_status = False
        return True, flash_burn_retry


def run():
    log_file = os.path.join(app_path, "log")
    if not os.path.exists(log_file):
        os.makedirs(log_file)

    parser = eflash_loader_parser_init()
    args = parser.parse_args()
    if args.version:
        if not conf_sign:
            bflb_utils.printf("eflash loader version: ", bflb_version.version_text.replace("(", "").replace(")", ""))
    # args = parser.parse_args(["--chipname=bl602", "--write", "--flash", "--baudrate=2000000", "--config=eflash_loader_cfg.ini"])
    if not args.chipname:
        bflb_utils.printf("error: chipname is none")
        return
    bflb_utils.printf("chipname: {}".format(args.chipname))
    eflash_loader_obj = BflbEflashLoader(args.chipname, gol.dict_chip_cmd[args.chipname])
    gol.chip_name = args.chipname
    if conf_sign:
        reload(cgc)
    while True:
        try:
            ret = eflash_loader_obj.efuse_flash_loader(args, None, None)
            if ret is not True:
                eflash_loader_obj.print_error_code("0005")
            eflash_loader_obj.close_port()
            time.sleep(2)
        except Exception as e:
            bflb_utils.printf(e)
        time.sleep(0.2)
        if not args.auto:
            break


if __name__ == "__main__":
    run()
