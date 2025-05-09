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
import time
import hashlib
import binascii
import traceback

try:
    import bflb_path
except ImportError:
    from libs import bflb_path
from libs import bflb_utils
from libs import bflb_security
from libs import bflb_img_create
from libs import bflb_interface_uart
from libs import bflb_interface_sdio
from libs import bflb_interface_jlink
from libs.bflb_configobj import BFConfigParser
import config as gol

try:
    from config import mutex

    th_sign = True
except ImportError:
    th_sign = False

try:
    from PySide2 import QtCore

    qt_sign = True
except ImportError:
    qt_sign = False


class BflbImgLoader(object):
    def __init__(self, chiptype="bl60x", chipname="bl60x", interface="uart", createcfg=None):
        self.bflb_boot_if = None
        self._imge_fp = None
        self._segcnt = 0
        self._chip_type = chiptype
        self._chip_name = chipname
        self._create_cfg = createcfg
        self._key = ""
        self._iv = ""
        self._publickey = ""
        self._privatekey = ""
        self.bl616_a0 = False

        if interface == "uart":
            self.bflb_boot_if = bflb_interface_uart.BflbUartPort()
        elif interface == "sdio":
            self.bflb_boot_if = bflb_interface_sdio.BflbSdioPort()
        elif interface == "jlink":
            self.bflb_boot_if = bflb_interface_jlink.BflbJLinkPort()

        self._bootrom_cmds = {
            "get_chip_id": {"cmd_id": "05", "data_len": "0000", "callback": None},
            "get_boot_info": {"cmd_id": "10", "data_len": "0000", "callback": None},
            "load_boot_header": {"cmd_id": "11", "data_len": "00b0", "callback": None},
            "808_load_boot_header": {"cmd_id": "11", "data_len": "0160", "callback": None},
            "628_load_boot_header": {"cmd_id": "11", "data_len": "0100", "callback": None},
            "616_load_boot_header": {"cmd_id": "11", "data_len": "0100", "callback": None},
            "702l_load_boot_header": {"cmd_id": "11", "data_len": "00F0", "callback": None},
            "load_publick_key": {"cmd_id": "12", "data_len": "0044", "callback": None},
            "load_publick_key2": {"cmd_id": "13", "data_len": "0044", "callback": None},
            "load_signature": {"cmd_id": "14", "data_len": "0004", "callback": None},
            "load_signature2": {"cmd_id": "15", "data_len": "0004", "callback": None},
            "load_aes_iv": {"cmd_id": "16", "data_len": "0014", "callback": None},
            "load_seg_header": {"cmd_id": "17", "data_len": "0010", "callback": None},
            "load_seg_data": {"cmd_id": "18", "data_len": "0100", "callback": None},
            "check_image": {"cmd_id": "19", "data_len": "0000", "callback": None},
            "run_image": {"cmd_id": "1a", "data_len": "0000", "callback": None},
            "change_rate": {"cmd_id": "20", "data_len": "0008", "callback": None},
            "reset": {"cmd_id": "21", "data_len": "0000", "callback": None},
            "set_timeout": {"cmd_id": "23", "data_len": "0004", "callback": None},
            "flash_erase": {"cmd_id": "30", "data_len": "0000", "callback": None},
            "flash_write": {"cmd_id": "31", "data_len": "0100", "callback": None},
            "flash_read": {"cmd_id": "32", "data_len": "0100", "callback": None},
            "flash_boot": {"cmd_id": "33", "data_len": "0000", "callback": None},
            "efuse_write": {"cmd_id": "40", "data_len": "0080", "callback": None},
            "efuse_read": {"cmd_id": "41", "data_len": "0000", "callback": None},
            "memory_write": {"cmd_id": "50", "data_len": "0080", "callback": None},
            "memory_read": {"cmd_id": "51", "data_len": "0000", "callback": None},
            "616l_load_boot_header": {"cmd_id": "11", "data_len": "0100", "callback": None},
            "616d_load_boot_header": {"cmd_id": "11", "data_len": "0100", "callback": None},
            "load_sha384_p2": {"cmd_id": "1b", "data_len": "0010", "callback": None},
            "load_publick_key_384": {"cmd_id": "12", "data_len": "0064", "callback": None},
            "load_publick_key2_384": {"cmd_id": "13", "data_len": "0064", "callback": None},
        }

    def close_port(self):
        if self.bflb_boot_if is not None:
            self.bflb_boot_if.if_close()

    def print_issue_log(self):
        bflb_utils.printf("########################################################################")
        bflb_utils.printf("请按照以下描述排查问题：")
        if self._chip_type == "bl60x":
            bflb_utils.printf("GPIO24是否上拉到板子自身的3.3V，而不是外部的3.3V")
            bflb_utils.printf("GPIO7(RX)是否连接到USB转串口的TX引脚")
            bflb_utils.printf("GPIO14(TX)是否连接到USB转串口的RX引脚")
            bflb_utils.printf("在使用烧录软件进行烧录前，是否在GPIO24拉高的情况下，使用Reset/Chip_En复位了芯片")
        elif self._chip_type == "bl602":
            bflb_utils.printf("GPIO8是否上拉到板子自身的3.3V，而不是外部的3.3V")
            bflb_utils.printf("GPIO7(RX)是否连接到USB转串口的TX引脚")
            bflb_utils.printf("GPIO16(TX)是否连接到USB转串口的RX引脚")
            bflb_utils.printf("在使用烧录软件进行烧录前，是否在GPIO8拉高的情况下，使用Reset/Chip_En复位了芯片")
        elif self._chip_type == "bl702":
            bflb_utils.printf("GPIO28是否上拉到板子自身的3.3V，而不是外部的3.3V")
            bflb_utils.printf("GPIO15(RX)是否连接到USB转串口的TX引脚")
            bflb_utils.printf("GPIO14(TX)是否连接到USB转串口的RX引脚")
            bflb_utils.printf("在使用烧录软件进行烧录前，是否在GPIO28拉高的情况下，使用Reset/Chip_En复位了芯片")
        else:
            bflb_utils.printf("Boot pin是否上拉到板子自身的3.3V，而不是外部的3.3V")
            bflb_utils.printf("UART RX是否连接到USB转串口的TX引脚")
            bflb_utils.printf("UART TX是否连接到USB转串口的RX引脚")
            bflb_utils.printf("在使用烧录软件进行烧录前，是否在Boot pin拉高的情况下，使用Reset/Chip_En复位了芯片")
        bflb_utils.printf("烧录软件所选择的COM口，是否是连接芯片的串口")
        bflb_utils.printf("烧录软件上选择的波特率是否是USB转串口支持的波特率")
        bflb_utils.printf("3.3V供电是否正常")
        bflb_utils.printf("板子供电电流是否正常(烧录模式下，芯片耗电电流5-7mA)")
        bflb_utils.printf("########################################################################")

    def boot_process_load_cmd(self, section, read_len):
        read_data = bytearray(0)
        if read_len != 0:
            read_data = bytearray(self._imge_fp.read(read_len))
            if len(read_data) != read_len:
                bflb_utils.printf("read error, expected len = ", read_len, ", read len = ", len(read_data))
                return bytearray(0)
            if section == "load_boot_header":
                tmp = bflb_utils.bytearray_reverse(read_data[120:124])
                self._segcnt = bflb_utils.bytearray_to_int(tmp)
                bflb_utils.printf("segcnt is ", self._segcnt)
            elif section == "808_load_boot_header":
                tmp = bflb_utils.bytearray_reverse(read_data[140:144])
                self._segcnt = bflb_utils.bytearray_to_int(tmp)
                bflb_utils.printf("segcnt is ", self._segcnt)
            elif section == "628_load_boot_header":
                tmp = bflb_utils.bytearray_reverse(read_data[136:140])
                self._segcnt = bflb_utils.bytearray_to_int(tmp)
                bflb_utils.printf("segcnt is ", self._segcnt)
            elif section == "616_load_boot_header":
                tmp = bflb_utils.bytearray_reverse(read_data[132:136])
                self._segcnt = bflb_utils.bytearray_to_int(tmp)
                bflb_utils.printf("segcnt is ", self._segcnt)
            elif section == "702l_load_boot_header":
                tmp = bflb_utils.bytearray_reverse(read_data[120:124])
                self._segcnt = bflb_utils.bytearray_to_int(tmp)
                bflb_utils.printf("segcnt is ", self._segcnt)
            if section == "load_signature" or section == "load_signature2":
                tmp = bflb_utils.bytearray_reverse(read_data[0:4])
                sig_len = bflb_utils.bytearray_to_int(tmp)
                read_data = read_data + bytearray(self._imge_fp.read(sig_len + 4))
                if len(read_data) != (sig_len + 8):
                    bflb_utils.printf(
                        "read signature error, expected len = ",
                        sig_len + 4,
                        ", read len = ",
                        len(read_data),
                    )
        return read_data

    def boot_process_one_cmd(self, section, cmd_id, cmd_len, baudrate=None):
        read_len = bflb_utils.bytearray_to_int(cmd_len)
        read_data = self._bootrom_cmds.get(section)["callback"](section, read_len)
        tmp = bytearray(2)
        tmp[0] = cmd_len[1]
        tmp[1] = cmd_len[0]
        data_read = bytearray(0)
        # in case data len change for some case
        tmp = bflb_utils.int_to_2bytearray_l(len(read_data))
        data = cmd_id + bytearray(1) + tmp + read_data

        if self._chip_type == "bl702" and section == "run_image":
            sub_module = __import__("libs." + self._chip_type, fromlist=[self._chip_type])
            data = sub_module.chiptype_patch.img_load_create_predata_before_run_img()
        baudrate_tmp = self.bflb_boot_if.if_get_baudrate()
        if baudrate:
            self.bflb_boot_if.if_set_baudrate(baudrate)
        self.bflb_boot_if.if_write(data)
        if section == "get_boot_info" or section == "load_seg_header" or section == "get_chip_id":
            res, data_read = self.bflb_boot_if.if_deal_response()
        else:
            res = self.bflb_boot_if.if_deal_ack(dmy_data=False)
        if res.startswith("OK") is True:
            pass
        else:
            self.bflb_boot_if.if_set_baudrate(baudrate_tmp)
            try:
                bflb_utils.printf("resp: ", res)
            except IOError:
                bflb_utils.printf("python IO error")
        return res, data_read

    def boot_process_one_section(self, section, data_len, baudrate=None):
        cmd_id = bflb_utils.hexstr_to_bytearray(self._bootrom_cmds.get(section)["cmd_id"])
        if data_len == 0:
            length = bflb_utils.hexstr_to_bytearray(self._bootrom_cmds.get(section)["data_len"])
        else:
            length = bflb_utils.int_to_2bytearray_b(data_len)
        return self.boot_process_one_cmd(section, cmd_id, length, baudrate=baudrate)

    def boot_inf_change_rate(self, comnum, section, newrate):
        cmd_id = bflb_utils.hexstr_to_bytearray(self._bootrom_cmds.get(section)["cmd_id"])
        cmd_len = bflb_utils.hexstr_to_bytearray(self._bootrom_cmds.get(section)["data_len"])
        bflb_utils.printf(
            "process ",
            section,
            ", cmd = ",
            binascii.hexlify(cmd_id),
            ", data len = ",
            binascii.hexlify(cmd_len),
        )
        baudrate = self.bflb_boot_if.if_get_rate()
        oldv = bflb_utils.int_to_4bytearray_l(baudrate)
        newv = bflb_utils.int_to_4bytearray_l(newrate)
        tmp = bytearray(3)
        tmp[1] = cmd_len[1]
        tmp[2] = cmd_len[0]
        data = cmd_id + tmp + oldv + newv
        self.bflb_boot_if.if_write(data)
        # wait for data send done
        stime = (11 * 10) / float(baudrate) * 2
        if stime < 0.003:
            stime = 0.003
        time.sleep(stime)
        self.bflb_boot_if.if_close()
        self.bflb_boot_if.if_init(comnum, newrate, self._chip_type, self._chip_name)
        return self.bflb_boot_if.if_deal_ack(dmy_data=False)

    def boot_install_cmds_callback(self):
        self._bootrom_cmds.get("get_chip_id")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("get_boot_info")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_boot_header")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("808_load_boot_header")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("628_load_boot_header")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("616_load_boot_header")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("702l_load_boot_header")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_publick_key")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_publick_key2")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_signature")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_signature2")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_aes_iv")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_seg_header")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_seg_data")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("check_image")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("run_image")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("reset")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("616l_load_boot_header")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("616d_load_boot_header")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_sha384_p2")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_publick_key_384")["callback"] = self.boot_process_load_cmd
        self._bootrom_cmds.get("load_publick_key2_384")["callback"] = self.boot_process_load_cmd

    def boot_check_encrpt_sign(self, security):
        read_data = bytearray(self._imge_fp.read(8))
        self._imge_fp.seek(0, 0)
        if len(read_data) != 8:
            bflb_utils.printf("get image file boot header info failed")
            bflb_utils.set_error_code("0051")
            return "FL"
        if read_data[4] != security:
            bflb_utils.printf("image file encrypt information doesn't match device")
            bflb_utils.printf(
                "image file: ",
                binascii.hexlify(read_data[4]),
                "device: ",
                binascii.hexlify(security),
            )
            bflb_utils.set_error_code("0051")
            return "FL"
        return "OK"

    def img_load_set_sec_cfg(self, key, iv, publickey, privatekey):
        self._key = key
        self._iv = iv
        self._publickey = publickey
        self._privatekey = privatekey

    def img_load_get_sec_cfg(self):
        if self._create_cfg is not None and self._create_cfg != "":
            create_cfg = BFConfigParser()
            create_cfg.read(self._create_cfg)
            img_create_section = "Img_Cfg"
            if self._chip_type == "bl808" or self._chip_type == "bl628":
                img_create_section = "Img_Group0_Cfg"
            elif self._chip_type == "bl616" or self._chip_type == "bl616l" or self._chip_type == "bl616d":
                img_create_section = "Img_Group0_Cfg"
            key = create_cfg.get(img_create_section, "aes_key_org")
            iv = create_cfg.get(img_create_section, "aes_iv")
            publickey = create_cfg.get(img_create_section, "publickey_file")
            privatekey = create_cfg.get(img_create_section, "privatekey_file_uecc")
            return key, iv, publickey, privatekey
        else:
            return self._key, self._iv, self._publickey, self._privatekey

    def img_load_interface_init(self, comnum, sh_baudrate):
        self.bflb_boot_if.if_init(comnum, sh_baudrate, self._chip_type, self._chip_name)
        self.boot_install_cmds_callback()

    def img_load_shake_hand(
        self,
        comnum,
        sh_baudrate,
        wk_baudrate,
        do_reset=False,
        reset_hold_time=100,
        shake_hand_delay=100,
        reset_revert=True,
        cutoff_time=0,
        shake_hand_retry=2,
        isp_timeout=0,
        boot_load=True,
    ):
        if self._chip_type == "wb03":
            self.bflb_boot_if.if_toggle_boot(
                do_reset,
                reset_hold_time,
                shake_hand_delay,
                reset_revert,
                cutoff_time,
                shake_hand_retry,
                isp_timeout,
                boot_load,
            )
            bflb_utils.printf("get chip id")
            # get chip id before download
            ret, data_read = self.boot_process_one_section("get_chip_id", 0)
            if ret.startswith("OK") is False:
                bflb_utils.printf("fail")
                return ret, None
            # check chip id
            data_read = binascii.hexlify(data_read)
            bflb_utils.printf("data read is ", data_read)
            chip_id = data_read.decode("utf-8")
            if chip_id != "43484950574230334130305f424c0000" and chip_id != "43484950574230334130305F424C0000":
                return "shake hand fail"
        else:
            if self._chip_type == "bl602":
                self.bflb_boot_if.if_set_602a0_download_fix(False)
            ret = self.bflb_boot_if.if_shakehand(
                do_reset,
                reset_hold_time,
                shake_hand_delay,
                reset_revert,
                cutoff_time,
                shake_hand_retry,
                isp_timeout,
                boot_load,
            )
            if self._chip_type == "bl602":
                self.bflb_boot_if.if_set_602a0_download_fix(False)
            if ret != "OK":
                bflb_utils.printf("handshake failed")
                self.print_issue_log()
                bflb_utils.set_error_code("0050")
                return "shake hand fail"

            if sh_baudrate != wk_baudrate:
                if self.boot_inf_change_rate(comnum, "change_rate", wk_baudrate) != "OK":
                    bflb_utils.printf("change rate failed")
                    return "change rate fail"

        bflb_utils.printf("handshake succeeded")
        return ret

    ########################main process###############################################
    def img_load_main_process(self, img_file, group, createcfg, callback=None, record_bootinfo=None, **kwargs):
        encrypt_blk_size = 16
        # self._imge_fp = open(img_file, 'rb')

        bflb_utils.printf("get boot info")
        # get boot information before download
        ret, data_read = self.boot_process_one_section("get_boot_info", 0)
        if ret.startswith("OK") is False:
            bflb_utils.printf("fail")
            return ret, None
        # check with image file
        data_read = binascii.hexlify(data_read)
        bflb_utils.printf("data read is ", data_read)
        bootinfo = data_read.decode("utf-8")
        chipid = None
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
        if qt_sign and th_sign and QtCore.QThread.currentThread().objectName():
            with mutex:
                num = str(QtCore.QThread.currentThread().objectName())
                gol.list_chipid[int(num) - 1] = chipid
                if chipid is not None:
                    gol.list_chipid_check[int(num) - 1] = chipid
                for i, j in gol.list_download_check_last:
                    if (chipid is not None) and (chipid == i) and (j is True):
                        return "repeat_burn", bootinfo
        # bflb_utils.printf(int(data_read[10:12], 16))
        bflb_utils.printf("last boot info: ", record_bootinfo)
        if record_bootinfo is not None and bootinfo[8:] == record_bootinfo[8:]:
            bflb_utils.printf("repeated chip")
            return "repeat_burn", bootinfo
        if bootinfo[:8] == "FFFFFFFF" or bootinfo[:8] == "ffffffff":
            bflb_utils.printf("eflash loader present")
            return "error_shakehand", bootinfo
        sign = 0
        encrypt = 0
        sign_384 = 0
        if self._chip_type == "bl60x":
            sign = int(data_read[8:10], 16) & 0x03
            encrypt = (int(data_read[8:10], 16) & 0x0C) >> 2
        elif self._chip_type == "bl602" or self._chip_type == "bl702" or self._chip_type == "bl702l":
            sign = int(data_read[8:10], 16)
            encrypt = int(data_read[10:12], 16)
        elif self._chip_type == "bl808" or self._chip_type == "bl628":
            if group == 0:
                sign = int(data_read[8:10], 16)
                encrypt = int(data_read[12:14], 16)
            else:
                sign = int(data_read[10:12], 16)
                encrypt = int(data_read[14:16], 16)
        elif self._chip_type == "bl616l":
            sign = int(data_read[8:10], 16)
            encrypt = int(data_read[10:12], 16)
            sign_384 = sign == 2
        elif self._chip_type == "bl616d":
            sign = int(data_read[8:10], 16)
            encrypt = int(data_read[10:12], 16)
            sign_384 = sign == 2
        else:
            sign = int(data_read[8:10], 16)
            encrypt = int(data_read[10:12], 16)
        bflb_utils.printf("sign is ", sign, ", encrypt is ", encrypt)
        key, iv, publickey, privatekey = self.img_load_get_sec_cfg()
        eflash_loader_dir = os.path.dirname(img_file)
        eflash_loader_file = os.path.basename(img_file).split(".")[0]

        key = None if not key else key
        iv = None if not iv else iv
        privatekey = None if not privatekey else privatekey
        publickey = None if not publickey else publickey
        privatekey_str = None
        if "privatekey_str" in kwargs and kwargs["privatekey_str"]:
            privatekey_str = kwargs["privatekey_str"]

        # encrypt eflash loader helper bin
        if (key and iv) or privatekey or privatekey_str:
            if sign and not privatekey and not privatekey_str:
                bflb_utils.printf("Error: private key must be provided")
                return "", bootinfo
            if encrypt and (not key or not iv):
                bflb_utils.printf("Error: aes key and aes iv must be provided")
                return "", bootinfo
            if (
                eflash_loader_file == "img_if"
                or eflash_loader_file == "img_group0_if"
                or eflash_loader_file == "img_group1_if"
            ):
                img_file = os.path.join(bflb_utils.app_path, img_file)
                self._imge_fp = open(img_file, "rb")
            else:
                ret, encrypted_data = bflb_img_create.encrypt_loader_bin(
                    self._chip_type, img_file, sign, encrypt, key, iv, publickey, privatekey, **kwargs
                )
                if ret is True:
                    # create new eflash loader helper bin
                    filename, ext = os.path.splitext(img_file)
                    file_encrypt = filename + "_encrypt" + ext
                    with open(file_encrypt, "wb") as fp:
                        fp.write(encrypted_data)
                    self._imge_fp = open(file_encrypt, "rb")
                else:
                    img_file = os.path.join(bflb_utils.app_path, img_file)
                    self._imge_fp = open(img_file, "rb")
        elif sign or encrypt:
            if "ram" in kwargs and kwargs["ram"]:
                img_file = os.path.join(bflb_utils.app_path, img_file)
                self._imge_fp = open(img_file, "rb")
            else:
                try:
                    eflash_loader_file = eflash_loader_file + "_encrypt.bin"
                    img_file = os.path.join(bflb_utils.app_path, eflash_loader_dir, eflash_loader_file)
                    self._imge_fp = open(img_file, "rb")
                except Exception as e:
                    bflb_utils.printf(e)
                    return "", bootinfo
        else:
            img_file = os.path.join(bflb_utils.app_path, img_file)
            self._imge_fp = open(img_file, "rb")
        if self._chip_type == "wb03":
            # wb03 img loader, read 0xD0 len for cut wb03 header
            self._imge_fp.read(0xD0)

        # start to process load flow
        if self._chip_type == "bl808":
            ret, dmy = self.boot_process_one_section("808_load_boot_header", 0)
        elif self._chip_type == "bl628":
            ret, dmy = self.boot_process_one_section("628_load_boot_header", 0)
        elif self._chip_type == "bl616" or self._chip_type == "wb03":
            ret, dmy = self.boot_process_one_section("616_load_boot_header", 0)
        elif self._chip_type == "bl702l":
            ret, dmy = self.boot_process_one_section("702l_load_boot_header", 0)
        elif self._chip_type == "bl616l":
            ret, dmy = self.boot_process_one_section("616l_load_boot_header", 0)
        elif self._chip_type == "bl616d":
            ret, dmy = self.boot_process_one_section("616d_load_boot_header", 0)
        else:
            ret, dmy = self.boot_process_one_section("load_boot_header", 0)
        if ret.startswith("OK") is False:
            return ret, bootinfo
        if sign_384:
            ret, dmy = self.boot_process_one_section("load_sha384_p2", 0)
            if ret.startswith("OK") is False:
                return ret, bootinfo
        if sign:
            if sign_384:
                ret, dmy = self.boot_process_one_section("load_publick_key_384", 0)
            else:
                ret, dmy = self.boot_process_one_section("load_publick_key", 0)
            if ret.startswith("OK") is False:
                return ret, bootinfo
            if self._chip_type == "bl60x" or self._chip_type == "bl808" or self._chip_type == "bl628":
                if sign_384:
                    ret, dmy = self.boot_process_one_section("load_publick_key2_384", 0)
                else:
                    ret, dmy = self.boot_process_one_section("load_publick_key2", 0)
                if ret.startswith("OK") is False:
                    return ret, bootinfo
            ret, dmy = self.boot_process_one_section("load_signature", 0)
            if ret.startswith("OK") is False:
                return ret, bootinfo
            if self._chip_type == "bl60x" or self._chip_type == "bl808" or self._chip_type == "bl628":
                ret, dmy = self.boot_process_one_section("load_signature2", 0)
                if ret.startswith("OK") is False:
                    return ret, bootinfo
        if encrypt:
            ret, dmy = self.boot_process_one_section("load_aes_iv", 0)
            if ret.startswith("OK") is False:
                return ret, bootinfo
        # process seg header and seg data
        segs = 0
        while segs < self._segcnt:
            send_len = 0
            segdata_len = 0
            ret, data_read = self.boot_process_one_section("load_seg_header", 0)
            if ret.startswith("OK") is False:
                return ret, bootinfo
            # bootrom will return decrypted seg header info
            tmp = bflb_utils.bytearray_reverse(data_read[4:8])
            segdata_len = bflb_utils.bytearray_to_int(tmp)
            bflb_utils.printf("segdata len is ", segdata_len)
            # for encrypted image, the segdata in segheader is the actual len of segdata
            # while the image is 16bytes aligned , so ,we the data we read for sending is also 16 bytes aligned
            if encrypt == 1:
                if segdata_len % encrypt_blk_size != 0:
                    segdata_len = segdata_len + encrypt_blk_size - segdata_len % encrypt_blk_size
            while send_len < segdata_len:
                left = segdata_len - send_len
                if left > 4080:
                    left = 4080
                ret, dmy = self.boot_process_one_section("load_seg_data", left)
                if ret.startswith("OK") is False:
                    return ret, bootinfo
                send_len = send_len + left
                bflb_utils.printf("{0}/{1}".format(send_len, segdata_len))
                if callback is not None:
                    callback(send_len, segdata_len, sys._getframe().f_code.co_name)
            segs = segs + 1
        ret, dmy = self.boot_process_one_section("check_image", 0)
        return ret, bootinfo

    def img_load_reset_cpu(self):
        bflb_utils.printf("========= reset cpu =========")
        ret, data_read = self.boot_process_one_section("reset", 0)
        if ret.startswith("OK") is False:
            bflb_utils.printf("cpu reset failed")
            return False
        return True

    def img_load_process(
        self,
        comnum,
        sh_baudrate,
        wk_baudrate,
        file1,
        file2,
        callback=None,
        do_reset=False,
        reset_hold_time=100,
        shake_hand_delay=100,
        reset_revert=True,
        cutoff_time=0,
        shake_hand_retry=2,
        isp_timeout=0,
        boot_load=True,
        record_bootinfo=None,
        **kwargs,
    ):
        bflb_utils.printf("========= image load =========")
        res = True
        bootinfo = None
        try:
            self.img_load_interface_init(comnum, sh_baudrate)
            # get bootinfo first, maybe shake hand is
            timeout = self.bflb_boot_if.if_get_rx_timeout()
            self.bflb_boot_if.if_set_rx_timeout(0.1)
            ret, data_read = self.boot_process_one_section("get_boot_info", 0)
            self.bflb_boot_if.if_set_rx_timeout(timeout)
            if ret.startswith("OK") is not True:
                ret = self.img_load_shake_hand(
                    comnum,
                    sh_baudrate,
                    wk_baudrate,
                    do_reset,
                    reset_hold_time,
                    shake_hand_delay,
                    reset_revert,
                    cutoff_time,
                    shake_hand_retry,
                    isp_timeout,
                    boot_load,
                )
                if ret == "shake hand fail" or ret == "change rate fail":
                    bflb_utils.printf("handshake failed")
                    self.bflb_boot_if.if_close()
                    res = False
                    return
            time.sleep(0.01)
            if file1 is not None and file1 != "":
                res, bootinfo = self.img_load_main_process(
                    file1, 0, self._create_cfg, callback, record_bootinfo, **kwargs
                )
                if res.startswith("OK") is False:
                    if res.startswith("repeat_burn") is True:
                        res = False
                        return
                    else:
                        bflb_utils.printf("image load failed")
                        if res.startswith("error_shakehand") is True:
                            bflb_utils.printf("handshake with eflash loader found")
                        res = False
                        return
            if file2 is not None and file2 != "":
                res, bootinfo = self.img_load_main_process(
                    file2, 1, self._create_cfg, callback, record_bootinfo, **kwargs
                )
                if res.startswith("OK") is False:
                    if res.startswith("repeat_burn") is True:
                        res = False
                        return
                    else:
                        bflb_utils.printf("image load failed")
                        if res.startswith("error_shakehand") is True:
                            bflb_utils.printf("handshake with eflash loader found")
                        res = False
                        return
            bflb_utils.printf("Run img")
            res, dmy = self.boot_process_one_section("run_image", 0)
            if res.startswith("OK") is False:
                bflb_utils.printf("Img run failed")
                res = False
            else:
                res = True
            time.sleep(0.1)
        except Exception as e:
            bflb_utils.printf(e)
            # traceback.print_exc(limit=5, file=sys.stdout)
            res = False
        finally:
            if self._imge_fp:
                self._imge_fp.close()
            # self.bflb_boot_if.if_close()
            return res, bootinfo, ""

    def img_get_bootinfo(
        self,
        comnum,
        sh_baudrate,
        wk_baudrate,
        file1,
        file2,
        callback=None,
        do_reset=False,
        reset_hold_time=100,
        shake_hand_delay=100,
        reset_revert=True,
        cutoff_time=0,
        shake_hand_retry=2,
        isp_timeout=0,
        boot_load=True,
        boot_baudrate=500000,
    ):
        bflb_utils.printf("========= image get bootinfo =========")
        self.img_load_interface_init(comnum, sh_baudrate)

        # get bootinfo first, maybe need handshake
        timeout = self.bflb_boot_if.if_get_rx_timeout()
        self.bflb_boot_if.if_set_rx_timeout(0.1)
        ret, data_read = self.boot_process_one_section("get_boot_info", 0, baudrate=boot_baudrate)
        self.bflb_boot_if.if_set_rx_timeout(timeout)
        if ret.startswith("OK") is True:
            # check with image file
            data_read = binascii.hexlify(data_read)
            bflb_utils.printf("data read is ", data_read)
            if self._chip_type == "bl616":
                if data_read.decode("utf-8")[:2] == "01":
                    self.bl616_a0 = True
            return True, data_read
        ret = self.img_load_shake_hand(
            comnum,
            sh_baudrate,
            wk_baudrate,
            do_reset,
            reset_hold_time,
            shake_hand_delay,
            reset_revert,
            cutoff_time,
            shake_hand_retry,
            isp_timeout,
            boot_load,
        )
        if ret == "shake hand fail" or ret == "change rate fail":
            bflb_utils.printf("handshake failed")
            self.bflb_boot_if.if_close()
            return False, ""
        time.sleep(0.5)
        ret, data_read = self.boot_process_one_section("get_boot_info", 0)
        if ret.startswith("OK") is False:
            bflb_utils.printf("get bootinfo is not ok")
            return ret, ""
        # check with image file
        data_read = binascii.hexlify(data_read)

        if self._chip_type == "bl616":
            if data_read.decode("utf-8")[:2] == "01":
                self.bl616_a0 = True
                # write memory, set bl616 a0 bootrom uart timeout to 10s
                tmp = bflb_utils.int_to_2bytearray_l(8)
                start_addr = bflb_utils.int_to_4bytearray_l(0x6102DF04)
                write_data = bflb_utils.int_to_4bytearray_l(0x27101200)
                cmd_id = bflb_utils.hexstr_to_bytearray(self._bootrom_cmds.get("memory_write")["cmd_id"])
                data = cmd_id + bytearray(1) + tmp + start_addr + write_data
                self.bflb_boot_if.if_write(data)
                ret, data_read_ack = self.bflb_boot_if.if_deal_ack(dmy_data=False)
            else:
                # 03 command to set bl616 ax bootrom uart timeout to 10s
                tmp = bflb_utils.int_to_2bytearray_l(4)
                timeout = bflb_utils.int_to_4bytearray_l(10000)
                cmd_id = bflb_utils.hexstr_to_bytearray(self._bootrom_cmds.get("set_timeout")["cmd_id"])
                data = cmd_id + bytearray(1) + tmp + timeout
                self.bflb_boot_if.if_write(data)
                ret, data_read_ack = self.bflb_boot_if.if_deal_ack(dmy_data=False)
        bflb_utils.printf("data read is ", data_read)
        return True, data_read

    def efuse_read_process(
        self,
        comnum,
        sh_baudrate,
        wk_baudrate,
        callback=None,
        do_reset=False,
        reset_hold_time=100,
        shake_hand_delay=100,
        reset_revert=True,
        cutoff_time=0,
        shake_hand_retry=2,
    ):
        res = True
        bflb_utils.printf("efuse read process")
        self.img_load_interface_init(comnum, sh_baudrate)
        ret = self.img_load_shake_hand(
            comnum,
            sh_baudrate,
            wk_baudrate,
            do_reset,
            reset_hold_time,
            shake_hand_delay,
            reset_revert,
            cutoff_time,
            shake_hand_retry,
        )
        if ret == "shake hand fail" or ret == "change rate fail":
            bflb_utils.printf("handshake failed")
            return False
        time.sleep(0.5)
        # in case data len change for some case
        bflb_utils.printf("efuse read: ")
        tmp = bflb_utils.int_to_2bytearray_l(8)
        start_addr = bflb_utils.int_to_4bytearray_l(0)
        read_len = bflb_utils.int_to_4bytearray_l(256)
        cmd_id = bflb_utils.hexstr_to_bytearray(self._bootrom_cmds.get("efuse_read")["cmd_id"])
        data = cmd_id + bytearray(1) + tmp + start_addr + read_len
        self.bflb_boot_if.if_write(data)
        res, data_read = self.bflb_boot_if.if_deal_response()
        # res, data_read = boot_process_one_section("efuse_read",0)
        bflb_utils.printf("data_read: ")
        bflb_utils.printf(binascii.hexlify(data_read))
        bflb_utils.printf("Finished")
        if ret.startswith("OK") is False:
            bflb_utils.printf("fail")
            res = False
        return res


if __name__ == "__main__":
    img_load_t = BflbImgLoader()
    if len(sys.argv) == 3:
        img_load_t.img_load_process(sys.argv[1], 115200, 115200, sys.argv[2], "")
    elif len(sys.argv) == 4:
        img_load_t.img_load_process(sys.argv[1], 115200, 115200, sys.argv[2], sys.argv[3])
