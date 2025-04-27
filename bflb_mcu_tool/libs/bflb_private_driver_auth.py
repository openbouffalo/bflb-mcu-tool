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
import hashlib
import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

try:
    import bflb_path
except ImportError:
    from libs import bflb_path

import config as gol
from libs import bflb_interface_uart
from libs import bflb_utils
from libs import bflb_ecdh
from libs.bflb_utils import (
    app_path,
    chip_path,
    open_file,
    eflash_loader_parser_init,
    convert_path,
)

FLASH_LOAD_SHAKE_HAND = "Flash load handshake"
FLASH_ERASE_SHAKE_HAND = "Flash erase handshake"

lock_file = "lock.txt"


def acquire_lock():
    while True:
        try:
            lock_fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(lock_fd, str(os.getpid()).encode())
            os.close(lock_fd)
            break
        except FileExistsError:
            # 文件已经被锁定，等待一段时间后重试
            time.sleep(0.3)


def release_lock():
    os.remove(lock_file)


class BflbAuthBase(object):
    def __init__(
        self,
        dfp_device,
        dup_device,
        com_speed,
        chipname="bl616",
        chiptype="bl616",
    ):
        self._bflb_auto_download = False
        # img loader class
        self._bflb_com_img_loader = None
        # communicate interface
        self._bflb_com_dup = None
        self._bflb_com_dfp = None
        # communicate device name
        self._bflb_dfp_device = dfp_device
        self._bflb_dup_device = dup_device
        # bootrom device speed
        self._bflb_boot_speed = 0
        # communicate device speed
        self._bflb_com_speed = com_speed
        # communicate device speed
        self._bflb_com_tx_size = 0
        # erase timeout
        self._erase_time_out = 10000
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
        self._outdir = "image_create_iot"

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
            "memory_write": {"cmd_id": "50", "data_len": "0080", "callback": None},
            "memory_read": {"cmd_id": "51", "data_len": "0000", "callback": None},
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
        self._bflb_com_dup.if_write(data)
        if section in self._resp_cmds:
            res, data_read = self._bflb_com_dup.if_deal_response()
            if res != "OK":
                bflb_utils.printf("Failed to get response, set baudrate to 115200 and retry")
                self._bflb_com_dup.if_set_baudrate(115200)
                self._bflb_com_dup.if_write(data)
                res, data_read = self._bflb_com_dup.if_deal_response()
                self._bflb_com_dup.if_set_baudrate(self._bflb_com_dup._baudrate)
        else:
            res = self._bflb_com_dup.if_deal_ack()
        return res, data_read

    def print_error_code(self, code):
        bflb_utils.set_error_code(code, self._task_num)
        bflb_utils.printf("ErrorCode: {0}, ErrorMsg: {1}".format(code, bflb_utils.eflash_loader_error_code[code]))

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

    def _handshake(self):
        self._bflb_com_dup = bflb_interface_uart.BflbUartPort()
        bflb_utils.printf("Init DUP: ", self._bflb_dup_device)
        bflb_utils.printf("Speed: ", str(self._bflb_com_speed))
        self._bflb_com_dup.if_init(
            self._bflb_dup_device, self._bflb_com_speed, self._chip_type, self._chip_name, False, False
        )
        self._bflb_com_dup.if_write(bytearray(b"\x10\x00\x00\x00"))
        res, data_read = self._bflb_com_dup.if_deal_response()
        if res != "OK":
            self._bflb_com_dup.if_shakehand()

    def get_ecdh_shared_key(self, shakehand=0):
        bflb_utils.printf("========= get ecdh shared key =========")
        publickey_file = "utils/pem/publickey_uecc.pem"
        if shakehand != 0:
            bflb_utils.printf("handshake")
            ret = self._handshake()
            if ret is False:
                return
        tmp_ecdh = bflb_ecdh.BflbEcdh()
        self._ecdh_public_key = tmp_ecdh.create_public_key()
        self._ecdh_private_key = binascii.hexlify(
            tmp_ecdh.private_key.private_numbers().private_value.to_bytes(32, "big")
        ).decode("utf-8")
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("ecdh_get_pk")["cmd_id"])
        data_send = bytearray.fromhex(self._ecdh_public_key)
        ret, data_read = self.com_process_one_cmd("ecdh_get_pk", cmd_id, data_send)
        if ret.startswith("OK") is True:
            self._ecdh_peer_public_key = binascii.hexlify(data_read).decode("utf-8")
            bflb_utils.printf("ecdh peer key")
            bflb_utils.printf(self._ecdh_peer_public_key)
            self._ecdh_shared_key = tmp_ecdh.create_shared_key(self._ecdh_peer_public_key[0:128])
            cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get("ecdh_challenge")["cmd_id"])
            data_send = bytearray(0)
            ret, data_read = self.com_process_one_cmd("ecdh_challenge", cmd_id, data_send)
            if ret.startswith("OK") is True:
                bflb_utils.printf("Challenge data")
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
                    bflb_utils.printf("Challenge verify fail")
                    return False
            else:
                bflb_utils.printf("Challenge ack fail")
                return False
        else:
            bflb_utils.printf("Get shared key fail")
            return False

    @staticmethod
    def efuse_compare(read_data, maskdata, write_data):
        i = 0
        for i in range(len(read_data)):
            compare_data = read_data[i] & maskdata[i]
            if (compare_data & write_data[i]) != write_data[i]:
                bflb_utils.printf("Compare fail: ", i)
                bflb_utils.printf(read_data[i], write_data[i])
                return False
        return True

    def efuse_load_main_process2(self, efuse_data, security_write=True):
        if security_write and (self.get_ecdh_shared_key() is not True):
            bflb_utils.printf("ECDH fail")
            return False
        bflb_utils.printf("Load efuse 0")
        # load normal data
        if security_write:
            cmd_name = "efuse_security_write"
        else:
            cmd_name = "efuse_write"
        cmd_id = bflb_utils.hexstr_to_bytearray(self._com_cmds.get(cmd_name)["cmd_id"])
        data_send = efuse_data[0:124] + bytearray(4)
        if security_write:
            data_send = self.ecdh_encrypt_data(data_send)
        data_send = bflb_utils.int_to_4bytearray_l(0) + data_send
        ret, dmy = self.com_process_one_cmd(cmd_name, cmd_id, data_send)
        if ret.startswith("OK") is False:
            bflb_utils.printf("Write failed")
            self.print_error_code("0021")
            return False
        # load read write protect data
        data_send = bytearray(12) + efuse_data[124:128]
        if security_write:
            data_send = self.ecdh_encrypt_data(data_send)
        data_send = bflb_utils.int_to_4bytearray_l(124 - 12) + data_send
        ret, dmy = self.com_process_one_cmd(cmd_name, cmd_id, data_send)
        if ret.startswith("OK") is False:
            bflb_utils.printf("Write failed")
            self.print_error_code("0021")
            return False
        bflb_utils.printf("All Successful")
        return True

    def efuse_load_shakehand(self):
        ret = self._handshake()
        if ret is False:
            return False
        return True

    def efuse_load_main_process(self, efuse_data, security_write=True):
        b_ok = bytearray(b"OK")

        self._bflb_com_dfp = bflb_interface_uart.BflbUartPort()
        bflb_utils.printf("Init DFP: ", self._bflb_dfp_device)
        bflb_utils.printf("Speed: 2000000")
        self._bflb_com_dfp.if_init(self._bflb_dfp_device, 2000000, self._chip_type, self._chip_name)

        # step1 Get ECDH request from DFP and forward to DUP
        c_data = [0xF0, 0x98, 0x45, 0x43]
        self._bflb_com_dfp.if_write(bytearray(c_data))
        success, ecdh_req = self._bflb_com_dfp.if_read(4 + 64)
        if success == 0:
            bflb_utils.printf("Request ECDH error")
            return False
        # bflb_utils.printf("Send to DUP",ecdh_req)
        self._bflb_com_dup.if_write(ecdh_req)
        # step2 read ECDH reuest response from DUP and forward to DFP
        success, ack = self._bflb_com_dup.if_read(2)
        if success == 0 or ack != b_ok:
            bflb_utils.printf("DUP Ack OK Error")
            return False
        success, data = self._bflb_com_dup.if_read(2 + 128)
        if success == 0:
            bflb_utils.printf("DUP Ack Data Error")
            return False
        # bflb_utils.printf("Send to DFP",ack+data)
        self._bflb_com_dfp.if_write(ack + data)

        # step3 get ECDH challenge request and forward to DUP
        success, chan_req = self._bflb_com_dfp.if_read(4)
        chanllege_request = bytes([0x91, 0x00, 0x00, 0x00])
        if success == 0 or chan_req != chanllege_request:
            bflb_utils.printf("Read challenge request from DFP fail")
            return False
        # bflb_utils.printf("Send challenge to DUP", chan_req)
        self._bflb_com_dup.if_write(chan_req)
        # step4 read ECDH challenge response from DUP and forward to DFP
        success, ack = self._bflb_com_dup.if_read(2)
        if success == 0 or ack != b_ok:
            bflb_utils.printf("DUP Ack OK Error")
            return False
        success, data = self._bflb_com_dup.if_read(2 + 96)
        if success == 0:
            bflb_utils.printf("DUP Ack Data Error")
            return False
        # bflb_utils.printf("Send to DFP", ack+data)
        self._bflb_com_dfp.if_write(ack + data)

        # step5 get efuse write data and forward to DUP
        success, efuse_write_data = self._bflb_com_dfp.if_read(136)
        if success == 0:
            bflb_utils.printf("Get efuse write data 0 from DFP fail")
            return False
        # bflb_utils.printf("Send efuse write data 0 to DUP",efuse_write_data)
        self._bflb_com_dup.if_write(efuse_write_data)

        # step6 read response from DUP and forward to DFP
        success, ack = self._bflb_com_dup.if_read(2)
        if success == 0 or ack != b_ok:
            bflb_utils.printf("DUP Ack OK Error")
            return False
        # bflb_utils.printf("Send to DFP",ack)
        self._bflb_com_dfp.if_write(ack)
        """
        #step7 get efuse write data and forward to DUP
        success, efuse_write_data = self._bflb_com_dfp.if_read(24)
        if success==0:
            bflb_utils.printf("Get efuse write data 1 from DFP fail")
            return False
        bflb_utils.printf("Send efuse write data 1 to DUP",efuse_write_data)
        self._bflb_com_dup.if_write(efuse_write_data)
        
        #step8 read response from DUP and forward to DFP
        success, ack = self._bflb_com_dup.if_read(2)
        if success==0 or ack!=b_ok:
            bflb_utils.printf("DUP Ack OK Error")
            return False
        bflb_utils.printf("Send to DFP",ack)
        self._bflb_com_dfp.if_write(ack)
        """
        bflb_utils.printf("Authorization succeeded")
        return True


def run():
    # efuse_data = bytearray(c_array)
    efuse_data = bytearray(128)

    if len(sys.argv) == 3:
        bflb_auth_obj = BflbAuthBase(sys.argv[1], sys.argv[2], 2000000)
    elif len(sys.argv) == 4:
        bflb_auth_obj = BflbAuthBase(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    else:
        bflb_utils.printf("No COM parameter")
        sys.exit()
    if bflb_auth_obj.efuse_load_shakehand():
        # 获取文件锁
        acquire_lock()
        bflb_auth_obj.efuse_load_main_process(efuse_data, security_write=True)
        release_lock()


if __name__ == "__main__":
    run()
