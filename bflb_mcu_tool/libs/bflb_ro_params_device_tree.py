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
import binascii

from libs import bflb_utils
from libs import bflb_fdt as fdt
from libs.bflb_utils import app_path, string_to_bytearray


def little_endian(data):
    return binascii.hexlify(binascii.unhexlify(data)[::-1]).decode("utf-8")


def bl_dts2dtb(src_addr="", dest_addr=""):
    if "" == src_addr or "" == dest_addr:
        bflb_utils.printf("bl_dts2dtb please check arg")
        return
    bflb_utils.printf("========= ", os.path.normpath(src_addr), " ——> ", os.path.normpath(dest_addr))
    with open(src_addr, "r", encoding="utf-8") as f:
        tmp1_dts = f.read()
    tmp2_dtb = fdt.parse_dts(tmp1_dts)
    dest_addr = os.path.join(app_path, dest_addr)
    with open(dest_addr, "wb") as f:
        f.write(tmp2_dtb.to_dtb(version=17))


def bl_ro_params_device_tree(in_dts_config, out_bin_file):
    dts_config = in_dts_config
    bin_file = out_bin_file
    bl_dts2dtb(dts_config, bin_file)


def bl_dts2hex(dts):
    with open(dts, "r", encoding="utf-8") as f:
        tmp_dts = f.read()
    fdt_obj = fdt.parse_dts(tmp_dts)

    xtal_mode = ""
    xtal = ""
    pwr_mode = ""
    pwr_table_11b = ""
    pwr_table_11g = ""
    pwr_table_11n = ""
    pwr_table_11n_ht20 = ""
    pwr_table_11n_ht40 = ""
    pwr_table_11ac_vht20 = ""
    pwr_table_11ac_vht40 = ""
    pwr_table_11ac_vht80 = ""
    pwr_table_11ax_he20 = ""
    pwr_table_11ax_he40 = ""
    pwr_table_11ax_he80 = ""
    pwr_table_11ax_he160 = ""
    pwr_offset_wifi = ""
    pwr_offset_wifi_lp = ""

    pwr_limit_2g_ch1 = ""
    pwr_limit_2g_ch2 = ""
    pwr_limit_2g_ch3 = ""
    pwr_limit_2g_ch4 = ""
    pwr_limit_2g_ch5 = ""
    pwr_limit_2g_ch6 = ""
    pwr_limit_2g_ch7 = ""
    pwr_limit_2g_ch8 = ""
    pwr_limit_2g_ch9 = ""
    pwr_limit_2g_ch10 = ""
    pwr_limit_2g_ch11 = ""
    pwr_limit_2g_ch12 = ""
    pwr_limit_2g_ch13 = ""
    pwr_limit_2g_ch14 = ""

    pwr_limit_2g_ext_ch1 = ""
    pwr_limit_2g_ext_ch2 = ""
    pwr_limit_2g_ext_ch3 = ""
    pwr_limit_2g_ext_ch4 = ""
    pwr_limit_2g_ext_ch5 = ""
    pwr_limit_2g_ext_ch6 = ""
    pwr_limit_2g_ext_ch7 = ""
    pwr_limit_2g_ext_ch8 = ""
    pwr_limit_2g_ext_ch9 = ""
    pwr_limit_2g_ext_ch10 = ""
    pwr_limit_2g_ext_ch11 = ""
    pwr_limit_2g_ext_ch12 = ""
    pwr_limit_2g_ext_ch13 = ""
    pwr_limit_2g_ext_ch14 = ""

    en_tcal = ""
    linear_or_follow = ""
    tchannels = ""
    tchannel_os = ""
    tchannel_os_low = ""
    troom_os = ""
    pwr_table_ble = ""
    pwr_table_bt = ""
    pwr_table_zigbee = ""
    pwr_offset_bz = ""
    country_code = ""
    en_cap_temp = ""
    cap_temp = ""
    capcode = ""

    if fdt_obj.exist_node("wifi/brd_rf"):
        xtal_mode = fdt_obj.get_property("xtal_mode", "wifi/brd_rf")
        xtal = fdt_obj.get_property("xtal", "wifi/brd_rf")
        pwr_mode = fdt_obj.get_property("pwr_mode", "wifi/brd_rf")
        pwr_offset_wifi = fdt_obj.get_property("pwr_offset", "wifi/brd_rf")
        pwr_offset_wifi_lp = fdt_obj.get_property("pwr_offset_lp", "wifi/brd_rf")
        pwr_table_11b = fdt_obj.get_property("pwr_table_11b", "wifi/brd_rf")
        pwr_table_11g = fdt_obj.get_property("pwr_table_11g", "wifi/brd_rf")
        pwr_table_11n = fdt_obj.get_property("pwr_table_11n", "wifi/brd_rf")
        pwr_table_11n_ht20 = fdt_obj.get_property("pwr_table_11n_ht20", "wifi/brd_rf")
        pwr_table_11n_ht40 = fdt_obj.get_property("pwr_table_11n_ht40", "wifi/brd_rf")
        pwr_table_11ac_vht20 = fdt_obj.get_property("pwr_table_11ac_vht20", "wifi/brd_rf")
        pwr_table_11ac_vht40 = fdt_obj.get_property("pwr_table_11ac_vht40", "wifi/brd_rf")
        pwr_table_11ac_vht80 = fdt_obj.get_property("pwr_table_11ac_vht80", "wifi/brd_rf")
        pwr_table_11ax_he20 = fdt_obj.get_property("pwr_table_11ax_he20", "wifi/brd_rf")
        pwr_table_11ax_he40 = fdt_obj.get_property("pwr_table_11ax_he40", "wifi/brd_rf")
        pwr_table_11ax_he80 = fdt_obj.get_property("pwr_table_11ax_he80", "wifi/brd_rf")
        pwr_table_11ax_he160 = fdt_obj.get_property("pwr_table_11ax_he160", "wifi/brd_rf")
        pwr_limit_2g_ch1 = fdt_obj.get_property("pwr_limit_2g_ch1", "wifi/brd_rf")
        pwr_limit_2g_ch2 = fdt_obj.get_property("pwr_limit_2g_ch2", "wifi/brd_rf")
        pwr_limit_2g_ch3 = fdt_obj.get_property("pwr_limit_2g_ch3", "wifi/brd_rf")
        pwr_limit_2g_ch4 = fdt_obj.get_property("pwr_limit_2g_ch4", "wifi/brd_rf")
        pwr_limit_2g_ch5 = fdt_obj.get_property("pwr_limit_2g_ch5", "wifi/brd_rf")
        pwr_limit_2g_ch6 = fdt_obj.get_property("pwr_limit_2g_ch6", "wifi/brd_rf")
        pwr_limit_2g_ch7 = fdt_obj.get_property("pwr_limit_2g_ch7", "wifi/brd_rf")
        pwr_limit_2g_ch8 = fdt_obj.get_property("pwr_limit_2g_ch8", "wifi/brd_rf")
        pwr_limit_2g_ch9 = fdt_obj.get_property("pwr_limit_2g_ch9", "wifi/brd_rf")
        pwr_limit_2g_ch10 = fdt_obj.get_property("pwr_limit_2g_ch10", "wifi/brd_rf")
        pwr_limit_2g_ch11 = fdt_obj.get_property("pwr_limit_2g_ch11", "wifi/brd_rf")
        pwr_limit_2g_ch12 = fdt_obj.get_property("pwr_limit_2g_ch12", "wifi/brd_rf")
        pwr_limit_2g_ch13 = fdt_obj.get_property("pwr_limit_2g_ch13", "wifi/brd_rf")
        pwr_limit_2g_ch14 = fdt_obj.get_property("pwr_limit_2g_ch14", "wifi/brd_rf")
    if fdt_obj.exist_node("wifi/rf_temp"):
        en_tcal = fdt_obj.get_property("en_tcal", "wifi/rf_temp")
        linear_or_follow = fdt_obj.get_property("linear_or_follow", "wifi/rf_temp")
        tchannels = fdt_obj.get_property("Tchannels", "wifi/rf_temp")
        tchannel_os = fdt_obj.get_property("Tchannel_os", "wifi/rf_temp")
        tchannel_os_low = fdt_obj.get_property("Tchannel_os_low", "wifi/rf_temp")
        troom_os = fdt_obj.get_property("Troom_os", "wifi/rf_temp")
    if fdt_obj.exist_node("bluetooth/brd_rf"):
        pwr_table_ble = fdt_obj.get_property("pwr_table_ble", "bluetooth/brd_rf")
        pwr_table_bt = fdt_obj.get_property("pwr_table_bt", "bluetooth/brd_rf")
        pwr_table_zigbee = fdt_obj.get_property("pwr_table_zigbee", "bluetooth/brd_rf")
        pwr_offset_bz = fdt_obj.get_property("pwr_offset", "bluetooth/brd_rf")
    if fdt_obj.exist_node("bluetooth_zigbee/brd_rf"):
        pwr_table_ble = fdt_obj.get_property("pwr_table_ble", "bluetooth_zigbee/brd_rf")
        pwr_table_bt = fdt_obj.get_property("pwr_table_bt", "bluetooth_zigbee/brd_rf")
        pwr_table_zigbee = fdt_obj.get_property("pwr_table_zigbee", "bluetooth_zigbee/brd_rf")
        pwr_offset_bz = fdt_obj.get_property("pwr_offset", "bluetooth_zigbee/brd_rf")
    if fdt_obj.exist_node("info/brd"):
        country_code = fdt_obj.get_property("country_code", "info/brd")
    if fdt_obj.exist_node("wifi/cap_temp"):
        en_cap_temp = fdt_obj.get_property("en_cap_temp", "wifi/cap_temp")
        cap_temp = fdt_obj.get_property("temp", "wifi/cap_temp")
        capcode = fdt_obj.get_property("capcode", "wifi/cap_temp")

    if fdt_obj.exist_node("wifi"):
        pwr_limit_2g_ext_ch1 = fdt_obj.get_property("pwr_limit_2g_ext_ch1", "wifi")
        pwr_limit_2g_ext_ch2 = fdt_obj.get_property("pwr_limit_2g_ext_ch2", "wifi")
        pwr_limit_2g_ext_ch3 = fdt_obj.get_property("pwr_limit_2g_ext_ch3", "wifi")
        pwr_limit_2g_ext_ch4 = fdt_obj.get_property("pwr_limit_2g_ext_ch4", "wifi")
        pwr_limit_2g_ext_ch5 = fdt_obj.get_property("pwr_limit_2g_ext_ch5", "wifi")
        pwr_limit_2g_ext_ch6 = fdt_obj.get_property("pwr_limit_2g_ext_ch6", "wifi")
        pwr_limit_2g_ext_ch7 = fdt_obj.get_property("pwr_limit_2g_ext_ch7", "wifi")
        pwr_limit_2g_ext_ch8 = fdt_obj.get_property("pwr_limit_2g_ext_ch8", "wifi")
        pwr_limit_2g_ext_ch9 = fdt_obj.get_property("pwr_limit_2g_ext_ch9", "wifi")
        pwr_limit_2g_ext_ch10 = fdt_obj.get_property("pwr_limit_2g_ext_ch10", "wifi")
        pwr_limit_2g_ext_ch11 = fdt_obj.get_property("pwr_limit_2g_ext_ch11", "wifi")
        pwr_limit_2g_ext_ch12 = fdt_obj.get_property("pwr_limit_2g_ext_ch12", "wifi")
        pwr_limit_2g_ext_ch13 = fdt_obj.get_property("pwr_limit_2g_ext_ch13", "wifi")
        pwr_limit_2g_ext_ch14 = fdt_obj.get_property("pwr_limit_2g_ext_ch14", "wifi")

    init_hex = little_endian(string_to_bytearray("k1bXkD6O").hex())

    if xtal_mode:
        length = "%02x" % len(xtal_mode[0])
        xtal_mode_hex = "0100" + length + "00" + string_to_bytearray(xtal_mode[0]).hex()
    else:
        xtal_mode_hex = ""

    if xtal:
        xtal_hex = "02001400"
        for item in xtal:
            item_hex = little_endian("%08x" % item)
            xtal_hex += item_hex
    else:
        xtal_hex = ""

    if pwr_mode:
        length = "%02x" % len(pwr_mode[0])
        pwr_mode_hex = "0300" + length + "00" + string_to_bytearray(pwr_mode[0]).hex()
    else:
        pwr_mode_hex = ""

    if pwr_table_11b:
        pwr_table_11b_hex = "05000400"
        for item in pwr_table_11b:
            item_hex = "%02x" % item
            pwr_table_11b_hex += item_hex
    else:
        pwr_table_11b_hex = ""

    if pwr_table_11g:
        pwr_table_11g_hex = "06000800"
        for item in pwr_table_11g:
            item_hex = "%02x" % item
            pwr_table_11g_hex += item_hex
    else:
        pwr_table_11g_hex = ""

    if pwr_table_11n:
        pwr_table_11n_hex = "07000800"
        for item in pwr_table_11n:
            item_hex = "%02x" % item
            pwr_table_11n_hex += item_hex
    else:
        pwr_table_11n_hex = ""

    if pwr_table_11n_ht20:
        pwr_table_11n_ht20_hex = "07000800"
        for item in pwr_table_11n_ht20:
            item_hex = "%02x" % item
            pwr_table_11n_ht20_hex += item_hex
    else:
        pwr_table_11n_ht20_hex = ""

    if pwr_table_11n_ht40:
        pwr_table_11n_ht40_hex = "09000800"
        for item in pwr_table_11n_ht40:
            item_hex = "%02x" % item
            pwr_table_11n_ht40_hex += item_hex
    else:
        pwr_table_11n_ht40_hex = ""

    if pwr_table_11ac_vht20:
        pwr_table_11ac_vht20_hex = "0a000a00"
        for item in pwr_table_11ac_vht20:
            item_hex = "%02x" % item
            pwr_table_11ac_vht20_hex += item_hex
    else:
        pwr_table_11ac_vht20_hex = ""

    if pwr_table_11ac_vht40:
        pwr_table_11ac_vht40_hex = "0b000a00"
        for item in pwr_table_11ac_vht40:
            item_hex = "%02x" % item
            pwr_table_11ac_vht40_hex += item_hex
    else:
        pwr_table_11ac_vht40_hex = ""

    if pwr_table_11ac_vht80:
        pwr_table_11ac_vht80_hex = "0c000a00"
        for item in pwr_table_11ac_vht80:
            item_hex = "%02x" % item
            pwr_table_11ac_vht80_hex += item_hex
    else:
        pwr_table_11ac_vht80_hex = ""

    if pwr_table_11ax_he20:
        pwr_table_11ax_he20_hex = "0d000c00"
        for item in pwr_table_11ax_he20:
            item_hex = "%02x" % item
            pwr_table_11ax_he20_hex += item_hex
    else:
        pwr_table_11ax_he20_hex = ""

    if pwr_table_11ax_he40:
        pwr_table_11ax_he40_hex = "0e000c00"
        for item in pwr_table_11ax_he40:
            item_hex = "%02x" % item
            pwr_table_11ax_he40_hex += item_hex
    else:
        pwr_table_11ax_he40_hex = ""

    if pwr_table_11ax_he80:
        pwr_table_11ax_he80_hex = "0f000c00"
        for item in pwr_table_11ax_he80:
            item_hex = "%02x" % item
            pwr_table_11ax_he80_hex += item_hex
    else:
        pwr_table_11ax_he80_hex = ""

    if pwr_table_11ax_he160:
        pwr_table_11ax_he160_hex = "10000c00"
        for item in pwr_table_11ax_he160:
            item_hex = "%02x" % item
            pwr_table_11ax_he160_hex += item_hex
    else:
        pwr_table_11ax_he160_hex = ""

    if pwr_offset_wifi:
        pwr_offset_wifi_hex = "08000e00"
        for item in pwr_offset_wifi:
            item_hex = "%02x" % item
            pwr_offset_wifi_hex += item_hex
    else:
        pwr_offset_wifi_hex = ""

    if pwr_offset_wifi_lp:
        pwr_offset_wifi_lp_hex = "11000e00"
        for item in pwr_offset_wifi_lp:
            item_hex = "%02x" % item
            pwr_offset_wifi_lp_hex += item_hex
    else:
        pwr_offset_wifi_lp_hex = ""

    if pwr_limit_2g_ch1:
        pwr_limit_2g_ch1_hex = "40000400"
        for item in pwr_limit_2g_ch1:
            item_hex = "%02x" % item
            pwr_limit_2g_ch1_hex += item_hex
    else:
        pwr_limit_2g_ch1_hex = ""

    if pwr_limit_2g_ch2:
        pwr_limit_2g_ch2_hex = "41000400"
        for item in pwr_limit_2g_ch2:
            item_hex = "%02x" % item
            pwr_limit_2g_ch2_hex += item_hex
    else:
        pwr_limit_2g_ch2_hex = ""

    if pwr_limit_2g_ch3:
        pwr_limit_2g_ch3_hex = "42000400"
        for item in pwr_limit_2g_ch3:
            item_hex = "%02x" % item
            pwr_limit_2g_ch3_hex += item_hex
    else:
        pwr_limit_2g_ch3_hex = ""

    if pwr_limit_2g_ch4:
        pwr_limit_2g_ch4_hex = "43000400"
        for item in pwr_limit_2g_ch4:
            item_hex = "%02x" % item
            pwr_limit_2g_ch4_hex += item_hex
    else:
        pwr_limit_2g_ch4_hex = ""

    if pwr_limit_2g_ch5:
        pwr_limit_2g_ch5_hex = "44000400"
        for item in pwr_limit_2g_ch5:
            item_hex = "%02x" % item
            pwr_limit_2g_ch5_hex += item_hex
    else:
        pwr_limit_2g_ch5_hex = ""

    if pwr_limit_2g_ch6:
        pwr_limit_2g_ch6_hex = "45000400"
        for item in pwr_limit_2g_ch6:
            item_hex = "%02x" % item
            pwr_limit_2g_ch6_hex += item_hex
    else:
        pwr_limit_2g_ch6_hex = ""

    if pwr_limit_2g_ch7:
        pwr_limit_2g_ch7_hex = "46000400"
        for item in pwr_limit_2g_ch7:
            item_hex = "%02x" % item
            pwr_limit_2g_ch7_hex += item_hex
    else:
        pwr_limit_2g_ch7_hex = ""

    if pwr_limit_2g_ch8:
        pwr_limit_2g_ch8_hex = "47000400"
        for item in pwr_limit_2g_ch8:
            item_hex = "%02x" % item
            pwr_limit_2g_ch8_hex += item_hex
    else:
        pwr_limit_2g_ch8_hex = ""

    if pwr_limit_2g_ch9:
        pwr_limit_2g_ch9_hex = "48000400"
        for item in pwr_limit_2g_ch9:
            item_hex = "%02x" % item
            pwr_limit_2g_ch9_hex += item_hex
    else:
        pwr_limit_2g_ch9_hex = ""

    if pwr_limit_2g_ch10:
        pwr_limit_2g_ch10_hex = "49000400"
        for item in pwr_limit_2g_ch10:
            item_hex = "%02x" % item
            pwr_limit_2g_ch10_hex += item_hex
    else:
        pwr_limit_2g_ch10_hex = ""

    if pwr_limit_2g_ch11:
        pwr_limit_2g_ch11_hex = "4a000400"
        for item in pwr_limit_2g_ch11:
            item_hex = "%02x" % item
            pwr_limit_2g_ch11_hex += item_hex
    else:
        pwr_limit_2g_ch11_hex = ""

    if pwr_limit_2g_ch12:
        pwr_limit_2g_ch12_hex = "4b000400"
        for item in pwr_limit_2g_ch12:
            item_hex = "%02x" % item
            pwr_limit_2g_ch12_hex += item_hex
    else:
        pwr_limit_2g_ch12_hex = ""

    if pwr_limit_2g_ch13:
        pwr_limit_2g_ch13_hex = "4c000400"
        for item in pwr_limit_2g_ch13:
            item_hex = "%02x" % item
            pwr_limit_2g_ch13_hex += item_hex
    else:
        pwr_limit_2g_ch13_hex = ""

    if pwr_limit_2g_ch14:
        pwr_limit_2g_ch14_hex = "4d000400"
        for item in pwr_limit_2g_ch14:
            item_hex = "%02x" % item
            pwr_limit_2g_ch14_hex += item_hex
    else:
        pwr_limit_2g_ch14_hex = ""

    if pwr_limit_2g_ext_ch1:
        pwr_limit_2g_ext_ch1_hex = "70000c00"
        for item in pwr_limit_2g_ext_ch1:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch1_hex += item_hex
    else:
        pwr_limit_2g_ext_ch1_hex = ""

    if pwr_limit_2g_ext_ch2:
        pwr_limit_2g_ext_ch2_hex = "71000c00"
        for item in pwr_limit_2g_ext_ch2:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch2_hex += item_hex
    else:
        pwr_limit_2g_ext_ch2_hex = ""

    if pwr_limit_2g_ext_ch3:
        pwr_limit_2g_ext_ch3_hex = "72000c00"
        for item in pwr_limit_2g_ext_ch3:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch3_hex += item_hex
    else:
        pwr_limit_2g_ext_ch3_hex = ""

    if pwr_limit_2g_ext_ch4:
        pwr_limit_2g_ext_ch4_hex = "73000c00"
        for item in pwr_limit_2g_ext_ch4:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch4_hex += item_hex
    else:
        pwr_limit_2g_ext_ch4_hex = ""

    if pwr_limit_2g_ext_ch5:
        pwr_limit_2g_ext_ch5_hex = "74000c00"
        for item in pwr_limit_2g_ext_ch5:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch5_hex += item_hex
    else:
        pwr_limit_2g_ext_ch5_hex = ""

    if pwr_limit_2g_ext_ch6:
        pwr_limit_2g_ext_ch6_hex = "75000c00"
        for item in pwr_limit_2g_ext_ch6:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch6_hex += item_hex
    else:
        pwr_limit_2g_ext_ch6_hex = ""

    if pwr_limit_2g_ext_ch7:
        pwr_limit_2g_ext_ch7_hex = "76000c00"
        for item in pwr_limit_2g_ext_ch7:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch7_hex += item_hex
    else:
        pwr_limit_2g_ext_ch7_hex = ""

    if pwr_limit_2g_ext_ch8:
        pwr_limit_2g_ext_ch8_hex = "77000c00"
        for item in pwr_limit_2g_ext_ch8:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch8_hex += item_hex
    else:
        pwr_limit_2g_ext_ch8_hex = ""

    if pwr_limit_2g_ext_ch9:
        pwr_limit_2g_ext_ch9_hex = "78000c00"
        for item in pwr_limit_2g_ext_ch9:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch9_hex += item_hex
    else:
        pwr_limit_2g_ext_ch9_hex = ""

    if pwr_limit_2g_ext_ch10:
        pwr_limit_2g_ext_ch10_hex = "79000c00"
        for item in pwr_limit_2g_ext_ch10:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch10_hex += item_hex
    else:
        pwr_limit_2g_ext_ch10_hex = ""

    if pwr_limit_2g_ext_ch11:
        pwr_limit_2g_ext_ch11_hex = "7a000c00"
        for item in pwr_limit_2g_ext_ch11:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch11_hex += item_hex
    else:
        pwr_limit_2g_ext_ch11_hex = ""

    if pwr_limit_2g_ext_ch12:
        pwr_limit_2g_ext_ch12_hex = "7b000c00"
        for item in pwr_limit_2g_ext_ch12:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch12_hex += item_hex
    else:
        pwr_limit_2g_ext_ch12_hex = ""

    if pwr_limit_2g_ext_ch13:
        pwr_limit_2g_ext_ch13_hex = "7c000c00"
        for item in pwr_limit_2g_ext_ch13:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch13_hex += item_hex
    else:
        pwr_limit_2g_ext_ch13_hex = ""

    if pwr_limit_2g_ext_ch14:
        pwr_limit_2g_ext_ch14_hex = "7d000c00"
        for item in pwr_limit_2g_ext_ch14:
            item_hex = "%02x" % item
            pwr_limit_2g_ext_ch14_hex += item_hex
    else:
        pwr_limit_2g_ext_ch14_hex = ""

    if en_tcal:
        en_tcal_hex = "20000100%02x" % en_tcal[0]
    else:
        en_tcal_hex = ""

    if linear_or_follow:
        linear_or_follow_hex = "21000100%02x" % linear_or_follow[0]
    else:
        linear_or_follow_hex = ""

    if tchannels:
        tchannels_hex = "22000a00"
        for item in tchannels:
            item_hex = little_endian("%04x" % item)
            tchannels_hex += item_hex
    else:
        tchannels_hex = ""

    if tchannel_os:
        tchannel_os_hex = "23000a00"
        for item in tchannel_os:
            item_hex = little_endian("%04x" % item)
            tchannel_os_hex += item_hex
    else:
        tchannel_os_hex = ""

    if tchannel_os_low:
        tchannel_os_low_hex = "24000a00"
        for item in tchannel_os_low:
            item_hex = little_endian("%04x" % item)
            tchannel_os_low_hex += item_hex
    else:
        tchannel_os_low_hex = ""

    if troom_os:
        troom_os_hex = "25000200" + little_endian("%04x" % troom_os[0])
    else:
        troom_os_hex = ""

    if pwr_table_ble:
        pwr_table_ble_hex = "30000400" + little_endian("%08x" % pwr_table_ble[0])
    else:
        pwr_table_ble_hex = ""

    if pwr_table_bt:
        pwr_table_bt_hex = "32000c00"
        for item in pwr_table_bt:
            item_hex = little_endian("%08x" % item)
            pwr_table_bt_hex += item_hex
    else:
        pwr_table_bt_hex = ""

    if pwr_table_zigbee:
        pwr_table_zigbee_hex = "33000400" + little_endian("%08x" % pwr_table_zigbee[0])
    else:
        pwr_table_zigbee_hex = ""

    if pwr_offset_bz:
        length = "%02x" % len(pwr_offset_bz)
        pwr_offset_bz_hex = "3100" + length + "00"
        for item in pwr_offset_bz:
            item_hex = "%02x" % item
            pwr_offset_bz_hex += item_hex
    else:
        pwr_offset_bz_hex = ""

    if country_code:
        if isinstance(country_code[0], int):
            country_code_hex = "50000200" + little_endian("%04x" % country_code[0])
        else:
            country_code_hex = "50000200" + string_to_bytearray(country_code[0]).hex()
    else:
        country_code_hex = ""

    if en_cap_temp:
        en_cap_temp_hex = "60000100%02x" % (en_cap_temp[0] % 256)
    else:
        en_cap_temp_hex = ""

    if cap_temp:
        cap_temp_hex = "61000a00"
        for item in cap_temp:
            item_hex = "%02x" % (item % 256)
            cap_temp_hex += item_hex
    else:
        cap_temp_hex = ""

    if capcode:
        capcode_hex = "62000b00"
        for item in capcode:
            item_hex = "%02x" % (item % 256)
            capcode_hex += item_hex
    else:
        capcode_hex = ""

    dts_hex = (
        init_hex
        + xtal_mode_hex
        + xtal_hex
        + pwr_mode_hex
        + pwr_table_11b_hex
        + pwr_table_11g_hex
        + pwr_table_11n_hex
        + pwr_offset_wifi_hex
        + pwr_offset_wifi_lp_hex
        + pwr_table_11n_ht20_hex
        + pwr_table_11n_ht40_hex
        + pwr_table_11ac_vht20_hex
        + pwr_table_11ac_vht40_hex
        + pwr_table_11ac_vht80_hex
        + pwr_table_11ax_he20_hex
        + pwr_table_11ax_he40_hex
        + pwr_table_11ax_he80_hex
        + pwr_table_11ax_he160_hex
        + en_tcal_hex
        + linear_or_follow_hex
        + tchannels_hex
        + tchannel_os_hex
        + tchannel_os_low_hex
        + troom_os_hex
        + pwr_table_ble_hex
        + pwr_offset_bz_hex
        + pwr_table_bt_hex
        + pwr_table_zigbee_hex
        + country_code_hex
        + en_cap_temp_hex
        + cap_temp_hex
        + capcode_hex
        + pwr_limit_2g_ch1_hex
        + pwr_limit_2g_ch2_hex
        + pwr_limit_2g_ch3_hex
        + pwr_limit_2g_ch4_hex
        + pwr_limit_2g_ch5_hex
        + pwr_limit_2g_ch6_hex
        + pwr_limit_2g_ch7_hex
        + pwr_limit_2g_ch8_hex
        + pwr_limit_2g_ch9_hex
        + pwr_limit_2g_ch10_hex
        + pwr_limit_2g_ch11_hex
        + pwr_limit_2g_ch12_hex
        + pwr_limit_2g_ch13_hex
        + pwr_limit_2g_ch14_hex
        + pwr_limit_2g_ext_ch1_hex
        + pwr_limit_2g_ext_ch2_hex
        + pwr_limit_2g_ext_ch3_hex
        + pwr_limit_2g_ext_ch4_hex
        + pwr_limit_2g_ext_ch5_hex
        + pwr_limit_2g_ext_ch6_hex
        + pwr_limit_2g_ext_ch7_hex
        + pwr_limit_2g_ext_ch8_hex
        + pwr_limit_2g_ext_ch9_hex
        + pwr_limit_2g_ext_ch10_hex
        + pwr_limit_2g_ext_ch11_hex
        + pwr_limit_2g_ext_ch12_hex
        + pwr_limit_2g_ext_ch13_hex
        + pwr_limit_2g_ext_ch14_hex
    )

    """
    dts_hex_little_end = ""
    for item in [dts_hex[i:i+8] for i in range(0, len(dts_hex), 8)]:
        dts_hex_little_end += little_endian(item.ljust(8, '0'))
    """
    return dts_hex
