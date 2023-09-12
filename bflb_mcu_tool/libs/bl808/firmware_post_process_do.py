# -*- coding:utf-8 -*-

import os
import sys
import hashlib
import binascii
import codecs

import ecdsa

from CryptoPlus.Cipher import AES as AES_XTS

from libs import bflb_utils
from libs.bflb_utils import img_create_sha256_data, img_create_encrypt_data
from libs.bflb_utils import img_create_decrypt_data

keyslot0 = 28
keyslot1 = keyslot0 + 16
keyslot2 = keyslot1 + 16
keyslot3 = keyslot2 + 16
keyslot3_end = keyslot3 + 16
keyslot4 = 128
keyslot5 = keyslot4 + 16
keyslot6 = keyslot5 + 16
keyslot7 = keyslot6 + 16
keyslot8 = keyslot7 + 16
keyslot9 = keyslot8 + 16
keyslot10 = keyslot9 + 16
keyslot10_end = keyslot10 + 16
keyslot11 = keyslot3_end + 16
keyslot11_end = keyslot11 + 16

wr_lock_boot_mode = 14
wr_lock_dbg_pwd = 15
wr_lock_wifi_mac = 16
wr_lock_key_slot_0 = 17
wr_lock_key_slot_1 = 18
wr_lock_key_slot_2 = 19
wr_lock_key_slot_3 = 20
wr_lock_sw_usage_0 = 21
wr_lock_sw_usage_1 = 22
wr_lock_sw_usage_2 = 23
wr_lock_sw_usage_3 = 24
wr_lock_key_slot_11 = 25
rd_lock_dbg_pwd = 26
rd_lock_key_slot_0 = 27
rd_lock_key_slot_1 = 28
rd_lock_key_slot_2 = 29
rd_lock_key_slot_3 = 30
rd_lock_key_slot_11 = 31

wr_lock_key_slot_4 = 15
wr_lock_key_slot_5 = 16
wr_lock_key_slot_6 = 17
wr_lock_key_slot_7 = 18
wr_lock_key_slot_8 = 19
wr_lock_key_slot_9 = 20
wr_lock_key_slot_10 = 21
rd_lock_key_slot_4 = 25
rd_lock_key_slot_5 = 26
rd_lock_key_slot_6 = 27
rd_lock_key_slot_7 = 28
rd_lock_key_slot_8 = 29
rd_lock_key_slot_9 = 30
rd_lock_key_slot_10 = 31


g_args=None

def bytearray_data_merge(data1, data2, len):
    for i in range(len):
        data1[i] |= data2[i]
    return data1

# update efuse info
def img_update_efuse_data(cfg,
                            sign,
                            pk_hash,
                            flash_encryp_type,
                            flash_key,
                            sec_eng_key_sel,
                            sec_eng_key,
                            security=False):
    if g_args and g_args.edatafile_in!=None:
        efuse_file_encrypted=g_args.edatafile_in
        with open(efuse_file_encrypted, 'rb') as fp:
            efuse_data = fp.read()
            fp.close()
        if len(efuse_data)>4096:
            bflb_utils.printf("Decrypt efuse data")
            efuse_save_crc = efuse_data[0:4]
            security_key, security_iv = bflb_utils.get_security_key()
            efuse_data = img_create_decrypt_data(efuse_data[4096:], security_key, security_iv, 0)
            efuse_crc = bflb_utils.get_crc32_bytearray(efuse_data)
            if efuse_crc != efuse_save_crc:
                bflb_utils.printf("Efuse crc check fail")
                return False
        efuse_data = bytearray(efuse_data)
        cfg, efuse_file_encrypted = os.path.split(efuse_file_encrypted)
        efuse_mask_data =  bytearray(256)
    else:
        efuse_file_encrypted="efusedata.bin"
        efuse_data = bytearray(256)
        efuse_mask_data =  bytearray(256)
    
    efuse_file_raw="efusedata_raw.bin"
    efuse_file_mask="efusedata_mask.bin"
    mask_4bytes = bytearray.fromhex("FFFFFFFF")

    # Set ef_sf_aes_mode
    if flash_encryp_type >= 3:
        efuse_data[0] |= 3
    else:
        efuse_data[0] |= flash_encryp_type
    # Set ef_sw_usage_0 --> sign_cfg
    if sign > 0:
        efuse_data[93] |= sign
        efuse_mask_data[93] |= 0xff
    # Set ef_sboot_en
    if flash_encryp_type > 0:
        efuse_data[0] |= 0x30
    efuse_mask_data[0] |= 0xff
    rw_lock0 = 0
    rw_lock1 = 0
    if pk_hash is not None:
        efuse_data[keyslot0:keyslot2] = pk_hash
        efuse_mask_data[keyslot0:keyslot2] = mask_4bytes * 8
        rw_lock0 |= (1 << wr_lock_key_slot_0)
        rw_lock0 |= (1 << wr_lock_key_slot_1)
    if flash_key is not None:
        if flash_encryp_type == 1:
            # aes 128
            efuse_data[keyslot2:keyslot3] = flash_key[0:16]
            efuse_mask_data[keyslot2:keyslot3] = mask_4bytes * 4
        elif flash_encryp_type == 2:
            # aes 192
            efuse_data[keyslot2:keyslot3_end] = flash_key[0:24]+bytearray(8)
            efuse_mask_data[keyslot2:keyslot3_end] = mask_4bytes * 8
            rw_lock0 |= (1 << wr_lock_key_slot_3)
            rw_lock0 |= (1 << rd_lock_key_slot_3)
        elif flash_encryp_type == 3:
            # aes 256
            efuse_data[keyslot2:keyslot3_end] = flash_key
            efuse_mask_data[keyslot2:keyslot3_end] = mask_4bytes * 8
            rw_lock0 |= (1 << wr_lock_key_slot_3)
            rw_lock0 |= (1 << rd_lock_key_slot_3)
        elif flash_encryp_type == 4 or \
             flash_encryp_type == 5 or \
             flash_encryp_type == 6:
            # aes xts 128/192/256
            efuse_data[keyslot2:keyslot3_end] = flash_key
            efuse_mask_data[keyslot2:keyslot3_end] = mask_4bytes * 8
            rw_lock0 |= (1 << wr_lock_key_slot_3)
            rw_lock0 |= (1 << rd_lock_key_slot_3)

        rw_lock0 |= (1 << wr_lock_key_slot_2)
        rw_lock0 |= (1 << rd_lock_key_slot_2)

    if sec_eng_key is not None:
        if flash_encryp_type == 0:
            if sec_eng_key_sel == 0:
                efuse_data[keyslot2:keyslot3] = sec_eng_key[16:32]
                efuse_data[keyslot3:keyslot3_end] = sec_eng_key[0:16]
                efuse_mask_data[keyslot2:keyslot3_end] = mask_4bytes * 8
                rw_lock0 |= (1 << wr_lock_key_slot_2)
                rw_lock0 |= (1 << wr_lock_key_slot_3)
                rw_lock0 |= (1 << rd_lock_key_slot_2)
                rw_lock0 |= (1 << rd_lock_key_slot_3)
            if sec_eng_key_sel == 1:
                efuse_data[keyslot3:keyslot3_end] = sec_eng_key[16:32]
                efuse_data[keyslot4:keyslot5] = sec_eng_key[0:16]
                efuse_mask_data[keyslot3:keyslot3_end] = mask_4bytes * 4
                efuse_mask_data[keyslot4:keyslot5] = mask_4bytes * 4
                rw_lock0 |= (1 << wr_lock_key_slot_3)
                rw_lock1 |= (1 << wr_lock_key_slot_4)
                rw_lock0 |= (1 << rd_lock_key_slot_3)
                rw_lock1 |= (1 << rd_lock_key_slot_4)
            if sec_eng_key_sel == 2:
                efuse_data[keyslot4:keyslot5] = sec_eng_key[16:32]
                efuse_data[keyslot2:keyslot3] = sec_eng_key[0:16]
                efuse_mask_data[keyslot3:keyslot5] = mask_4bytes * 8
                rw_lock1 |= (1 << wr_lock_key_slot_4)
                rw_lock0 |= (1 << wr_lock_key_slot_2)
                rw_lock1 |= (1 << rd_lock_key_slot_4)
                rw_lock0 |= (1 << rd_lock_key_slot_2)
            if sec_eng_key_sel == 3:
                efuse_data[keyslot4:keyslot5] = sec_eng_key[16:32]
                efuse_data[keyslot2:keyslot3] = sec_eng_key[0:16]
                efuse_mask_data[keyslot3:keyslot5] = mask_4bytes * 8
                rw_lock1 |= (1 << wr_lock_key_slot_4)
                rw_lock0 |= (1 << wr_lock_key_slot_2)
                rw_lock1 |= (1 << rd_lock_key_slot_4)
                rw_lock0 |= (1 << rd_lock_key_slot_2)
        if flash_encryp_type == 1:
            if sec_eng_key_sel == 0:
                efuse_data[keyslot5:keyslot6] = sec_eng_key[0:16]
                efuse_mask_data[keyslot5:keyslot6] = mask_4bytes * 4
                rw_lock1 |= (1 << wr_lock_key_slot_5)
                rw_lock1 |= (1 << rd_lock_key_slot_5)
            if sec_eng_key_sel == 1:
                efuse_data[keyslot4:keyslot5] = sec_eng_key[0:16]
                efuse_mask_data[keyslot4:keyslot5] = mask_4bytes * 4
                rw_lock1 |= (1 << wr_lock_key_slot_4)
                rw_lock1 |= (1 << rd_lock_key_slot_4)
            if sec_eng_key_sel == 2:
                if flash_key is not None:
                    # Sec eng use xip key
                    pass
                else:
                    efuse_data[keyslot3:keyslot3_end] = sec_eng_key[0:16]
                    efuse_mask_data[keyslot3:keyslot3_end] = mask_4bytes * 4
                    rw_lock0 |= (1 << wr_lock_key_slot_3)
                    rw_lock0 |= (1 << rd_lock_key_slot_3)
            if sec_eng_key_sel == 3:
                if flash_key is not None:
                    # Sec eng use xip key
                    pass
                else:
                    efuse_data[keyslot2:keyslot3] = sec_eng_key[0:16]
                    efuse_mask_data[keyslot2:keyslot3] = mask_4bytes * 4
                    rw_lock0 |= (1 << wr_lock_key_slot_2)
                    rw_lock0 |= (1 << rd_lock_key_slot_2)
        if flash_encryp_type == 2 or \
           flash_encryp_type == 3 or \
           flash_encryp_type == 4 or \
           flash_encryp_type == 5 or \
           flash_encryp_type == 6:
            if sec_eng_key_sel == 0:
                efuse_data[keyslot6:keyslot7] = sec_eng_key[16:32]
                efuse_data[keyslot10:keyslot10_end] = sec_eng_key[0:16]
                efuse_mask_data[keyslot6:keyslot7] = mask_4bytes * 4
                efuse_mask_data[keyslot10:keyslot10_end] = mask_4bytes * 4
                rw_lock1 |= (1 << wr_lock_key_slot_6)
                rw_lock1 |= (1 << wr_lock_key_slot_10)
                rw_lock1 |= (1 << rd_lock_key_slot_6)
                rw_lock1 |= (1 << rd_lock_key_slot_10)
            if sec_eng_key_sel == 1:
                efuse_data[keyslot10:keyslot10_end] = sec_eng_key[16:32]
                efuse_data[keyslot6:keyslot7] = sec_eng_key[0:16]
                efuse_mask_data[keyslot6:keyslot7] = mask_4bytes * 4
                efuse_mask_data[keyslot10:keyslot10_end] = mask_4bytes * 4
                rw_lock1 |= (1 << wr_lock_key_slot_6)
                rw_lock1 |= (1 << wr_lock_key_slot_10)
                rw_lock1 |= (1 << rd_lock_key_slot_6)
                rw_lock1 |= (1 << rd_lock_key_slot_10)
            if sec_eng_key_sel == 2:
                if flash_key is not None:
                    # Sec eng use xip key
                    pass
                else:
                    efuse_data[keyslot2:keyslot3] = sec_eng_key[16:32]
                    efuse_data[keyslot3:keyslot3_end] = sec_eng_key[0:16]
                    efuse_mask_data[keyslot2:keyslot3_end] = mask_4bytes * 8
                    rw_lock0 |= (1 << wr_lock_key_slot_2)
                    rw_lock0 |= (1 << rd_lock_key_slot_2)
                    rw_lock0 |= (1 << wr_lock_key_slot_3)
                    rw_lock0 |= (1 << rd_lock_key_slot_3)
            if sec_eng_key_sel == 3:
                if flash_key is not None:
                    # Sec eng use xip key
                    pass
                else:
                    efuse_data[keyslot2:keyslot3_end] = sec_eng_key
                    efuse_mask_data[keyslot2:keyslot3_end] = mask_4bytes * 8
                    rw_lock0 |= (1 << wr_lock_key_slot_2)
                    rw_lock0 |= (1 << rd_lock_key_slot_2)
                    rw_lock0 |= (1 << wr_lock_key_slot_3)
                    rw_lock0 |= (1 << rd_lock_key_slot_3)
    # set read write lock key
    efuse_data[124:128] = bytearray_data_merge(efuse_data[124:128],\
                                               bflb_utils.int_to_4bytearray_l(rw_lock0), 4)
    efuse_mask_data[124:128] = bytearray_data_merge(efuse_mask_data[124:128],\
                                               bflb_utils.int_to_4bytearray_l(rw_lock0), 4)
    efuse_data[252:256] = bytearray_data_merge(efuse_data[252:256],\
                                               bflb_utils.int_to_4bytearray_l(rw_lock1), 4)
    efuse_mask_data[252:256] = bytearray_data_merge(efuse_mask_data[252:256],\
                                               bflb_utils.int_to_4bytearray_l(rw_lock1), 4)
    #feature specified efuse 
    if g_args!=None:
        if g_args.dbg_mode=="pswd":
            efuse_data[3]|=(0x3<<4)
        if g_args.dbg_mode=="close":
            efuse_data[3]|=(0xf<<4)
        if g_args.jtag_close=="true":
            efuse_data[3]|=(0xf)
        if g_args.pswd!=None:
            pswd=bytearray.fromhex(g_args.pswd)
            if len(pswd)!=16:
                bflb_utils.printf("Password len should be 16 bytes")
                sys.exit()
            efuse_data[4:4+len(pswd)]=pswd
        if g_args.hbn_jump=="false":
            efuse_data[0x5C+3]|=(1<<7)
        if g_args.hbn_sign=="true":
            efuse_data[0x5C+3]|=(1<<5)
        if g_args.flash_pdelay!=None:
            efuse_data[0x5C+3]|=((int(g_args.flash_pdelay)&0x3))
        if g_args.edata!=None:
            edata_array=g_args.edata.split(";")
            for edata_item in edata_array:
                data_list=edata_item.split(",")
                start=int(data_list[0],16)
                if len(data_list[1])%2 != 0:
                    bflb_utils.printf("[Error]:edata hex_str not correct hexadecimal string")
                    sys.exit()
                content=bytearray.fromhex(data_list[1])
                data_len=len(content)
                efuse_data[start:start+data_len]=bytearray_data_merge(efuse_data[start:start+data_len],content,data_len)

    if security is True:
        fp = open(os.path.join(cfg,efuse_file_raw), 'wb+')
        fp.write(efuse_data)
        fp.close()
        bflb_utils.printf("Encrypt efuse data")
        efuse_crc = bflb_utils.get_crc32_bytearray(efuse_data)
        security_key, security_iv = bflb_utils.get_security_key()
        efuse_data = img_create_encrypt_data(efuse_data, security_key, security_iv, 0)
        efuse_data = bytearray(4096) + efuse_data
        efuse_data[0:4] = efuse_crc
    fp = open(os.path.join(cfg,efuse_file_encrypted), 'wb+')
    fp.write(efuse_data)
    fp.close()
    fp = open(os.path.join(cfg,efuse_file_mask), 'wb+')
    fp.write(efuse_mask_data)
    fp.close()

# sign image(hash code)
def img_create_sign_data(data_bytearray, privatekey, publickey):
    sk = ecdsa.SigningKey.from_pem(privatekey)
    if publickey!=None:
        vk = ecdsa.VerifyingKey.from_pem(publickey)
    else:
        bflb_utils.printf("Get Public key from private key")
        vk = sk.get_verifying_key()
    pk_data = vk.to_string()
    #bflb_utils.printf("Private key: ", binascii.hexlify(sk.to_string()))
    bflb_utils.printf("Public key: ", binascii.hexlify(pk_data))
    pk_hash = img_create_sha256_data(pk_data)
    bflb_utils.printf("Public key hash=", binascii.hexlify(pk_hash))
    signature = sk.sign(data_bytearray,
                        hashfunc=hashlib.sha256,
                        sigencode=ecdsa.util.sigencode_string)
    bflb_utils.printf("Signature=", binascii.hexlify(signature))
    # return len+signature+crc
    len_array = bflb_utils.int_to_4bytearray_l(len(signature))
    sig_field = len_array + signature
    crcarray = bflb_utils.get_crc32_bytearray(sig_field)
    return pk_data, pk_hash, sig_field + crcarray

def reverse_str_data_unit_number(str_data_unit_number):
    '''
    high position low data
    data unit number:00000280
    storage format:  80020000
    '''
    reverse_str = ''
    if len(str_data_unit_number) == 8:
        str_part1 = str_data_unit_number[0:2]
        str_part2 = str_data_unit_number[2:4]
        str_part3 = str_data_unit_number[4:6]
        str_part4 = str_data_unit_number[6:8]
        reverse_str = str_part4 + str_part3 + str_part2 + str_part1
    return reverse_str

def reverse_iv(need_reverse_iv_bytearray):
    temp_reverse_iv_bytearray = binascii.hexlify(need_reverse_iv_bytearray).decode()
    if temp_reverse_iv_bytearray[24:32] != '00000000':
        bflb_utils.printf(
            "The lower 4 bytes of IV should be set 0, if set IV is less than 16 bytes, make up 0 for the low 4 bytes of IV "
        )
        sys.exit()
    reverse_iv_bytearray = '00000000' + temp_reverse_iv_bytearray[0:24]
    return reverse_iv_bytearray

def img_create_encrypt_data_xts(data_bytearray, key_bytearray, iv_bytearray, encrypt):
    counter = binascii.hexlify(iv_bytearray[4:16]).decode()
    # data unit number default value is 0
    data_unit_number = 0

    key = (key_bytearray[0:16], key_bytearray[16:32])
    if encrypt == 2 or encrypt == 3:
        key = (key_bytearray, key_bytearray)
    # bflb_utils.printf(key)
    cipher = AES_XTS.new(key, AES_XTS.MODE_XTS)
    total_len = len(data_bytearray)
    ciphertext = bytearray(0)
    deal_len = 0

    while deal_len < total_len:
        data_unit_number = str(hex(data_unit_number)).replace("0x", "")
        data_unit_number_to_str = str(data_unit_number)
        right_justify_str = data_unit_number_to_str.rjust(8, '0')
        reverse_data_unit_number_str = reverse_str_data_unit_number(right_justify_str)
        tweak = reverse_data_unit_number_str + counter
        tweak = bflb_utils.hexstr_to_bytearray("0" * (32 - len(tweak)) + tweak)
        # bflb_utils.printf(tweak)
        if 32 + deal_len <= total_len:
            cur_block = data_bytearray[0 + deal_len:32 + deal_len]
            # bflb_utils.printf(binascii.hexlify(cur_block))
            ciphertext += cipher.encrypt(cur_block, tweak)
        else:
            cur_block = data_bytearray[0 + deal_len:16 + deal_len] + bytearray(16)
            # bflb_utils.printf(binascii.hexlify(cur_block))
            ciphertext += (cipher.encrypt(cur_block, tweak)[0:16])
        deal_len += 32
        data_unit_number = (int(data_unit_number, 16))
        data_unit_number += 1

    # bflb_utils.printf("Result:")
    # bflb_utils.printf(binascii.hexlify(ciphertext))

    return ciphertext

def firmware_post_get_flash_encrypt_type(encrypt,xts_mode):    
    flash_encrypt_type = 0
    if encrypt != 0:
        if encrypt == 1:
            # AES 128
            flash_encrypt_type = 1
        if encrypt == 2:
            # AES 256
            flash_encrypt_type = 3
        if encrypt == 3:
            # AES 192
            flash_encrypt_type = 2
        if xts_mode == 1:
            # AES XTS mode
            flash_encrypt_type += 3
    return flash_encrypt_type

def firmware_post_proc_do_encrypt(data_bytearray,aeskey_hexstr,aesiv_hexstr,xts_mode,privatekey, publickey,imgfile):
    flash_img=1
    bootcfg_start=8+4+84+4+4+20+4
    segheader = bytearray(0)
    xip_addr=bflb_utils.bytearray_reverse(data_bytearray[0xC0:0xC4])
    if bflb_utils.bytearray_to_int(xip_addr)!=0x00 and \
       bflb_utils.bytearray_to_int(xip_addr)!=0x58000000:
        flash_img=0
        if data_bytearray[0x160+12:0x160+16]!=bflb_utils.get_crc32_bytearray(data_bytearray[0x160+0:0x160+12]):
            bflb_utils.printf("[Error]:This image maybe has already been dealed(wrong segheader crc32 found)")
            sys.exit()
    if data_bytearray[0x160+4:0x160+8] == b'SEGH':
        flash_img=0

    if flash_img:
        bflb_utils.printf("Flash  Image")
        #get image offset
        image_offset=firmware_post_proc_get_image_offset(data_bytearray)
        bflb_utils.printf("Image Offset:"+hex(image_offset))
        image_data=data_bytearray[image_offset:len(data_bytearray)]
        boot_data=data_bytearray[0:image_offset]
    else:
        bflb_utils.printf("RAM  Image")
        #clock cfg flag invalid
        data_bytearray[0x64:0x68]=bytearray(4)
        #flash cfg flag invalid
        data_bytearray[0x8:0xC]=bytearray(4)
        image_data=data_bytearray[0x160+16:]
        segheader=data_bytearray[0x160:0x160+16]
        boot_data=data_bytearray[0:0x160]

        #update boot entry and len
        boot_data[0xC0:0xC4]=segheader[0:4]
        segheader[4:8]=bflb_utils.int_to_4bytearray_l(len(image_data))
        segheader[8:12]=bflb_utils.get_crc32_bytearray(image_data)
        segheader[12:16]=bflb_utils.get_crc32_bytearray(segheader[0:12])

    if aeskey_hexstr!=None:
        bflb_utils.printf("Image need encryption")
        if  aesiv_hexstr== None:
            bflb_utils.printf("[Error] AES IV not given, skip encryption")
            return data_bytearray,None,flash_img

    #get xts mode 
    if xts_mode!=None:
        xts_mode=int(xts_mode)
    else:
        xts_mode=0
    if xts_mode == 1:
        if len(aeskey_hexstr)!=64:
            bflb_utils.printf("[Error] Key len must be 32 when xts mode enabled!!!!")
            return data_bytearray,None,flash_img
        else:
            bflb_utils.printf("Enable xts mode")

    data_tohash = bytearray(0)

    aesiv_data= bytearray(0)
    encrypt=0
    encrypt_key=None    
    flash_encrypt_key=None
    sec_eng_encrypt_key=None
    if aeskey_hexstr!=None:
        data_toencrypt = bytearray(0)
        # get aeskey
        aeskey_bytearray=bflb_utils.hexstr_to_bytearray(aeskey_hexstr)
        if len(aeskey_bytearray)!=32 and len(aeskey_bytearray)!=24 and len(aeskey_bytearray)!=16:
            bflb_utils.printf("Key length error")
            return data_bytearray,None,flash_img

        if len(aeskey_bytearray)==16:
            encrypt = 1
        elif len(aeskey_bytearray)==32:
            if xts_mode == 1:
                encrypt=1
            else:
                encrypt = 2
        elif len(aeskey_bytearray)==24:
            encrypt = 3
        encrypt_key = aeskey_bytearray
        #bflb_utils.printf("Key= ", binascii.hexlify(encrypt_key))
        boot_data[bootcfg_start] |=((encrypt<<2)+(xts_mode<<6))

        # get IV
        iv_value = aesiv_hexstr
        if xts_mode == 1:
            iv_value = iv_value[24:32] + iv_value[:24]
        encrypt_iv = bflb_utils.hexstr_to_bytearray(iv_value)
        iv_crcarray = bflb_utils.get_crc32_bytearray(encrypt_iv)
        aesiv_data = encrypt_iv + iv_crcarray

        data_tohash +=aesiv_data
        data_toencrypt +=image_data

        unencrypt_mfg_data = bytearray(0)
        if len(data_toencrypt) >= 0x2000:
            if data_toencrypt[0x1000:0x1004] == bytearray("0mfg".encode("utf-8")):
                unencrypt_mfg_data = data_toencrypt[0x1000:0x2000]

        if xts_mode != 0:
            # encrypt_iv = codecs.decode(reverse_iv(encrypt_iv), 'hex')
            image_data = img_create_encrypt_data_xts(segheader+data_toencrypt, encrypt_key, encrypt_iv,
                                                            encrypt)
        else:
            image_data = img_create_encrypt_data(segheader+data_toencrypt, encrypt_key, encrypt_iv,
                                                        flash_img)
        if unencrypt_mfg_data != bytearray(0):
            image_data = image_data[0:0x1000+len(segheader)] + unencrypt_mfg_data + image_data[0x2000+len(segheader):]

        data_tohash += image_data
    else:
        image_data=segheader+image_data
        data_tohash += image_data

    # hash fw img
    hash = img_create_sha256_data(data_tohash)
    bflb_utils.printf("Image hash is ", binascii.hexlify(hash))

    #get signature
    pk_data=bytearray(0)
    signature=bytearray(0)
    sign=0
    pk_hash=None
    if privatekey!=None:
        pk_data, pk_hash, signature = img_create_sign_data(data_tohash, privatekey,
                                                           publickey)
        pk_data = pk_data + bflb_utils.get_crc32_bytearray(pk_data)
        boot_data[bootcfg_start] |=(1<<0)
        sign=1
    elif publickey!=None:
        #maybe dump public key only
        vk = ecdsa.VerifyingKey.from_pem(publickey)
        pk_data = vk.to_string()
        bflb_utils.printf("Public key: ", binascii.hexlify(pk_data))
        pk_hash = img_create_sha256_data(pk_data)
        bflb_utils.printf("Public key hash=", binascii.hexlify(pk_hash))
        sign=1
        bflb_utils.printf("Image not sign!!!")
    
    if flash_img:
        pk_sig_len=len(pk_data+pk_data+signature+signature)
        boot_data[352:352+pk_sig_len]=pk_data+pk_data+signature+signature
        boot_data[352+pk_sig_len:352+pk_sig_len+len(aesiv_data)]=aesiv_data
    else:
        boot_data+=(pk_data+pk_data+signature+signature)
        boot_data+=aesiv_data    

    #save efuse data
    filedir, ext = os.path.split(imgfile)
    flash_encrypt_type=firmware_post_get_flash_encrypt_type(encrypt,xts_mode)
    key_sel=0
    security=True
    if flash_img:
        flash_encrypt_key=encrypt_key
    else:
        sec_eng_encrypt_key=encrypt_key

    img_update_efuse_data(filedir, sign, pk_hash, flash_encrypt_type, flash_encrypt_key , \
                                key_sel, sec_eng_encrypt_key, security)
    return boot_data+image_data,hash,flash_img

def firmware_post_proc_update_flash_crc(image_data):
    flash_cfg_start=8
    crcarray = bflb_utils.get_crc32_bytearray(image_data[flash_cfg_start+4:flash_cfg_start+4+84])
    image_data[flash_cfg_start+4+84:flash_cfg_start+4+84+4] = crcarray
    bflb_utils.printf("Flash config crc: ", binascii.hexlify(crcarray))
    return image_data

def firmware_post_proc_update_clock_crc(image_data):
    clockcfg_start=8+4+84+4
    crcarray = bflb_utils.get_crc32_bytearray(image_data[clockcfg_start+4:clockcfg_start+24])
    image_data[clockcfg_start+24:clockcfg_start+24+4] = crcarray
    bflb_utils.printf("Clock config crc: ", binascii.hexlify(crcarray))
    return image_data

def firmware_post_proc_update_bootheader_crc(image_data):
    crcarray = bflb_utils.get_crc32_bytearray(image_data[0:348])
    image_data[348:348+4] = crcarray
    bflb_utils.printf("Bootheader config crc: ", binascii.hexlify(crcarray))
    return image_data

# get hash ignore ignore
def firmware_post_proc_get_hash_ignore(image_data):
    bootcfg_start=(4+4)+(4+84+4)+(4+20+4)
    return  (image_data[bootcfg_start + 2] >> 1) & 0x1

# get hash ignore ignore
def firmware_post_proc_enable_hash_cfg(image_data):
    bootcfg_start=(4+4)+(4+84+4)+(4+20+4)
    image_data[bootcfg_start + 2]&=(~0x02)
    return  image_data

# get image offset
def firmware_post_proc_get_image_offset(image_data):
    cpucfg_start=(4+4)+(4+84+4)+(4+20+4)+4
    return  ((image_data[cpucfg_start + 0])+
             (image_data[cpucfg_start + 1]<<8) +
             (image_data[cpucfg_start + 2]<<16) +
             (image_data[cpucfg_start + 3]<<24) )

def firmware_post_proc_update_hash(image_data,force_update,args,hash,flash_img):
    #get image offset
    image_offset=firmware_post_proc_get_image_offset(image_data)
    bflb_utils.printf("Image Offset:"+hex(image_offset))
    #udpate image len
    bootcfg_start=(4+4)+(4+84+4)+(4+20+4)
    if flash_img:
        image_data[bootcfg_start+12 :bootcfg_start +12+4]=bflb_utils.int_to_4bytearray_l(len(image_data)-image_offset)
    else:
        image_data[bootcfg_start+12 :bootcfg_start +12+4]=bflb_utils.int_to_4bytearray_l(1)
    #add apeend data
    if args.hd_append!=None:
        bflb_utils.printf("Append bootheader data")
        bh_append_data=firmware_get_file_data(args.hd_append)
        if len(bh_append_data)<=image_offset-512:
            image_data[image_offset-len(bh_append_data):image_offset]=bh_append_data
        else:
            bflb_utils.printf("Append data is too long,not append!!!!!!",len(bh_append_data))
    #udpate hash
    if firmware_post_proc_get_hash_ignore(image_data) ==1:
        if force_update==False:
            bflb_utils.printf("Image hash ignore,not calculate")
            return image_data
    image_data=firmware_post_proc_enable_hash_cfg(image_data)
    if hash==None:
        hash = img_create_sha256_data(image_data[image_offset:len(image_data)])
        bflb_utils.printf("Image hash:",binascii.hexlify(hash))
    image_data[bootcfg_start + 16:bootcfg_start + 16+32]=hash
    
    return image_data

def firmware_get_file_data(file):
    with open(file, 'rb') as fp:
        data = fp.read()
    return bytearray(data)

def firmware_save_file_data(file,data):
    datas = []
    with open(file, 'wb+') as fp:
        fp.write(data)
        fp.close()

def firmware_get_ecc_key_whole_str(key_str):
    n = 64
    list_sk = [key_str[i:i+n] for i in range(0, len(key_str), n)]
    str_sk = "-----BEGIN EC PRIVATE KEY-----\n"
    for item in list_sk:
        str_sk = str_sk + item + "\n"
    str_sk = str_sk + "-----END EC PRIVATE KEY-----\n"
    return str_sk

def add_user_key(args):
    global g_args
    g_args=args
    filedir, ext = os.path.split(args.datafile)
    #deal edata input
    img_update_efuse_data(filedir, 0, None, 0, None, 0, None, True)

    #deal aes key using edata
    if args.aeskeyoffset!=None:
        g_args.edata=args.aeskeyoffset+","+args.aeskey
    else:
        g_args.edata="0x4c,"+args.aeskey+";0x7c,00001040"
    img_update_efuse_data(filedir, 0, None, 0, None, 0, None, True)

def firmware_post_proc(args):
    global g_args
    g_args=args
    bflb_utils.printf("========= sp image create =========")

    image_data=firmware_get_file_data(args.imgfile)
    if len(image_data)%16 !=0:
        image_data=image_data+bytearray(16-len(image_data)%16)

    img_hash=None
    image_data=firmware_post_proc_update_flash_crc(image_data)
    image_data=firmware_post_proc_update_clock_crc(image_data)
    #get publickey and private key whole string 
    privatekey=None
    publickey=None
    if args.privatekey!=None:
        privatekey=open(args.privatekey).read()
    if args.publickey!=None:
        publickey=open(args.publickey).read()
    if args.privatekey_str!=None:
        privatekey=firmware_get_ecc_key_whole_str(args.privatekey_str)
    if args.publickey_str!=None:
        publickey=firmware_get_ecc_key_whole_str(args.publickey_str)
    #do encrypt and sign
    image_data,img_hash,flash_img=firmware_post_proc_do_encrypt(image_data,args.aeskey,args.aesiv,args.xtsmode,privatekey,publickey,args.imgfile)
    if privatekey!=None:
        image_data=firmware_post_proc_update_hash(image_data,True,args,img_hash,flash_img)
    else:
        image_data=firmware_post_proc_update_hash(image_data,False,args,img_hash,flash_img)

    image_data=firmware_post_proc_update_bootheader_crc(image_data)
    firmware_save_file_data(args.imgfile,image_data)


if __name__ == '__main__':
    data_bytearray = codecs.decode(
        '42464E500100000046434647040101036699FF039F00B7E904EF0001C72052D8' +
        '060232000B010B013B01BB006B01EB02EB02025000010001010002010101AB01' +
        '053500000131000038FF20FF77030240770302F02C01B004B0040500FFFF0300' +
        '36C3DD9E5043464704040001010105000101050000010101A612AC8600014465' +
        '0020000000000000503100007A6345494BCABEC7307FD8F8396729EB67DDC8C6' +
        '3B7AD69B797B08564E982A8701000000000000000000000000000000000000D8' +
        '0000000000010000000000000000000000200100000001D80000000000010000' +
        '0000000000000000002002000000025800000000000100000000000000000000' +
        '00200300000003580000000000010000D0C57503C09E75030020040000000458' +
        '0000000000000000000000000000000000000000000000000000000000000000' +
        '0000000000000000000000000000000000000000000000000000000000000000' +
        '00000000000000000000000000000000000000000000000000000000935F92BB', 'hex')
    key_bytearray = codecs.decode(
        'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0000102030405060708090a0b0c0d0e0f', 'hex')
    #key = (codecs.decode('00112233445566778899AABBCCDDEEFF', 'hex'), codecs.decode('112233445566778899AABBCCDDEEFF00', 'hex'))
    need_reverse_iv_bytearray = codecs.decode('01000000000000000000000000000000', 'hex')
    iv_bytearray = codecs.decode(reverse_iv(need_reverse_iv_bytearray), 'hex')
    #iv_bytearray = codecs.decode('000000000000000000000000000000000', 'hex')
    img_create_encrypt_data_xts(data_bytearray, key_bytearray, iv_bytearray, 0)
