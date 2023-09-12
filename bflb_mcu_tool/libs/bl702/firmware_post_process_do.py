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
keyslot4 = keyslot3 + 16
keyslot5 = keyslot4 + 16
keyslot6 = keyslot5 + 16

wr_lock_key_slot_4_l = 13
wr_lock_key_slot_5_l = 14
wr_lock_boot_mode = 15
wr_lock_dbg_pwd = 16
wr_lock_sw_usage_0 = 17
wr_lock_wifi_mac = 18
wr_lock_key_slot_0 = 19
wr_lock_key_slot_1 = 20
wr_lock_key_slot_2 = 21
wr_lock_key_slot_3 = 22
wr_lock_key_slot_4_h = 23
wr_lock_key_slot_5_h = 24
rd_lock_dbg_pwd = 25
rd_lock_key_slot_0 = 26
rd_lock_key_slot_1 = 27
rd_lock_key_slot_2 = 28
rd_lock_key_slot_3 = 29
rd_lock_key_slot_4 = 30
rd_lock_key_slot_5 = 31

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
        efuse_mask_data =  bytearray(128)
    else:
        efuse_file_encrypted="efusedata.bin"
        efuse_data = bytearray(128)
        efuse_mask_data =  bytearray(128)
    
    efuse_file_raw="efusedata_raw.bin"
    efuse_file_mask="efusedata_mask.bin"

    mask_4bytes = bytearray.fromhex("FFFFFFFF")

    efuse_data[0] |= flash_encryp_type
    efuse_data[0] |= (sign << 2)
    # efuse_data[1] |= (sec_eng_key_sel << 4)
    if flash_encryp_type > 0:
        efuse_data[0] |= 0x80
        efuse_data[0] |= 0x30
    efuse_mask_data[0] |= 0xff
    rw_lock = 0
    if pk_hash is not None:
        efuse_data[keyslot0:keyslot2] = pk_hash
        efuse_mask_data[keyslot0:keyslot2] = mask_4bytes * 8
        rw_lock |= (1 << wr_lock_key_slot_0)
        rw_lock |= (1 << wr_lock_key_slot_1)
    if flash_key is not None:
        if flash_encryp_type == 1:
            # aes 128
            efuse_data[keyslot2:keyslot3] = flash_key[0:16]
            efuse_mask_data[keyslot2:keyslot3] = mask_4bytes * 4
        elif flash_encryp_type == 2:
            # aes 192
            efuse_data[keyslot2:keyslot4] = flash_key[0:24]+bytearray(8)
            efuse_mask_data[keyslot2:keyslot4] = mask_4bytes * 8
            rw_lock |= (1 << wr_lock_key_slot_3)
            rw_lock |= (1 << rd_lock_key_slot_3)
        elif flash_encryp_type == 3:
            # aes 256
            efuse_data[keyslot2:keyslot4] = flash_key
            efuse_mask_data[keyslot2:keyslot4] = mask_4bytes * 8
            rw_lock |= (1 << wr_lock_key_slot_3)
            rw_lock |= (1 << rd_lock_key_slot_3)

        rw_lock |= (1 << wr_lock_key_slot_2)
        rw_lock |= (1 << rd_lock_key_slot_2)

    if sec_eng_key is not None:
        if flash_encryp_type == 0:
            if sec_eng_key_sel == 0:
                efuse_data[keyslot3:keyslot4] = sec_eng_key[0:16]
                efuse_mask_data[keyslot3:keyslot4] = mask_4bytes * 4
                rw_lock |= (1 << wr_lock_key_slot_3)
                rw_lock |= (1 << rd_lock_key_slot_3)
            if sec_eng_key_sel == 1:
                efuse_data[keyslot2:keyslot3] = sec_eng_key[0:16]
                efuse_mask_data[keyslot2:keyslot3] = mask_4bytes * 4
                rw_lock |= (1 << wr_lock_key_slot_2)
                rw_lock |= (1 << rd_lock_key_slot_2)
        if flash_encryp_type == 1:
            if sec_eng_key_sel == 0:
                efuse_data[keyslot5:keyslot6] = sec_eng_key[0:16]
                efuse_mask_data[keyslot5:keyslot6] = mask_4bytes * 4
                rw_lock |= (1 << wr_lock_key_slot_5_l)
                rw_lock |= (1 << wr_lock_key_slot_5_h)
                rw_lock |= (1 << rd_lock_key_slot_5)
            if sec_eng_key_sel == 1:
                efuse_data[keyslot4:keyslot5] = sec_eng_key[0:16]
                efuse_mask_data[keyslot4:keyslot5] = mask_4bytes * 4
                rw_lock |= (1 << wr_lock_key_slot_4_l)
                rw_lock |= (1 << wr_lock_key_slot_4_h)
                rw_lock |= (1 << rd_lock_key_slot_4)
    # set read write lock key
    efuse_data[124:128] = bytearray_data_merge( efuse_data[124:128], bflb_utils.int_to_4bytearray_l(rw_lock), 4)
    efuse_mask_data[124:128] = bytearray_data_merge( efuse_data[124:128], bflb_utils.int_to_4bytearray_l(rw_lock), 4)
    
    #feature specified efuse 
    if g_args!=None:
        if g_args.dbg_mode=="pswd":
            efuse_data[3]|=(0x3<<4)
        if g_args.dbg_mode=="close":
            efuse_data[3]|=(0xf<<4)
        if g_args.jtag_close=="true":
            efuse_data[3]|=(0x3<<2)
        if g_args.pswd!=None:
            pswd=bytearray.fromhex(g_args.pswd)
            if len(pswd)!=8:
                bflb_utils.printf("Password len should be 8 bytes")
                sys.exit()
            efuse_data[4:4+len(pswd)]=pswd
        if g_args.hbn_jump=="false":
            efuse_data[0x10+3]|=(1<<3)
        if g_args.hbn_sign=="true":
            efuse_data[0x10+2]|=(1<<6)
        if g_args.flash_pdelay!=None:
            efuse_data[0x10+2]|=((int(g_args.flash_pdelay)&0x3)<<2)
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
    bootcfg_start=8+4+84+4+4+8+4
    segheader = bytearray(0)
    xip_addr=bflb_utils.bytearray_reverse(data_bytearray[0x7C:0x80])
    if bflb_utils.bytearray_to_int(xip_addr)!=0x00 and \
       bflb_utils.bytearray_to_int(xip_addr)!=0x23000000:
        flash_img=0
        if data_bytearray[0xB0+12:0xB0+16]!=bflb_utils.get_crc32_bytearray(data_bytearray[0xB0+0:0xB0+12]):
            bflb_utils.printf("[Error]:This image maybe has already been dealed(wrong segheader crc32 found)")
            sys.exit()
    if data_bytearray[0xB0+4:0xB0+8] == b'SEGH':
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
        image_data=data_bytearray[0xB0+16:]
        segheader=data_bytearray[0xB0:0xB0+16]
        boot_data=data_bytearray[0:0xB0]

        #update boot entry and len
        boot_data[0x7C:0x80]=segheader[0:4]
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
        bflb_utils.printf("[Error] XTS mode not support!!!!")
        return data_bytearray,None,flash_img

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
            encrypt = 2
        elif len(aeskey_bytearray)==24:
            encrypt = 3
        encrypt_key = aeskey_bytearray
        #bflb_utils.printf("Key= ", binascii.hexlify(encrypt_key))
        boot_data[bootcfg_start] |=((encrypt<<2)+(xts_mode<<6))

        # get IV
        iv_value = aesiv_hexstr
        encrypt_iv = bflb_utils.hexstr_to_bytearray(iv_value)
        iv_crcarray = bflb_utils.get_crc32_bytearray(encrypt_iv)
        aesiv_data = encrypt_iv + iv_crcarray

        data_tohash +=aesiv_data
        data_toencrypt +=image_data

        unencrypt_mfg_data = bytearray(0)
        if data_toencrypt[len(data_toencrypt) - 16:len(data_toencrypt) - 12] == bytearray("0mfg".encode("utf-8")):
            unencrypt_mfg_data = data_toencrypt[len(data_toencrypt) - 16:len(data_toencrypt)]

        image_data = img_create_encrypt_data(segheader+data_toencrypt, encrypt_key, encrypt_iv,
                                                        flash_img)
        if unencrypt_mfg_data != bytearray(0):
            image_data = image_data[0:len(data_toencrypt)+len(segheader) - 16] + unencrypt_mfg_data

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
        boot_data[176:176+len(pk_data+signature)]=pk_data+signature
        boot_data[176+len(pk_data+signature):176+len(pk_data+signature)+len(aesiv_data)]=aesiv_data
    else:
        boot_data+=(pk_data+signature)
        boot_data+=aesiv_data

    #save efuse data
    filedir, ext = os.path.split(imgfile)
    flash_encrypt_type=firmware_post_get_flash_encrypt_type(encrypt,xts_mode)
    key_sel=1
    security=True
    if flash_img:
        flash_encrypt_key=encrypt_key
    else:
        sec_eng_encrypt_key=encrypt_key

    img_update_efuse_data(filedir, sign, pk_hash, flash_encrypt_type,flash_encrypt_key, \
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
    crcarray = bflb_utils.get_crc32_bytearray(image_data[clockcfg_start+4:clockcfg_start+12])
    image_data[clockcfg_start+12:clockcfg_start+12+4] = crcarray
    bflb_utils.printf("Clock config crc: ", binascii.hexlify(crcarray))
    return image_data

def firmware_post_proc_update_bootheader_crc(image_data):
    crcarray = bflb_utils.get_crc32_bytearray(image_data[0:172])
    image_data[172:172+4] = crcarray
    bflb_utils.printf("Bootheader config crc: ", binascii.hexlify(crcarray))
    return image_data

# get hash ignore ignore
def firmware_post_proc_get_hash_ignore(image_data):
    bootcfg_start=(4+4)+(4+84+4)+(4+8+4)
    return  (image_data[bootcfg_start + 2] >> 1) & 0x1

# get hash ignore ignore
def firmware_post_proc_enable_hash_cfg(image_data):
    bootcfg_start=(4+4)+(4+84+4)+(4+8+4)
    image_data[bootcfg_start + 2]&=(~0x02)
    return  image_data

# get image offset
def firmware_post_proc_get_image_offset(image_data):
    cpucfg_start=(4+4)+(4+84+4)+(4+8+4)+12
    return  ((image_data[cpucfg_start + 0])+
             (image_data[cpucfg_start + 1]<<8) +
             (image_data[cpucfg_start + 2]<<16) +
             (image_data[cpucfg_start + 3]<<24) )

def firmware_post_proc_update_hash(image_data,force_update,args,hash,flash_img):
    #get image offset
    image_offset=firmware_post_proc_get_image_offset(image_data)
    bflb_utils.printf("Image Offset:"+hex(image_offset))
    #udpate image len
    bootcfg_start=(4+4)+(4+84+4)+(4+8+4)
    if flash_img:
        image_data[bootcfg_start+4 :bootcfg_start +4+4]=bflb_utils.int_to_4bytearray_l(len(image_data)-image_offset)
    else:
        image_data[bootcfg_start+4 :bootcfg_start +4+4]=bflb_utils.int_to_4bytearray_l(1)
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
        g_args.edata="0x5c,"+args.aeskey+";0x7c,00208040"
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

