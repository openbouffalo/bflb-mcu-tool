# -*- coding: utf-8 -*-
#  Copyright (C) 2021- BOUFFALO LAB (NANJING) CO., LTD.
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
import hashlib
import lzma
import binascii

try:
    import bflb_path
except ImportError:
    from libs import bflb_path
from libs import bflb_utils
from libs.bflb_utils import img_create_sha256_data


chip_dict = ("bl602", "bl604", "bl702", "bl704", "bl706", "bl702l", "bl704l", "bl606p", "bl808", "bl616", "bl618")

def get_nicky_name(chipname):
    if chipname == "bl604":
        return "bl602"
    if chipname == "bl704" or chipname == "bl706":
        return "bl702"
    if chipname == "bl704l":
        return "bl702l"
    if chipname == "bl618":
        return "bl616"
    return chipname


def check_header(chipname,file):
    try:
        with open(file, "rb") as fp:
            content = fp.read()
            fp.close()
            if content[0:4] != b'BFNP' and content[0:4] != b'BFAP':
                bflb_utils.printf("[Error] Bootheader not found")
                return False
            if content[56*1024+0:56*1024+4] != b'BFPT' or content[60*1024+0:60*1024+4] != b'BFPT':
                bflb_utils.printf("[Error] Partition not found")
                return False
            if content[64*1024+0:64*1024+4] != b'BFNP' and content[64*1024+0:64*1024+4] != b'BFAP':
                bflb_utils.printf("[Error] APP not found")
                return False
            return True  
    except Exception as e:
        bflb_utils.printf(e)
        bflb_utils.printf("[Warning] Check header[boot2/partition/app] fail")
    return False

def get_bootheader_inf(chipname):
    if chipname=="bl602":
        hash_offset=128+4
        image_offset=(4+4)+(4+84+4)+(4+8+4)+12
        image_len_offset=(4+4)+(4+84+4)+(4+8+4)+4
    elif chipname=="bl702":
        hash_offset=128+4
        image_offset=(4+4)+(4+84+4)+(4+8+4)+12
        image_len_offset=(4+4)+(4+84+4)+(4+8+4)+4
    elif chipname=="bl606p" or chipname=="bl808":
        hash_offset=128+16
        image_offset=(4+4)+(4+84+4)+(4+20+4)+4
        image_len_offset=140
    elif chipname=="bl616":
        hash_offset=128+8
        image_offset=(4+4)+(4+84+4)+(4+12+4)+4
        image_len_offset=(4+4)+(4+84+4)+(4+12+4)+4+8

    return image_offset,image_len_offset,hash_offset

def parse_boot2(chipname,file):
    try:
        with open(file, "rb") as fp:
            content = fp.read()
            fp.close()
            bflb_utils.printf("File len=", len(content))
            image_offset,image_len_offset,hash_offset=get_bootheader_inf(chipname)
            image_offset=int.from_bytes(content[image_offset:image_offset+4],'little')
            image_len=int.from_bytes(content[image_len_offset:image_len_offset+4],'little')
            hash_val_hd=content[hash_offset:hash_offset+32]
            hash_val_cal=img_create_sha256_data(content[image_offset:image_offset+image_len])
            bflb_utils.printf("Boot2 offset=", image_offset)
            bflb_utils.printf("Boot2 len=", image_len)
            bflb_utils.printf("Boot2 hash=", binascii.hexlify(hash_val_cal))
            with open("boot2_with_header.bin", 'wb+') as fp:
                fp.write(content[0:image_offset+image_len])
                fp.close()
            with open("partition.bin", 'wb+') as fp:
                fp.write(content[0xE000:0x10000])
                fp.close()
            if len(content)<image_offset+image_len:
                bflb_utils.printf("Boot2 is corrupt")
                return False
            if int.from_bytes(content[hash_offset:hash_offset+4],'little') != 0xdeadbeef:
                if hash_val_hd!=hash_val_cal:
                    bflb_utils.printf("Boot2 hash error")
                    return False
                else:
                    bflb_utils.printf("Boot2 hash correct")
            else:
                bflb_utils.printf("Boot2 not cal hash")            
            return True
    except Exception as e:
        bflb_utils.printf(e)
        bflb_utils.printf("[Warning] Check header[boot2/partition/app] fail")
    return False

def parse_one_partition_entry(chipname,entryname,entrydata,maxlen):
    bflb_utils.printf(entryname)
    if entryname.startswith('FW') or entryname.startswith('mfg'):
        if entrydata[0:4] != b'BFNP' and entrydata[0:4] != b'BFAP':
            bflb_utils.printf("No firmware header found")
            return False
        image_offset,image_len_offset,hash_offset=get_bootheader_inf(chipname)
        image_offset=int.from_bytes(entrydata[image_offset:image_offset+4],'little')
        image_len=int.from_bytes(entrydata[image_len_offset:image_len_offset+4],'little')
        hash_val_hd=entrydata[hash_offset:hash_offset+32]
        hash_val_cal=img_create_sha256_data(entrydata[image_offset:image_offset+image_len])
        bflb_utils.printf("Offset=", image_offset)
        bflb_utils.printf("Len=", image_len)
        bflb_utils.printf("Hash=", binascii.hexlify(hash_val_cal))
        bflb_utils.printf("Max size=", maxlen)
        if image_len>maxlen:
            bflb_utils.printf("Image actual size is larger than max len")
            return False
        if len(entrydata)<image_offset+image_len:
            bflb_utils.printf("Image is corrupt")
            return False
        if int.from_bytes(entrydata[hash_offset:hash_offset+4],'little') != 0xdeadbeef:
            if hash_val_hd!=hash_val_cal:
                bflb_utils.printf("Image hash error")
                return False
            else:
                bflb_utils.printf("Image hash correct")
        else:
            bflb_utils.printf("Image not cal hash")

        with open(entryname+".bin", 'wb+') as fp:
            bflb_utils.printf("Create "+entryname+".bin")
            fp.write(entrydata[image_offset:image_offset+image_len])
            fp.close()
        with open(entryname+"_with_header.bin", 'wb+') as fp:
            fp.write(entrydata[0:image_offset+image_len])
            fp.close()
    else:
        if maxlen!=0 and len(entrydata)!=0:
            bflb_utils.printf("Create "+entryname+".bin")
            with open(entryname+".bin", 'wb+') as fp:
                if len(entrydata)<maxlen:
                    fp.write(entrydata)
                else:                
                    fp.write(entrydata[0:maxlen])
                fp.close()
    return True

def parse_partition(chipname,file):
    try:
        with open(file, "rb") as fp:
            content = fp.read()
            fp.close()
            start=56*1024
            magicCode=int.from_bytes(content[start:start+4],'little')
            bflb_utils.printf("Partition magic:",binascii.hexlify(bflb_utils.int_to_4bytearray_l(magicCode)))
            version=int.from_bytes(content[start+4:start+6],'little')
            bflb_utils.printf("Partition version:",version)
            entryCnt=int.from_bytes(content[start+6:start+8],'little')
            bflb_utils.printf("Partition entry count:",entryCnt)
            age=int.from_bytes(content[start+8:start+12],'little')
            bflb_utils.printf("Partition age:",age)
            crc32_table=content[start+12:start+16]
            bflb_utils.printf("Partition table crc32:",binascii.hexlify(crc32_table))
            crcarray = bflb_utils.get_crc32_bytearray(content[start:start+12])
            if crc32_table!=crcarray:
                bflb_utils.printf("Partition table crc32 error,cal=",binascii.hexlify(crcarray))
                return False
            
            entry_len=36
            entry_offset=start+16
            crc32_entry=content[entry_offset+entry_len*entryCnt:entry_offset+entry_len*entryCnt+4]
            bflb_utils.printf("Partition entry crc32:",binascii.hexlify(crc32_entry))
            crcarray = bflb_utils.get_crc32_bytearray(content[entry_offset:entry_offset+entry_len*entryCnt])
            if crc32_entry!=crcarray:
                bflb_utils.printf("Partition entry crc32 error,cal=",binascii.hexlify(crcarray))
                return False
                
            for itr in range(entryCnt):
                offset=itr*entry_len
                i=3
                while i<=12:
                    if content[entry_offset+offset+i]!=0:
                        i+=1
                    else:
                        break
                name=str(content[entry_offset+offset+3:entry_offset+offset+i].decode('utf-8'))
                start_addr0=int.from_bytes(content[entry_offset+offset+12:entry_offset+offset+16],'little')
                start_addr1=int.from_bytes(content[entry_offset+offset+16:entry_offset+offset+20],'little')
                max_len0=int.from_bytes(content[entry_offset+offset+20:entry_offset+offset+24],'little')
                max_len1=int.from_bytes(content[entry_offset+offset+24:entry_offset+offset+28],'little')
                actual_len=int.from_bytes(content[entry_offset+offset+28:entry_offset+offset+32],'little')
                age=int.from_bytes(content[entry_offset+offset+32:entry_offset+offset+36],'little')
                bflb_utils.printf("---------------------------------------")
                bflb_utils.printf("partition name:",name)
                bflb_utils.printf("partition start_addr0:",hex(start_addr0))
                bflb_utils.printf("partition start_addr1:",hex(start_addr1))
                bflb_utils.printf("partition max_len0:",hex(max_len0))
                bflb_utils.printf("partition max_len1:",hex(max_len1))
                bflb_utils.printf("partition length:",hex(actual_len))
                bflb_utils.printf("partition age:",age)
                #if name.startswith('FW') or name.startswith('mfg'):
                #    if len(content)<start_addr0+max_len0 or len(content)<start_addr1+max_len1:
                #        bflb_utils.printf("Image is corrupt,file is larger than partiton:",len(content))
                #        return False
                #
                if parse_one_partition_entry(chipname,name,content[start_addr0:],max_len0)==False:
                    return False
            return True
    except Exception as e:
        bflb_utils.printf(e)
        bflb_utils.printf("[Warning] Check header[boot2/partition/app] fail")
    return False

def dump_partiton(chipname,imgfile):
    if check_header(chipname,imgfile) == False:
        bflb_utils.printf("[Error] Not a whole_flash_data.bin file!!!")
        return
    if parse_boot2(chipname,imgfile) == False:
        bflb_utils.printf("[Error] Boot2 parse fail")
        return
    if parse_partition(chipname,imgfile) == False:
        bflb_utils.printf("[Error] partition parse fail")
        return

def run():
    parser = bflb_utils.firmware_post_proc_parser_init()
    args = parser.parse_args()
    # args = parser_image.parse_args("--image=media", "--signer=none")
    bflb_utils.printf("Chipname: %s" % args.chipname)

    if args.chipname.lower() in chip_dict:
        chipname = get_nicky_name(args.chipname.lower())
        dump_partiton(chipname,args.checkpartition)


if __name__ == '__main__':
    run()
