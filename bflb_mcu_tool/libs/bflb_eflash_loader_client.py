# -*- coding:utf-8 -*-
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


import os
import sys
import time
import socket
import signal
import binascii

from Crypto.Cipher import AES

try:
    import bflb_path
except ImportError:
    from libs import bflb_path
from libs import bflb_utils
from libs import bflb_ecdh
from libs.bflb_utils import eflash_loader_parser_init

ecdh_enable = False
key = None


def create_encrypt_data(data_bytearray, key_bytearray, iv_bytearray):
    cryptor = AES.new(key_bytearray, AES.MODE_CBC, iv_bytearray)
    ciphertext = cryptor.encrypt(data_bytearray)
    return ciphertext


def udp_socket_recv_key(udp_socket_client):
    recv_data, recv_addr = udp_socket_client.recvfrom(1024)
    if recv_data.decode('utf-8', 'ignore').startswith("ssk:"):
        public_key = recv_data[4:]
        return public_key
    else:
        print('Recieve server shared key error ', recv_data.decode('utf-8', 'ignore'))
    return None


def udp_socket_recv_log(udp_socket_client):
    recv_data, recv_addr = udp_socket_client.recvfrom(1024)
    print('Recieve:[from IP:%s>]' % recv_addr[0],
          recv_data.decode('utf-8', 'ignore') + '\n',
          end='')
    return recv_data


def udp_socket_send_client(udp_socket_client, send_address, key=None):
    time.sleep(0.1)
    send_data = input('Iuput:')
    sdata = bytes(send_data, encoding="utf8")
    if send_data == 'quit':
        udp_socket_client.close()
        print('Quit successfully')
        os.kill(os.getpid(), signal.SIGKILL)
    else:
        if ecdh_enable:
            tmp_ecdh = bflb_ecdh.BflbEcdh()
            csk = tmp_ecdh.create_public_key()
            ecdh_private_key = binascii.hexlify(
                tmp_ecdh.ecdh.private_key.to_string()).decode("utf-8")
            udp_socket_client.sendto(
                bytearray.fromhex(binascii.hexlify(b'csk:').decode("utf-8") + csk), send_address)
            public_key = udp_socket_recv_key(udp_socket_client)
            if public_key is not None:
                ecdh_peer_public_key = binascii.hexlify(public_key).decode("utf-8")
                ecdh_shared_key = tmp_ecdh.create_shared_key(ecdh_peer_public_key)

                if len(sdata) % 16 != 0:
                    sdata = sdata + bytearray(16 - (len(sdata) % 16))
                sdata = create_encrypt_data(sdata, bytearray.fromhex(ecdh_shared_key[0:32]),
                                            bytearray(16))
            else:
                return False
        else:
            if key:
                if len(sdata) % 16 != 0:
                    sdata = sdata + bytearray(16 - (len(sdata) % 16))
                sdata = create_encrypt_data(sdata, bytearray.fromhex(key), bytearray(16))
        print(binascii.hexlify(sdata))
        udp_socket_client.sendto(sdata, send_address)
        while True:
            log = udp_socket_recv_log(udp_socket_client)
            if log.decode('utf-8', 'ignore').find("Finished with success") != -1:
                print("Program success")
                return True
            elif log.decode('utf-8', 'ignore').find("Finished with fail") != -1:
                print("Program fail")
                return False
            else:
                pass
    return False


def main(port, key=None):
    udp_socket_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print('Enter quit to exist program')
    host = socket.gethostname()
    # send_address is server address
    send_address = (host, port)
    udp_socket_send_client(udp_socket_client, send_address, key)
    udp_socket_client.close()


def usage():
    print(sys.argv[0])
    print("-p/--port=     :specify UDP port")
    print("--key=         :aes 128 encrypt")
    print("--ecdh=        :open ecdh function")


if __name__ == '__main__':
    port = 8080
    parser = eflash_loader_parser_init()
    args = parser.parse_args()
    if args.port:
        port = int(args.port)
    if args.key:
        key = args.key
    if args.ecdh:
        ecdh_enable = True
        bflb_utils.printf("ECDH Enable")
    else:
        ecdh_enable = False
    if args.usage:
        usage()
    if key and ecdh_enable is True:
        print("key and ecdh can only set one")
        time.sleep(2)
        sys.exit()
    main(port, key)
