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
import sys
import time
import socket
import threading
import binascii
import concurrent.futures

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization

try:
    import bflb_path
except ImportError:
    from libs import bflb_path
import config as gol
from libs import bflb_eflash_loader
from libs import bflb_version
from libs import bflb_ecdh
from libs import bflb_utils
from libs.bflb_utils import eflash_loader_parser_init

total_cnt = 0
success_cnt = 0
ecdh_enable = False

try:
    import changeconf as cgc

    conf_sign = True
except ImportError:
    conf_sign = False

import ctypes
import inspect

import multiprocessing

list_process = []

from libs.bflb_eflash_loader_worker import eflash_loader_worker


def _async_raise(tid, exctype):
    """Raises an exception in the threads with id tid"""
    if not inspect.isclass(exctype):
        raise TypeError("Only types can be raised (not instances)")
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stop_thread(thread_name):
    print(threading.enumerate())
    for thread in threading.enumerate():
        if thread.name == thread_name:
            bflb_utils.printf("Kill thread {0}".format(thread_name))
            # thread.terminate()
            _async_raise(thread.ident, SystemExit)


def stop_process(process_name):
    for process in list_process:
        if process.name == process_name:
            if process.is_alive():
                bflb_utils.printf("Kill process {0}".format(process_name))
                process.terminate()
            list_process.remove(process)


def create_decrypt_data(data_bytearray, key_bytearray, iv_bytearray):
    # 创建 AES-CBC解密器
    cipher = Cipher(algorithms.AES(key_bytearray), modes.CBC(iv_bytearray))
    decryptor = cipher.decryptor()
    # 解密数据
    plaintext = decryptor.update(data_bytearray) + decryptor.finalize()
    return plaintext


def eflash_loader_server(socket_server, port, echo, aes_key):
    ecdh_shared_key = None
    socket_address = ("", port)
    socket_server.bind(socket_address)
    bflb_utils.enable_udp_send_log(echo)
    count_total = multiprocessing.Value("i", 0)
    count_success = multiprocessing.Value("i", 0)
    try:
        while True:
            try:
                recv_data, recv_addr = socket_server.recvfrom(1024)
                bflb_utils.printf("Receive: [from IP:<{}>]".format(recv_addr[0]))
            except Exception as e:
                bflb_utils.printf(e)
                continue
            global ecdh_enable
            if aes_key:
                try:
                    if len(recv_data) % 16 != 0:
                        recv_data = recv_data + bytearray(16 - (len(recv_data) % 16))
                    recv_data = create_decrypt_data(recv_data, bytearray.fromhex(aes_key), bytearray(16))
                    for i in range(len(recv_data)):
                        if recv_data[i : i + 1] == bytearray(1):
                            recv_data = recv_data[0:i]
                            break
                except Exception as e:
                    bflb_utils.printf(e)
            elif ecdh_enable:
                if ecdh_shared_key is None:
                    try:
                        tmp_ecdh = bflb_ecdh.BflbEcdh()
                        ssk = tmp_ecdh.create_public_key()
                        ecdh_private_key = binascii.hexlify(
                            tmp_ecdh.private_key.private_numbers().private_value.to_bytes(32, "big")
                        ).decode("utf-8")
                        # bflb_utils.printf("ecdh private key")
                        # bflb_utils.printf(ecdh_private_key)
                        if recv_data.decode("utf-8", "ignore").startswith("csk:"):
                            ecdh_peer_public_key = binascii.hexlify(recv_data[4:]).decode("utf-8")
                            # bflb_utils.printf("ecdh peer key")
                            # bflb_utils.printf(ecdh_peer_public_key)
                            ecdh_shared_key = tmp_ecdh.create_shared_key(ecdh_peer_public_key)
                            socket_server.sendto(
                                bytearray.fromhex(binascii.hexlify(b"ssk:").decode("utf-8") + ssk),
                                recv_addr,
                            )
                            continue
                    except Exception as e:
                        bflb_utils.printf(e)
                else:
                    try:
                        if len(recv_data) % 16 != 0:
                            recv_data = recv_data + bytearray(16 - (len(recv_data) % 16))
                        recv_data = create_decrypt_data(
                            recv_data, bytearray.fromhex(ecdh_shared_key[0:32]), bytearray(16)
                        )
                        ecdh_shared_key = None
                        i = 0
                        while True:
                            if recv_data[i : i + 1] == bytearray(1):
                                recv_data = recv_data[0:i]
                                break
                            i += 1
                    except Exception as e:
                        bflb_utils.printf(e)

            if recv_data.decode("utf-8", "ignore").startswith("stop"):
                socket_server.sendto(
                    bytearray.fromhex(binascii.hexlify(b"Stop success.").decode("utf-8")),
                    recv_addr,
                )
                bflb_utils.printf("Stop server successfully")
                socket_server.close()
                break
            match = re.search("--port=(\S*)\s", recv_data.decode("utf-8", "ignore"), re.I)
            if match is not None:
                name_port = match.group(1)
            else:
                name_port = None
            if name_port:
                stop_process(name_port)
                p = multiprocessing.Process(
                    target=eflash_loader_worker, args=(recv_addr, recv_data, count_total, count_success)
                )
                p.name = name_port
            else:
                p = multiprocessing.Process(
                    target=eflash_loader_worker, args=(recv_addr, recv_data, count_total, count_success)
                )
            list_process.append(p)
            p.start()
            time.sleep(0.001)
    finally:
        return


def eflash_loader_monitor(client_addr, client_data):
    global total_cnt, success_cnt
    total_cnt += 1
    try:
        # eflash_loader_worker_thread = threading.Thread(target=eflash_loader_worker,
        #                                                args=(socket_server, client_addr, client_data))
        # eflash_loader_worker_thread.start()
        # bflb_utils.printf(eflash_loader_worker_thread.join())
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(eflash_loader_worker, client_addr, client_data)
            return_value = future.result()
            if return_value:
                success_cnt += 1
            bflb_utils.printf("State: {0}/{1}".format(success_cnt, total_cnt))
    except Exception:
        bflb_utils.printf("eflash loader monitor failed")
        bflb_utils.printf("State: {0}/{1}".format(success_cnt, total_cnt))


def usage():
    bflb_utils.printf(sys.argv[0])
    bflb_utils.printf("-p/--port=     :specify UDP listen port")
    bflb_utils.printf("--echo         :open local log echo")
    bflb_utils.printf("--ecdh         :open ecdh function")
    bflb_utils.printf("--key=         :aes 128 encrypt")


def eflash_loader_server_main():
    global ecdh_enable
    port = 8080
    echo = False
    aes_key = ""
    parser = eflash_loader_parser_init()
    # args = parser.parse_args()
    args, unparsed = parser.parse_known_args()
    if conf_sign:
        bflb_utils.printf(
            "Version: ",
            bflb_version.eflash_loader_version_text.replace("bflb", cgc.eflash_loader_version_text_first_value),
        )
    else:
        bflb_utils.printf("eflash loader version: ", bflb_version.version_text.replace("(", "").replace(")", ""))
    if args.port:
        port = int(args.port)
    if args.key:
        aes_key = args.key
    if args.ecdh:
        ecdh_enable = True
        bflb_utils.printf("ECDH Enable")
    else:
        ecdh_enable = False
    if args.echo:
        echo = True
    if args.usage:
        usage()
        return
    if aes_key != "" and ecdh_enable is True:
        bflb_utils.printf("key and ecdh can only set one")
        time.sleep(2)
        sys.exit()
    socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bflb_utils.printf("Listening on ", port)
    #     eflash_loader_server_thread = threading.Thread(
    #         target=eflash_loader_server, args=(socket_server, port, echo, aes_key)
    #     )
    #     eflash_loader_server_thread.start()
    eflash_loader_server(socket_server, port, echo, aes_key)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    eflash_loader_server_main()
