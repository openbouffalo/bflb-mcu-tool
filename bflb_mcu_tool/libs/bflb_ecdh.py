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

import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from libs import bflb_utils


class BflbEcdh:
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve
        self.private_key = None
        self.public_key = None
        self.shared_key = None

    def create_public_key(self):
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        self.public_key = self.private_key.public_key()
        public_numbers = self.public_key.public_numbers()
        x = public_numbers.x
        y = public_numbers.y
        x_bytes = x.to_bytes(32, "big")
        y_bytes = y.to_bytes(32, "big")
        ret = binascii.hexlify(x_bytes + y_bytes).decode("utf-8")
        bflb_utils.printf("local public key")
        bflb_utils.printf(ret)
        return ret

    def create_shared_key(self, peer_pk):
        peer_pk = "04" + peer_pk
        peer_pk = binascii.unhexlify(peer_pk)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pk)
        self.shared_key = self.private_key.exchange(ec.ECDH(), public_key)  # 32bytes
        ret = binascii.hexlify(self.shared_key).decode("utf-8")
        return ret
