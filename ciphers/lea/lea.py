#!/usr/bin/env python
"""
https://github.com/maryanne5/Cryptography-Project
"""

import platform
import struct
import base64
import random

SIZE_128 = 16
SIZE_192 = 24
SIZE_256 = 32

block_size = 16


class LEA(object):
    # valid key sizes
    keySize = (SIZE_128, SIZE_192, SIZE_256)
    delta = [0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
             0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957]

    rk = None
    rounds = 0

    py_version = platform.python_version_tuple()
    py_under3 = int(py_version[0]) < 3

    @staticmethod
    def ROL(state, num):
        return ((state << num) | (state >> (32-num))) & 0xffffffff

    @staticmethod
    def ROR(state, num):
        return ((state >> num) | (state << (32-num))) & 0xffffffff

    @staticmethod
    def xorAr(lhsAr, rhsAr):
        # like (lhsAr ^ rhsAr)

        # assume len(lhsAr) <= len(rhsAr) <= 16

        bLen = min(len(lhsAr), 16)
        aLen = min(len(rhsAr), bLen)
        retVal = bytearray(16)

        for i in range(aLen):
            retVal[i] = lhsAr[i] ^ rhsAr[i]
        for i in range(aLen, bLen):
            retVal[i] = lhsAr[i]

        return retVal

    @staticmethod
    def to_bytearray(obj, obj_name='', encoding='utf-8', forcecopy=False):
        if obj is None:
            raise AttributeError("`%s` is None" % obj_name)
        if type(obj) == bytearray:
            if forcecopy:
                return bytearray(obj)
            return obj
        if type(obj) == str and str != bytes:
            return bytearray(obj, encoding)
        elif type(obj) in (int, float):
            raise AttributeError("`%s` must be a bytes-like object" % obj_name)
        else:
            return bytearray(obj)

    def __init__(self, key):

        if isinstance(key, LEA):
            old_lea = key
            self.rounds = old_lea.rounds
            self.rk = old_lea.rk
            return

        key_size = len(key)
        if key_size == SIZE_128:
            rounds = 24
        elif key_size == SIZE_192:
            rounds = 28
        elif key_size == SIZE_256:
            rounds = 32
        else:
            raise AttributeError('Improper key size: %d' % key_size)

        self.rounds = rounds
        # LEA delta

        T = [0] * 8
        mk_len = len(key)
        mk = LEA.to_bytearray(key)
        self.rk = [[0 for x in range(6)] for x in range(32)]
        self.rounds = (mk_len >> 1) + 16
        T[0], T[1], T[2], T[3] = struct.unpack('<LLLL', mk[:16])

        if mk_len == 16:
            for i in range(0, self.rounds, 1):
                temp = self.ROL(self.delta[i & 3], i)

                self.rk[i][0] = T[0] = self.ROL((T[0] + temp) & 0xffffffff, 1)
                self.rk[i][1] = self.rk[i][3] = self.rk[i][5] = T[1] = self.ROL(
                    (T[1] + self.ROL(temp, 1)) & 0xffffffff, 3)
                self.rk[i][2] = T[2] = self.ROL(
                    (T[2] + self.ROL(temp, 2)) & 0xffffffff, 6)
                self.rk[i][4] = T[3] = self.ROL(
                    (T[3] + self.ROL(temp, 3)) & 0xffffffff, 11)

        elif mk_len == 24:
            T[4], T[5] = struct.unpack('<LL', mk[16:24])

            for i in range(0, self.rounds, 1):
                temp = self.ROL(self.delta[i % 6], i)

                self.rk[i][0] = T[0] = self.ROL((T[0] + temp) & 0xffffffff, 1)
                self.rk[i][1] = T[1] = self.ROL(
                    (T[1] + self.ROL(temp, 1)) & 0xffffffff, 3)
                self.rk[i][2] = T[2] = self.ROL(
                    (T[2] + self.ROL(temp, 2)) & 0xffffffff, 6)
                self.rk[i][3] = T[3] = self.ROL(
                    (T[3] + self.ROL(temp, 3)) & 0xffffffff, 11)
                self.rk[i][4] = T[4] = self.ROL(
                    (T[4] + self.ROL(temp, 4)) & 0xffffffff, 13)
                self.rk[i][5] = T[5] = self.ROL(
                    (T[5] + self.ROL(temp, 5)) & 0xffffffff, 17)

        elif mk_len == 32:
            T[4], T[5], T[6], T[7] = struct.unpack('<LLLL', mk[16:32])

            for i in range(0, self.rounds, 1):
                temp = self.ROL(self.delta[i & 7], i & 0x1f)

                self.rk[i][0] = T[(
                    6 * i) & 7] = self.ROL((T[(6 * i) & 7] + temp) & 0xffffffff, 1)
                self.rk[i][1] = T[(
                    6 * i + 1) & 7] = self.ROL((T[(6 * i + 1) & 7] + self.ROL(temp, 1)) & 0xffffffff, 3)
                self.rk[i][2] = T[(
                    6 * i + 2) & 7] = self.ROL((T[(6 * i + 2) & 7] + self.ROL(temp, 2)) & 0xffffffff, 6)
                self.rk[i][3] = T[(
                    6 * i + 3) & 7] = self.ROL((T[(6 * i + 3) & 7] + self.ROL(temp, 3)) & 0xffffffff, 11)
                self.rk[i][4] = T[(
                    6 * i + 4) & 7] = self.ROL((T[(6 * i + 4) & 7] + self.ROL(temp, 4)) & 0xffffffff, 13)
                self.rk[i][5] = T[(
                    6 * i + 5) & 7] = self.ROL((T[(6 * i + 5) & 7] + self.ROL(temp, 5)) & 0xffffffff, 17)

    # encrypts a 128 bit input block
    def encrypt(self, pt):
        if len(pt) != 16:
            raise AttributeError('length of pt should be 16 not %d' % len(pt))

        # pt = LEA.to_bytearray(pt)
        temp = list(struct.unpack('<LLLL', pt))

        for i in range(0, self.rounds, 4):
            temp[3] = self.ROR(
                ((temp[2] ^ self.rk[i][4]) + (temp[3] ^ self.rk[i][5])) & 0xffffffff, 3)
            temp[2] = self.ROR(
                ((temp[1] ^ self.rk[i][2]) + (temp[2] ^ self.rk[i][3])) & 0xffffffff, 5)
            temp[1] = self.ROL(
                ((temp[0] ^ self.rk[i][0]) + (temp[1] ^ self.rk[i][1])) & 0xffffffff, 9)
            i += 1
            temp[0] = self.ROR(
                ((temp[3] ^ self.rk[i][4]) + (temp[0] ^ self.rk[i][5])) & 0xffffffff, 3)
            temp[3] = self.ROR(
                ((temp[2] ^ self.rk[i][2]) + (temp[3] ^ self.rk[i][3])) & 0xffffffff, 5)
            temp[2] = self.ROL(
                ((temp[1] ^ self.rk[i][0]) + (temp[2] ^ self.rk[i][1])) & 0xffffffff, 9)
            i += 1
            temp[1] = self.ROR(
                ((temp[0] ^ self.rk[i][4]) + (temp[1] ^ self.rk[i][5])) & 0xffffffff, 3)
            temp[0] = self.ROR(
                ((temp[3] ^ self.rk[i][2]) + (temp[0] ^ self.rk[i][3])) & 0xffffffff, 5)
            temp[3] = self.ROL(
                ((temp[2] ^ self.rk[i][0]) + (temp[3] ^ self.rk[i][1])) & 0xffffffff, 9)
            i += 1
            temp[2] = self.ROR(
                ((temp[1] ^ self.rk[i][4]) + (temp[2] ^ self.rk[i][5])) & 0xffffffff, 3)
            temp[1] = self.ROR(
                ((temp[0] ^ self.rk[i][2]) + (temp[1] ^ self.rk[i][3])) & 0xffffffff, 5)
            temp[0] = self.ROL(
                ((temp[3] ^ self.rk[i][0]) + (temp[0] ^ self.rk[i][1])) & 0xffffffff, 9)

        ct = bytearray(struct.pack(
            '<LLLL', temp[0], temp[1], temp[2], temp[3]))
        return ct

    # decrypts a 128 bit input block
    def decrypt(self, ct):
        ct = LEA.to_bytearray(ct)
        if len(ct) != 16:
            raise AttributeError('length of ct should be 16 not %d' % len(ct))

        temp = list(struct.unpack('<LLLL', ct))

        for i in range(self.rounds - 1, 0, -4):
            temp[0] = ((self.ROR(temp[0], 9) - (temp[3] ^ self.rk[i][0]))
                       & 0xffffffff) ^ self.rk[i][1]
            temp[1] = ((self.ROL(temp[1], 5) - (temp[0] ^ self.rk[i][2]))
                       & 0xffffffff) ^ self.rk[i][3]
            temp[2] = ((self.ROL(temp[2], 3) - (temp[1] ^ self.rk[i][4]))
                       & 0xffffffff) ^ self.rk[i][5]
            i -= 1
            temp[3] = ((self.ROR(temp[3], 9) - (temp[2] ^ self.rk[i][0]))
                       & 0xffffffff) ^ self.rk[i][1]
            temp[0] = ((self.ROL(temp[0], 5) - (temp[3] ^ self.rk[i][2]))
                       & 0xffffffff) ^ self.rk[i][3]
            temp[1] = ((self.ROL(temp[1], 3) - (temp[0] ^ self.rk[i][4]))
                       & 0xffffffff) ^ self.rk[i][5]
            i -= 1
            temp[2] = ((self.ROR(temp[2], 9) - (temp[1] ^ self.rk[i][0]))
                       & 0xffffffff) ^ self.rk[i][1]
            temp[3] = ((self.ROL(temp[3], 5) - (temp[2] ^ self.rk[i][2]))
                       & 0xffffffff) ^ self.rk[i][3]
            temp[0] = ((self.ROL(temp[0], 3) - (temp[3] ^ self.rk[i][4]))
                       & 0xffffffff) ^ self.rk[i][5]
            i -= 1
            temp[1] = ((self.ROR(temp[1], 9) - (temp[0] ^ self.rk[i][0]))
                       & 0xffffffff) ^ self.rk[i][1]
            temp[2] = ((self.ROL(temp[2], 5) - (temp[1] ^ self.rk[i][2]))
                       & 0xffffffff) ^ self.rk[i][3]
            temp[3] = ((self.ROL(temp[3], 3) - (temp[2] ^ self.rk[i][4]))
                       & 0xffffffff) ^ self.rk[i][5]

        pt = bytearray(struct.pack(
            '<LLLL', temp[0], temp[1], temp[2], temp[3]))

        return pt

class CipherMode(object):
    lea = None
    no_more = False
    buffer = bytearray()

    def update(self, data):
        raise AssertionError('Only for reference')

    def encrypt(self, pt):
        ct = bytearray(16)
        raise AssertionError('Only for reference')

    def decrypt(self, ct):
        pt = bytearray(16)
        raise AssertionError('Only for reference')

    def final(self, *args, **kwargs):
        self.no_more = True
        return b''

class CBC(CipherMode):
    def __init__(self, do_enc, key, iv, PKCS5Padding=False):
        self.buffer = bytearray()
        self.lea = LEA(key)
        self.PKCS5Padding = PKCS5Padding
        self.chain_vec = LEA.to_bytearray(iv, 'IV', forcecopy=True)

        if do_enc:
            self.update = self.encrypt
        else:
            self.update = self.decrypt

    def encrypt(self, pt):
        if pt is None:
            raise AttributeError('Improper pt')
        if self.no_more:
            raise RuntimeError('Already finished')

        self.buffer += LEA.to_bytearray(pt)
        offset = 0
        ct = bytearray()

        len_x16 = len(self.buffer)-16
        while offset <= len_x16:
            self.chain_vec = self.lea.encrypt(LEA.xorAr(self.chain_vec, self.buffer[offset:offset+16]))
            ct += self.chain_vec

            offset += 16

        if offset != 0:
            self.buffer = self.buffer[offset:]

        return ct

    def decrypt(self, ct):
        if ct is None:
            raise AttributeError('Improper ct')
        if self.no_more:
            raise RuntimeError('Already finished')

        self.buffer += LEA.to_bytearray(ct)
        offset = 0
        pt = bytearray()

        len_x16 = len(self.buffer)-16
        if self.PKCS5Padding and len_x16 % 16 == 0:
            len_x16 -= 16
        while offset <= len_x16:
            temp = self.buffer[offset:offset+16]
            pt += LEA.xorAr(self.chain_vec, self.lea.decrypt(temp))
            self.chain_vec = temp

            offset += 16

        if offset != 0:
            self.buffer = self.buffer[offset:]

        return pt

    def final(self):
        result = bytearray()
        if self.PKCS5Padding and self.encrypt == self.update:
            more = 16 - len(self.buffer)
            self.buffer += bytearray([more])*more
            result += self.lea.encrypt(LEA.xorAr(self.chain_vec, self.buffer))

        elif self.PKCS5Padding and self.decrypt == self.update:
            if len(self.buffer) != 16:
                raise ValueError('Improper data length')
            self.buffer = LEA.xorAr(self.chain_vec, self.lea.decrypt(self.buffer))
            more = self.buffer[-1]
            for i in range(16-more, 15):
                if self.buffer[i] != more:
                    raise ValueError('Padding error')
            result += self.buffer[:16-more]
        elif len(self.buffer) > 0:
            self.buffer = bytearray()
            raise ValueError('Improper data length')
        self.buffer = bytearray()
        self.chain_vec = bytearray(16)
        self.no_more = True
        return result

if __name__ == "__main__":
    dec = "blacksnakeblacksnake1234"
    input_str='Hello Alice,I am sending you this e-mail to make sure you are alive!'
    
    pt = bytearray(input_str, "utf8")
    
    #a random 128 bit initial vector
    iv = base64.b16encode(random.getrandbits(128).to_bytes(16, byteorder='little'))
    
    #encryption
    leaCBC = CBC(True, dec,iv,True)
    ct = leaCBC.update(pt)
    ct += leaCBC.final()

    #decryption
    leaCBC = CBC(False, dec,iv, True)
    pt = leaCBC.update(ct)
    pt += leaCBC.final()

    decrypt_output = pt.decode('utf8')
    print(decrypt_output)