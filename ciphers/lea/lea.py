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


def print_msg_box(msg, indent=0, align=1, width=None, title=None):
    lines = msg.split("\n")
    space = " " * align

    if not width:
        width = max(map(len, lines))

    buf = f"{' ' * indent}+{'-' * (width + align * 2)}+\n"

    if title:
        buf += f"{' ' * indent}|{space}{title:<{width}}{space}|\n"
        buf += f"{' ' * indent}|{space}{'-' * len(title):<{width}}{space}|\n"

    buf += "".join([f"{' ' * indent}|{space}{line:<{width}}{space}|\n" for line in lines])

    buf += f"{' ' * indent}+{'-' * (width + align * 2)}+\n"

    output_file.write(buf)


def print_array_bit_diff_column(array_1, array_2, indent=0, column=8, hex=True):
    assert isinstance(array_1, list) or isinstance(
        array_1, bytes), f"\"{array_1}\" is not array or bytes!"
    length_a1 = len(array_1)

    assert isinstance(array_2, list) or isinstance(
        array_2, bytes), f"\"{array_2}\" is not array or bytes!"
    length_a2 = len(array_2)

    assert column > 0, f"column number can not be: {column}"

    if length_a1 > length_a2:
        length_max = length_a1
        length_min = length_a2
    else:
        length_min = length_a1
        length_max = length_a2

    if length_max == 0:
        return

    buf = ""
    count = 0

    for index in range(0, length_max, column):
        buf += " " * indent
        buf += ("+--------" + "---" * (1 if hex else 0)) * (column if index+column <=
                                                            length_max else length_max - index) + "+" * (1 if length_max > 0 else 0) + "\n"

        if index < length_a1:
            buf += " " * (indent+1)
            for cell in range(index, (index+column) if (index+column) <= length_a1 else length_a1):
                if hex:
                    buf += "{:02X}:".format(array_1[cell])
                buf += "{:08b} ".format(array_1[cell])
        buf += "\n"

        if index < length_a2:
            buf += " " * (indent+1)
            for cell in range(index, (index+column) if (index+column) <= length_a2 else length_a2):
                if hex:
                    buf += "{:02X}:".format(array_2[cell])
                buf += "{:08b} ".format(array_2[cell])
        buf += "\n"

        buf += " " * indent
        buf += ("+--------" + "---" * (1 if hex else 0)) * (column if index+column <=
                                                            length_max else length_max - index) + "+" * (1 if length_max > 0 else 0) + "\n"

        buf += " " * (indent+1)
        for cell_index in range(index, (index+column) if (index+column) <= length_max else length_max):
            diff = (array_1[cell_index] if cell_index < length_a1 else (0xFF ^ (array_2[cell_index]))) ^ (
                array_2[cell_index] if cell_index < length_a2 else (0xFF ^ (array_1[cell_index])))
            while diff:
                count += diff & 1
                diff >>= 1
            if hex:
                buf += "{:02X}:".format(((array_1[cell_index]) if cell_index < length_a1 else (0xFF ^ (array_2[cell_index]))) ^ (
                    array_2[cell_index] if cell_index < length_a2 else (0xFF ^ (array_1[cell_index]))))
            buf += "{:08b} ".format(((array_1[cell_index]) if cell_index < length_a1 else (0xFF ^ (array_2[cell_index]))) ^ (
                array_2[cell_index] if cell_index < length_a2 else (0xFF ^ (array_1[cell_index])))).replace("0", "-").replace("1", "X")
        buf += "\n"

        buf += " " * indent
        buf += ("+--------" + "---" * (1 if hex else 0)) * (column if index+column <=
                                                            length_max else length_max - index) + "+" * (1 if length_max > 0 else 0) + "\n"
        buf += "\n"

    output_file.write(buf)

    print_msg_box("Bit difference: {}".format(count), indent)
    output_file.write("\n")


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
    def encrypt_block(self, pt):
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

        ct = bytes(struct.pack(
            '<LLLL', temp[0], temp[1], temp[2], temp[3]))
        return ct

    # decrypts a 128 bit input block
    def decrypt_block(self, ct):
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

        pt = bytes(struct.pack(
            '<LLLL', temp[0], temp[1], temp[2], temp[3]))

        return pt

    def encrypt_ecb(self, plaintext):
        """
        Encrypts `plaintext` using ECB mode and PKCS#7 padding.
        """
        plaintext = pad(plaintext)

        blocks = []
        for plaintext_block in split_blocks(plaintext):
            # ECB mode encrypt: encrypt(plaintext_block)
            blocks.append(self.encrypt_block(plaintext_block))

        return b''.join(blocks)

    def decrypt_ecb(self, ciphertext):
        """
        Decrypts `ciphertext` using ECB mode and PKCS#7 padding.
        """

        blocks = []
        for ciphertext_block in split_blocks(ciphertext):
            # ECB mode decrypt: decrypt(ciphertext_block)
            blocks.append(self.decrypt_block(ciphertext_block))

        return unpad(b''.join(blocks))

    def encrypt_ctr(self, plaintext, iv):
        """
        Encrypts `plaintext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            encrypted_nonce = self.encrypt_block(nonce)
            block = xor_bytes(plaintext_block, encrypted_nonce)

            print_msg_box("Plaintext Block <XOR> Encrypted Nonce")
            output_file.write("xor_bytes({}, {})\nCiphertext Block: {}\n\n".format(
                plaintext_block.hex(), encrypted_nonce.hex(), block.hex()))

            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            encrypted_nonce = self.encrypt_block(nonce)
            block = xor_bytes(ciphertext_block, encrypted_nonce)

            print_msg_box("Ciphertext Block <XOR> Encrypted Nonce")
            output_file.write("xor_bytes({}, {})\nPlaintext Block: {}\n\n".format(
                ciphertext_block.hex(), encrypted_nonce.hex(), block.hex()))

            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)


def encrypt_block(plaintext, key):
    output_file.write("encrypt_block({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_block({}, {})\n\n".format(
        plaintext.hex(), key.hex()))
    return LEA(key).encrypt_block(plaintext)


def decrypt_block(ciphertext, key):
    output_file.write("decrypt_block({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_block({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return LEA(key).decrypt_block(ciphertext)


def encrypt_ecb(plaintext, key):
    output_file.write("encrypt_ecb({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_ecb({}, {})\n\n".format(
        plaintext.hex(), key.hex()))
    return LEA(key).encrypt_ecb(plaintext)


def decrypt_ecb(ciphertext, key):
    output_file.write("decrypt_ecb({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_ecb({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return LEA(key).decrypt_ecb(ciphertext)


def encrypt_ctr(plaintext, key, iv):
    output_file.write("encrypt_ctr({}, {}, {})\n".format(plaintext, key, iv))
    output_file.write("encrypt_ctr({}, {}, {})\n\n".format(
        plaintext.hex(), key.hex(), iv.hex()))
    return LEA(key).encrypt_ctr(plaintext, iv)


def decrypt_ctr(ciphertext, key, iv):
    output_file.write("decrypt_ctr({}, {}, {})\n".format(ciphertext, key, iv))
    output_file.write("decrypt_ctr({}, {}, {})\n\n".format(
        ciphertext.hex(), key.hex(), iv.hex()))
    return LEA(key).decrypt_ctr(ciphertext, iv)


if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) < 3:
        # output_file.close()
        exit()

    text = bytes.fromhex(sys.argv[2].strip())
    key = bytes.fromhex(sys.argv[3].strip())

    # output_file_name = os.path.splitext(os.path.basename(__file__))[0] + ".txt"
    output_file_name = "output.txt"
    output_file = open(output_file_name, "w")

    output_file.write("LEA\n\n")

    if "encrypt_block".startswith(sys.argv[1]):
        ciphertext = encrypt_block(text, key)
        output_file.write(
            "encrypt_block({}, {}):\nEncrypted message: {}\n\n".format(text, key, ciphertext))
        output_file.write(
            "encrypt_block({}, {}):\nEncrypted message: {}\n".format(text.hex(), key.hex(), ciphertext.hex()))
        print_array_bit_diff_column(text, ciphertext)
        print(ciphertext.hex(), end="")
    elif "decrypt_block".startswith(sys.argv[1]):
        plaintext = decrypt_block(text, key)
        output_file.write(
            "decrypt_block({}, {}):\nDecrypted message: {}\n\n".format(text, key, plaintext))
        output_file.write(
            "decrypt_block({}, {}):\nDecrypted message: {}\n".format(text.hex(), key.hex(), plaintext.hex()))
        print_array_bit_diff_column(text, plaintext)
        print(plaintext.hex(), end="")
    elif "encrypt_ecb".startswith(sys.argv[1]):
        ciphertext = encrypt_ecb(text, key)
        output_file.write(
            "encrypt_ecb({}, {}):\nEncrypted message: {}\n\n".format(text, key, ciphertext))
        output_file.write(
            "encrypt_ecb({}, {}):\nEncrypted message: {}\n".format(text.hex(), key.hex(), ciphertext.hex()))
        print_array_bit_diff_column(text, ciphertext)
        print(ciphertext.hex(), end="")
    elif "decrypt_ecb".startswith(sys.argv[1]):
        plaintext = decrypt_ecb(text, key)
        output_file.write(
            "decrypt_ecb({}, {}):\nDecrypted message: {}\n\n".format(text, key, plaintext))
        output_file.write(
            "decrypt_ecb({}, {}):\nDecrypted message: {}\n".format(text.hex(), key.hex(), plaintext.hex()))
        print_array_bit_diff_column(text, plaintext)
        print(plaintext.hex(), end="")
    elif "encrypt_ctr".startswith(sys.argv[1]):
        iv = bytes.fromhex(sys.argv[4].strip())
        ciphertext = encrypt_ctr(text, key, iv)
        output_file.write(
            "encrypt_ctr({}, {}, {}):\nEncrypted message: {}\n\n".format(text, key, iv, ciphertext))
        output_file.write(
            "encrypt_ctr({}, {}, {}):\nEncrypted message: {}\n".format(text.hex(), key.hex(), iv.hex(), ciphertext.hex()))
        print_array_bit_diff_column(text, ciphertext)
        print(ciphertext.hex(), end="")
    elif "decrypt_ctr".startswith(sys.argv[1]):
        iv = bytes.fromhex(sys.argv[4].strip())
        plaintext = decrypt_ctr(text, key, iv)
        output_file.write(
            "decrypt_ctr({}, {}, {}):\nDecrypted message: {}\n\n".format(text, key, iv, plaintext))
        output_file.write(
            "decrypt_ctr({}, {}, {}):\nDecrypted message: {}\n".format(text.hex(), key.hex(), iv.hex(), plaintext.hex()))
        print_array_bit_diff_column(text, plaintext)
        print(plaintext.hex(), end="")
    output_file.close()

# python3 lea.py encrypt_block <plaintext> <key>
# python3 lea.py encrypt_block 41545441434b204154204441574e2101 534f4d452031323820424954204b4559
#                              "ATTACK AT DAWN!\x01"             "SOME 128 BIT KEY"

# python3 lea.py decrypt_block <ciphertext> <key>
# python3 lea.py decrypt_block 7d354e8b1dc429a300abac87c050951a 534f4d452031323820424954204b4559
#                                  <ciphertext>                  "SOME 128 BIT KEY"

# python3 lea.py encrypt_ecb 41545441434b204154204441574e2101 534f4d452031323820424954204b4559
# python3 lea.py decrypt_ecb 7d354e8b1dc429a300abac87c050951a3485873e087a21ed908331410fcb2fe4 534f4d452031323820424954204b4559

# python3 lea.py encrypt_ctr 41545441434b204154204441574e2101 534f4d452031323820424954204b4559 00000000000000000000000000000000
# python3 lea.py decrypt_ctr f2ff3999c8a82dd91e952d830853ca88 534f4d452031323820424954204b4559 00000000000000000000000000000000
