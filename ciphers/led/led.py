#!/usr/bin/env python
"""
https://github.com/CrYpTo-DuCkS/LED_Cipher_Term_paper
"""

import numpy as np
import galois

from hmac import new as new_hmac, compare_digest
from hashlib import pbkdf2_hmac

# from copy import deepcopy
import os


S_BOX = {0: 12, 1: 5, 2: 6, 3: 11, 4: 9, 5: 0, 6: 10, 7: 13,
         8: 3, 9: 14, 10: 15, 11: 8, 12: 4, 13: 7, 14: 1, 15: 2}
S_BOX_INV = {v: k for (k, v) in S_BOX.items()}
R_CON = [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1E,
         0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30]
MIX_MATRIX = [[0x4, 0x1, 0x2, 0x2],
              [0x8, 0x6, 0x5, 0x6],
              [0xB, 0xE, 0XA, 0x9],
              [0x2, 0x2, 0xF, 0xB]]


GF16 = galois.GF(2**4)

MIX_MATRIX_INV = np.linalg.inv(GF16(MIX_MATRIX))


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [[(text[i] & 0xf0) >> 4, text[i] & 0x0f, (text[i+1] & 0xf0) >> 4, text[i+1] & 0x0f] for i in range(0, len(text), 2)]


def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes([(matrix[i][j] << 4)+matrix[i][j+1] for i in range(4) for j in range(0, 4, 2)])


def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i ^ j for i, j in zip(a, b))


def inc_bytes(a):
    """ Returns a new byte array with the value increment by 1 """
    output_file.write("inc_bytes(a: {})\n".format(a.hex()))
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)


def sub_cells(s):
    output_file.write("sub_cells(s: {})\n".format(s))
    for i in range(4):
        for j in range(4):
            s[i][j] = S_BOX[s[i][j]]


def inv_sub_cells(s):
    output_file.write("inv_sub_cells(s: {})\n".format(s))
    for i in range(4):
        for j in range(4):
            s[i][j] = S_BOX_INV[s[i][j]]


def shift_rows(s):
    output_file.write("shift_rows(s: {})\n".format(s))
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]


def inv_shift_rows(s):
    output_file.write("inv_shift_rows(s: {})\n".format(s))
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]


def add_round_key(s, k):
    output_file.write("inv_shift_rows(s: {}, k: {})\n".format(s, k))
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


def add_constants(s, key_size, rn):
    output_file.write(
        "add_constants(s: {}, key_size: {}, rn: {})\n".format(s, key_size, rn))
    msb_k = (key_size & 0xF0) >> 4
    lsb_k = key_size & 0x0F
    msb_rc = (R_CON[rn] & 0x38) >> 3
    lsb_rc = R_CON[rn] & 0x07
    ac_mat = [[0 ^ msb_k, msb_rc, 0, 0],
              [1 ^ msb_k, lsb_rc, 0, 0],
              [2 ^ lsb_k, msb_rc, 0, 0],
              [3 ^ lsb_k, lsb_rc, 0, 0]]
    for i in range(4):
        for j in range(4):
            s[i][j] ^= ac_mat[i][j]


def mix_columns_serial(s):
    output_file.write("mix_columns_serial(s: {})\n".format(s))
    ans = np.matmul(GF16(MIX_MATRIX), GF16(s))
    for i in range(4):
        for j in range(4):
            s[i][j] = int(ans[i][j])


def inv_mix_columns_serial(s):
    output_file.write("inv_mix_columns_serial(s: {})\n".format(s))
    ans = np.matmul(MIX_MATRIX_INV, GF16(s))
    for i in range(4):
        for j in range(4):
            s[i][j] = int(ans[i][j])


def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    output_file.write("pad({})\n".format(plaintext.hex()))
    padding_len = 8 - (len(plaintext) % 8)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding


def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    output_file.write("unpad({})\n".format(plaintext.hex()))
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message


def split_blocks(message, block_size=8, require_padding=True):
    output_file.write("split_blocks({})\n".format(message.hex()))
    assert len(message) % block_size == 0 or not require_padding
    return [message[i:i+block_size] for i in range(0, len(message), block_size)]


class LED:
    rounds_by_key_size = {8: 8, 16: 12}

    def __init__(self, master_key):
        output_file.write(
            "__init__(master_key: {})\n".format(master_key.hex()))
        self.__master_key = master_key
        self.n_rounds = LED.rounds_by_key_size[len(master_key)]
        self.key_schedule()
        self.modes_dict = {'ebc': (self.encrypt_ebc, self.decrypt_ebc),
                           'cbc': (self.encrypt_cbc, self.decrypt_cbc),
                           'pcbc': (self.encrypt_pcbc, self.decrypt_pcbc),
                           'cfb': (self.encrypt_cfb, self.decrypt_cfb),
                           'ofb': (self.encrypt_ofb, self.decrypt_ofb),
                           'ctr': (self.encrypt_ctr, self.decrypt_ctr)}

    def key_schedule(self):
        self.__subkeys = []
        if len(self.__master_key) == 8:
            self.__subkeys.append(bytes2matrix(self.__master_key))
        else:
            self.__subkeys.append(bytes2matrix(self.__master_key[0:8]))
            self.__subkeys.append(bytes2matrix(self.__master_key[8:16]))
        # print(self.__subkeys)

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 8

        plain_state = bytes2matrix(plaintext)
        # state_after_every_round = []
        # state_after_every_round.append(deepcopy(plain_state))

        for i in range(self.n_rounds-1):
            add_round_key(plain_state, self.__subkeys[min(
                i % 2, len(self.__subkeys)-1)])
            # state_after_every_round.append(deepcopy(plain_state))
            add_constants(plain_state, len(self.__master_key), i)
            # state_after_every_round.append(deepcopy(plain_state))
            sub_cells(plain_state)
            # state_after_every_round.append(deepcopy(plain_state))
            shift_rows(plain_state)
            # state_after_every_round.append(deepcopy(plain_state))
            mix_columns_serial(plain_state)
            # state_after_every_round.append(deepcopy(plain_state))

        add_round_key(plain_state, self.__subkeys[min(
            (self.n_rounds-1) % 2, len(self.__subkeys)-1)])
        # state_after_every_round.append(deepcopy(plain_state))

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 8

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self.__subkeys[min(
            (self.n_rounds-1) % 2, len(self.__subkeys)-1)])

        for i in range(self.n_rounds - 2, -1, -1):
            inv_mix_columns_serial(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_cells(cipher_state)
            add_constants(cipher_state, len(self.__master_key), i)
            add_round_key(cipher_state, self.__subkeys[min(
                i % 2, len(self.__subkeys)-1)])

        return matrix2bytes(cipher_state)

    def encrypt_ebc(self, plaintext, iv):
        """
        Encrypts `plaintext` using EBC mode and PKCS#7 padding.
        """

        plaintext = pad(plaintext)

        blocks = []
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(plaintext_block)
            blocks.append(block)

        return b''.join(blocks)

    def decrypt_ebc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """

        blocks = []
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(self.decrypt_block(ciphertext_block))

        return unpad(b''.join(blocks))

    def encrypt_cbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 8

        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(
                xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return unpad(b''.join(blocks))

    def encrypt_pcbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 8

        plaintext = pad(plaintext)

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for plaintext_block in split_blocks(plaintext):
            # PCBC mode encrypt: encrypt(plaintext_block XOR (prev_ciphertext XOR prev_plaintext))
            ciphertext_block = self.encrypt_block(
                xor_bytes(plaintext_block, xor_bytes(prev_ciphertext, prev_plaintext)))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return b''.join(blocks)

    def decrypt_pcbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for ciphertext_block in split_blocks(ciphertext):
            # PCBC mode decrypt: (prev_plaintext XOR prev_ciphertext) XOR decrypt(ciphertext_block)
            plaintext_block = xor_bytes(xor_bytes(
                prev_ciphertext, prev_plaintext), self.decrypt_block(ciphertext_block))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return unpad(b''.join(blocks))

    def encrypt_cfb(self, plaintext, iv):
        """
        Encrypts `plaintext` with the given initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        prev_ciphertext = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CFB mode encrypt: plaintext_block XOR encrypt(prev_ciphertext)
            ciphertext_block = xor_bytes(
                plaintext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def decrypt_cfb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` with the given initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        prev_ciphertext = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CFB mode decrypt: ciphertext XOR decrypt(prev_ciphertext)
            plaintext_block = xor_bytes(
                ciphertext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def encrypt_ofb(self, plaintext, iv):
        """
        Encrypts `plaintext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # OFB mode encrypt: plaintext_block XOR encrypt(previous)
            block = self.encrypt_block(previous)
            ciphertext_block = xor_bytes(plaintext_block, block)
            blocks.append(ciphertext_block)
            previous = block

        return b''.join(blocks)

    def decrypt_ofb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # OFB mode decrypt: ciphertext XOR encrypt(previous)
            block = self.encrypt_block(previous)
            plaintext_block = xor_bytes(ciphertext_block, block)
            blocks.append(plaintext_block)
            previous = block

        return b''.join(blocks)

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
        assert len(iv) == 8

        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            block = xor_bytes(plaintext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 8

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)


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


def encrypt_block(plaintext, key):
    output_file.write("encrypt_block({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_block({}, {})\n\n".format(
        plaintext.hex(), key.hex()))
    return LED(key).encrypt_block(plaintext)


def decrypt_block(ciphertext, key):
    output_file.write("decrypt_block({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_block({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return LED(key).decrypt_block(ciphertext)


def encrypt_ecb(plaintext, key):
    output_file.write("encrypt_ecb({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_ecb({}, {})\n\n".format(
        plaintext.hex(), key.hex()))
    return LED(key).encrypt_ecb(plaintext)


def decrypt_ecb(ciphertext, key):
    output_file.write("decrypt_ecb({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_ecb({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return LED(key).decrypt_ecb(ciphertext)


def encrypt_ctr(plaintext, key, iv):
    output_file.write("encrypt_ctr({}, {}, {})\n".format(plaintext, key, iv))
    output_file.write("encrypt_ctr({}, {}, {})\n\n".format(
        plaintext.hex(), key.hex(), iv.hex()))
    return LED(key).encrypt_ctr(plaintext, iv)


def decrypt_ctr(ciphertext, key, iv):
    output_file.write("decrypt_ctr({}, {}, {})\n".format(ciphertext, key, iv))
    output_file.write("decrypt_ctr({}, {}, {})\n\n".format(
        ciphertext.hex(), key.hex(), iv.hex()))
    return LED(key).decrypt_ctr(ciphertext, iv)


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

    output_file.write("LED\n\n")

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


# python3 led.py encrypt_block <plaintext> <key>
# python3 led.py encrypt_block 41545441434b204154204441574e2101 534f4d452031323820424954204b4559
#                              "ATTACK AT DAWN!\x01"             "SOME 128 BIT KEY"

# python3 led.py decrypt_block <ciphertext> <key>
# python3 led.py decrypt_block 7d354e8b1dc429a300abac87c050951a 534f4d452031323820424954204b4559
#                                  <ciphertext>                  "SOME 128 BIT KEY"

# python3 led.py encrypt_ecb 41545441434b204154204441574e2101 534f4d452031323820424954204b4559
# python3 led.py decrypt_ecb 7d354e8b1dc429a300abac87c050951a3485873e087a21ed908331410fcb2fe4 534f4d452031323820424954204b4559

# python3 led.py encrypt_ctr 41545441434b204154204441574e2101 534f4d452031323820424954204b4559 00000000000000000000000000000000
# python3 led.py decrypt_ctr f2ff3999c8a82dd91e952d830853ca88 534f4d452031323820424954204b4559 00000000000000000000000000000000


# python3 led.py encrypt_block <plaintext> <key>
# python3 led.py encrypt_block 0000000000000000 0000000000000000
# Expected: 39c2401003A0c798
# Result: d28bdc60bfa11ecf

# Test vectors:
# LED-64
# <plaintext>       <key>             <ciphertext>      <result>
# 0000000000000000  0000000000000000  39C2401003A0C798  d28bdc60bfa11ecf
# 0123456789ABCDEF  0123456789ABCDEF  A003551E3893FC58  81be2de9ced7452d
