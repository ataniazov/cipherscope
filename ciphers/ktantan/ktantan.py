#!/usr/bin/env python
"""
https://github.com/bozhu/KTANTAN-Python
"""
"""
Bo Zhu
"""

IR = (
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0,
    1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0,
    0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
)

k_a_index = (
    63,  31,  31,  15,  14,  60,  40,  49,  35,  54,  45,  58,  37,  74,  69,  74,
    53,  43,  71,  63,  30,  45,  11,  54,  28,  41,   3,  38,  60,  25,  34,   5,
    26,  20,   9,   2,  20,  24,   1,   2,  52,  24,  17,   3,   6,  76,  72,  49,
    19,  23,  15,  14,  12,  24,  16,   1,   2,   4,  40,  48,  17,  18,   5,  10,
    4,   8,  64,  64,  65,  51,  23,  47,  15,  78,  76,  73,  67,  55,  47,  63,
    47,  62,  29,  26,   5,  10,  36,  56,  33,  50,  21,  42,   5,  58,  20,  25,
    3,   6,  12,  56,  16,  33,   3,  70,  60,  41,  67,  71,  78,  77,  59,  39,
    79,  79,  62,  45,  59,  23,  46,  13,  42,  52,  41,  66,  53,  42,  53,  27,
    38,  13,  74,  52,  25,  35,   7,  62,  44,  73,  51,  22,  29,  11,   6,  44,
    72,  65,  50,  37,  75,  55,  46,  77,  75,  70,  61,  27,  39,  15,  46,  76,
    57,  34,  69,  59,  38,  61,  43,  70,  77,  58,  21,  43,   7,  30,  44,   9,
    18,  36,   9,  50,  36,  57,  19,  22,  13,  10,  68,  56,  17,  19,   7,  14,
    28,  40,   1,  66,  68,  57,  35,  55,  31,  30,  13,  10,   4,  72,  48,  33,
    51,  39,  78,  61,  26,  21,  11,   6,  12,   8,  32,  64,  49,  18,  37,  11,
    22,  28,   9,   2,   4,   8,   0,  48,  32,  65,  67,  54,  29,  27,   7,  14,
    12,   8,   0,   0,  16,  32,   1,  34,  68,  73,  66,  69,  75,  71,
)

k_b_index = (
    31,  63,  63,  47,  14,  76,  40,  17,  67,  22,  77,  26,  69,  10,  69,  10,
    21,  43,   7,  79,  62,  45,  11,  70,  60,  41,  19,  70,  28,  73,  34,  21,
    74,  52,  41,  18,  68,  56,  33,   2,  68,  56,  49,  35,   6,  76,   8,  17,
    51,  55,  63,  46,  28,  72,  48,  49,  34,  20,  72,  16,  65,  50,  53,  58,
    36,   8,  64,   0,   1,  19,  55,  47,  15,  78,  12,   9,   3,  23,  47,  31,
    79,  30,  77,  58,  37,  26,  68,  24,  65,  18,  69,  42,   5,  74,  52,  57,
    51,  38,  12,  72,  48,  33,   3,  70,  28,  41,   3,  71,  14,  13,  27,  39,
    15,  79,  30,  45,  27,  71,  46,  29,  74,  20,  73,   2,  69,  42,  21,  75,
    38,  13,  74,  20,  57,  35,   7,  78,  44,   9,  67,  54,  61,  43,  22,  76,
    8,  65,  18,  37,  11,  71,  46,  13,  75,   6,  29,  59,  39,  31,  78,  12,
    73,  34,   5,  75,  38,  29,  75,   6,  77,  26,  53,  43,  23,  78,  44,  25,
    66,  36,   9,  66,  36,  25,  67,  54,  45,  10,  68,  24,  49,  51,  39,  30,
    76,  40,   1,  66,   4,  25,  35,  23,  79,  62,  61,  42,   4,  72,  16,  33,
    19,  71,  14,  77,  58,  53,  59,  54,  44,  24,  64,   0,  65,  50,  37,  27,
    70,  60,  57,  50,  52,  40,   0,  64,  32,   1,  67,  22,  61,  59,  55,  62,
    60,  56,  32,  16,  64,  32,  17,  66,   4,  73,   2,   5,  11,   7,
)


def num2bits(num, bitlength):
    bits = []
    for i in range(bitlength):
        bits.append(num & 1)
        num >>= 1
    return bits


def bits2num(bits):
    num = 0
    for i, x in enumerate(bits):
        assert x == 0 or x == 1
        num += (x << i)
    return num


class KTANTAN():
    def __init__(self, master_key=0, version=32):
        assert version in (32, 48, 64)
        self.version = version
        output_file.write(
            "__init__(master_key: {}, version: {})\n".format(master_key, version))

        if 32 == self.version:
            self.LEN_L1 = 13
            self.LEN_L2 = 19
            self.X = (None, 12, 7, 8, 5, 3)  # starting from 1
            self.Y = (None, 18, 7, 12, 10, 8, 3)
        elif 48 == self.version:
            self.LEN_L1 = 19
            self.LEN_L2 = 29
            self.X = (None, 18, 12, 15, 7, 6)
            self.Y = (None, 28, 19, 21, 13, 15, 6)
        else:
            self.LEN_L1 = 25
            self.LEN_L2 = 39
            self.X = (None, 24, 15, 20, 11, 9)
            self.Y = (None, 38, 25, 33, 21, 14, 9)

        self.change_key(master_key)

    def change_key(self, master_key):
        output_file.write("change_key(master_key: {})\n".format(master_key))
        self.key = tuple(num2bits(master_key, 80))

    def one_round_encrypt(self, round):
        output_file.write("one_round_encrypt(round: {})\n".format(round))
        self.f_a = self.L1[self.X[1]] ^ self.L1[self.X[2]]  \
            ^ (self.L1[self.X[3]] & self.L1[self.X[4]]) \
            ^ (self.L1[self.X[5]] & IR[round])          \
            ^ self.key[k_a_index[round]]

        self.f_b = self.L2[self.Y[1]] ^ self.L2[self.Y[2]]  \
            ^ (self.L2[self.Y[3]] & self.L2[self.Y[4]]) \
            ^ (self.L2[self.Y[5]] & self.L2[self.Y[6]]) \
            ^ self.key[k_b_index[round]]

        self.L1.pop()
        self.L1.insert(0, self.f_b)

        self.L2.pop()
        self.L2.insert(0, self.f_a)

    def encrypt(self, plaintext, from_round=0, to_round=253):
        output_file.write("encrypt(plaintext: {}, from_round: {}, to_round: {})\n".format(
            plaintext, from_round, to_round))
        self.plaintext_bits = num2bits(plaintext, self.version)
        self.L2 = self.plaintext_bits[:self.LEN_L2]
        self.L1 = self.plaintext_bits[self.LEN_L2:]

        for round in range(from_round, to_round + 1):
            self.one_round_encrypt(round)
            if self.version > 32:
                self.one_round_encrypt(round)
                if self.version > 48:
                    self.one_round_encrypt(round)
        return bits2num(self.L2 + self.L1)

    def one_round_decrypt(self, round):
        output_file.write("one_round_decrypt(round: {})\n".format(round))
        self.f_a = self.L2[0] ^ self.L1[self.X[2] + 1]              \
            ^ (self.L1[self.X[3] + 1] & self.L1[self.X[4] + 1]) \
            ^ (self.L1[self.X[5] + 1] & IR[round])              \
            ^ self.key[k_a_index[round]]

        self.f_b = self.L1[0] ^ self.L2[self.Y[2] + 1]              \
            ^ (self.L2[self.Y[3] + 1] & self.L2[self.Y[4] + 1]) \
            ^ (self.L2[self.Y[5] + 1] & self.L2[self.Y[6] + 1]) \
            ^ self.key[k_b_index[round]]

        self.L1.pop(0)
        self.L1.append(self.f_a)

        self.L2.pop(0)
        self.L2.append(self.f_b)

    def decrypt(self, ciphertext, from_round=253, to_round=0):
        output_file.write("decrypt(ciphertext: {}, from_round: {}, to_round: {})\n".format(
            ciphertext, from_round, to_round))
        self.ciphertext_bits = num2bits(ciphertext, self.version)
        self.L2 = self.ciphertext_bits[:self.LEN_L2]
        self.L1 = self.ciphertext_bits[self.LEN_L2:]

        for round in range(from_round, to_round - 1, -1):
            self.one_round_decrypt(round)
            if self.version > 32:
                self.one_round_decrypt(round)
                if self.version > 48:
                    self.one_round_decrypt(round)
        return bits2num(self.L2 + self.L1)


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


def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i ^ j for i, j in zip(a, b))


def inc_bytes(a):
    """ Returns a new byte array with the value increment by 1 """
    output_file.write("inc_bytes({})\n".format(a.hex()))
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)


def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 8 bytes.
    Note that if the plaintext size is a multiple of 8,
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


def encrypt_block(plaintext, key):
    output_file.write("encrypt_block({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_block({}, {})\n\n".format(
        plaintext.hex(), key.hex()))
    key = int.from_bytes(key, byteorder='big', signed=False)
    plaintext = int.from_bytes(plaintext, byteorder='big', signed=False)
    ktantan = KTANTAN(key, 64)
    encoded_block = ktantan.encrypt(plaintext)
    ciphertext = encoded_block.to_bytes(
        (encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False)
    return ciphertext


def decrypt_block(ciphertext, key):
    output_file.write("decrypt_block({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_block({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    key = int.from_bytes(key, byteorder='big', signed=False)
    ciphertext = int.from_bytes(ciphertext, byteorder='big', signed=False)
    ktantan = KTANTAN(key, 64)
    encoded_block = ktantan.decrypt(ciphertext)
    plaintext = encoded_block.to_bytes(
        (encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False)
    return plaintext


def encrypt_ecb(plaintext, key):
    """
    Encrypts `plaintext` using ECB mode and PKCS#7 padding.
    """
    output_file.write("encrypt_ecb({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_ecb({}, {})\n\n".format(
        plaintext.hex(), key.hex()))

    plaintext = pad(plaintext)

    blocks = []
    for plaintext_block in split_blocks(plaintext):
        # ECB mode encrypt: encrypt(plaintext_block, key)
        blocks.append(encrypt_block(plaintext_block, key))

    return b''.join(blocks)


def decrypt_ecb(ciphertext, key):
    """
    Decrypts `ciphertext` using ECB mode and PKCS#7 padding.
    """
    output_file.write("decrypt_ecb({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_ecb({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))

    blocks = []
    for ciphertext_block in split_blocks(ciphertext):
        # ECB mode decrypt: decrypt(ciphertext_block, key)
        blocks.append(decrypt_block(ciphertext_block, key))

    return unpad(b''.join(blocks))


def encrypt_ctr(plaintext, key, iv):
    """
    Encrypts `plaintext` using CTR mode with the given nounce/IV.
    """
    output_file.write("encrypt_ctr({}, {}, {})\n".format(plaintext, key, iv))
    output_file.write("encrypt_ctr({}, {}, {})\n\n".format(
        plaintext.hex(), key.hex(), iv.hex()))

    assert len(iv) == 8

    blocks = []
    nonce = iv
    for plaintext_block in split_blocks(plaintext, require_padding=False):
        # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
        encrypted_nonce = encrypt_block(nonce, key)
        block = xor_bytes(plaintext_block, encrypted_nonce)

        print_msg_box("Plaintext Block <XOR> Encrypted Nonce")
        output_file.write("xor_bytes({}, {})\nCiphertext Block: {}\n\n".format(
            plaintext_block.hex(), encrypted_nonce.hex(), block.hex()))

        blocks.append(block)
        nonce = inc_bytes(nonce)

    return b''.join(blocks)


def decrypt_ctr(ciphertext, key, iv):
    """
    Decrypts `ciphertext` using CTR mode with the given nounce/IV.
    """
    output_file.write("decrypt_ctr({}, {}, {})\n".format(ciphertext, key, iv))
    output_file.write("decrypt_ctr({}, {}, {})\n\n".format(
        ciphertext.hex(), key.hex(), iv.hex()))

    assert len(iv) == 8

    blocks = []
    nonce = iv
    for ciphertext_block in split_blocks(ciphertext, require_padding=False):
        # CTR mode decrypt: ciphertext XOR encrypt(nonce)
        encrypted_nonce = encrypt_block(nonce, key)
        block = xor_bytes(ciphertext_block, encrypted_nonce)

        print_msg_box("Ciphertext Block <XOR> Encrypted Nonce")
        output_file.write("xor_bytes({}, {})\nPlaintext Block: {}\n\n".format(
            ciphertext_block.hex(), encrypted_nonce.hex(), block.hex()))

        blocks.append(block)
        nonce = inc_bytes(nonce)

    return b''.join(blocks)


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

    output_file.write("KTANTAN\n\n")

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

# python3 ktantan.py encrypt_block <plaintext> <key>
# python3 ktantan.py encrypt_block 486920576f726c64 534f4d45203830424954
#                                     "Hi World"        "SOME 80BIT"

# python3 ktantan.py decrypt_block <ciphertext> <key>
# python3 ktantan.py decrypt_block 0eb47169eace5faa 534f4d45203830424954
#                                    <ciphertext>       "SOME 80BIT"

# python3 ktantan.py encrypt_ecb 486920576f726c64 534f4d45203830424954
# python3 ktantan.py decrypt_ecb 0eb47169eace5faadaf8e03ca397bcb9 534f4d45203830424954

# python3 ktantan.py encrypt_ctr 486920576f726c64 534f4d45203830424954 0000000000000000
# python3 ktantan.py decrypt_ctr c54de69c79c2f215 534f4d45203830424954 0000000000000000
