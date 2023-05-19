#!/usr/bin/env python
"""
https://github.com/ataniazov/cipherscope
"""
"""
Ata Niyazov
"""

output_file = ""

try:
    import struct
    number_type = int, long
except NameError:
    number_type = int

try:
    iter_range = xrange
except NameError:
    iter_range = range

EXPANSION = (
    31, 0,  1,  2,  3,  4,
    3,  4,  5,  6,  7,  8,
    7,  8,  9,  10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31, 0,
)

PERMUTATION = (
    15, 6,  19, 20, 28, 11, 27, 16,
    0,  14, 22, 25, 4,  17, 30, 9,
    1,  7,  23, 13, 31, 26, 2,  8,
    18, 12, 29, 5,  21, 10, 3,  24,
)

PERMUTED_CHOICE1 = (
    56, 48, 40, 32, 24, 16, 8,
    0,  57, 49, 41, 33, 25, 17,
    9,  1,  58, 50, 42, 34, 26,
    18, 10, 2,  59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
    6,  61, 53, 45, 37, 29, 21,
    13, 5,  60, 52, 44, 36, 28,
    20, 12, 4,  27, 19, 11, 3,
)

PERMUTED_CHOICE2 = (
    13, 16, 10, 23, 0,  4,
    2,  27, 14, 5,  20, 9,
    22, 18, 11, 3,  25, 7,
    15, 6,  26, 19, 12, 1,
    40, 51, 30, 36, 46, 54,
    29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,
    45, 41, 49, 35, 28, 31,
)

""" DESL & DESXL S-Box """
SUBSTITUTION_BOX = (
    14, 5,  7,  2,  11, 8,  1,  15, 0,  10, 9,  4,  6,  13, 12, 3,
    5,  0,  8,  15, 14, 3,  2,  12, 11, 7,  6,  9,  13, 4,  1,  10,
    4,  9,  2,  14, 8,  7,  13, 0,  10, 12, 15, 1,  5,  11, 3,  6,
    9,  6,  15, 5,  3,  8,  4,  11, 7,  1,  12, 2,  0,  14, 10, 13
)

ROTATES = (
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
)


def rotate_left(i28, k):
    return i28 << k & 0x0fffffff | i28 >> 28 - k


def permute(data, bits, mapper):
    ret = 0
    for i, v in enumerate(mapper):
        if data & 1 << bits - 1 - v:
            ret |= 1 << len(mapper) - 1 - i
    return ret


def f(block, key):
    block = permute(block, 32, EXPANSION) ^ key
    ret = 0
    desxl_sbox = SUBSTITUTION_BOX
    for i in range(8):
        i6 = block >> 42 - i * 6 & 0x3f
        ret = ret << 4 | desxl_sbox[i6 & 0x20 |
                                    (i6 & 0x01) << 4 | (i6 & 0x1e) >> 1]
    return permute(ret, 32, PERMUTATION)


def derive_keys(key):
    key, = struct.unpack(">Q", key)
    next_key = permute(key, 64, PERMUTED_CHOICE1)
    next_key = next_key >> 28, next_key & 0x0fffffff
    for bits in ROTATES:
        next_key = rotate_left(
            next_key[0], bits), rotate_left(next_key[1], bits)
        yield permute(next_key[0] << 28 | next_key[1], 56, PERMUTED_CHOICE2)


def encode_block(block, derived_keys, encryption):
    block = (block >> 32, block & 0xffffffff)

    if not encryption:
        derived_keys = reversed(derived_keys)
    for key in derived_keys:
        block = block[1], block[0] ^ f(block[1], key)

    return (block[1] << 32 | block[0])


def pad(plaintext):
    output_file.write("pad({})\n".format(plaintext.hex()))
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 8 - (len(plaintext) % 8)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding


def unpad(plaintext):
    output_file.write("unpad({})\n".format(plaintext.hex()))
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    print(message.hex())
    assert all(p == padding_len for p in padding)
    return message


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


class DESXL(object):
    """A class for encryption using DES Key"""

    def __init__(self, key, pre_whiten_key_1, post_whiten_key_2):
        self.__encryption_key = guard_key(key)
        self.__decryption_key = self.__encryption_key[::-1]
        self.__key = key
        self.__key_1 = int.from_bytes(
            pre_whiten_key_1, byteorder='big', signed=False)
        self.__key_2 = int.from_bytes(
            post_whiten_key_2, byteorder='big', signed=False)

    def encrypt_block(self, plaintext):
        # plaintext = bytes(pt ^ k1 for pt, k1 in zip(plaintext, self.__key_1))
        block = int.from_bytes(plaintext, byteorder='big', signed=False)
        # encoded_block = encode(block, self.__encryption_key, 1) ^ self.__key_2
        encoded_block = encode(
            block, self.__encryption_key, self.__key_1, self.__key_2, 1)
        ciphertext = encoded_block.to_bytes(
            (encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False)
        # return bytes(ct ^ k2 for ct, k2 in zip(ciphertext, self.__key_2))
        return ciphertext

    def decrypt_block(self, ciphertext):
        # ciphertext = bytes(ct ^ k2 for ct, k2 in zip(ciphertext, self.__key_2))
        block = int.from_bytes(ciphertext, byteorder='big', signed=False)
        # encoded_block = encode(block, self.__decryption_key, 0) ^ self.__key_1
        encoded_block = encode(
            block, self.__decryption_key, self.__key_1, self.__key_2, 0)
        plaintext = encoded_block.to_bytes(
            (encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False)
        # return bytes(pt ^ k1 for pt, k1 in zip(plaintext, self.__key_1))
        return plaintext

    def encrypt_ctr(self, message, initial):
        """Encrypts the message with the key object.

        :param message: {bytes} The message to be encrypted
        :return: {bytes} Encrypted bytes
        """
        return handle(message, self.__encryption_key, self.__key_1, self.__key_2, initial, encryption=1)

    def decrypt_ctr(self, message, initial):
        """Decrypts the encrypted message with the key object.

        :param message: {bytes} The message to be decrypted
        :return: {bytes} Decrypted bytes
        """
        return handle(message, self.__encryption_key, self.__key_1, self.__key_2, initial, encryption=0)

    def encrypt_ecb(self, message):
        """Encrypts the message with the key object.

        :param message: {bytes} The message to be encrypted
        :return: {bytes} Encrypted bytes
        """
        plaintext = pad(message)
        print(plaintext.hex())
        return handle(plaintext, self.__encryption_key, self.__key_1, self.__key_2, initial=None, encryption=1)

    def decrypt_ecb(self, message):
        """Decrypts the encrypted message with the key object.

        :param message: {bytes} The message to be decrypted
        :return: {bytes} Decrypted bytes
        """
        print(message.hex())
        plaintext = handle(message, self.__encryption_key, self.__key_1, self.__key_2, initial=None, encryption=0)
        print(plaintext.hex())
        return unpad(plaintext)


def encode(block, key, key_1, key_2, encryption):
    block ^= (key_1 if encryption else key_2)

    for k in key:
        block = encode_block(block, k, encryption)
        # encryption = not encryption

    block ^= (key_2 if encryption else key_1)

    return block


def guard_key(key):
    if isinstance(key, bytearray):
        key = bytes(key)

    assert isinstance(key, bytes), "The key should be `bytes` or `bytearray`"
    assert len(key) in (8, 16, 24), "The key should be of length 8, 16, or 24"

    k0, k1, k2 = key[:8], key[8:16], key[16:]
    if k1 == k2:
        return tuple(derive_keys(k0)),

    k2 = k2 or k0
    if k1 == k0:
        return tuple(derive_keys(k2)),

    return tuple(tuple(derive_keys(k)) for k in (k0, k1, k2))


def handle(message, key, key_1, key_2, initial, encryption):
    output_file.write("handle({}, {}, {}, {}, {}, {})\n".format(message.hex(), key, key_1, key_2, initial, encryption))
    blocks = [int.from_bytes(message[i:i+8], byteorder="big", signed=False)
              for i in iter_range(0, len(message), 8)]

    if initial is None:
        # ECB
        encoded_blocks = ecb(blocks, key, key_1, key_2, encryption)
    else:
        # CTR
        initial = int.from_bytes(initial, byteorder="big", signed=False)
        encoded_blocks = ctr(blocks, key, key_1, key_2, initial)

    return b"".join(encoded_block.to_bytes((encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False) for encoded_block in encoded_blocks)


def ctr(blocks, key, key_1, key_2, initial):
    output_file.write("ctr({}, {}, {}, {}, {})\n".format(blocks, key, key_1, key_2, initial))
    for block in blocks:
        block = block ^ encode(initial, key, key_1, key_2, 1)
        initial += 1
        yield block


def ecb(blocks, key, key_1, key_2, encryption):
    output_file.write("ecb({}, {}, {}, {}, {})\n".format(blocks, key, key_1, key_2, encryption))
    for block in blocks:
        yield encode(block, key, key_1, key_2, encryption)


try:
    bytes.fromhex
except AttributeError:
    def h2b(byte_string):
        return bytes(bytearray.fromhex(byte_string))
else:
    def h2b(byte_string):
        return bytes.fromhex(byte_string)

# if __name__ == "__main__":
#     # key = h2b("0000000000000000".strip())
#     # plaintext = h2b("0000000000000000".strip())

#     # des_key = h2b("0123456789ABCDEF".strip())
#     # plaintext = h2b("0123456789ABCDEF".strip())

#     # pre_whiten_key_1 = h2b("FEDCBA9876543210".strip())
#     # post_whiten_key_2 = h2b("0123456789ABCDEF".strip())

#     # plaintext = h2b("desdesxl".encode("utf-8").hex())
#     # des_key = h2b("0123456789ABCDEF")

#     # pre_whiten_key_1 = h2b("FEDCBA9876543210".strip())
#     # post_whiten_key_2 = h2b("ABCDEF0123456789".strip())

#     plaintext = h2b("0123456789ABCDEF".strip())
#     des_key = h2b("0000000000000000".strip())

#     pre_whiten_key_1 = h2b("0000000000000000".strip())
#     post_whiten_key_2 = h2b("0000000000000000".strip())

#     desxl = DESXL(des_key, pre_whiten_key_1, post_whiten_key_2)

#     initial = h2b("FFFFFFFFFFFFFFFFFFFFFFFF".strip())
#     ciphertext = desxl.encrypt(plaintext, initial)

#     print("ciphertext: {}".format(ciphertext.hex()))

#     decrypted_plaintext = desxl.decrypt(ciphertext, initial)

#     print("plaintext: {}\ndecrypted_plaintext: {}".format(
#         plaintext.hex(), decrypted_plaintext.hex()))


def encrypt_block(plaintext, desl_key, pre_whiten_key_1, post_whiten_key_2):
    output_file.write("encrypt_block({}, {}, {}, {})\n".format(
        plaintext, desl_key, pre_whiten_key_1, post_whiten_key_2))
    output_file.write("encrypt_block({}, {}, {}, {})\n\n".format(
        plaintext.hex(), desl_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex()))
    return DESXL(desl_key, pre_whiten_key_1, post_whiten_key_2).encrypt_block(plaintext)


def decrypt_block(ciphertext, desl_key, pre_whiten_key_1, post_whiten_key_2):
    output_file.write("decrypt_block({}, {}, {}, {})\n".format(
        ciphertext, desl_key, pre_whiten_key_1, post_whiten_key_2))
    output_file.write("decrypt_block({}, {}, {}, {})\n\n".format(
        ciphertext.hex(), desl_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex()))
    return DESXL(desl_key, pre_whiten_key_1, post_whiten_key_2).decrypt_block(ciphertext)


def encrypt_ecb(plaintext, desl_key, pre_whiten_key_1, post_whiten_key_2):
    output_file.write("encrypt_ecb({}, {}, {}, {})\n".format(
        plaintext, desl_key, pre_whiten_key_1, post_whiten_key_2))
    output_file.write("encrypt_ecb({}, {}, {}, {})\n\n".format(
        plaintext.hex(), desl_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex()))
    return DESXL(desl_key, pre_whiten_key_1, post_whiten_key_2).encrypt_ecb(plaintext)


def decrypt_ecb(ciphertext, desl_key, pre_whiten_key_1, post_whiten_key_2):
    output_file.write("decrypt_ecb({}, {}, {}, {})\n".format(
        ciphertext, desl_key, pre_whiten_key_1, post_whiten_key_2))
    output_file.write("decrypt_ecb({}, {}, {}, {})\n\n".format(
        ciphertext.hex(), desl_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex()))
    return DESXL(desl_key, pre_whiten_key_1, post_whiten_key_2).decrypt_ecb(ciphertext)


def encrypt_ctr(plaintext, desl_key, pre_whiten_key_1, post_whiten_key_2, iv):
    output_file.write("encrypt_ctr({}, {}, {}, {})\n".format(
        plaintext, desl_key, pre_whiten_key_1, post_whiten_key_2, iv))
    output_file.write("encrypt_ctr({}, {}, {}, {})\n\n".format(
        plaintext.hex(), desl_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex(), iv.hex()))
    return DESXL(desl_key, pre_whiten_key_1, post_whiten_key_2).encrypt_ctr(plaintext, iv)


def decrypt_ctr(ciphertext, desl_key, pre_whiten_key_1, post_whiten_key_2, iv):
    output_file.write("decrypt_block({}, {}, {}, {})\n".format(
        ciphertext, desl_key, pre_whiten_key_1, post_whiten_key_2, iv))
    output_file.write("decrypt_block({}, {}, {}, {})\n\n".format(
        ciphertext.hex(), desl_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex(), iv.hex()))
    return DESXL(desl_key, pre_whiten_key_1, post_whiten_key_2).decrypt_ctr(ciphertext, iv)


if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) < 3:
        # output_file.close()
        exit()

    text = bytes.fromhex(sys.argv[2].strip())
    des_key = bytes.fromhex(sys.argv[3].strip())
    pre_whiten_key_1 = bytes.fromhex(sys.argv[4].strip())
    post_whiten_key_2 = bytes.fromhex(sys.argv[5].strip())

    # output_file_name = os.path.splitext(os.path.basename(__file__))[0] + ".txt"
    output_file_name = "output.txt"
    output_file = open(output_file_name, "w")

    if "encrypt_block".startswith(sys.argv[1]):
        ciphertext = encrypt_block(
            text, des_key, pre_whiten_key_1, post_whiten_key_2)
        output_file.write(
            "encrypt_block({}, {}, {}, {}):\nEncrypted message: {}\n\n".format(text, des_key, pre_whiten_key_1, post_whiten_key_2, ciphertext))
        output_file.write(
            "encrypt_block({}, {}, {}, {}):\nEncrypted message: {}\n".format(text.hex(), des_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex(), ciphertext.hex()))
        print_array_bit_diff_column(text, ciphertext)
        print(ciphertext.hex(), end="")
    elif "decrypt_block".startswith(sys.argv[1]):
        plaintext = decrypt_block(
            text, des_key, pre_whiten_key_1, post_whiten_key_2)
        output_file.write(
            "decrypt_block({}, {}, {}, {}):\nDecrypted message: {}\n\n".format(text, des_key, pre_whiten_key_1, post_whiten_key_2, plaintext))
        output_file.write(
            "decrypt_block({}, {}, {}, {}):\nDecrypted message: {}\n".format(text.hex(), des_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex(), plaintext.hex()))
        print_array_bit_diff_column(text, plaintext)
        print(plaintext.hex(), end="")
    elif "encrypt_ecb".startswith(sys.argv[1]):
        ciphertext = encrypt_ecb(
            text, des_key, pre_whiten_key_1, post_whiten_key_2)
        output_file.write(
            "encrypt_ecb({}, {}, {}, {}):\nEncrypted message: {}\n\n".format(text, des_key, pre_whiten_key_1, post_whiten_key_2, ciphertext))
        output_file.write(
            "encrypt_ecb({}, {}, {}, {}):\nEncrypted message: {}\n".format(text.hex(), des_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex(), ciphertext.hex()))
        print_array_bit_diff_column(text, ciphertext)
        print(ciphertext.hex(), end="")
    elif "decrypt_ecb".startswith(sys.argv[1]):
        plaintext = decrypt_ecb(
            text, des_key, pre_whiten_key_1, post_whiten_key_2)
        output_file.write(
            "decrypt_ecb({}, {}, {}, {}):\nDecrypted message: {}\n\n".format(text, des_key, pre_whiten_key_1, post_whiten_key_2, plaintext))
        output_file.write(
            "decrypt_ecb({}, {}, {}, {}):\nDecrypted message: {}\n".format(text.hex(), des_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex(), plaintext.hex()))
        print_array_bit_diff_column(text, plaintext)
        print(plaintext.hex(), end="")
    elif "encrypt_ctr".startswith(sys.argv[1]):
        iv = bytes.fromhex(sys.argv[6].strip())
        ciphertext = encrypt_ctr(
            text, des_key, pre_whiten_key_1, post_whiten_key_2, iv)
        output_file.write(
            "encrypt_ctr({}, {}, {}, {}, {}):\nEncrypted message: {}\n\n".format(text, des_key, pre_whiten_key_1, post_whiten_key_2, iv, ciphertext))
        output_file.write(
            "encrypt_ctr({}, {}, {}, {}, {}):\nEncrypted message: {}\n".format(text.hex(), des_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex(), iv.hex(), ciphertext.hex()))
        print_array_bit_diff_column(text, ciphertext)
        print(ciphertext.hex(), end="")
    elif "decrypt_ctr".startswith(sys.argv[1]):
        iv = bytes.fromhex(sys.argv[6].strip())
        plaintext = decrypt_ctr(
            text, des_key, pre_whiten_key_1, post_whiten_key_2, iv)
        output_file.write(
            "decrypt_ctr({}, {}, {}, {}, {}):\nDecrypted message: {}\n\n".format(text, des_key, pre_whiten_key_1, post_whiten_key_2, iv, plaintext))
        output_file.write(
            "decrypt_ctr({}, {}, {}, {}, {}):\nDecrypted message: {}\n".format(text.hex(), des_key.hex(), pre_whiten_key_1.hex(), post_whiten_key_2.hex(), iv.hex(), plaintext.hex()))
        print_array_bit_diff_column(text, plaintext)
        print(plaintext.hex(), end="")
    output_file.close()

# python3 desxl.py encrypt_block 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
# python3 desxl.py decrypt_block 26e2d9e7e71be11e 0123456789abcdef 0123456789abcdef 0123456789abcdef

# python3 desxl.py encrypt_ecb 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
# python3 desxl.py decrypt_ecb 26e2d9e7e71be11ed12c59fde93ca4b1 0123456789abcdef 0123456789abcdef 0123456789abcdef

# python3 desxl.py encrypt_ecb 0123456789abcdef 123456789abcdef0 23456789abcdef01 3456789abcdef012
# python3 desxl.py decrypt_ecb ec03f93c3ba9381744a8dcde25258f7e 123456789abcdef0 23456789abcdef01 3456789abcdef012

# python3 desxl.py encrypt_ecb 0123456789abcdefabcdef9876543210 123456789abcdef0 23456789abcdef01 3456789abcdef012
# python3 desxl.py decrypt_ecb ec03f93c3ba93817bcbb41eaf5baac9044a8dcde25258f7e 123456789abcdef0 23456789abcdef01 3456789abcdef012

# python3 desxl.py encrypt_ctr 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef 0000000000000001
# python3 desxl.py decrypt_ctr a3e6705c9eb08c28 0123456789abcdef 0123456789abcdef 0123456789abcdef 0000000000000001

# python3 desxl.py encrypt_ctr 0123456789abcdef 123456789abcdef0 23456789abcdef01 3456789abcdef012 0000000000000001
# python3 desxl.py decrypt_ctr 77278a987f7bbd71 123456789abcdef0 23456789abcdef01 3456789abcdef012 0000000000000001

# python3 desxl.py encrypt_ctr 0123456789abcdefabcdef9876543210 123456789abcdef0 23456789abcdef01 3456789abcdef012 0000000000000001
# python3 desxl.py decrypt_ctr 77278a987f7bbd71d496a61664262d6b 123456789abcdef0 23456789abcdef01 3456789abcdef012 0000000000000001