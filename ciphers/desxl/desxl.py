#!/usr/bin/env python
"""
https://github.com/ataniazov/cipherscope
"""
"""
Ata Niyazov
"""

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

    # def encrypt(self, message, initial=None, padding=False):
    #     """Encrypts the message with the key object.

    #     :param message: {bytes} The message to be encrypted
    #     :param initial: {union[bytes, int, long, NoneType]} The initial value, using CBC Mode when is not None
    #     :param padding: {any} Uses PKCS5 Padding when TRUTHY
    #     :return: {bytes} Encrypted bytes
    #     """
    #     return handle(message, self.__encryption_key, initial, padding, 1)

    # def decrypt(self, message, initial=None, padding=False):
    #     """Decrypts the encrypted message with the key object.

    #     :param message: {bytes} The message to be decrypted
    #     :param initial: {union[bytes, int, long, NoneType]} The initial value, using CBC Mode when is not None
    #     :param padding: {any} Uses PKCS5 Padding when TRUTHY
    #     :return: {bytes} Decrypted bytes
    #     """
    #     return handle(message, self.__decryption_key, initial, padding, 0)

    def encrypt(self, message, initial):
        """Encrypts the message with the key object.

        :param message: {bytes} The message to be encrypted
        :param initial: {union[bytes, int, long, NoneType]} The initial value, using CBC Mode when is not None
        :return: {bytes} Encrypted bytes
        """
        return handle_xex(message, self.__encryption_key, self.__key_1, self.__key_2, initial, 1)

    def decrypt(self, message, initial):
        """Decrypts the encrypted message with the key object.

        :param message: {bytes} The message to be decrypted
        :param initial: {union[bytes, int, long, NoneType]} The initial value, using CBC Mode when is not None
        :return: {bytes} Decrypted bytes
        """
        return handle_xex(message, self.__encryption_key, self.__key_1, self.__key_2, initial, 0)

    def __hash__(self):
        return hash((self.__class__, self.__encryption_key))

    # def encrypt_block(self, plaintext):
    #     # plaintext = bytes(pt ^ k1 for pt, k1 in zip(plaintext, self.__key_1))
    #     block = int.from_bytes(plaintext, byteorder='big', signed=False)
    #     # encoded_block = encode(block, self.__encryption_key, 1) ^ self.__key_2
    #     encoded_block = encode_xex(
    #         block, self.__encryption_key, self.__key_1, self.__key_2, 1)
    #     ciphertext = encoded_block.to_bytes(
    #         (encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False)
    #     # return bytes(ct ^ k2 for ct, k2 in zip(ciphertext, self.__key_2))
    #     return ciphertext

    # def decrypt_block(self, ciphertext):
    #     # ciphertext = bytes(ct ^ k2 for ct, k2 in zip(ciphertext, self.__key_2))
    #     block = int.from_bytes(ciphertext, byteorder='big', signed=False)
    #     # encoded_block = encode(block, self.__decryption_key, 0) ^ self.__key_1
    #     encoded_block = encode_xex(
    #         block, self.__decryption_key, self.__key_1, self.__key_2, 0)
    #     plaintext = encoded_block.to_bytes(
    #         (encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False)
    #     # return bytes(pt ^ k1 for pt, k1 in zip(plaintext, self.__key_1))
    #     return plaintext


# def encode(block, key, encryption):
#     for k in key:
#         block = encode_block(block, k, encryption)
#         encryption = not encryption

#     return block


def encode_xex(block, key, key_1, key_2, encryption):
    block ^= key_1 if encryption else key_2

    for k in key:
        block = encode_block(block, k, encryption)
        encryption = not encryption

    block ^= key_2 if encryption else key_1

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


# def guard_message(message, padding, encryption):
#     assert isinstance(message, bytes), "The message should be bytes"
#     length = len(message)
#     if encryption and padding:
#         return message.ljust(length + 8 >> 3 << 3, chr(8 - (length & 7)).encode())

#     assert length & 7 == 0, (
#         "The length of the message should be divisible by 8"
#         "(or set `padding` to `True` in encryption mode)"
#     )
#     return message


# def guard_initial(initial):
#     if initial is not None:
#         if isinstance(initial, bytearray):
#             initial = bytes(initial)
#         if isinstance(initial, bytes):
#             assert len(
#                 initial) & 7 == 0, "The initial value should be of length 8(as `bytes` or `bytearray`)"
#             return struct.unpack(">Q", initial)[0]
#         assert isinstance(
#             initial, number_type), "The initial value should be an integer or bytes object"
#         assert - \
#             1 < initial < 1 << 32, "The initial value should be in range [0, 2**32) (as an integer)"
#     return initial


# def handle(message, key, initial, padding, encryption):
#     message = guard_message(message, padding, encryption)
#     initial = guard_initial(initial)

#     blocks = (struct.unpack(">Q", message[i: i + 8])[0]
#               for i in iter_range(0, len(message), 8))

#     if initial is None:
#         # ECB
#         encoded_blocks = ecb(blocks, key, encryption)
#     else:
#         # CBC
#         encoded_blocks = cbc(blocks, key, initial, encryption)

#     ret = b"".join(struct.pack(">Q", block) for block in encoded_blocks)
#     return ret[:-ord(ret[-1:])] if not encryption and padding else ret


# def ecb(blocks, key, encryption):
#     for block in blocks:
#         yield encode(block, key, encryption)


# def cbc(blocks, key, initial, encryption):
#     if encryption:
#         for block in blocks:
#             initial = encode(block ^ initial, key, encryption)
#             yield initial
#     else:
#         for block in blocks:
#             initial, block = block, initial ^ encode(block, key, encryption)
#             yield block


# def ctr(blocks, key, initial):
#     for block in blocks:
#         block = block ^ encode(initial, key, 1)
#         initial += 1
#         yield block


def handle_xex(message, key, key_1, key_2, initial, encryption):
    blocks = [int.from_bytes(message[i:i+8], byteorder='big', signed=False)
              for i in iter_range(0, len(message), 8)]

    initial = int.from_bytes(initial, byteorder='big', signed=False)

    encoded_blocks = ctr_xex(blocks, key, key_1, key_2, initial)

    return b"".join(encoded_block.to_bytes((encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False) for encoded_block in encoded_blocks)


def ctr_xex(blocks, key, key_1, key_2, initial):
    for block in blocks:
        block = block ^ encode_xex(initial, key, key_1, key_2, 1)
        initial += 1
        yield block


try:
    bytes.fromhex
except AttributeError:
    def h2b(byte_string):
        return bytes(bytearray.fromhex(byte_string))
else:
    def h2b(byte_string):
        return bytes.fromhex(byte_string)

if __name__ == "__main__":
    # key = h2b("0000000000000000".strip())
    # plaintext = h2b("0000000000000000".strip())

    # des_key = h2b("0123456789ABCDEF".strip())
    # plaintext = h2b("0123456789ABCDEF".strip())

    # pre_whiten_key_1 = h2b("FEDCBA9876543210".strip())
    # post_whiten_key_2 = h2b("0123456789ABCDEF".strip())

    # plaintext = h2b("desdesxl".encode("utf-8").hex())
    # des_key = h2b("0123456789ABCDEF")

    # pre_whiten_key_1 = h2b("FEDCBA9876543210".strip())
    # post_whiten_key_2 = h2b("ABCDEF0123456789".strip())

    plaintext = h2b("0123456789ABCDEF".strip())
    des_key = h2b("0000000000000000".strip())

    pre_whiten_key_1 = h2b("0000000000000000".strip())
    post_whiten_key_2 = h2b("0000000000000000".strip())

    desxl = DESXL(des_key, pre_whiten_key_1, post_whiten_key_2)

    initial = h2b("FFFFFFFFFFFFFFFFFFFFFFFF".strip())
    ciphertext = desxl.encrypt(plaintext, initial)

    print("ciphertext: {}".format(ciphertext.hex()))

    decrypted_plaintext = desxl.decrypt(ciphertext, initial)

    print("plaintext: {}\ndecrypted_plaintext: {}".format(
        plaintext.hex(), decrypted_plaintext.hex()))