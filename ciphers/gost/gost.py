#!/usr/bin/env python3
"""
https://github.com/SantonioTheFirst/GOST28147_89
"""

import struct


class GOST28147_89:
    def __init__(self):
        self._mod = 1 << 32
        # Central Bank of Russian Federation uses this S-boxes
        self._s_box = (
            (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
            (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
            (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
            (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
            (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
            (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
            (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
            (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
        )

    # Nonlinear function

    def f(self, right, k_i):
        right = (right + k_i) & 0xFFFFFFFF  # % self._mod
        # print(f'Temp: {hex(right)}')
        right = self.s(right)
        output = ((right << 11) & 0xFFFFFFFF) | (right >> 21)
        # print(f'F_output: {hex(output)}')
        return output

    # Substitution

    def s(self, right):
        result = 0
        for i in range(8):
            result |= ((self._s_box[i][(right >> (4 * i)) & 0xf]) << (4 * i))
        return result

    def encryption_round(self, input_left, input_right, round_key):
        output_left = input_right
        output_right = input_left ^ self.f(
            input_right, round_key)  # calculate right part
        return output_left, output_right

    def decryption_round(self, input_left, input_right, round_key):
        output_right = input_left
        output_left = input_right ^ self.f(input_left, round_key)
        return output_left, output_right

    def encrypt(self, block, key):
        left, right = block >> 32, block & 0xFFFFFFFF  # left-right partition
        for i in range(32):
            # K_0, ..., K_7 for i < 24 and K_7, ..., K_0 for i >= 24
            k_i = key[i % 8] if i < 24 else key[7 - (i % 8)]
            left, right = self.encryption_round(left, right, k_i)
        return (left << 32) | right  # make 64 bit block

    def decrypt(self, block, key):
        left, right = block >> 32, block & 0xFFFFFFFF  # left-right partition
        for i in range(32):
            # K_0, ..., K_7 for i < 8 and K_7, ..., K_0 for i >= 8
            k_i = key[i] if i < 8 else key[7 - (i % 8)]
            left, right = self.decryption_round(left, right, k_i)
        return (left << 32) | right  # make 64 bit block


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
    key = struct.unpack('<8I', key)
    plaintext = int.from_bytes(plaintext, byteorder='big', signed=False)
    gost = GOST28147_89()
    encoded_block = gost.encrypt(plaintext, key)
    ciphertext = encoded_block.to_bytes(
        (encoded_block.bit_length() + 7) // 8, byteorder='big', signed=False)
    return ciphertext


def decrypt_block(ciphertext, key):
    output_file.write("decrypt_block({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_block({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    key = struct.unpack('<8I', key)
    ciphertext = int.from_bytes(ciphertext, byteorder='big', signed=False)
    gost = GOST28147_89()
    encoded_block = gost.decrypt(ciphertext, key)
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

    output_file.write("GOST\n\n")

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

# python3 gost.py encrypt_block <plaintext> <key>
# python3 gost.py encrypt_block 486920576f726c64 534f4d452056455259204c4f4e472032353620424954204b455920494e505554
#                                  "Hi World"                  "SOME VERY LONG 256 BIT KEY INPUT"

# python3 gost.py decrypt_block <ciphertext> <key>
# python3 gost.py decrypt_block 3f52d3595470aada 534f4d452056455259204c4f4e472032353620424954204b455920494e505554
#                                 <ciphertext>                 "SOME VERY LONG 256 BIT KEY INPUT"

# python3 gost.py encrypt_ecb 486920576f726c64 534f4d452056455259204c4f4e472032353620424954204b455920494e505554
# python3 gost.py decrypt_ecb 3f52d3595470aada4cac10156cf9a450 534f4d452056455259204c4f4e472032353620424954204b455920494e505554

# python3 gost.py encrypt_ctr 486920576f726c64 534f4d452056455259204c4f4e472032353620424954204b455920494e505554 0000000000000000
# python3 gost.py decrypt_ctr 8d6650cde9d6db85 534f4d452056455259204c4f4e472032353620424954204b455920494e505554 0000000000000000
