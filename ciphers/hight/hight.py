#!/usr/bin/env python3
"""
https://github.com/DenseLance/HIGHT-Python
"""
"""
Lance Chin
"""


def list_to_byte(lst):
    byte = 0
    for bit in lst:
        byte = (byte << 1) | bit
    return byte


def rotate_bits(x, n):  # shift bits leftward
    return ((x << n) % 256) | (x >> (8 - n))


def whitening_key_generation(MK):
    WK = [None] * 8
    for i in range(4):
        WK[i] = MK[i + 12]
        WK[i + 4] = MK[i]
    return WK


def constant_generation():
    s = [0, 1, 0, 1, 1, 0, 1]
    delta = [list_to_byte(s[::-1])]
    for i in range(1, 128):
        s.append(s[i + 2] ^ s[i - 1])
        delta.append(list_to_byte(s[i:i + 7][::-1]))
    return delta


def subkey_generation(delta, MK):
    SK = [None] * 128
    for i in range(8):
        for j in range(8):
            SK[16 * i + j] = (MK[(j - i) % 8] + delta[16 * i + j]) % 256
        for j in range(8):
            SK[16 * i + j + 8] = (MK[(j - i) % 8 + 8] +
                                  delta[16 * i + j + 8]) % 256
    return SK


def encryption_key_schedule(MK):
    delta = constant_generation()
    WK = whitening_key_generation(MK)
    SK = subkey_generation(delta, MK)
    return WK, SK


def decryption_key_schedule(MK):
    delta = constant_generation()
    WK = whitening_key_generation(MK)
    SK = subkey_generation(delta, MK)[::-1]
    return WK, SK


def encryption_initial_transformation(P, WK):
    X_0 = [
        (P[0] + WK[0]) % 256,
        P[1],
        P[2] ^ WK[1],
        P[3],
        (P[4] + WK[2]) % 256,
        P[5],
        P[6] ^ WK[3],
        P[7]
    ]
    return X_0


def decryption_initial_transformation(C, WK):
    X_0 = [
        C[7],
        (C[0] - WK[4]) % 256,
        C[1],
        C[2] ^ WK[5],
        C[3],
        (C[4] - WK[6]) % 256,
        C[5],
        C[6] ^ WK[7]
    ]
    return X_0


def f_0(x):
    return rotate_bits(x, 1) ^ rotate_bits(x, 2) ^ rotate_bits(x, 7)


def f_1(x):
    return rotate_bits(x, 3) ^ rotate_bits(x, 4) ^ rotate_bits(x, 6)


def encryption_round_function(i, X_i, SK):
    X_j = [
        X_i[7] ^ ((f_0(X_i[6]) + SK[4 * i + 3]) % 256),
        X_i[0],
        (X_i[1] + (f_1(X_i[0]) ^ SK[4 * i])) % 256,
        X_i[2],
        X_i[3] ^ ((f_0(X_i[2]) + SK[4 * i + 1]) % 256),
        X_i[4],
        (X_i[5] + (f_1(X_i[4]) ^ SK[4 * i + 2])) % 256,
        X_i[6]
    ]
    return X_j


def decryption_round_function(i, X_i, SK):
    X_j = [
        X_i[1],
        (X_i[2] - (f_1(X_i[1]) ^ SK[4 * i + 3])) % 256,
        X_i[3],
        X_i[4] ^ ((f_0(X_i[3]) + SK[4 * i + 2]) % 256),
        X_i[5],
        (X_i[6] - (f_1(X_i[5]) ^ SK[4 * i + 1])) % 256,
        X_i[7],
        X_i[0] ^ ((f_0(X_i[7]) + SK[4 * i]) % 256)
    ]
    return X_j


def encryption_final_transformation(X_32, WK):
    C = [
        (X_32[1] + WK[4]) % 256,
        X_32[2],
        X_32[3] ^ WK[5],
        X_32[4],
        (X_32[5] + WK[6]) % 256,
        X_32[6],
        X_32[7] ^ WK[7],
        X_32[0]
    ]
    return C


def decryption_final_transformation(X_32, WK):
    D = [
        (X_32[0] - WK[0]) % 256,
        X_32[1],
        X_32[2] ^ WK[1],
        X_32[3],
        (X_32[4] - WK[2]) % 256,
        X_32[5],
        X_32[6] ^ WK[3],
        X_32[7]
    ]
    return D


def encryption_transformation(P, WK, SK):
    X_i = encryption_initial_transformation(P, WK)
    for i in range(32):
        X_i = encryption_round_function(i, X_i, SK)
    C = encryption_final_transformation(X_i, WK)
    return C


def decryption_transformation(C, WK, SK):
    X_i = decryption_initial_transformation(C, WK)
    for i in range(32):
        X_i = decryption_round_function(i, X_i, SK)
    D = decryption_final_transformation(X_i, WK)
    return D


def hight_encryption(P, MK):
    WK, SK = encryption_key_schedule(MK)
    C = encryption_transformation(P, WK, SK)
    return C


def hight_decryption(C, MK):
    WK, SK = decryption_key_schedule(MK)
    D = decryption_transformation(C, WK, SK)
    return D


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

# def cbc_hight_encryption(P, IV, MK):
#     assert not len(P) % 8 and P
#     assert all(0 <= byte <= 0xFF for byte in P)
#     assert len(IV) == 8
#     assert all(0 <= byte <= 0xFF for byte in IV)
#     assert len(MK) == 16
#     assert all(0 <= byte <= 0xFF for byte in MK)

#     WK, SK = encryption_key_schedule(MK)
#     C = encryption_transformation(
#         [P_i ^ IV_i for P_i, IV_i in zip(P[:8], IV)], WK, SK)
#     for block in range(8, len(P), 8):
#         C += encryption_transformation([P_i ^ C_i for P_i, C_i in zip(
#             P[block:block + 8], C[block - 8:block])], WK, SK)
#     return C


# def cbc_hight_decryption(C, IV, MK):
#     assert not len(C) % 8 and C
#     assert all(0 <= byte <= 0xFF for byte in C)
#     assert len(IV) == 8
#     assert all(0 <= byte <= 0xFF for byte in IV)
#     assert len(MK) == 16
#     assert all(0 <= byte <= 0xFF for byte in MK)

#     WK, SK = decryption_key_schedule(MK)
#     D = [C_i ^ IV_i for C_i, IV_i in zip(
#         decryption_transformation(C[:8], WK, SK), IV)]
#     for block in range(8, len(C), 8):
#         D += [C_i ^ D_i for C_i, D_i in zip(decryption_transformation(
#             C[block:block + 8], WK, SK), C[block - 8:block])]
#     return D


def ecb_hight_encryption(P, MK):
    assert not len(P) % 8 and P
    assert all(0 <= byte <= 0xFF for byte in P)
    assert len(MK) == 16
    assert all(0 <= byte <= 0xFF for byte in MK)

    WK, SK = encryption_key_schedule(MK)
    C = encryption_transformation(P, WK, SK)
    for block in range(8, len(P), 8):
        C += encryption_transformation(P[block:block + 8], WK, SK)
    return C


def ecb_hight_decryption(C, MK):
    assert not len(C) % 8 and C
    assert all(0 <= byte <= 0xFF for byte in C)
    assert len(MK) == 16
    assert all(0 <= byte <= 0xFF for byte in MK)

    WK, SK = decryption_key_schedule(MK)
    D = decryption_transformation(C, WK, SK)
    for block in range(8, len(C), 8):
        D += decryption_transformation(C[block:block + 8], WK, SK)
    return D


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
    return bytes(hight_encryption(list(plaintext), list(key)))


def decrypt_block(ciphertext, key):
    output_file.write("decrypt_block({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_block({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return bytes(hight_decryption(list(ciphertext), list(key)))


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

    output_file.write("HIGHT\n\n")

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

# python3 hight.py encrypt_block <plaintext> <key>
# python3 hight.py encrypt_block 486920576f726c64 534f4d452031323820424954204b4559
#                                "Hi World"              "SOME 128 BIT KEY"

# python3 hight.py decrypt_block <ciphertext> <key>
# python3 hight.py decrypt_block f0c93f321a5f394f 534f4d452031323820424954204b4559
#                                  <ciphertext>          "SOME 128 BIT KEY"

# python3 hight.py encrypt_ecb 486920416e6f7468657220576f726c64 534f4d452031323820424954204b4559
# python3 hight.py decrypt_ecb 7a7028c492c17a246b1ed43284194cfe0b643e934546f62d 534f4d452031323820424954204b4559

# python3 hight.py encrypt_ctr 486920416e6f7468657220576f726c64 534f4d452031323820424954204b4559 0000000000000000
# python3 hight.py decrypt_ctr f8af14eb63b6fc610b1043e04f47f2f6 534f4d452031323820424954204b4559 0000000000000000
