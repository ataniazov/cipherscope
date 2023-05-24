#!/usr/bin/env python3
"""
https://github.com/Daksh-Axel/Midori
"""


def sbox(state, base):
    Sb0 = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7,
           0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
    Sb1 = [0x1, 0x0, 0x5, 0x3, 0xe, 0x2, 0xf, 0x7,
           0xd, 0xa, 0x9, 0xb, 0xc, 0x8, 0x4, 0x6]
    if base == 64:
        for i in range(4):
            for j in range(4):
                state[i][j] = Sb0[state[i][j]]
    else:
        # base 128 construction of SSb_i
        y = []  # input bit permutation
        y.append([4, 1, 6, 3, 0, 5, 2, 7])  # SSb_0
        y.append([1, 6, 7, 0, 5, 2, 3, 4])  # SSb_1
        y.append([2, 3, 4, 1, 6, 7, 0, 5])  # SSb_2
        y.append([7, 4, 1, 2, 3, 0, 5, 6])  # SSb_3
        for i in range(4):
            for j in range(4):
                state_num = i*4+j
                bin_state = [bin(state[i][j])[2:].zfill(8)[k]
                             for k in range(8)]  # 8 bit state in binary
                per_state = [bin_state[y[state_num % 4][i]] for i in range(8)]
                # MSB
                MSB = ""
                MSB = Sb1[int(MSB.join(per_state[:4]), 2)]  # Sub byte
                MSB = [bin(MSB)[2:].zfill(4)[i] for i in range(4)]

                # LSB
                LSB = ""
                LSB = Sb1[int(LSB.join(per_state[4:]), 2)]  # Sub byte
                LSB = [bin(LSB)[2:].zfill(4)[i] for i in range(4)]

                # permutation inverse
                MSB.extend(LSB)
                per_state = MSB
                bin_state = [per_state[y[state_num %
                                         4].index(k)] for k in range(8)]
                bin_str = ""
                state[i][j] = int(bin_str.join(bin_state), 2)


def ShuffleCell(state):
    per = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8]
    new_state = [[0]*4 for i in range(4)]
    for i in range(len(state)):
        for j in range(len(state[0])):
            r = per[i*4+j]//4
            c = per[i*4+j] % 4
            new_state[i][j] = state[r][c]
    for i in range(len(state)):
        for j in range(len(state[0])):
            state[i][j] = new_state[i][j]


def InvShuffleCell(state):
    per = [0, 7, 14, 9, 5, 2, 11, 12, 15, 8, 1, 6, 10, 13, 4, 3]
    new_state = [[0]*4 for i in range(4)]
    for i in range(4):
        for j in range(4):
            r = per[i*4+j]//4
            c = per[i*4+j] % 4
            new_state[i][j] = state[r][c]
    for i in range(len(state)):
        for j in range(len(state[0])):
            state[i][j] = new_state[i][j]


def MixColumn(state):
    M = [[0, 1, 1, 1], [1, 0, 1, 1], [1, 1, 0, 1], [1, 1, 1, 0]]
    new_state = [[0]*4 for i in range(4)]
    for r in range(4):
        for i in range(4):
            sum = 0
            for j in range(4):
                sum ^= M[i][j]*state[r][j]
            new_state[r][i] = sum
    for i in range(4):
        for j in range(4):
            state[i][j] = new_state[i][j]

# key addition function


def KeyAdd(state, key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]


def round_key_generation(base, key, round_num):
    beta = [[3, 5, 7, 8, 10, 11, 14, 15],
            [1, 2, 3, 4, 8, 9],
            [0, 2, 5, 10, 11, 13, 15],
            [1, 2, 6, 11, 14, 15],
            [3, 9, 12, 13, 14, 15],
            [0, 1, 3, 7, 9, 10, 11],
            [6, 9, 10, 13, 14],
            [4, 6, 7, 8, 9, 12, 13],
            [0, 3, 5, 8, 15],
            [1, 8, 10, 11, 12],
            [1, 2, 3, 7, 8, 11, 13, 14, 15],
            [2, 6, 8, 12, 13, 14],
            [1, 3, 7, 10, 11],
            [0, 1, 2, 3, 4, 8, 9, 12, 14],
            [0, 1, 3, 4, 5, 6, 7, 8, 11],
            [1, 2, 3, 4, 5, 8, 15],
            [3, 4, 5, 10, 13],
            [2, 6, 7, 8, 10, 11, 13],
            [1, 2, 6, 8, 12, 14]]
    RK = []
    if base == 64:
        k0 = key[2:18]
        k1 = key[18:]

        if round_num % 2 == 0:
            for i in range(4):
                RK.append([int(k0[i*4+j], 16) for j in range(4)])
        else:
            for i in range(4):
                RK.append([int(k1[i*4+j], 16) for j in range(4)])
        for ind in beta[round_num]:
            r = ind//4
            c = ind % 4
            RK[r][c] ^= 1

    else:

        for i in range(4):
            RK.append([int(key[i*4+j+2:i*4+j+4], 16) for j in range(0, 8, 2)])
        for ind in beta[round_num]:
            r = ind//4
            c = ind % 4
            RK[r][c] ^= 1
    return RK


def White_Key(key, base):

    if base == 64:
        k0 = key[2:18]
        k1 = key[18:]
        WK = [[0]*4 for i in range(4)]
        WK0 = []
        WK1 = []
        for i in range(4):
            WK0.append([int(k0[i*4+j], 16) for j in range(4)])
        for i in range(4):
            WK1.append([int(k1[i*4+j], 16) for j in range(4)])
        for i in range(4):
            for j in range(4):
                WK[i][j] = WK0[i][j] ^ WK1[i][j]
        return WK
    else:
        WK = []
        for i in range(4):
            WK.append([int(key[i*4+j+2:i*4+j+4], 16) for j in range(0, 8, 2)])
        return WK


def encrypt(plaintext, key, base):
    state = hex_to_matrix(plaintext)
    WK = White_Key(key, base)
    KeyAdd(state, WK)
    t_round = 16
    if base == 128:
        t_round = 20
    for round in range(t_round-1):
        sbox(state, base)
        ShuffleCell(state)
        MixColumn(state)
        KeyAdd(state,  round_key_generation(base, key, round))
    sbox(state, base)
    KeyAdd(state, WK)
    return matrix_to_hex(state)


def decrypt(ciphertext, key, base):
    state = hex_to_matrix(ciphertext)
    WK = White_Key(key, base)
    KeyAdd(state, WK)
    t_round = 16
    if base == 128:
        t_round = 20
    for round in range(t_round-2, -1, -1):
        sbox(state, base)
        MixColumn(state)
        InvShuffleCell(state)
        RKi = round_key_generation(base, key, round)
        MixColumn(RKi)
        InvShuffleCell(RKi)
        KeyAdd(state, RKi)
    sbox(state, base)
    KeyAdd(state, WK)
    return matrix_to_hex(state)


def hex_to_matrix(hex_string):
    # Remove any whitespace characters from the string
    hex_string = hex_string.replace(" ", "")
    # Convert the hexadecimal string to a list of 16 integers
    hex_list = [int(hex_string[i:i+2], 16)
                for i in range(0, len(hex_string), 2)]
    # Create a 4x4 matrix from the list
    matrix = [hex_list[i:i+4] for i in range(0, len(hex_list), 4)]
    return matrix


def matrix_to_hex(matrix):
    # Flatten the matrix into a single list
    flat_list = [item for sublist in matrix for item in sublist]

    # Convert the integers to hexadecimal strings
    hex_list = [format(num, '02x') for num in flat_list]

    # Join the hexadecimal strings to form the final string
    return ''.join(hex_list)


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
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    output_file.write("pad({})\n".format(plaintext.hex()))
    padding_len = 16 - (len(plaintext) % 16)
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


def split_blocks(message, block_size=16, require_padding=True):
    output_file.write("split_blocks({})\n".format(message.hex()))
    assert len(message) % block_size == 0 or not require_padding
    return [message[i:i+block_size] for i in range(0, len(message), block_size)]


def encrypt_block(plaintext, key):
    output_file.write("encrypt_block({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_block({}, {})\n\n".format(
        plaintext.hex(), key.hex()))
    return bytes.fromhex(encrypt(plaintext.hex(), key.hex(), 128))


def decrypt_block(ciphertext, key):
    output_file.write("decrypt_block({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_block({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return bytes.fromhex(decrypt(ciphertext.hex(), key.hex(), 128))


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

    assert len(iv) == 16

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

    assert len(iv) == 16

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

    output_file.write("Midori\n\n")

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

# python3 midori.py encrypt_block <plaintext> <key>
# python3 midori.py encrypt_block 41545441434b204154204441574e2101 534f4d452031323820424954204b4559
#                                     "ATTACK AT DAWN!\x01"             "SOME 128 BIT KEY"

# python3 midori.py decrypt_block <ciphertext> <key>
# python3 midori.py decrypt_block 6e33815a84448597c84fb38dc637df45 534f4d452031323820424954204b4559
#                                           <ciphertext>                  "SOME 128 BIT KEY"

# python3 midori.py encrypt_ecb 41545441434b204154204441574e2101 534f4d452031323820424954204b4559
# python3 midori.py decrypt_ecb 6e33815a84448597c84fb38dc637df450d40e9f033a7e0ad66c8e2f62fceddf0 534f4d452031323820424954204b4559

# python3 midori.py encrypt_ctr 41545441434b204154204441574e2101 534f4d452031323820424954204b4559 00000000000000000000000000000000
# python3 midori.py decrypt_ctr d908976c16f6a74bdb2187a16d0bfaa7 534f4d452031323820424954204b4559 00000000000000000000000000000000


# Midori128
# Plaintext : 00000000000000000000000000000000
# Key: 00000000000000000000000000000000
# Ciphertext : c055cbb95996d14902b60574d5e728d6

# Plaintext : 51084ce6e73a5ca2ec87d7babc297543
# Key: 687ded3b3c85b3f35b1009863e2a8cbf
# Ciphertext : 1e0ac4fddff71b4c1801b73ee4afc83d

# Midori64
# Plaintext : 0000000000000000
# Key: 00000000000000000000000000000000
# Ciphertext : 3c9cceda2bbd449a

# Plaintext : 42c20fd3b586879e
# Key: 687ded3b3c85b3f35b1009863e2a8cbf
# Ciphertext : 66bcdc6270d901cd
