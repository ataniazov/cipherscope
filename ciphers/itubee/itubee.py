#!/usr/bin/env python3
"""
https://github.com/andrey-justo/ITUbee
"""
"""
Andrey Victor Justo
"""

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16
]
RC = [
    '1428', '1327', '1226', '1125', '1024', '0f23',
    '0e22', '0d21', '0c20', '0b1f', '0a1e', '091d',
    '081c', '071b', '061a', '0519', '0418', '0317',
    '0216', '0115'
]


def xor(list1, list2):
    list3 = []
    for i in range(0, len(list1)):
        list3 += [list1[i] ^ list2[i]]

    return list3


def generate_rc(i):
    # 16 bit round add to rc
    return [0, 0, 0, int(RC[i][0:2], 16), int(RC[i][2:4], 16)]


def generate_hexadecimal_array(text):
    return [int(text[x:x+2], 16) for x in range(0, len(text), 2)]


class ITUbee():

    def l(self, a):
        x = []
        x.append((a[4] ^ a[0]) ^ a[1])
        x.append((a[0] ^ a[1]) ^ a[2])
        x.append((a[1] ^ a[2]) ^ a[3])
        x.append((a[2] ^ a[3]) ^ a[4])
        x.append((a[3] ^ a[4]) ^ a[0])
        return x

    def f(self, a):
        temp_x = self.l(list(map(lambda x: SBOX[x & 255], a)))

        return list(map(lambda x: SBOX[x & 255], temp_x))

    def encrypt_block(self, message, key):
        h_message = generate_hexadecimal_array(message)
        h_key = generate_hexadecimal_array(key)

        x = []
        half = len(h_message) // 2
        pl = h_message[:half]
        pr = h_message[-half:]
        kl = h_key[:half]
        kr = h_key[-half:]
        x += [xor(pr, kr)]
        x += [xor(pl, kl)]

        for i in range(1, 21):
            rk = []

            if (i % 2 == 0):
                rk = kl
            else:
                rk = kr

            rc = generate_rc(i - 1)
            x += [xor(x[i - 1], self.f(self.l(xor(xor(rk, rc), self.f(x[i])))))]

        cl = xor(x[20], kr)
        cr = xor(x[21], kl)

        # return "".join(map(lambda x: '{0:02X}'.format(x), cl + cr))
        return bytes(cl+cr)

    def decrypt_block(self, enc_message, key):
        h_message = generate_hexadecimal_array(enc_message)
        h_key = generate_hexadecimal_array(key)

        x = []
        half = len(h_message) // 2
        pl = h_message[:half]
        pr = h_message[-half:]
        kl = h_key[:half]
        kr = h_key[-half:]
        x += [xor(pr, kl)]
        x += [xor(pl, kr)]

        for i in range(1, 21):
            rk = []

            if (i % 2 == 0):
                rk = kr
            else:
                rk = kl

            rc = generate_rc(-i)
            x += [xor(x[i - 1], self.f(self.l(xor(xor(rk, rc), self.f(x[i])))))]

        cl = xor(x[20], kl)
        cr = xor(x[21], kr)

        # return "".join(map(lambda x: '{0:02X}'.format(x), cl + cr))
        return bytes(cl+cr)

    def encrypt_ecb(self, plaintext, key):
        """
        Encrypts `plaintext` using ECB mode and PKCS#7 padding.
        """
        plaintext = pad(plaintext)

        blocks = []
        for plaintext_block in split_blocks(plaintext):
            # ECB mode encrypt: encrypt(plaintext_block)
            blocks.append(self.encrypt_block(plaintext_block.hex(), key.hex()))

        return b''.join(blocks)

    def decrypt_ecb(self, ciphertext, key):
        """
        Decrypts `ciphertext` using ECB mode and PKCS#7 padding.
        """

        blocks = []
        for ciphertext_block in split_blocks(ciphertext):
            # ECB mode decrypt: decrypt(ciphertext_block)
            blocks.append(self.decrypt_block(
                ciphertext_block.hex(), key.hex()))

        return unpad(b''.join(blocks))

    def encrypt_ctr(self, plaintext, key, iv):
        """
        Encrypts `plaintext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 10

        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            encrypted_nonce = self.encrypt_block(nonce.hex(), key.hex())
            block = xor_bytes(plaintext_block, encrypted_nonce)

            print_msg_box("Plaintext Block <XOR> Encrypted Nonce")
            output_file.write("xor_bytes({}, {})\nCiphertext Block: {}\n\n".format(
                plaintext_block.hex(), encrypted_nonce.hex(), block.hex()))

            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext, key, iv):
        """
        Decrypts `ciphertext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 10

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            encrypted_nonce = self.encrypt_block(nonce.hex(), key.hex())
            block = xor_bytes(ciphertext_block, encrypted_nonce)

            print_msg_box("Ciphertext Block <XOR> Encrypted Nonce")
            output_file.write("xor_bytes({}, {})\nPlaintext Block: {}\n\n".format(
                ciphertext_block.hex(), encrypted_nonce.hex(), block.hex()))

            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)


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
    Pads the given plaintext with PKCS#7 padding to a multiple of 10 bytes.
    Note that if the plaintext size is a multiple of 10,
    a whole block will be added.
    """
    output_file.write("pad({})\n".format(plaintext.hex()))
    padding_len = 10 - (len(plaintext) % 10)
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


def split_blocks(message, block_size=10, require_padding=True):
    assert len(message) % block_size == 0 or not require_padding
    return [message[i:i+block_size] for i in range(0, len(message), block_size)]


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
    return ITUbee().encrypt_block(plaintext.hex(), key.hex())


def decrypt_block(ciphertext, key):
    output_file.write("decrypt_block({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_block({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return ITUbee().decrypt_block(ciphertext.hex(), key.hex())


def encrypt_ecb(plaintext, key):
    output_file.write("encrypt_ecb({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_ecb({}, {})\n\n".format(
        plaintext.hex(), key.hex()))
    return ITUbee().encrypt_ecb(plaintext, key)


def decrypt_ecb(ciphertext, key):
    output_file.write("decrypt_ecb({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_ecb({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return ITUbee().decrypt_ecb(ciphertext, key)


def encrypt_ctr(plaintext, key, iv):
    output_file.write("encrypt_ctr({}, {}, {})\n".format(plaintext, key, iv))
    output_file.write("encrypt_ctr({}, {}, {})\n\n".format(
        plaintext.hex(), key.hex(), iv.hex()))
    return ITUbee().encrypt_ctr(plaintext, key, iv)


def decrypt_ctr(ciphertext, key, iv):
    output_file.write("decrypt_ctr({}, {}, {})\n".format(ciphertext, key, iv))
    output_file.write("decrypt_ctr({}, {}, {})\n\n".format(
        ciphertext.hex(), key.hex(), iv.hex()))
    return ITUbee().decrypt_ctr(ciphertext, key, iv)


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

    output_file.write("ITUbee\n\n")

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

# python3 itubee.py encrypt_block <plaintext> <key>
# python3 itubee.py encrypt_block
#                              "HelloWorld"             "SOME 80BIT"

# python3 itubee.py decrypt_block <ciphertext> <key>
# python3 itubee.py decrypt_block
#                                  <ciphertext>                  "SOME 80BIT"

# python3 itubee.py encrypt_ecb
# python3 itubee.py decrypt_ecb

# python3 itubee.py encrypt_ctr
# python3 itubee.py decrypt_ctr
