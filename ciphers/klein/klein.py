#!/usr/bin/env python3
"""
https://github.com/joostrijneveld/readable-crypto
https://asecuritysite.com/encryption/klein
"""
"""
Joost Rijneveld
"""

SBOX = [0x7, 0x4, 0xA, 0x9, 0x1, 0xF, 0xB, 0x0,
        0xC, 0x3, 0x2, 0x6, 0x8, 0xE, 0xD, 0x5]


def sbox_nibble(bits, i, N):
    """Replaces the i-th nibble (0-base) in N bits with SBOX[nibble]."""
    offset = N - (i+1)*4
    nibble = (bits >> offset) & 0xF  # fetch the nibble
    return bits & ~(0xF << offset) | (SBOX[nibble] << offset)  # add back in


class KLEIN(object):

    def __init__(self, nr=12, size=64):
        self.nr = nr
        self.size = size

    def addRoundKey(self, state, sk):
        return state ^ (sk >> self.size-64) & 0xFFFFFFFFFFFFFFFF

    def subNibbles(self, state):
        for i in range(16):
            state = sbox_nibble(state, i, 64)
        return state

    def rotateNibbles(self, state):
        return (state << 16) & 0xFFFFFFFFFFFFFFFF | (state >> 48)

    def mixNibbles(self, state):
        def mix_columns(bits):
            c01 = 0xFF & (bits >> 24)
            c23 = 0xFF & (bits >> 16)
            c45 = 0xFF & (bits >> 8)
            c67 = 0xFF & bits

            def mul2or3(x, n):  # this is not nearly as generic as galoisMult
                x = (x << 1) if n == 2 else ((x << 1) ^ x)
                if x > 0xFF:
                    return (x ^ 0x1B) & 0xFF
                return x

            s01 = mul2or3(c01, 2) ^ mul2or3(c23, 3) ^ c45 ^ c67
            s23 = c01 ^ mul2or3(c23, 2) ^ mul2or3(c45, 3) ^ c67
            s45 = c01 ^ c23 ^ mul2or3(c45, 2) ^ mul2or3(c67, 3)
            s67 = mul2or3(c01, 3) ^ c23 ^ c45 ^ mul2or3(c67, 2)
            return s01 << 24 | s23 << 16 | s45 << 8 | s67

        col1 = mix_columns(state >> 32)
        col2 = mix_columns(state & 0xFFFFFFFFFFFFFFFF)
        return col1 << 32 | col2

    def keySchedule(self, sk, i):
        a = (sk >> self.size//2)
        b = sk & int('1' * (self.size//2), 2)
        a = (a << 8) & int('1' * (self.size//2), 2) | (a >> (self.size//2 - 8))
        b = (b << 8) & int('1' * (self.size//2), 2) | (b >> (self.size//2 - 8))
        a ^= b
        a, b = b, a
        a ^= i << (self.size//2 - 24)
        for i in range(2, 6):
            b = sbox_nibble(b, i, self.size//2)
        return a << self.size//2 | b

    def encrypt(self, key, plaintext):
        state = plaintext
        sk = key
        for i in range(1, self.nr+1):
            state = self.addRoundKey(state, sk)
            state = self.subNibbles(state)
            state = self.rotateNibbles(state)
            state = self.mixNibbles(state)
            sk = self.keySchedule(sk, i)
        state = self.addRoundKey(state, sk)
        return state


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


def encrypt(plaintext, key):
    output_file.write("encrypt({}, {})\n".format(plaintext, key))
    output_file.write("encrypt({}, {})\n\n".format(plaintext.hex(), key.hex()))

    k = int.from_bytes(key, byteorder='big', signed=False)
    m = int.from_bytes(plaintext, byteorder='big', signed=False)
    mac = KLEIN(nr=12, size=64).encrypt(k, m)

    return mac.to_bytes((mac.bit_length() + 7) // 8, byteorder='big', signed=False)


if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) < 3:
        # output_file.close()
        exit()

    text = bytes.fromhex(sys.argv[2].strip())
    key = bytes.fromhex(sys.argv[3].strip())
    # text = sys.argv[2].strip()
    # key = sys.argv[3].strip()

    # output_file_name = os.path.splitext(os.path.basename(__file__))[0] + ".txt"
    output_file_name = "output.txt"
    output_file = open(output_file_name, "w")

    output_file.write("KLEIN\n\n")

    if "encrypt".startswith(sys.argv[1]):
        ciphertext = encrypt(text, key)
        output_file.write(
            "encrypt({}, {}):\nEncrypted message: {}\n\n".format(text, key, ciphertext))
        output_file.write(
            "encrypt({}, {}):\nEncrypted message: {}\n".format(text.hex(), key.hex(), ciphertext.hex()))
        print_array_bit_diff_column(text, ciphertext)
        print(ciphertext.hex(), end="")
    output_file.close()

# Message:	 KLEIN
# Key:		 Hello
# KLEIN64 (NR=12, Size=64):	 0x8e741a4d91b5be41
# KLEIN80 (NR=16, Size=80):	 0x505f98f812acfecc
# KLEIN96 (NR=20, Size=96):	 0x6c9ee592521314ac

# Test vectors for KLEIN-64
# Message
# FFFF FFFF FFFF FFFF
# 0000 0000 0000 0000
# FFFF FFFF FFFF FFFF
# 1234 5678 90AB CDEF

# Key
# 0000 0000 0000 0000
# FFFF FFFF FFFF FFFF
# 1234 5678 90AB CDEF
# 0000 0000 0000 0000

# Cipher
# CDC0 B51F 1472 2BBE
# 6456 764E 8602 E154
# 5923 56C4 9971 76C8
# 629F 9D6D FF95 800E


# Test vectors for KLEIN-80
# Message
# FFFF FFFF FFFF FFFF
# 0000 0000 0000 0000
# FFFF FFFF FFFF FFFF
# 1234 5678 90AB CDEF

# Key
# 0000 0000 0000 0000 0000
# FFFF FFFF FFFF FFFF FFFF
# 1234 5678 90AB CDEF 1234
# 0000 0000 0000 0000 0000

# Cipher
# 6677 E20D 1A53 A431
# 8224 7502 273D CC5F
# 3F21 0F67 CB23 687A
# BA52 39E9 3E78 4366


# Test vectors for KLEIN-96
# Message
# FFFF FFFF FFFF FFFF
# 0000 0000 0000 0000
# FFFF FFFF FFFF FFFF
# 1234 5678 90AB CDEF

# Key                               
# 0000 0000 0000 0000 0000 0000     
# FFFF FFFF FFFF FFFF FFFF FFFF     
# 1234 5678 90AB CDEF 1234 5678     
# 0000 0000 0000 0000 0000 0000     

# Cipher
# DB9F A7D3 3D8E 8E36
# 15A3 A033 86A7 FEC6
# 7968 7798 AFDA 0BC3
# 5006 A987 A500 BFDD