#!/usr/bin/env python3

output_file = ""

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)


def sub_bytes(s):
    output_file.write("sub_bytes()\n")
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    output_file.write("inv_sub_bytes()\n")
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    output_file.write("shift_rows()\n")
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    output_file.write("inv_shift_rows()\n")
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def add_round_key(s, k):
    output_file.write("add_round_key()\n")
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


# learned from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
def xtime(a): return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    output_file.write("mix_columns()\n")
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    output_file.write("inv_mix_columns()\n")
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))


def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i ^ j for i, j in zip(a, b))


def inc_bytes(a):
    """ Returns a new byte array with the value increment by 1 """
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)


def split_blocks(message, block_size=16, require_padding=True):
    assert len(message) % block_size == 0 or not require_padding
    return [message[i:i+16] for i in range(0, len(message), block_size)]


def print_matrix(matrix, indent=8):
    assert isinstance(matrix, list), f"\"{matrix}\" is not matrix!"
    rows = len(matrix)
    if rows > 0:
        # assert all(isinstance(row, list)
        #            for row in matrix), f"\"{matrix}\" is not matrix!"
        cols = len(matrix[0])
        if cols == 0:
            return
    else:
        return

    buf = ""

    for row in range(rows):
        buf += " " * indent
        buf += "+----" * cols + "+" * (1 if cols > 0 else 0) + "\n"

        buf += " " * indent

        for col in range(cols):
            buf += "| {:02X} ".format(matrix[row][col])
        buf += "|\n"

    buf += " " * indent
    buf += "+----" * cols + "+" * (1 if cols > 0 else 0) + "\n"

    output_file.write(buf)


def print_2_matrix(matrix_1, matrix_2, indent=8, gap=4):
    assert isinstance(matrix_1, list), f"\"{matrix_1}\" is not matrix!"
    rows_m1 = len(matrix_1)
    if rows_m1 > 0:
        # assert all(isinstance(row, list)
        #            for row in matrix_1), f"\"{matrix_1}\" is not matrix!"
        cols_m1 = len(matrix_1[0])
    else:
        cols_m1 = 0
        gap = 0

    assert isinstance(matrix_2, list), f"\"{matrix_2}\" is not matrix!"
    rows_m2 = len(matrix_2)
    if rows_m2 > 0:
        # assert all(isinstance(row, list)
        #            for row in matrix_2), f"\"{matrix_2}\" is not matrix!"
        cols_m2 = len(matrix_2[0])
    else:
        cols_m2 = 0
        gap = 0

    rows = rows_m1 if rows_m1 > rows_m2 else rows_m2

    if rows == 0:
        return

    buf = ""

    for row in range(rows):
        buf += " " * indent

        if rows_m1 >= row:
            buf += "+----" * cols_m1 + "+" * \
                (1 if cols_m1 > 0 else 0) + " " * gap
        else:
            buf += " " * 5 * cols_m1 + " " * \
                (1 if cols_m1 > 0 else 0) + " " * gap

        if rows_m2 >= row:
            buf += "+----" * cols_m2 + "+" * (1 if cols_m2 > 0 else 0)
        buf += "\n"

        buf += " " * indent
        if row < rows_m1:
            for col in range(cols_m1):
                buf += "| {:02X} ".format(matrix_1[row][col])
            buf += "|" + " " * gap
        else:
            buf += " " * 5 * cols_m1 + " " * \
                (1 if cols_m1 > 0 else 0) + " " * gap

        if row < rows_m2:
            for col in range(cols_m2):
                buf += "| {:02X} ".format(matrix_2[row][col])
            buf += "|"
        buf += "\n"

    buf += " " * indent

    if rows_m1 >= rows:
        buf += "+----" * cols_m1 + "+" * (1 if cols_m1 > 0 else 0) + " " * gap
    else:
        buf += " " * 5 * cols_m1 + " " * (1 if cols_m1 > 0 else 0) + " " * gap

    if rows_m2 >= rows:
        buf += "+----" * cols_m2 + "+" * (1 if cols_m2 > 0 else 0)

    output_file.write(buf + "\n")


def print_matrix_transpose(matrix, indent=8):
    transpose = list(zip(*matrix))
    print_matrix(transpose, indent)


def print_2_matrix_transpose(matrix_1, matrix_2, indent=8, gap=4):
    transpose_m1 = list(zip(*matrix_1))
    transpose_m2 = list(zip(*matrix_2))
    print_2_matrix(transpose_m1, transpose_m2, indent, gap)


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


class AES:
    """
    Class for AES-128 encryption with CBC mode and PKCS#7.

    This is a raw implementation of AES, without key stretching or IV
    management. Unless you need that, please use `encrypt` and `decrypt`.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, master_key):
        output_file.write(
            "__init__(master_key: {})\n".format(master_key.hex()))
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        output_file.write("rounds_by_key_size: {}\n\n".format(self.n_rounds))
        self._key_matrices = self._expand_key(master_key)

        output_file.write("Key:\n")
        print_matrix_transpose(self._key_matrices[0])
        output_file.write("\n")

        for i in range(1, len(self._key_matrices)):
            output_file.write("Key {}:\n".format(i))
            print_matrix_transpose(self._key_matrices[i])
            output_file.write("\n")

        # output_file.write(str((matrix2bytes(self._key_matrices[0])).hex()))
        # output_file.write(self._key_matrices[0])
        # output_file.write("\n")

        # for i in range(1, len(self._key_matrices)):
        #     output_file.write("\n")
        #     for j in range(len(self._key_matrices[i])):
        #         output_file.write(str(self._key_matrices[i][j].hex()), end="\n")
        #     output_file.write("\n")

    def _expand_key(self, master_key):
        output_file.write(
            "_expand_key(master_key: {})\n".format(master_key.hex()))
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i: 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        output_file.write(
            "encrypt_block(plaintext: {})\n".format(plaintext.hex()))
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        output_file.write("plaintext:\n")
        print_matrix_transpose(plain_state)
        output_file.write("\n")

        add_round_key(plain_state, self._key_matrices[0])
        print_2_matrix_transpose(plain_state, self._key_matrices[0])
        # print_matrix_transpose(self._key_matrices[0])

        # output_file.write("plain_state:\n")
        # print_matrix_transpose(plain_state)
        output_file.write("\n")

        for i in range(1, self.n_rounds):
            print_msg_box("Round: {:2}".format(i))

            sub_bytes(plain_state)
            print_matrix_transpose(plain_state)
            output_file.write("\n")

            shift_rows(plain_state)
            print_matrix_transpose(plain_state)
            output_file.write("\n")

            mix_columns(plain_state)
            print_matrix_transpose(plain_state)
            output_file.write("\n")

            add_round_key(plain_state, self._key_matrices[i])
            print_2_matrix_transpose(plain_state, self._key_matrices[i])
            # print_matrix_transpose(self._key_matrices[i])
            # output_file.write("plain_state:\n")
            # print_matrix_transpose(plain_state)
            output_file.write("\n")

        sub_bytes(plain_state)
        print_matrix_transpose(plain_state)
        output_file.write("\n")

        shift_rows(plain_state)
        print_matrix_transpose(plain_state)
        output_file.write("\n")

        add_round_key(plain_state, self._key_matrices[-1])
        print_2_matrix_transpose(plain_state, self._key_matrices[-1])
        # print_matrix_transpose(self._key_matrices[-1])
        # output_file.write("plain_state:\n")
        # print_matrix_transpose(plain_state)
        output_file.write("\n")

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        output_file.write(
            "decrypt_block(ciphertext: {})\n".format(ciphertext.hex()))
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        output_file.write("ciphertext:\n")
        print_matrix_transpose(cipher_state)
        output_file.write("\n")

        add_round_key(cipher_state, self._key_matrices[-1])
        print_2_matrix_transpose(cipher_state, self._key_matrices[-1])
        # print_matrix_transpose(self._key_matrices[-1])

        # output_file.write("cipher_state:\n")
        # print_matrix_transpose(cipher_state)
        output_file.write("\n")

        inv_shift_rows(cipher_state)
        print_matrix_transpose(cipher_state)
        output_file.write("\n")

        inv_sub_bytes(cipher_state)
        print_matrix_transpose(cipher_state)
        output_file.write("\n")

        for i in range(self.n_rounds - 1, 0, -1):
            print_msg_box("Round: {:2}".format(self.n_rounds-i))

            add_round_key(cipher_state, self._key_matrices[i])
            print_2_matrix_transpose(cipher_state, self._key_matrices[i])
            # print_matrix_transpose(self._key_matrices[i])
            # output_file.write("cipher_state:\n")
            # print_matrix_transpose(cipher_state)
            output_file.write("\n")

            inv_mix_columns(cipher_state)
            print_matrix_transpose(cipher_state)
            output_file.write("\n")

            inv_shift_rows(cipher_state)
            print_matrix_transpose(cipher_state)
            output_file.write("\n")

            inv_sub_bytes(cipher_state)
            print_matrix_transpose(cipher_state)
            output_file.write("\n")

        add_round_key(cipher_state, self._key_matrices[0])
        print_2_matrix_transpose(cipher_state, self._key_matrices[0])
        # print_matrix_transpose(self._key_matrices[0])

        # output_file.write("cipher_state:\n")
        # print_matrix_transpose(cipher_state)
        output_file.write("\n")

        return matrix2bytes(cipher_state)

    def encrypt_ctr(self, plaintext, iv):
        """
        Encrypts `plaintext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 16

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
        assert len(iv) == 16

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)


def encrypt_block(plaintext, key):
    output_file.write("encrypt_block({}, {})\n".format(plaintext, key))
    output_file.write("encrypt_block({}, {})\n\n".format(
        plaintext.hex(), key.hex()))
    return AES(key).encrypt_block(plaintext)


def decrypt_block(ciphertext, key):
    output_file.write("decrypt_block({}, {})\n".format(ciphertext, key))
    output_file.write("decrypt_block({}, {})\n\n".format(
        ciphertext.hex(), key.hex()))
    return AES(key).decrypt_block(ciphertext)


def encrypt_ctr(plaintext, key, iv):
    output_file.write("encrypt_ctr({}, {}, {})\n".format(plaintext, key, iv))
    output_file.write("encrypt_ctr({}, {}, {})\n\n".format(
        plaintext.hex(), key.hex(), iv.hex()))
    return AES(key).encrypt_ctr(plaintext, iv)


def decrypt_ctr(ciphertext, key, iv):
    output_file.write("decrypt_ctr({}, {}, {})\n".format(ciphertext, key, iv))
    output_file.write("decrypt_ctr({}, {}, {})\n\n".format(
        ciphertext.hex(), key.hex(), iv.hex()))
    return AES(key).decrypt_ctr(ciphertext, iv)


if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) < 3:
        # output_file.close()
        exit()

    text = int(sys.argv[2].strip(), 16).to_bytes(16, "big")
    key = int(sys.argv[3].strip(), 16).to_bytes(16, "big")

    output_file_name = os.path.splitext(os.path.basename(__file__))[0] + ".txt"
    output_file = open(output_file_name, "w")

    if "encrypt_block".startswith(sys.argv[1]):
        ciphertext = encrypt_block(text, key)
        output_file.write(
            "encrypt_block({}, {}):\n{}\n\n".format(text, key, ciphertext))
        output_file.write(
            "encrypt_block({}, {}):\n{}\n".format(text.hex(), key.hex(), ciphertext.hex()))
        print(ciphertext.hex(), end="")
    elif "decrypt_block".startswith(sys.argv[1]):
        plaintext = decrypt_block(text, key)
        output_file.write(
            "decrypt_block({}, {}):\n{}\n\n".format(text, key, plaintext))
        output_file.write(
            "decrypt_block({}, {}):\n{}\n".format(text.hex(), key.hex(), plaintext.hex()))
        print(plaintext.hex(), end="")
    elif "encrypt_ctr".startswith(sys.argv[1]):
        iv = int(sys.argv[4].strip(), 16).to_bytes(16, "big")
        ciphertext = encrypt_ctr(text, key, iv)
        output_file.write(
            "encrypt_ctr({}, {}, {}):\n{}\n\n".format(text, key, iv, ciphertext))
        output_file.write(
            "encrypt_ctr({}, {}, {}):\n{}\n".format(text.hex(), key.hex(), iv.hex(), ciphertext.hex()))
        print(ciphertext.hex(), end="")
    elif "decrypt_ctr".startswith(sys.argv[1]):
        iv = int(sys.argv[4].strip(), 16).to_bytes(16, "big")
        plaintext = decrypt_ctr(text, key, iv)
        output_file.write(
            "decrypt_ctr({}, {}, {}):\n{}\n\n".format(text, key, iv, plaintext))
        output_file.write(
            "decrypt_ctr({}, {}, {}):\n{}\n".format(text.hex(), key.hex(), iv.hex(), plaintext.hex()))
        print(plaintext.hex(), end="")
    output_file.close()

# python3 aes.py encrypt_block <plaintext> <key>
# python3 aes.py encrypt_block 41545441434b204154204441574e2101 534f4d452031323820424954204b4559
#                              "ATTACK AT DAWN!\x01"             "SOME 128 BIT KEY"

# python3 aes.py decrypt_block <ciphertext> <key>
# python3 aes.py decrypt_block 7d354e8b1dc429a300abac87c050951a 534f4d452031323820424954204b4559
#                                  <ciphertext>                  "SOME 128 BIT KEY"