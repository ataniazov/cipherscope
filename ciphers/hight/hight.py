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


def cbc_hight_encryption(P, IV, MK):
    assert not len(P) % 8 and P
    assert all(0 <= byte <= 0xFF for byte in P)
    assert len(IV) == 8
    assert all(0 <= byte <= 0xFF for byte in IV)
    assert len(MK) == 16
    assert all(0 <= byte <= 0xFF for byte in MK)

    WK, SK = encryption_key_schedule(MK)
    C = encryption_transformation(
        [P_i ^ IV_i for P_i, IV_i in zip(P[:8], IV)], WK, SK)
    for block in range(8, len(P), 8):
        C += encryption_transformation([P_i ^ C_i for P_i, C_i in zip(
            P[block:block + 8], C[block - 8:block])], WK, SK)
    return C


def cbc_hight_decryption(C, IV, MK):
    assert not len(C) % 8 and C
    assert all(0 <= byte <= 0xFF for byte in C)
    assert len(IV) == 8
    assert all(0 <= byte <= 0xFF for byte in IV)
    assert len(MK) == 16
    assert all(0 <= byte <= 0xFF for byte in MK)

    WK, SK = decryption_key_schedule(MK)
    D = [C_i ^ IV_i for C_i, IV_i in zip(
        decryption_transformation(C[:8], WK, SK), IV)]
    for block in range(8, len(C), 8):
        D += [C_i ^ D_i for C_i, D_i in zip(decryption_transformation(
            C[block:block + 8], WK, SK), C[block - 8:block])]
    return D


def ctr_hight_encryption(P, IV, MK):
    assert not len(P) % 8 and P
    assert all(0 <= byte <= 0xFF for byte in P)
    assert len(IV) == 8
    assert all(0 <= byte <= 0xFF for byte in IV)
    assert len(MK) == 16
    assert all(0 <= byte <= 0xFF for byte in MK)

    WK, SK = encryption_key_schedule(MK)
    C = [P_i ^ CIV_i for P_i, CIV_i in zip(
        P[:8], encryption_transformation(IV, WK, SK))]
    for block in range(8, len(P), 8):
        C += [P_i ^ CIV_i for P_i, CIV_i in zip(
            P[block:block + 8], encryption_transformation(IV[block:block + 8], WK, SK))]
    return C


def ctr_hight_decryption(C, IV, MK):
    assert not len(C) % 8 and C
    assert all(0 <= byte <= 0xFF for byte in C)
    assert len(IV) == 8
    assert all(0 <= byte <= 0xFF for byte in IV)
    assert len(MK) == 16
    assert all(0 <= byte <= 0xFF for byte in MK)

    WK, SK = encryption_key_schedule(MK)
    D = [C_i ^ CIV_i for C_i, CIV_i in zip(
        C[:8], encryption_transformation(IV, WK, SK))]
    for block in range(8, len(C), 8):
        D += [C_i ^ CIV_i for C_i, CIV_i in zip(
            C[block:block + 8], encryption_transformation(IV[block:block + 8], WK, SK))]
    return D


if __name__ == "__main__":
    # ECB TEST CASE
    MK = [0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1,
          0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89]
    P = [0xD7, 0x6D, 0x0D, 0x18, 0x32, 0x7E, 0xC5, 0x62]
    expected_C = [0xE4, 0xBC, 0x2E, 0x31, 0x22, 0x77, 0xE4, 0xDD]

    # MAIN CODE
    print("Plaintext:", [hex(byte)[2:].upper() for byte in P])

    C = ecb_hight_encryption(P, MK)

    print("Encrypted bytes:", [hex(byte)[2:].upper() for byte in C])

    assert C == expected_C

    D = ecb_hight_decryption(C, MK)

    print("Decrypted bytes:", [hex(byte)[2:].upper() for byte in D])

    assert D == P

    # CBC TEST CASE
    MK = [0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1,
          0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89]
    IV = [0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81]
    P = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
    expected_C = [0xCE, 0x15, 0x95, 0x08, 0x5A, 0x18, 0x8C, 0x28]

    # MAIN CODE
    print("Plaintext:", [hex(byte)[2:].upper() for byte in P])

    C = cbc_hight_encryption(P, IV, MK)

    print("Encrypted bytes:", [hex(byte)[2:].upper() for byte in C])

    assert C == expected_C

    D = cbc_hight_decryption(C, IV, MK)

    print("Decrypted bytes:", [hex(byte)[2:].upper() for byte in D])

    assert D == P

    # CTR TEST CASE
    MK = [0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1,
          0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89]
    IV = [0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81]
    P = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
    # expected_C = [0xCE, 0x15, 0x95, 0x08, 0x5A, 0x18, 0x8C, 0x28]

    # MAIN CODE
    print("Plaintext:", [hex(byte)[2:].upper() for byte in P])

    C = ctr_hight_encryption(P, IV, MK)

    print("Encrypted bytes:", [hex(byte)[2:].upper() for byte in C])

    # assert C == expected_C

    D = ctr_hight_decryption(C, IV, MK)

    print("Decrypted bytes:", [hex(byte)[2:].upper() for byte in D])

    assert D == P
