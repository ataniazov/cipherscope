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


def encrypt(msg, key, base):
    state = [[0]*4 for i in range(4)]
    for i in range(16):
        r = i//4
        c = i % 4
        state[r][c] = ord(msg[i])
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
    return state


def decrypt(state, key, base):
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
    return state


if __name__ == "__main__":
    import random

    def print_stmt(code, state):
        if code == 0:
            digest = "0x"
            for i in range(4):
                for j in range(4):
                    digest += hex(state[i][j])[2:]
            print("Encrypted Text: ", digest)
        else:
            text = ""
            for i in range(4):
                for j in range(4):
                    text += chr(state[i][j])
            print("Decrypted Text: ", text)

    hash = random.getrandbits(128)
    key = hex(hash)

    msg = input("Enter message (max 16 characters) :")
    print("Key Generated: ", key)
    msg = msg.ljust(16, '0')

    state = encrypt(msg, key, 128)
    print_stmt(0, state)
    state = decrypt(state, key, 128)
    print_stmt(1, state)
