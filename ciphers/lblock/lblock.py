#!/usr/bin/env python3
"""
https://gist.github.com/raullenchai/5000010
"""
"""
POC implementation of LBlock Cipher (http://eprint.iacr.org/2011/345.pdf)
Uncompatible with Test Vectors given in the paper
"""

s0 = [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5]
s1 = [4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3]
s2 = [1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10]
s3 = [7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1]
s4 = [14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3]
s5 = [2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5]
s6 = [11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2]
s7 = [13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6]
s8 = [8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3]
s9 = [11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6]


def F(x):
    return s6[(x & 0xf000000) >> 24] << 28 | \
        s4[(x & 0xf0000) >> 16] << 24 | \
        s7[(x & 0xf0000000) >> 28] << 20 | \
        s5[(x & 0xf00000) >> 20] << 16 | \
        s2[(x & 0xf00) >> 8] << 12 | \
        s0[(x & 0xf) >> 0] << 8 | \
        s3[(x & 0xf000) >> 12] << 4 | \
        s1[(x & 0xf0) >> 4] << 0


def Key_Schedule(K):
    RK = list()
    for r in range(32):
        RK.append(K & 0xffffffff000000000000)
        K = ((K & 0xfffffff8000000000000) >> 51) | (
            (K & 0x7ffffffffffff) << 29)
        K = (s9[(K & 0xf0000000000000000000) >> 76] << 76) | (
            s8[(K & 0xf000000000000000000) >> 72] << 72) | (K & 0xffffffffffffffffff)
        K = K ^ (r << 46)
    return RK


def Enc(P, RK):
    L = (P >> 32) & 0xffffffff
    R = P & 0xffffffff

    for r in range(32):
        tmpL = F(L ^ RK[r]) ^ (
            ((R & 0xff000000) >> 24) | ((R & 0x00ffffff) << 8))
        tmpR = L
        L = tmpL
        R = tmpR
    return (L << 32) | R


if __name__ == '__main__':
    RK = Key_Schedule(0x0123456789abcdef)
    print(hex(Enc(0x0123456789abcdef, RK)))
    RK_0 = Key_Schedule(0x0000000000000000)
    print(hex(Enc(0x0000000000000000, RK_0)))
