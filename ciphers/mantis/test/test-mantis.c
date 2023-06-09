/*
 * Copyright (C) 2017 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "mantis-cipher.h"
#include "mantis-parallel.h"
#include <stdio.h>
#include <string.h>

typedef struct
{
    const char *name;
    uint8_t plaintext[8];
    uint8_t ciphertext[8];
    uint8_t key[16];
    uint8_t tweak[8];
    unsigned rounds;

} MantisTestVector;

static MantisTestVector const testMantis5 = {
    "Mantis5",
    {0x3b, 0x5c, 0x77, 0xa4, 0x92, 0x1f, 0x97, 0x18},
    {0xd6, 0x52, 0x20, 0x35, 0xc1, 0xc0, 0xc6, 0xc1},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    5
};
static MantisTestVector const testMantis6 = {
    "Mantis6",
    {0xd6, 0x52, 0x20, 0x35, 0xc1, 0xc0, 0xc6, 0xc1},
    {0x60, 0xe4, 0x34, 0x57, 0x31, 0x19, 0x36, 0xfd},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    6
};
static MantisTestVector const testMantis7 = {
    "Mantis7",
    {0x60, 0xe4, 0x34, 0x57, 0x31, 0x19, 0x36, 0xfd},
    {0x30, 0x8e, 0x8a, 0x07, 0xf1, 0x68, 0xf5, 0x17},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    7
};
static MantisTestVector const testMantis8 = {
    "Mantis8",
    {0x30, 0x8e, 0x8a, 0x07, 0xf1, 0x68, 0xf5, 0x17},
    {0x97, 0x1e, 0xa0, 0x1a, 0x86, 0xb4, 0x10, 0xbb},
    {0x92, 0xf0, 0x99, 0x52, 0xc6, 0x25, 0xe3, 0xe9,
     0xd7, 0xa0, 0x60, 0xf7, 0x14, 0xc0, 0x29, 0x2b},
    {0xba, 0x91, 0x2e, 0x6f, 0x10, 0x55, 0xfe, 0xd2},
    8
};

static int error = 0;

#define CTR_BLOCK_COUNT 256

static void mantisEcbTest(const MantisTestVector *test)
{
    MantisKey_t ks;
    uint8_t plaintext1[MANTIS_BLOCK_SIZE];
    uint8_t ciphertext1[MANTIS_BLOCK_SIZE];
    uint8_t plaintext2[MANTIS_BLOCK_SIZE];
    uint8_t ciphertext2[MANTIS_BLOCK_SIZE];
    int plaintext_ok, ciphertext_ok;

    printf("%s ECB: ", test->name);
    fflush(stdout);

    /* Start with the mode set to encrypt first */
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_ENCRYPT);
    mantis_set_tweak(&ks, test->tweak, MANTIS_TWEAK_SIZE);
    mantis_ecb_crypt(ciphertext1, test->plaintext, &ks);
    mantis_swap_modes(&ks); /* Switch to decryption */
    mantis_ecb_crypt(plaintext1, test->ciphertext, &ks);

    /* Perform the test again with the mode set to decrypt first */
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_DECRYPT);
    mantis_set_tweak(&ks, test->tweak, MANTIS_TWEAK_SIZE);
    mantis_ecb_crypt(plaintext2, test->ciphertext, &ks);
    mantis_swap_modes(&ks); /* Switch to encryption */
    mantis_ecb_crypt(ciphertext2, test->plaintext, &ks);

    /* Check the results */
    plaintext_ok =
        memcmp(plaintext1, test->plaintext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(plaintext2, test->plaintext, MANTIS_BLOCK_SIZE) == 0;
    ciphertext_ok =
        memcmp(ciphertext1, test->ciphertext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(ciphertext2, test->ciphertext, MANTIS_BLOCK_SIZE) == 0;

    /* Do the above again, but supply the tweak during encryption */
    memset(plaintext1, 0, sizeof(plaintext1));
    memset(plaintext2, 0, sizeof(plaintext2));
    memset(ciphertext1, 0, sizeof(ciphertext1));
    memset(ciphertext2, 0, sizeof(ciphertext2));
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_ENCRYPT);
    mantis_ecb_crypt_tweaked(ciphertext1, test->plaintext, test->tweak, &ks);
    mantis_swap_modes(&ks);
    mantis_ecb_crypt_tweaked(plaintext1, test->ciphertext, test->tweak, &ks);
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_DECRYPT);
    mantis_ecb_crypt_tweaked(plaintext2, test->ciphertext, test->tweak, &ks);
    mantis_swap_modes(&ks);
    mantis_ecb_crypt_tweaked(ciphertext2, test->plaintext, test->tweak, &ks);

    /* Check the results */
    plaintext_ok &=
        memcmp(plaintext1, test->plaintext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(plaintext2, test->plaintext, MANTIS_BLOCK_SIZE) == 0;
    ciphertext_ok &=
        memcmp(ciphertext1, test->ciphertext, MANTIS_BLOCK_SIZE) == 0 &&
        memcmp(ciphertext2, test->ciphertext, MANTIS_BLOCK_SIZE) == 0;

    /* Report the results */
    if (plaintext_ok && ciphertext_ok) {
        printf("ok");
    } else {
        error = 1;
        if (plaintext_ok)
            printf("plaintext ok");
        else
            printf("plaintext INCORRECT");
        if (ciphertext_ok)
            printf(", ciphertext ok");
        else
            printf(", ciphertext INCORRECT");
    }
    printf("\n");
}

static void mantisCtrTest(const MantisTestVector *test)
{
    static uint8_t const base_counter[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    MantisKey_t ks;
    MantisCTR_t ctr;
    uint8_t counter[MANTIS_BLOCK_SIZE];
    uint8_t plaintext[CTR_BLOCK_COUNT][MANTIS_BLOCK_SIZE];
    uint8_t ciphertext[CTR_BLOCK_COUNT][MANTIS_BLOCK_SIZE];
    uint8_t actual[CTR_BLOCK_COUNT][MANTIS_BLOCK_SIZE];
    unsigned index, carry, posn, inc, size;
    int ok = 1;

    printf("%s CTR: ", test->name);
    fflush(stdout);

    /* Simple implementation of counter mode to cross-check the real one */
    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE, test->rounds, MANTIS_ENCRYPT);
    mantis_set_tweak(&ks, test->tweak, MANTIS_TWEAK_SIZE);
    for (index = 0; index < CTR_BLOCK_COUNT; ++index) {
        carry = index;
        for (posn = MANTIS_BLOCK_SIZE; posn > 0; ) {
            --posn;
            carry += base_counter[posn];
            counter[posn] = (uint8_t)carry;
            carry >>= 8;
        }
        mantis_ecb_crypt(&(ciphertext[index]), counter, &ks);
        for (posn = 0; posn < MANTIS_BLOCK_SIZE; ++posn) {
            plaintext[index][posn] =
                test->plaintext[(posn + index) % MANTIS_BLOCK_SIZE];
            ciphertext[index][posn] ^= plaintext[index][posn];
        }
    }

    /* Encrypt the entire plaintext in a single request */
    memset(actual, 0, sizeof(actual));
    mantis_ctr_init(&ctr);
    mantis_ctr_set_key(&ctr, test->key, MANTIS_KEY_SIZE, test->rounds);
    mantis_ctr_set_tweak(&ctr, test->tweak, MANTIS_TWEAK_SIZE);
    mantis_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
    mantis_ctr_encrypt(actual, plaintext, sizeof(plaintext), &ctr);
    if (memcmp(ciphertext, actual, sizeof(actual)) != 0)
        ok = 0;

    /* Decrypt the ciphertext back to the plaintext, in-place */
    mantis_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
    mantis_ctr_encrypt(actual, actual, sizeof(ciphertext), &ctr);
    mantis_ctr_cleanup(&ctr);
    if (memcmp(plaintext, actual, sizeof(actual)) != 0)
        ok = 0;

    /* Use various size increments to check data that is not block-aligned */
    for (inc = 1; inc <= (MANTIS_BLOCK_SIZE * 3); ++inc) {
        memset(actual, 0, sizeof(actual));
        mantis_ctr_init(&ctr);
        mantis_ctr_set_key(&ctr, test->key, MANTIS_KEY_SIZE, test->rounds);
        mantis_ctr_set_tweak(&ctr, test->tweak, MANTIS_TWEAK_SIZE);
        mantis_ctr_set_counter(&ctr, base_counter, sizeof(base_counter));
        for (posn = 0; posn < sizeof(plaintext); posn += inc) {
            size = sizeof(plaintext) - posn;
            if (size > inc)
                size = inc;
            mantis_ctr_encrypt
                (((uint8_t *)actual) + posn,
                 ((uint8_t *)plaintext) + posn, size, &ctr);
        }
        mantis_ctr_cleanup(&ctr);
        if (memcmp(ciphertext, actual, sizeof(actual)) != 0)
            ok = 0;
    }

    /* Report the results */
    if (ok) {
        printf("ok\n");
    } else {
        printf("INCORRECT\n");
        error = 1;
    }
}

static void mantisParallelEcbTest(const MantisTestVector *test)
{
    MantisKey_t ks;
    MantisParallelECB_t ctx;
    uint8_t plaintext[MANTIS_BLOCK_SIZE * 128];
    uint8_t ciphertext[MANTIS_BLOCK_SIZE * 128];
    uint8_t rplaintext[MANTIS_BLOCK_SIZE * 128];
    uint8_t tweak[MANTIS_BLOCK_SIZE * 128];
    int plaintext_ok, ciphertext_ok;
    unsigned index;

    printf("%s Parallel ECB: ", test->name);
    fflush(stdout);

    for (index = 0; index < sizeof(plaintext); ++index) {
        plaintext[index] = (uint8_t)(index % 251);
        tweak[sizeof(tweak) - 1 - index] = (uint8_t)(index % 251);
    }

    mantis_parallel_ecb_init(&ctx);
    mantis_parallel_ecb_set_key
        (&ctx, test->key, MANTIS_KEY_SIZE, test->rounds, MANTIS_ENCRYPT);
    mantis_parallel_ecb_crypt
        (ciphertext, plaintext, tweak, sizeof(plaintext), &ctx);
    mantis_parallel_ecb_swap_modes(&ctx);
    mantis_parallel_ecb_crypt
        (rplaintext, ciphertext, tweak, sizeof(ciphertext), &ctx);
    mantis_parallel_ecb_cleanup(&ctx);

    plaintext_ok = memcmp(rplaintext, plaintext, sizeof(plaintext)) == 0;

    mantis_set_key(&ks, test->key, MANTIS_KEY_SIZE,
                   test->rounds, MANTIS_ENCRYPT);
    for (index = 0; index < sizeof(plaintext); index += MANTIS_BLOCK_SIZE) {
        mantis_set_tweak(&ks, tweak + index, MANTIS_TWEAK_SIZE);
        mantis_ecb_crypt(rplaintext + index, plaintext + index, &ks);
    }

    ciphertext_ok = memcmp(rplaintext, ciphertext, sizeof(ciphertext)) == 0;

    if (plaintext_ok && ciphertext_ok) {
        printf("ok");
    } else {
        error = 1;
        if (plaintext_ok)
            printf("plaintext ok");
        else
            printf("plaintext INCORRECT");
        if (ciphertext_ok)
            printf(", ciphertext ok");
        else
            printf(", ciphertext INCORRECT");
    }
    printf("\n");
}

/* Define to 1 to include the sbox generator */
#define GEN_SBOX 0

#if GEN_SBOX
void generate_sboxes(void);
#endif

int main(int argc, char **argv)
{
    mantisEcbTest(&testMantis5);
    mantisEcbTest(&testMantis6);
    mantisEcbTest(&testMantis7);
    mantisEcbTest(&testMantis8);

    mantisCtrTest(&testMantis5);
    mantisCtrTest(&testMantis6);
    mantisCtrTest(&testMantis7);
    mantisCtrTest(&testMantis8);

    mantisParallelEcbTest(&testMantis5);
    mantisParallelEcbTest(&testMantis6);
    mantisParallelEcbTest(&testMantis7);
    mantisParallelEcbTest(&testMantis8);

#if GEN_SBOX
    generate_sboxes();
#endif
    return error;
}

#if GEN_SBOX

/* This sbox generator is used to verify the bit-sliced implementation.
   We do not use this in the actual implementation because table lookups
   do not have constant-cache behaviour. */

int permute1(int y)
{
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */
    return ((y & 0x01) << 2) |
           ((y & 0x06) << 5) |
           ((y & 0x20) >> 5) |
           ((y & 0xC8) >> 2) |
           ((y & 0x10) >> 1);
}

int permute1_inv(int y)
{
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */
    return ((y & 0x08) << 1) |
           ((y & 0x32) << 2) |
           ((y & 0x01) << 5) |
           ((y & 0xC0) >> 5) |
           ((y & 0x04) >> 2);
}

int permute2(int y)
{
    return (y & 0xF9) | ((y >> 1) & 0x02) | ((y << 1) & 0x04);
}

void generate_sbox(void)
{
    int x, y;
    printf("static unsigned char const sbox[256] = {\n");
    for (x = 0; x <= 255; ++x) {
        y = x;
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute2(y);
        printf("0x%02x, ", y);
        if ((x % 12) == 11)
            printf("\n");
    }
    printf("\n};\n\n");
}

void generate_inv_sbox(void)
{
    int x, y;
    printf("static unsigned char const sbox_inv[256] = {\n");
    for (x = 0; x <= 255; ++x) {
        y = x;
        y = permute2(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        y = permute1_inv(y);
        y = ((~(((y >> 1) | y) >> 2)) & 0x11) ^ y;
        printf("0x%02x, ", y);
        if ((x % 12) == 11)
            printf("\n");
    }
    printf("\n};\n\n");
}

#define NAND(x, y)  (~((x) & (y)))
#define NOR(x, y)   (~((x) | (y)))

void generate_mantis_sbox(void)
{
    int x, y, a, b, c, d;
    int aout, bout, cout, dout;
    printf("static unsigned char const mantis_sbox[14] = {\n");
    for (x = 0; x <= 15; ++x) {
        a = x >> 3;
        b = x >> 2;
        c = x >> 1;
        d = x;
        /* aout = NAND(NAND(~c, NAND(a, b)), (a | d)); */
        aout = ~((c | (a & b)) & (a | d));

        /* bout = NAND(NOR(NOR(a, d), (b & c)), NAND((a & c), d)); */
        bout = (~(a | d)) | (b & c) | (a & c & d);

        /* cout = NAND(NAND(b, d), (NOR(b, d) | a)); */
        cout = (b & d) | ((b | d) & ~a);

        /* dout = NOR(NOR(a, (b | c)), NAND(NAND(a, b), (c | d))); */
        dout = (a | b | c) & (~(a & b)) & (c | d);

        y = ((aout & 0x01) << 3) | ((bout & 0x01) << 2) |
            ((cout & 0x01) << 1) | (dout & 0x01);
        printf("%x, ", y);
    }
    printf("\n};\n\n");
}

void generate_sboxes(void)
{
    generate_sbox();
    generate_inv_sbox();
    generate_mantis_sbox();
}

#endif /* GEN_SBOX */
