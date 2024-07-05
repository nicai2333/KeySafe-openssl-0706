#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include "./include/openssl/err.h"
#include "./include/openssl/evp.h"
// #include "./include/crypto/sm4_bs256.h"
// #include "./include/crypto/sm4_bs512.h"
#include "./include/crypto/sm3-avx.h"

/* Before OpenSSL 1.1.1-pre1, we did not have EVP_sm4_ecb() */
#if defined(OPENSSL_VERSION_NUMBER) \
    && OPENSSL_VERSION_NUMBER < 0x10101001L
static const EVP_CIPHER *(*EVP_sm4_ecb)()=EVP_aes_128_ecb;
#endif

typedef struct {
    /* input (byte) */
    char *in;
    /* hash (hex) */
    char *hash;
} SM3_TEST_VECTOR;

/* you can add more test vectors here :) */
static SM3_TEST_VECTOR sm3_test_vec[] =
{
    /* 1 */
    {
        "abc",
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    },
    /* 2 */
    {
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    },
    /* 3 */
    {
        "hello world",
        "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88",
    },
    /* 4 */
    {
        "Crazy Thursday",
        "27542186a1f429c4e6ed751712844b433d8b33ad8edd05f7f5f1fb0c682ee51b",
    },
    /* 5 */
    {
        "Happy birthday to you Happy birthday to you Happy birthday happy birthday Happy birthday to you",
        "4ec61390d1a923782db0f3bcebb6609bad81e3d3479ce229f6c4f3cf1a300024",
    },
};

static const unsigned char ascii_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static const u8 inv_ascii_table[128] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0,    1,    2,    3,    4,    5,    6,    7,
       8,    9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   10,   11,   12,   13,   14,   15, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   10,   11,   12,   13,   14,   15, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

int u8_to_hex(unsigned char *out, const unsigned char *in, unsigned long inlen)
{
    unsigned long i;

    if (out == NULL)
        return -1;

    for (i = 0; i < inlen; i++) {
        out[0] = ascii_table[in[i] >> 4];
        out[1] = ascii_table[in[i] & 0xf];
        out += 2;
    }

    return 0;
}

int hex_to_u8(u8 *out, const u8 *in, size_t inlen)
{
    size_t i;

    if (out == NULL)
        return -1;

    i = 0;
    if (inlen % 2 == 1) {
        out[0] = inv_ascii_table[in[i]];
        if (out[0] == 0xff)
            return -1;
        out++;
        i++;
    }

    for (; i < inlen; i += 2) {
        out[0] = (inv_ascii_table[in[i]] << 4) | inv_ascii_table[in[i+1]];
        // if (out[0] == 0xff)
        //     return FP256_ERR;
        out++;
    }
    return 0;
}

void print_hex(const char *desp, const unsigned char *s, unsigned long slen)
{
    unsigned long i;

    for(i = 0; i < strlen(desp); i++)
        printf("%c", desp[i]);

    unsigned char *hex = (unsigned char*)malloc(2*slen);
    u8_to_hex(hex, s, slen);
    for(i = 0; i < 2*slen; i++)
        printf("%c", hex[i]);
    printf("\n");
    free(hex);
}

int main()
{
    unsigned long i;
    unsigned char h1[32];
    unsigned char h2[32];

    for (i = 0; i < sizeof(sm3_test_vec) / sizeof(SM3_TEST_VECTOR); i++) {

        EVP_MD_CTX *ctx;
        EVP_MD *md;
        unsigned int outlen;
        
        unsigned char outbuf[1024];
        printf("\nSM3_AVX Encrypt:\n");
        printf("Plaintext:\n ");
        printf("%s\n",(unsigned char*)sm3_test_vec[i].in );
        ctx = EVP_MD_CTX_new();
        md = EVP_get_digestbyname("SM3-AVX");
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx,  (unsigned char*)sm3_test_vec[i].in, strlen(sm3_test_vec[i].in));
        EVP_DigestFinal_ex(ctx, h1, &outlen);
        EVP_MD_CTX_free(ctx);
        // SM3_AVX_CTX sm3_ctx;
        // sm3_init(&sm3_ctx);
        // sm3_update(&sm3_ctx, (unsigned char*)sm3_test_vec[i].in, strlen(sm3_test_vec[i].in));
        // sm3_final(h1, &sm3_ctx);

        hex_to_u8(h2, (unsigned char*)sm3_test_vec[i].hash, 64);
        if (memcmp(h1, h2, 32) != 0) {
            printf("sm3 test case %ld"  " failed\n", i+1);
            print_hex("hash = ", h1, 32);
            printf("hash should be:\n");
            print_hex("hash = ", h2, 32);
            return 0;
        }
        else print_hex("Ciphertext :\n ",h1 , 32);
    }

    printf("sm3 test vector passed \n");
}