/** 文件名: https://github.com/liuqun/openssl-sm4-demo/blob/cmake/src/main.c */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include "include/openssl/err.h"
#include "include/openssl/evp.h"
// #include "./include/crypto/sm4_bs256.h"
// #include "./include/crypto/sm4_bs512.h"
#include "./include/crypto/sm4.h"

/* Before OpenSSL 1.1.1-pre1, we did not have EVP_sm4_ecb() */
#if defined(OPENSSL_VERSION_NUMBER) \
    && OPENSSL_VERSION_NUMBER < 0x10101001L
static const EVP_CIPHER *(*EVP_sm4_ecb)()=EVP_aes_128_ecb;
#endif

// #define OPENSSL_NO_SM4
#ifndef OPENSSL_NO_BS512_SM4
typedef struct {
    const unsigned char *in_data;
    size_t in_data_len;
    int in_data_is_already_padded;
    const unsigned char *in_ivec;
    const unsigned char *in_key;
    size_t in_key_len;
} test_case_t;

void dump_hex(uint8_t * h, int len)
{
    while(len--)
    {   
        printf("%02hhx ",*h++);
        if(len%16==0) printf("\n");
    }
}

void test_encrypt_with_cipher(const test_case_t *in, const EVP_CIPHER *cipher)
{
 
	unsigned char *out_buf = NULL;
	int out_len;
	int out_padding_len;
    EVP_CIPHER_CTX *ctx;
 
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, in->in_key, in->in_ivec);

    if (in->in_data_is_already_padded)
    {
        /* Check whether the input data is already padded.
        And its length must be an integral multiple of the cipher's block size. */
        const size_t bs = EVP_CIPHER_block_size(cipher);
        if (in->in_data_len % bs != 0)
        {
            printf("ERROR-1: data length=%d which is not added yet; block size=%d\n", (int) in->in_data_len, (int) bs);
            /* Warning: Remember to do some clean-ups */
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        /* Disable the implicit PKCS#7 padding defined in EVP_CIPHER */
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    out_buf = (unsigned char *) malloc(((in->in_data_len>>4)+1) << 4);
    out_len = 0;
    EVP_EncryptUpdate(ctx, out_buf, &out_len, in->in_data, in->in_data_len);
    if (1)
    {
        printf("Debug: out_len=%d\n", out_len);
    }

    out_padding_len = 0;
    EVP_EncryptFinal_ex(ctx, out_buf+out_len, &out_padding_len);
    if (1)
    {
        printf("Debug: out_padding_len=%d\n", out_padding_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    if (1)
    {
        int i;
        int len;
        len = out_len + out_padding_len;
        for (i=0; i<len; i++)
        {
            printf("%02x ", out_buf[i]);
            if((i+1)%16 == 0)
                printf("\n");
        }
        printf("\n");
    }

    if (out_buf)
    {
        free(out_buf);
        out_buf = NULL;
    }
}

void test_encrypt_with_gcm(){
    #define SM4_GCM_TESTS_BYTES 48
    //test case from GB/T 0042--2015 三元对等密码安全协议测试规范
    //test code from https://github.com/openssl/openssl/blob/master/demos/evp/aesgcm.c
    uint8_t key_vector[16] =
    {   
        0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
        0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08
    };
    // uint8_t iv_vector[16]  =
    //     {0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x00, 0x00, 0x00, 0x00};
    uint8_t iv_vector[12]  =
        {0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36};
    uint8_t Associated_Data[]={
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
        0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    uint8_t pt_vector[SM4_GCM_TESTS_BYTES] =
        {0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x03,0x7f,0xff,0xff,0xfe,
        0xc0,0xa8,0x14,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0x14,0x0d,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t ct_vector[SM4_GCM_TESTS_BYTES] =
       {0x0a,0x59,0x91,0xa6,0x70,0xdc,0x0e,0xa2,0x6f,0x84,0xe4,0x55,0xa1,0xc0,0x61,0x47,
        0x8a,0xa0,0x9f,0x2f,0xbe,0x90,0x49,0x46,0x29,0xbc,0x58,0xe7,0x5b,0xe5,0xe9,0x1d,
        0xbc,0x6d,0x21,0x49,0xbc,0x1f,0xba,0xca,0xca,0xa9,0x72,0x2d,0x61,0x0f,0xde,0x1d};
    uint8_t tag[16] = 
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    printf("SM4 GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, pt_vector, sizeof(pt_vector));
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_sm4_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, EVP_sm4_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(iv_vector), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key_vector, iv_vector);
    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, Associated_Data, sizeof(Associated_Data));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, pt_vector, sizeof(pt_vector));
    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outbuf, 16);
    EVP_CIPHER_CTX_free(ctx);
}

void test_encrypt_with_sm4bs256_gcm(){
    #define SM4_GCM_TESTS_BYTES 48
    //tect vector from GB/T 0042--2015 三元对等密码安全协议测试规范
    //test code from https://github.com/openssl/openssl/blob/master/demos/evp/aesgcm.c
    uint8_t key_vector[16] =
    {   
        0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
        0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08
    };
    // uint8_t iv_vector[16]  =
    //     {0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x00, 0x00, 0x00, 0x00};
    uint8_t iv_vector[12]  =
        {0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36};
    uint8_t Associated_Data[]={
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
        0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    uint8_t pt_vector[SM4_GCM_TESTS_BYTES] =
        {0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x03,0x7f,0xff,0xff,0xfe,
        0xc0,0xa8,0x14,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0x14,0x0d,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t ct_vector[SM4_GCM_TESTS_BYTES] =
       {0x0a,0x59,0x91,0xa6,0x70,0xdc,0x0e,0xa2,0x6f,0x84,0xe4,0x55,0xa1,0xc0,0x61,0x47,
        0x8a,0xa0,0x9f,0x2f,0xbe,0x90,0x49,0x46,0x29,0xbc,0x58,0xe7,0x5b,0xe5,0xe9,0x1d,
        0xbc,0x6d,0x21,0x49,0xbc,0x1f,0xba,0xca,0xca,0xa9,0x72,0x2d,0x61,0x0f,0xde,0x1d};
    uint8_t tag[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    printf("SM4_bit-slice GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, pt_vector, sizeof(pt_vector));
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_sm4_bs256_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(iv_vector), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key_vector, iv_vector);
    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, Associated_Data, sizeof(Associated_Data));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, pt_vector, sizeof(pt_vector));
    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outbuf, 16);
    EVP_CIPHER_CTX_free(ctx);
}


#ifndef OPENSSL_NO_SM4
void test_encrypt_with_sm4bs512_gcm(){
    #define SM4_GCM_TESTS_BYTES 48
    //tect vector from GB/T 0042--2015 三元对等密码安全协议测试规范
    //test code from https://github.com/openssl/openssl/blob/master/demos/evp/aesgcm.c
    uint8_t key_vector[16] =
    {   
        0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
        0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08
    };
    // uint8_t iv_vector[16]  =
    //     {0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x00, 0x00, 0x00, 0x00};
    uint8_t iv_vector[12]  =
        {0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36};
    uint8_t Associated_Data[]={
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
        0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    uint8_t pt_vector[SM4_GCM_TESTS_BYTES] =
        {0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x03,0x7f,0xff,0xff,0xfe,
        0xc0,0xa8,0x14,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0x14,0x0d,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t ct_vector[SM4_GCM_TESTS_BYTES] =
       {0x0a,0x59,0x91,0xa6,0x70,0xdc,0x0e,0xa2,0x6f,0x84,0xe4,0x55,0xa1,0xc0,0x61,0x47,
        0x8a,0xa0,0x9f,0x2f,0xbe,0x90,0x49,0x46,0x29,0xbc,0x58,0xe7,0x5b,0xe5,0xe9,0x1d,
        0xbc,0x6d,0x21,0x49,0xbc,0x1f,0xba,0xca,0xca,0xa9,0x72,0x2d,0x61,0x0f,0xde,0x1d};
    uint8_t tag[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    printf("SM4_bit-slice GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, pt_vector, sizeof(pt_vector));
    ctx = EVP_CIPHER_CTX_new();
    /* Set cipher type and mode */
    EVP_EncryptInit_ex(ctx, EVP_sm4_bs512_gcm(), NULL, NULL, NULL);
    /* Set IV length if default 96 bits is not appropriate */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(iv_vector), NULL);
    /* Initialise key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key_vector, iv_vector);
    /* Zero or more calls to specify any AAD */
    EVP_EncryptUpdate(ctx, NULL, &outlen, Associated_Data, sizeof(Associated_Data));
    /* Encrypt plaintext */
    EVP_EncryptUpdate(ctx, outbuf, &outlen, pt_vector, sizeof(pt_vector));
    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);
    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf);
    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outbuf, 16);
    EVP_CIPHER_CTX_free(ctx);
}
#endif

/* test_bitsice_sm4_gcm(){
    #define SM4_GCM_TESTS_BYTES 48
    printf("SM4 GCM 4 block:\n");

    uint8_t key_vector[16] =
    {   
        0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
        0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08
    };
    uint8_t iv_vector[16]  =
        {0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x00, 0x00, 0x00, 0x00};

    uint8_t Associated_Data[]={
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
        0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    };
    uint8_t pt_vector[SM4_GCM_TESTS_BYTES] =
        {0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x03,0x7f,0xff,0xff,0xfe,
        0xc0,0xa8,0x14,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0x14,0x0d,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t ct_vector[SM4_GCM_TESTS_BYTES] =
       {0x0a,0x59,0x91,0xa6,0x70,0xdc,0x0e,0xa2,0x6f,0x84,0xe4,0x55,0xa1,0xc0,0x61,0x47,
        0x8a,0xa0,0x9f,0x2f,0xbe,0x90,0x49,0x46,0x29,0xbc,0x58,0xe7,0x5b,0xe5,0xe9,0x1d,
        0xbc,0x6d,0x21,0x49,0xbc,0x1f,0xba,0xca,0xca,0xa9,0x72,0x2d,0x61,0x0f,0xde,0x1d};
    uint8_t tag[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t T[16][256][16];

    uint8_t output[SM4_GCM_TESTS_BYTES];
    uint8_t input[SM4_GCM_TESTS_BYTES];
    uint8_t t[SM4_GCM_TESTS_BYTES];
    __m256i rk[32][32];
    SM4_BS256_KEY *key;

    //SM4_BS256_set_key(key_vector, key);
    // EVP_CIPHER_CTX *ctx;
    // sm4_ecb_bs_encrypt(ctx, output, input, SM4_GCM_TESTS_BYTES);
    // EVP_sm4_bs256_ecb()

    //EVP_sm4_bs256_gcm
    // //compute table
    // uint8_t p_h[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    // uint8_t c_h[16];
    // sm4_bs256_ecb_encrypt(c_h,p_h,16,key->bs_rk);
    // //sm4_bs256_ecb_encrypt
    // computeTable(T, c_h);

    // sm4_bs256_gcm_encrypt(output,pt_vector,sizeof(pt_vector),rk,
    //      iv_vector,sizeof(iv_vector),Associated_Data, sizeof(Associated_Data),
    //      tag, sizeof(tag),T);
    // printf("ciphertext: \n");
    // dump_hex(output,SM4_GCM_TESTS_BYTES);
    // printf("tag: \n");
    // dump_hex(tag,sizeof(tag));
}
 */


void main()
{
    int have_sm4 = (OPENSSL_VERSION_NUMBER >= 0x10101001L);
    int have_aes = 1;
    int have_sm4_bs256 = 1;
    int have_sm4_bs512 = 1;
    const unsigned char data[]=
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char ivec[EVP_MAX_IV_LENGTH]; ///< IV 向量
    const unsigned char key1[16] = ///< key_data, 密钥内容, 至少16字节
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    test_case_t tc;
    tc.in_data = data;
    tc.in_data_len = sizeof(data);
    tc.in_data_is_already_padded = (tc.in_data_len % 16)==0; // Hard coded 16 as the cipher's block size
    tc.in_key = key1;
    tc.in_key_len = sizeof(key1);
    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    tc.in_ivec = ivec;

    const unsigned char data_2[16*2]={
        0xAA,0xAA,0xAA,0xAA,0xBB,0xBB,0xBB,0xBB,0xCC,0xCC,0xCC,0xCC,0xDD,0xDD,0xDD,0xDD,
        0xEE,0xEE,0xEE,0xEE,0xFF,0xFF,0xFF,0xFF,0xAA,0xAA,0xAA,0xAA,0xBB,0xBB,0xBB,0xBB
    };
    unsigned char cipher_2[16*2]={
        0x5E,0xC8,0x14,0x3D,0xE5,0x09,0xCF,0xF7,0xB5,0x17,0x9F,0x8F,0x47,0x4B,0x86,0x19,
        0x2F,0x1D,0x30,0x5A,0x7F,0xB1,0x7D,0xF9,0x85,0xF8,0x1C,0x84,0x82,0x19,0x23,0x04
    };

    test_case_t tc_2;
    tc_2.in_data = data_2;
    tc_2.in_data_len = sizeof(data_2);
    tc_2.in_data_is_already_padded = (tc_2.in_data_len % 16)==0; // Hard coded 16 as the cipher's block size
    tc_2.in_key = key1;
    tc_2.in_key_len = sizeof(key1);
    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    tc_2.in_ivec = ivec;

#if defined(OPENSSL_NO_SM4)
    have_sm4 = 0;
#endif
    if (have_sm4)
    {
        printf("[1]\n");
        printf("Debug: EVP_sm4_ecb() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_ecb());
        test_encrypt_with_cipher(&tc_2, EVP_sm4_ecb());
        printf("Debug: EVP_sm4_ctr() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_ctr());
        test_encrypt_with_cipher(&tc_2, EVP_sm4_ctr());
        // printf("Debug: EVP_sm4_gcm() test\n");
        // test_encrypt_with_cipher(&tc, EVP_sm4_gcm());
        // test_encrypt_with_cipher(&tc_2, EVP_sm4_ctr());
    }

#if defined(OPENSSL_NO_BS256_SM4)
    have_sm4_bs256 = 0;
#endif
    if (have_sm4_bs256)
    {
        printf("[2]\n");
        printf("Debug: EVP_sm4_bs256_ecb() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_bs256_ecb());
        test_encrypt_with_cipher(&tc_2, EVP_sm4_bs256_ecb());
        printf("Debug: EVP_sm4_bs256_ctr() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_bs256_ctr());
        test_encrypt_with_cipher(&tc_2, EVP_sm4_bs256_ctr());
    }

#ifndef OPENSSL_NO_SM4
#if defined(OPENSSL_NO_BS512_SM4)
    have_sm4_bs512 = 0;
#endif
    if (have_sm4_bs512)
    {
        printf("[3]\n");
        printf("Debug: EVP_sm4_bs512_ecb() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_bs512_ecb());
        test_encrypt_with_cipher(&tc_2, EVP_sm4_bs512_ecb());
        printf("Debug: EVP_sm4_bs512_ctr() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_bs512_ctr());
        test_encrypt_with_cipher(&tc_2, EVP_sm4_bs512_ctr());
    }
#endif

    printf("Debug: EVP_sm4_gcm() test\n");
    test_encrypt_with_gcm();
    test_encrypt_with_gcm();

    printf("\nDebug: EVP_sm4-bs256_gcm() test\n");
    test_encrypt_with_sm4bs256_gcm();

#ifndef OPENSSL_NO_SM4
    printf("\n\tDebug: EVP_sm4-bs512_gcm() test\n");
    test_encrypt_with_sm4bs512_gcm();
#endif

}
#endif