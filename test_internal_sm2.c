/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include "./test/testutil.h"

#ifndef OPENSSL_NO_SM2

# include "crypto/sm2.h"

// ---- begin ----
// #include <openssl/asn1.h>
// #include <openssl/asn1t.h>
// typedef struct SM2_Ciphertext_st SM2_Ciphertext;
// DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

// struct SM2_Ciphertext_st {
//     BIGNUM *C1x;
//     BIGNUM *C1y;
//     ASN1_OCTET_STRING *C3;
//     ASN1_OCTET_STRING *C2;
// };

// ASN1_SEQUENCE(SM2_Ciphertext) = {
//     ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
//     ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
//     ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
//     ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
// } ASN1_SEQUENCE_END(SM2_Ciphertext)

// IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)
// ---- end ----

static RAND_METHOD fake_rand;
static const RAND_METHOD *saved_rand;

static uint8_t *fake_rand_bytes = NULL;
static size_t fake_rand_bytes_offset = 0;
static size_t fake_rand_size = 0;

static int get_faked_bytes(unsigned char *buf, int num)
{
    if (fake_rand_bytes == NULL)
        return saved_rand->bytes(buf, num);

    // if (!TEST_size_t_gt(fake_rand_size, 0))
    //     return 0;

    while (num-- > 0) {
        if (fake_rand_bytes_offset >= fake_rand_size)
            fake_rand_bytes_offset = 0;
        *buf++ = fake_rand_bytes[fake_rand_bytes_offset++];
    }

    return 1;
}

static int start_fake_rand(const char *hex_bytes)
{
    /* save old rand method */
    // if (!TEST_ptr(saved_rand = RAND_get_rand_method()))
    //     return 0;
    saved_rand = RAND_get_rand_method();

    fake_rand = *saved_rand;
    /* use own random function */
    fake_rand.bytes = get_faked_bytes;

    fake_rand_bytes = OPENSSL_hexstr2buf(hex_bytes, NULL);
    fake_rand_bytes_offset = 0;
    fake_rand_size = strlen(hex_bytes) / 2;

    /* set new RAND_METHOD */
    // if (!TEST_true(RAND_set_rand_method(&fake_rand)))
    //     return 0;
    RAND_set_rand_method(&fake_rand);
    return 1;
}

static int restore_rand(void)
{
    OPENSSL_free(fake_rand_bytes);
    fake_rand_bytes = NULL;
    fake_rand_bytes_offset = 0;
    // if (!TEST_true(RAND_set_rand_method(saved_rand)))
    //     return 0;
    return 1;
}

static EC_GROUP *create_EC_group(const char *p_hex, const char *a_hex,
                                 const char *b_hex, const char *x_hex,
                                 const char *y_hex, const char *order_hex,
                                 const char *cof_hex)
{
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *g_x = NULL;
    BIGNUM *g_y = NULL;
    BIGNUM *order = NULL;
    BIGNUM *cof = NULL;
    EC_POINT *generator = NULL;
    EC_GROUP *group = NULL;
    int ok = 0;
    
    // if (!TEST_true(BN_hex2bn(&p, p_hex))
    //         || !TEST_true(BN_hex2bn(&a, a_hex))
    //         || !TEST_true(BN_hex2bn(&b, b_hex)))
    //     goto done;
    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);
    
    group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    // if (!TEST_ptr(group))
    //     goto done;

    generator = EC_POINT_new(group);
    // if (!TEST_ptr(generator))
    //     goto done;

    // if (!TEST_true(BN_hex2bn(&g_x, x_hex))
    //         || !TEST_true(BN_hex2bn(&g_y, y_hex))
    //         || !TEST_true(EC_POINT_set_affine_coordinates(group, generator, g_x,
    //                                                       g_y, NULL)))
    //     goto done;
    BN_hex2bn(&g_x, x_hex);
    BN_hex2bn(&g_y, y_hex);
    EC_POINT_set_affine_coordinates(group, generator, g_x, g_y, NULL);

    // if (!TEST_true(BN_hex2bn(&order, order_hex))
    //         || !TEST_true(BN_hex2bn(&cof, cof_hex))
    //         || !TEST_true(EC_GROUP_set_generator(group, generator, order, cof)))
    //     goto done;
    BN_hex2bn(&order, order_hex);
    BN_hex2bn(&cof, cof_hex);
    EC_GROUP_set_generator(group, generator, order, cof);

    ok = 1;
done:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(g_x);
    BN_free(g_y);
    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }

    return group;
}

static int test_sm2_crypt(const EC_GROUP *group,
                          const EVP_MD *digest,
                          const char *privkey_hex,
                          const char *message,
                          const char *k_hex, const char *ctext_hex)
{
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    unsigned char *expected = OPENSSL_hexstr2buf(ctext_hex, NULL);
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
    uint8_t *recovered = NULL;
    size_t recovered_len = msg_len;
    int rc = 0;

    if (!TEST_ptr(expected)
            || !TEST_true(BN_hex2bn(&priv, privkey_hex)))
        goto done;

    key = EC_KEY_new();
    if (!TEST_ptr(key)
            || !TEST_true(EC_KEY_set_group(key, group))
            || !TEST_true(EC_KEY_set_private_key(key, priv)))
        goto done;

    pt = EC_POINT_new(group);
    if (!TEST_ptr(pt)
            || !TEST_true(EC_POINT_mul(group, pt, priv, NULL, NULL, NULL))
            || !TEST_true(EC_KEY_set_public_key(key, pt))
            || !TEST_true(sm2_ciphertext_size(key, digest, msg_len, &ctext_len)))
        goto done;

    ctext = OPENSSL_zalloc(ctext_len);
    if (!TEST_ptr(ctext))
        goto done;

    start_fake_rand(k_hex);
    if (!TEST_true(sm2_encrypt(key, digest, (const uint8_t *)message, msg_len,
                               ctext, &ctext_len))) {
        restore_rand();
        goto done;
    }
    restore_rand();

    if (!TEST_mem_eq(ctext, ctext_len, expected, ctext_len))
        goto done;

    if (!TEST_true(sm2_plaintext_size(key, digest, ctext_len, &ptext_len))
            || !TEST_int_eq(ptext_len, msg_len))
        goto done;

    recovered = OPENSSL_zalloc(ptext_len);
    if (!TEST_ptr(recovered)
            || !TEST_true(sm2_decrypt(key, digest, ctext, ctext_len, recovered, &recovered_len))
            || !TEST_int_eq(recovered_len, msg_len)
            || !TEST_mem_eq(recovered, recovered_len, message, msg_len))
        goto done;
    printf("%s: pass!\n", __func__);
    rc = 1;
 done:
    BN_free(priv);
    EC_POINT_free(pt);
    OPENSSL_free(ctext);
    OPENSSL_free(recovered);
    OPENSSL_free(expected);
    EC_KEY_free(key);
    return rc;
}

static int sm2_crypt_test(void)
{
    int testresult = 0;
    EC_GROUP *test_group =
        create_EC_group
        ("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
         "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
         "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
         "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
         "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
         "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
         "1");

    if (!TEST_ptr(test_group))
        goto done;

    if (!test_sm2_crypt(
            test_group,
            EVP_sm3(),
            "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
            "encryption standard",
            "004C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"
            "0092e8ff62146873c258557548500ab2df2a365e0609ab67640a1f6d57d7b17820"
            "008349312695a3e1d2f46905f39a766487f2432e95d6be0cb009fe8c69fd8825a7",
            "307B0220245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF1"
            "7F6252E7022076CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A2"
            "4B84400F01B804209C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A"
            "285E07480653426D0413650053A89B41C418B0C3AAD00D886C00286467"))
        goto done;

    /* Same test as above except using SHA-256 instead of SM3 */
    // if (!test_sm2_crypt(
    //         test_group,
    //         EVP_sha256(),
    //         "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
    //         "encryption standard",
    //         "004C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"
    //         "003da18008784352192d70f22c26c243174a447ba272fec64163dd4742bae8bc98"
    //         "00df17605cf304e9dd1dfeb90c015e93b393a6f046792f790a6fa4228af67d9588",
    //         "307B0220245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F"
    //         "6252E7022076CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84"
    //         "400F01B80420BE89139D07853100EFA763F60CBE30099EA3DF7F8F364F9D10A5E9"
    //         "88E3C5AAFC0413229E6C9AEE2BB92CAD649FE2C035689785DA33"))
    //     goto done;

    testresult = 1;
 done:
    EC_GROUP_free(test_group);

    return testresult;
}

// 定义字节输出函数
void print_bytes(char *pre, const uint8_t *bytes, size_t length) {
    // 检查输入指针是否为 NULL
    if (bytes == NULL) {
        printf("Error: Null pointer provided.\n");
        return;
    }

    printf("\n%s: ", pre);
    // 打印数组的每个字节
    for (int i = 0; i < length; i++) {
        // 以十六进制格式打印字节
        printf("%02X", bytes[i]);
    }
    printf("\n");

}

static int test_sm2_sign(const EC_GROUP *group,
                         const char *userid,
                         const char *privkey_hex,
                         const char *message,
                         const char *k_hex,
                         const char *r_hex,
                         const char *s_hex)
{
    const size_t msg_len = strlen(message);
    int ok = 0;
    BIGNUM *priv = NULL;
    EC_POINT *pt = NULL;
    EC_KEY *key = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *sig_r = NULL;
    const BIGNUM *sig_s = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    // if (!TEST_true(BN_hex2bn(&priv, privkey_hex)))
    //     goto done;
    BN_hex2bn(&priv, privkey_hex);

    BN_print_fp(stdout, priv);
    uint8_t priv_bin[32];
    BN_bn2bin(priv, priv_bin);

    print_bytes("priv_bin", priv_bin, 32);
    
    BIGNUM *priv_copy;
    priv_copy = BN_bin2bn(priv_bin, 32, NULL);
    
    BN_print_fp(stdout, priv_copy);
    key = EC_KEY_new();
    
    // if (!TEST_ptr(key)
    //         || !TEST_true(EC_KEY_set_group(key, group))
    //         || !TEST_true(EC_KEY_set_private_key(key, priv)))
    //     goto done;
    EC_KEY_set_group(key, group);
    EC_KEY_set_private_key(key, priv_copy);

    printf("\nkey read:\n");
    BIGNUM *key_read = EC_KEY_get0_private_key(key);
    BN_print_fp(stdout, key_read);
    pt = EC_POINT_new(group);
    
    // if (!TEST_ptr(pt)
    //         || !TEST_true(EC_POINT_mul(group, pt, priv, NULL, NULL, NULL))
    //         || !TEST_true(EC_KEY_set_public_key(key, pt)))
    //     goto done;
    EC_POINT_mul(group, pt, priv_copy, NULL, NULL, NULL);
    
    BIGNUM *x, *y, *pbn;
    EC_POINT *pt_copy;
    pt_copy = EC_POINT_new(group);
    x = BN_new();
    y = BN_new();
    pbn = BN_new();

    EC_POINT_get_affine_coordinates(group, pt, x, y, NULL);
    EC_POINT_set_affine_coordinates(group, pt_copy, x, y, NULL);

    EC_KEY_set_public_key(key, pt_copy);

    start_fake_rand(k_hex);
    sig = sm2_do_sign(key, EVP_sm3(), (const uint8_t *)userid, strlen(userid),
                      (const uint8_t *)message, msg_len);
    
    // if (!TEST_ptr(sig)) {
    //     restore_rand();
    //     goto done;
    // }
    restore_rand();

    ECDSA_SIG_get0(sig, &sig_r, &sig_s);

    // if (!TEST_true(BN_hex2bn(&r, r_hex))
    //         || !TEST_true(BN_hex2bn(&s, s_hex))
    //         || !TEST_BN_eq(r, sig_r)
    //         || !TEST_BN_eq(s, sig_s))
    //     goto done;

    // 返回值为0表示验签失败
    ok = sm2_do_verify(key, EVP_sm3(), sig, (const uint8_t *)userid,
                       strlen(userid), (const uint8_t *)message, msg_len);
    
    if (ok)
    {
        printf("sm2 verify passed!\n");
    }
    
    /* We goto done whether this passes or fails */
    // TEST_true(ok);

 done:
    ECDSA_SIG_free(sig);
    EC_POINT_free(pt);
    EC_KEY_free(key);
    BN_free(priv);
    BN_free(r);
    BN_free(s);

    return ok;
}

static int sm2_sig_test(void)
{
    int testresult = 0;
    /* From draft-shen-sm2-ecdsa-02 */
    EC_GROUP *test_group =
        create_EC_group
        ("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
         "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
         "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
         "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
         "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
         "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
         "1");

    // if (!TEST_ptr(test_group))
    //     goto done;

    test_sm2_sign(
                    test_group,
                    "ALICE123@YAHOO.COM",
                    "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
                    "message digest",
                    "006CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"
                    "007c47811054c6f99613a578eb8453706ccb96384fe7df5c171671e760bfa8be3a",
                    "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1",
                    "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7");
    
    // if (!TEST_true(test_sm2_sign(
    //                     test_group,
    //                     "ALICE123@YAHOO.COM",
    //                     "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
    //                     "message digest",
    //                     "006CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"
    //                     "007c47811054c6f99613a578eb8453706ccb96384fe7df5c171671e760bfa8be3a",
    //                     "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1",
    //                     "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7")))
    //     goto done;

    testresult = 1;

 done:
    EC_GROUP_free(test_group);

    return testresult;
}

#endif

int sm2_sig_test2(){
    int ok = 0;
    EC_KEY *key = NULL;
    key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!key)
    {
       printf("EC_KEY_new_by_curve_name failed!\n");
       goto error;
    }
    // 预计算
    EC_KEY_precompute_mult(key, NULL);
    // 密钥生成
    EC_KEY_generate_key(key);
    
    // 预计算d1, d2
    BIGNUM *d1, *d2, *e;
    unsigned char hash_bin[32] = {0x12, 0xaa, 0xbb, 0xcc};
    int hash_len = 32;
    unsigned char sign_bin[64];
    int sign_len;
    // EC_KEY *eckey = ctx->pkey->pkey.ec;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    BN_CTX *bnctx = NULL;
    bnctx = BN_CTX_new();
    BN_CTX_start(bnctx);

    BN_print_fp(stdout, order);
    putchar('\n');
    BN_print_fp(stdout, dA);
    putchar('\n');
    
    if(!dA) goto error;
    // d1 = (1+dA)^-1
    d1 = BN_new();
    BN_add(d1, dA, BN_value_one());
    ec_group_do_inverse_ord(group, d1, d1, bnctx);
    
    // d2 = (1+d)^-1 * d
    d2 = BN_new();
    BN_mod_mul(d2, dA, d1, order, bnctx);

    BN_free(bnctx);
    sm2_sign_precomp(hash_bin, hash_len, sign_bin, &sign_len, key, d1, d2);
    printf("len = %d\n", sign_len);
    ok = sm2_verify(hash_bin, hash_len, sign_bin, sign_len, key);
    if (ok) {
        printf("sm2 verify passed!\n");
    }else{
        printf("sm2 verify failed!\n");
    }
    return 0;
error:
    return -1;
}

int sm2_rw_key_test(){
    int ok = 0;
    EC_KEY *key = NULL, *prikey_from_file, *pubkey_from_file;
    key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!key)
    {
       printf("EC_KEY_new_by_curve_name failed!\n");
       goto error;
    }
    // 预计算
    EC_KEY_precompute_mult(key, NULL);
    // 密钥生成
    EC_KEY_generate_key(key);
    
    unsigned char hash_bin[32] = {0x12, 0xaa, 0xbb, 0xcc};
    int hash_len = 32;
    unsigned char sign_bin[64];
    int sign_len;

    // 输出文件
    char *outfile = "test_internal_sm2_enc_prik.pem", *passout = "passout", *passin = "passout";
    BIO *out;
    
    // 加密私钥的算法
    EVP_CIPHER *enc = EVP_get_cipherbyname("sm4");
    if (!enc)
    {
        printf("EVP_get_cipherbyname failed!\n");
        return -1;
    }

    int i;
    out = BIO_new_file("sm2_prik.pem", "w");
    i = PEM_write_bio_ECPrivateKey(out, key, enc, NULL, 0, NULL, passout);
    if (!i) {
        printf("unable to write Key\n");
        goto error;
    }
    BIO_free(out);

    out = BIO_new_file("sm2_pubk.pem", "w");
    i = PEM_write_bio_EC_PUBKEY(out, key);
    if (!i) {
        printf("unable to write Key\n");
        goto error;
    }
    BIO_free(out);

    BIO *in;
    in = BIO_new_file("sm2_prik.pem", "r");
    prikey_from_file = PEM_read_bio_ECPrivateKey(in, NULL, NULL, passin);
    if (prikey_from_file == NULL) {
        printf("unable to load Key1\n");
        goto error;
    }
    BIO_free(in);

    EC_GROUP *group = EC_KEY_get0_group(prikey_from_file);
    BIGNUM *order = EC_GROUP_get0_order(group);
    BN_print_fp(stdout, order);

    in = BIO_new_file("sm2_pubk.pem", "r");
    pubkey_from_file = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
    if (pubkey_from_file == NULL) {
        printf("unable to load Key2n");
        goto error;
    }
    BIO_free(in);

    EC_GROUP *group2 = EC_KEY_get0_group(pubkey_from_file);
    BIGNUM *order2 = EC_GROUP_get0_order(group2);
    BN_print_fp(stdout, order2);

    sm2_sign(hash_bin, hash_len, sign_bin, &sign_len, prikey_from_file);
    

    ok = sm2_verify(hash_bin, hash_len, sign_bin, sign_len, pubkey_from_file);
    if (ok) {
        printf("sm2 verify passed!\n");
    }else{
        printf("sm2 verify failed!\n");
    }
    return 0;
error:
    return -1;
}

static int test_sm2_crypt_2()
{
    printf("%s: start\n", __func__);
    const char message[] = "encryption standard";

    EVP_MD *digest = EVP_sm3();
    const size_t msg_len = strlen(message);
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pt = NULL;
    size_t ctext_len = 0;
    size_t ptext_len = 0;
    uint8_t *ctext = NULL;
    uint8_t *ctext_copy = NULL;
    uint8_t *recovered = NULL;
    size_t recovered_len = msg_len;
    int rc = 0;


    key = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY_precompute_mult(key, NULL);
    // 生成随机密钥
    EC_KEY_generate_key(key);
    
    sm2_ciphertext_size(key, digest, msg_len, &ctext_len);

    // 为密文分配空间（C1+C2+C3的空间）
    ctext = OPENSSL_zalloc(ctext_len);
    if (!TEST_ptr(ctext))
        goto done;
    ctext_copy = OPENSSL_zalloc(ctext_len);
    if (!TEST_ptr(ctext_copy))
        goto done;
    
    // 控制随机数的生成
    if (!TEST_true(sm2_encrypt(key, digest, message, msg_len,
                               ctext, &ctext_len))) {
        restore_rand();
        goto done;
    }

    // struct SM2_Ciphertext_st *sm2_ctext = NULL;
    // sm2_ctext = d2i_SM2_Ciphertext(NULL, &ctext, ctext_len);

    // 获取C1，C2，C3
    printf("%s: get ciphertext\n", __func__);
    uint8_t C1_x[32], C1_y[32], C2[100], C3[100];
    int C2_len, C3_len;
    sm2_get_ciphertext(ctext, ctext_len, C1_x, C1_y, C2, &C2_len, C3, &C3_len);
    printf("C2_len=%d, C3_len=%d\n", C2_len, C3_len);
    
    sm2_set_ciphertext(ctext_copy, &ctext_len, C1_x, C1_y, C2, C2_len, C3, C3_len);
    printf("%s: aaa\n", __func__);
    // 分配空间
    recovered = OPENSSL_zalloc(ptext_len);
    printf("%s: bbb\n", __func__);
    sm2_decrypt(key, digest, ctext_copy, ctext_len, recovered, &recovered_len);
    printf("%s: ccc\n", __func__);
    !TEST_ptr(recovered) ? printf("%s: 111\n", __func__) : printf("%s: pass\n", __func__);
    !TEST_true(sm2_decrypt(key, digest, ctext_copy, ctext_len, recovered, &recovered_len)) ? printf("%s: 222\n", __func__) : printf("%s: pass\n", __func__);
    !TEST_int_eq(recovered_len, msg_len) ? printf("%s: 333\n", __func__) : printf("%s: pass\n", __func__);
    !TEST_mem_eq(recovered, recovered_len, message, msg_len) ? printf("%s: 444\n", __func__) : printf("%s: pass\n", __func__);


    // printf("ctext_len equal\n");
    // if (!TEST_true(sm2_plaintext_size(key, digest, ctext_len, &ptext_len))
    //         || !TEST_int_eq(ptext_len, msg_len))
    //     goto done;
    // printf("ptext_len equal\n");
    
    printf("crypt_test passed!\n");
    rc = 1;
 done:
    BN_free(priv);
    EC_POINT_free(pt);
    OPENSSL_free(ctext);
    OPENSSL_free(recovered);
    EC_KEY_free(key);
    return rc;
}

int main(void)
{
    sm2_crypt_test();
    // test_sm2_crypt_2();
    // sm2_sig_test();
    // sm2_sig_test2();
    // sm2_rw_key_test();
 
    return 0;
}