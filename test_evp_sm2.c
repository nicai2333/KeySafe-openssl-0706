#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/dh.h>
#include "./test/testutil.h"
#include "internal/nelem.h"
#include "crypto/evp.h"
#include "debug.h"

#ifndef OPENSSL_NO_SM2
static const unsigned char kMsg[] = { 1, 2, 3, 4 };

static int test_EVP_SM2_verify(void)
{
    /* From https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02#appendix-A */
    const char *pubkey =
       "-----BEGIN PUBLIC KEY-----\n"
       "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEAhULWnkwETxjouSQ1\n"
       "v2/33kVyg5FcRVF9ci7biwjx38MwRAQgeHlotPoyw/0kF4Quc7v+/y88hItoMdfg\n"
       "7GUiizk35JgEIGPkxtOyOwyEnPhCQUhL/kj2HVmlsWugbm4S0donxSSaBEEEQh3r\n"
       "1hti6rZ0ZDTrw8wxXjIiCzut1QvcTE5sFH/t1D0GgFEry7QsB9RzSdIVO3DE5df9\n"
       "/L+jbqGoWEG55G4JogIhAIVC1p5MBE8Y6LkkNb9v990pdyBjBIVijVrnTufDLnm3\n"
       "AgEBA0IABArkx3mKoPEZRxvuEYJb5GICu3nipYRElel8BP9N8lSKfAJA+I8c1OFj\n"
       "Uqc8F7fxbwc1PlOhdtaEqf4Ma7eY6Fc=\n"
       "-----END PUBLIC KEY-----\n";

    const char *msg = "message digest";
    const char *id = "ALICE123@YAHOO.COM";

    const uint8_t signature[] = {
       0x30, 0x44, 0x02, 0x20,

       0x40, 0xF1, 0xEC, 0x59, 0xF7, 0x93, 0xD9, 0xF4, 0x9E, 0x09, 0xDC,
       0xEF, 0x49, 0x13, 0x0D, 0x41, 0x94, 0xF7, 0x9F, 0xB1, 0xEE, 0xD2,
       0xCA, 0xA5, 0x5B, 0xAC, 0xDB, 0x49, 0xC4, 0xE7, 0x55, 0xD1,

       0x02, 0x20,

       0x6F, 0xC6, 0xDA, 0xC3, 0x2C, 0x5D, 0x5C, 0xF1, 0x0C, 0x77, 0xDF,
       0xB2, 0x0F, 0x7C, 0x2E, 0xB6, 0x67, 0xA4, 0x57, 0x87, 0x2F, 0xB0,
       0x9E, 0xC5, 0x63, 0x27, 0xA6, 0x7E, 0xC7, 0xDE, 0xEB, 0xE7
    };

    int rc = 0;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    bio = BIO_new_mem_buf(pubkey, strlen(pubkey));
    if (!TEST_true(bio != NULL))
        goto done;

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!TEST_true(pkey != NULL))
        goto done;

    if (!TEST_true(EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)))
        goto done;

    if (!TEST_ptr(mctx = EVP_MD_CTX_new()))
        goto done;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new(pkey, NULL)))
        goto done;

    if (!TEST_int_gt(EVP_PKEY_CTX_set1_id(pctx, (const uint8_t *)id,
                                          strlen(id)), 0))
        goto done;

    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

    if (!TEST_true(EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey)))
        goto done;

    if (!TEST_true(EVP_DigestVerifyUpdate(mctx, msg, strlen(msg))))
        goto done;

    if (!TEST_true(EVP_DigestVerifyFinal(mctx, signature, sizeof(signature))))
        goto done;
    rc = 1;

 done:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_MD_CTX_free(mctx);
    return rc;
}

static int test_EVP_SM2(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    size_t sig_len = 0;
    unsigned char *sig = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_MD_CTX *md_ctx_verify = NULL;
    EVP_PKEY_CTX *cctx = NULL;

    uint8_t ciphertext[128];
    size_t ctext_len = sizeof(ciphertext);

    uint8_t plaintext[8];
    size_t ptext_len = sizeof(plaintext);

    uint8_t sm2_id[] = {1, 2, 3, 4, 'l', 'e', 't', 't', 'e', 'r'};

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!TEST_ptr(pctx))
        goto done;

    if (!TEST_true(EVP_PKEY_paramgen_init(pctx) == 1))
        goto done;

    if (!TEST_true(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2)))
        goto done;

    if (!TEST_true(EVP_PKEY_paramgen(pctx, &params)))
        goto done;

    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!TEST_ptr(kctx))
        goto done;

    if (!TEST_true(EVP_PKEY_keygen_init(kctx)))
        goto done;

    if (!TEST_true(EVP_PKEY_keygen(kctx, &pkey)))
        goto done;

    if (!TEST_true(EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)))
        goto done;

    if (!TEST_ptr(md_ctx = EVP_MD_CTX_new()))
        goto done;

    if (!TEST_ptr(md_ctx_verify = EVP_MD_CTX_new()))
        goto done;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new(pkey, NULL)))
        goto done;

    EVP_MD_CTX_set_pkey_ctx(md_ctx, sctx);
    EVP_MD_CTX_set_pkey_ctx(md_ctx_verify, sctx);

    if (!TEST_int_gt(EVP_PKEY_CTX_set1_id(sctx, sm2_id, sizeof(sm2_id)), 0))
        goto done;

    if (!TEST_true(EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey)))
        goto done;

    if(!TEST_true(EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg))))
        goto done;

    /* Determine the size of the signature. */
    if (!TEST_true(EVP_DigestSignFinal(md_ctx, NULL, &sig_len)))
        goto done;

    if (!TEST_size_t_eq(sig_len, (size_t)EVP_PKEY_size(pkey)))
        goto done;

    if (!TEST_ptr(sig = OPENSSL_malloc(sig_len)))
        goto done;

    if (!TEST_true(EVP_DigestSignFinal(md_ctx, sig, &sig_len)))
        goto done;

    /* Ensure that the signature round-trips. */

    if (!TEST_true(EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey)))
        goto done;

    if (!TEST_true(EVP_DigestVerifyUpdate(md_ctx_verify, kMsg, sizeof(kMsg))))
        goto done;

    if (!TEST_true(EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len)))
        goto done;

    /* now check encryption/decryption */

    if (!TEST_ptr(cctx = EVP_PKEY_CTX_new(pkey, NULL)))
        goto done;

    if (!TEST_true(EVP_PKEY_encrypt_init(cctx)))
        goto done;

    if (!TEST_true(EVP_PKEY_encrypt(cctx, ciphertext, &ctext_len, kMsg, sizeof(kMsg))))
        goto done;

    if (!TEST_true(EVP_PKEY_decrypt_init(cctx)))
        goto done;

    if (!TEST_true(EVP_PKEY_decrypt(cctx, plaintext, &ptext_len, ciphertext, ctext_len)))
        goto done;

    if (!TEST_true(ptext_len == sizeof(kMsg)))
        goto done;

    if (!TEST_true(memcmp(plaintext, kMsg, sizeof(kMsg)) == 0))
        goto done;

    ret = 1;
done:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(params);
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_CTX_free(md_ctx_verify);
    OPENSSL_free(sig);
    return ret;
}
#endif

static int demo_EVP_SM2(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    size_t sig_len = 0;
    unsigned char *sig = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_MD_CTX *md_ctx_verify = NULL;
    EVP_PKEY_CTX *cctx = NULL;

    uint8_t ciphertext[128];
    size_t ctext_len = sizeof(ciphertext);

    uint8_t plaintext[8];
    size_t ptext_len = sizeof(plaintext);

    uint8_t sm2_id[] = {1, 2, 3, 4, 'l', 'e', 't', 't', 'e', 'r'};

    // 设置曲线并生成曲线参数
    printf("[+] 设置曲线并生成曲线参数\n");
    // EVP_PKEY_CTX可以通过参数id、e、evp_pkey三个参数进行初始化
    // ret->engine = e;
    // ret->pmeth = pmeth;
    // ret->operation = EVP_PKEY_OP_UNDEFINED;
    // ret->pkey = pkey;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(pctx);  // ctx->pmeth->paramgen_init(ctx);
    // 生成group，并让pctx->data->gen_group = group
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2);  // ret = ctx->pmeth->ctrl(ctx, cmd, p1, p2);
    // 新建ec，ec->group = pctx->data->gen_group，params = ec
    // params的type什么时候赋值？ EVP_PKEY_assign_EC_KEY(pkey, ec) 针对pkey->ec和type进行赋值
    EVP_PKEY_paramgen(pctx, &params);  // ret = ctx->pmeth->paramgen(ctx, *ppkey);
    
    // 根据曲线参数生成密钥对
    printf("[+] 根据曲线参数生成密钥对\n");
    kctx = EVP_PKEY_CTX_new(params, NULL);  // 通过params初始化kctx
    // null
    EVP_PKEY_keygen_init(kctx);  // ret = ctx->pmeth->keygen_init(ctx);
    // 1. 调用kctx->meth->keygen
    // 1.1 创建ec_key
    // 1.2 复制kctx->pkey的曲线参数到ec_key
    // 1.3 pkey指向ec_key
    // 1.4 调用ec_key->meth->kegen生成密钥对
    EVP_PKEY_keygen(kctx, &pkey);  // ret = ctx->pmeth->keygen(ctx, *ppkey);
    // 修改pkey->type指向EVP_PKEY_SM2
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);  // pkey->type = type;
    
    printf("[+] 设置SM2 pmeth\n");

    sctx = EVP_PKEY_CTX_new(pkey, NULL);  // 
    EVP_PKEY_CTX_set1_id(sctx, sm2_id, sizeof(sm2_id));

    md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(md_ctx, sctx);
    EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);
    EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg));
    EVP_DigestSignFinal(md_ctx, NULL, &sig_len);
    sig = OPENSSL_malloc(sig_len);
    debug(DEBUG_INFO, "sig_len = %zu\n", sig_len);
    EVP_DigestSignFinal(md_ctx, sig, &sig_len);

    // 签名验证
    md_ctx_verify = EVP_MD_CTX_new();
    EVP_MD_CTX_set_pkey_ctx(md_ctx_verify, sctx);
    EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey);
    EVP_DigestVerifyUpdate(md_ctx_verify, kMsg, sizeof(kMsg));
    EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len);

    ret = 1;
done:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(params);
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_CTX_free(md_ctx_verify);
    OPENSSL_free(sig);
    return ret;
}

int main(){
    debug(DEBUG_INFO, "test_EVP_SM2\n");
    if (test_EVP_SM2())
    {
        debug(DEBUG_SUCCESS, "passed!\n");
    }else{
        debug(DEBUG_ERROR, "test_EVP_SM2 failed!\n");
    }
    

    debug(DEBUG_INFO, "test_EVP_SM2_verify\n");
    if (test_EVP_SM2_verify())
    {
        debug(DEBUG_SUCCESS, "passed!\n");
    }else{
        debug(DEBUG_ERROR, "test_EVP_SM2_verify failed!\n");
    }

    debug(DEBUG_INFO, "demo_EVP_SM2\n");
    demo_EVP_SM2();
    return 0;
}