/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_SM3_NEON
# include <openssl/evp.h>
# include "crypto/evp.h"
# include "crypto/sm3-neon.h"

static int neon_init(EVP_MD_CTX *ctx)
{
    return sm3_neon_init(EVP_MD_CTX_md_data(ctx));
}

static int neon_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return sm3_neon_update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int neon_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return sm3_neon_final(md, EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD sm3_neon_md = {
    NID_sm3_neon,
    NID_sm3WithRSAEncryption,
    SM3_DIGEST_LENGTH,
    0,
    neon_init,
    neon_update,
    neon_final,
    NULL,
    NULL,
    SM3_BLOCK_SIZE,
    sizeof(EVP_MD *) + sizeof(SM3_NEON_CTX),
};

const EVP_MD *EVP_sm3_neon(void)
{
    return &sm3_neon_md;
}

#endif