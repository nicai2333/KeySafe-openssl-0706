/******************************************************************************
 *                                                                            *
 * Copyright 2020-2021 Meng-Shan Jiang                                        *
 *                                                                            *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *    http://www.apache.org/licenses/LICENSE-2.0                              *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 *                                                                            *
 *****************************************************************************/


#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#ifndef OSSL_CRYPTO_SM3_NEON_H
# define OSSL_CRYPTO_SM3_NEON_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_SM3_NEON

#define SM3_OK    0
#define SM3_ERR  -1

#define SM3_DIGEST_LENGTH   32
#define SM3_BLOCK_SIZE      64
# define SM3_WORD unsigned int

#define u8  unsigned char
#define u32 unsigned int
#define u64 unsigned long long

#define ORDER_BIG_ENDIAN     0
#define ORDER_LITTLE_ENDIAN  1

typedef struct {
    u8 buf[SM3_BLOCK_SIZE];  // hold last few bytes that have not been processed
    u32 digest[8];           // ...
    size_t bits;             // number of bits compressed
} SM3_NEON_CTX;

int sm3_neon_init(SM3_NEON_CTX *ctx);

int sm3_neon_update(SM3_NEON_CTX *ctx, const u8* data, size_t datalen);

int sm3_neon_final(u8 *digest, SM3_NEON_CTX *ctx);

#endif
#endif

