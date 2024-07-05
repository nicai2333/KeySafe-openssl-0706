# ifndef OPENSSL_NO_SM3_NEON
#include "sm3-neon_local.h"
#include <openssl/e_os2.h>

u32 ll_neon_bswap4(const u32 a);
u64 ll_neon_bswap8(const u64 a);
void sm3_compress_neon(u32 digest[8], const u8 *buf, u64 nb);

static const u8 PAD_neon[64] = { 
    0x80, 0, 0, 0, 0, 0, 0, 0, 
    0,    0, 0, 0, 0, 0, 0, 0, 
    0,    0, 0, 0, 0, 0, 0, 0, 
    0,    0, 0, 0, 0, 0, 0, 0, 
    0,    0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 
    0,    0, 0, 0, 0, 0, 0, 0, 
    0,    0, 0, 0, 0, 0, 0, 0,
};

static inline u32 neon_to_be32(const u32 in)
{
    u32 ret;
    int i = 1;
    char c = (*(char*)&i);
#if (c)
    ret = in;
#else 
    ret = ll_neon_bswap4(in);
#endif

    return ret;
}

static inline u64 neon_to_be64(u64 in)
{
    u64 ret;
    int i = 1;
    char c = (*(char*)&i);
#if (c)
    ret = in;
#else 
    ret = ll_neon_bswap8(in);
#endif

    return ret;
}

static inline void neon_clean(u8 *p, size_t plen)
{
    size_t i;
    volatile u8 *pp;

    i = 0;
    pp = (volatile u8*)p;
    while (i < plen)
        pp[i++] = 0;
}

int sm3_neon_init(SM3_NEON_CTX *ctx)
{
    ctx->digest[0] = 0x7380166FU;
    ctx->digest[1] = 0x4914B2B9U;
    ctx->digest[2] = 0x172442D7U;
    ctx->digest[3] = 0xDA8A0600U;
    ctx->digest[4] = 0xA96F30BCU;
    ctx->digest[5] = 0x163138AAU;
    ctx->digest[6] = 0xE38DEE4DU;
    ctx->digest[7] = 0xB0FB0E4EU;

    ctx->bits = 0;
    return SM3_OK;
}

int sm3_neon_update(SM3_NEON_CTX *ctx, const u8* data, size_t datalen)
{
    size_t n, left;

    /* number of bytes in ctx->buf */
    n = (ctx->bits >> 3) & 0x3fU;

    ctx->bits += (datalen << 3);
    left = SM3_BLOCK_SIZE - n;
    if (datalen < left) {
        memcpy(ctx->buf + n, data, datalen);
        return SM3_OK;
    } else {
        /* concatenate ctx->buf and data to make up one block */
        memcpy(ctx->buf + n, data, left);
        sm3_compress_neon(ctx->digest, ctx->buf, 1);
        data += left;
        datalen -= left;
    }

    /* compress the remaining data */
    n = (datalen >> 6);
    sm3_compress_neon(ctx->digest, data, n);

    data += (SM3_BLOCK_SIZE*n);
    datalen &= 0x3fU;

    /* coppy the last few bytes to ctx->buf */
    memcpy(ctx->buf, data, datalen);
    return SM3_OK;
}

int sm3_neon_final(u8 *digest, SM3_NEON_CTX *ctx)
{
    int i;
    size_t n;
    u8 tbuf[SM3_BLOCK_SIZE];
    u32 tdigest[8];
    u32 *pdigest;

    /* number of bytes in ctx->buf */
    n = (ctx->bits >> 3) & 0x3fU;
    
    /* copy ctx */
    memcpy(tbuf, ctx->buf, n);
    tdigest[0] = ctx->digest[0];
    tdigest[1] = ctx->digest[1];
    tdigest[2] = ctx->digest[2];
    tdigest[3] = ctx->digest[3];
    tdigest[4] = ctx->digest[4];
    tdigest[5] = ctx->digest[5];
    tdigest[6] = ctx->digest[6];
    tdigest[7] = ctx->digest[7];
    pdigest = (u32*)digest;

    if (n < 56)
        memcpy(tbuf + n, PAD_neon, 56 - n);
    else {
        memcpy(tbuf + n, PAD_neon, 64 - n);
        sm3_compress_neon(tdigest, tbuf, 1);
        memset(tbuf, 0, 56);
    }

    *(u64*)(&tbuf[56]) = neon_to_be64(ctx->bits);
    sm3_compress_neon(tdigest, tbuf, 1);

    /* big endian */
    for (i = 0; i < 8; i++)
        pdigest[i] = neon_to_be32(tdigest[i]);

    neon_clean(tbuf, SM3_BLOCK_SIZE);
    return SM3_OK;
}
#endif