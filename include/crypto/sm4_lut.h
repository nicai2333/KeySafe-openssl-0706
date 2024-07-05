#ifndef OSSL_CRYPTO_SM4_LUT_H
# define OSSL_CRYPTO_SM4_LUT_H

#include <stdint.h>

# ifdef OPENSSL_NO_LUT_SM4
#  error SM4_LUT is disabled.
# endif

# define SM4_LUT_ENCRYPT     1
# define SM4_LUT_DECRYPT     0

# define SM4_LUT_BLOCK_SIZE    16
# define SM4_LUT_KEY_SCHEDULE  32

typedef struct SM4_LUT_KEY_st {
    uint32_t rk[SM4_LUT_KEY_SCHEDULE];
} SM4_LUT_KEY;


int SM4_LUT_set_key(const uint8_t *key, SM4_LUT_KEY *ks);

void SM4_LUT_encrypt(const uint8_t *in, uint8_t *out, SM4_LUT_KEY *ks);

void SM4_LUT_decrypt(const uint8_t *in, uint8_t *out, SM4_LUT_KEY *ks);

#endif 