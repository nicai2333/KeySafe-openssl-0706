/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef SDF_SM2_H
#define SDF_SM2_H

#include <string.h>
#include <stdint.h>
#include <crypto/sm2.h>

#ifdef __cplusplus
extern "C" {
#endif


EC_KEY *sm2_key_generate();
void sm2_key_get_private(EC_KEY *sm2_key, uint8_t priv_bin[32]);
BIGNUM * sm2_new_bn(uint8_t priv_bin[32]);
void sm2_key_get_public(EC_KEY *sm2_key, uint8_t x_bin[32], uint8_t y_bin[32]);
EC_POINT * sm2_new_point(uint8_t x_bin[32], uint8_t y_bin[32]);
EC_KEY * sm2_public_key_info_from_pem(char *filename);
EC_KEY * sm2_private_key_info_decrypt_from_pem(char *filename, char *pass);


#ifdef __cplusplus
}
#endif
#endif
