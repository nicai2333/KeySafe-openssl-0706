#include <crypto/sdf_sm2.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <crypto/sdf_error.h>
#include "crypto/ec/ec_local.h"

EC_KEY *sm2_key_generate(){
	EC_KEY *sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
	EC_KEY_precompute_mult(sm2_key, NULL);
	EC_KEY_generate_key(sm2_key);
	return sm2_key;
}

void sm2_key_get_private(EC_KEY *sm2_key, uint8_t priv_bin[32]){
	BIGNUM *priv = EC_KEY_get0_private_key(sm2_key);
	BN_bn2bin(priv, priv_bin);
}

BIGNUM * sm2_new_bn(uint8_t priv_bin[32]){
	// EC_KEY *sm2_key;
	BIGNUM *priv = BN_bin2bn(priv_bin, 32, NULL);
	// EC_KEY_set_private_key(sm2_key, priv);
	return priv;
}

void sm2_key_get_public(EC_KEY *sm2_key, uint8_t x_bin[32], uint8_t y_bin[32]){
	const EC_POINT *pubk;
	pubk = EC_KEY_get0_public_key(sm2_key);
	EC_GROUP *group = EC_KEY_get0_group(sm2_key);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	EC_POINT_get_affine_coordinates(group, pubk, x, y, NULL);
	BN_bn2bin(x, x_bin);
	BN_bn2bin(y, y_bin);
	BN_free(x);
	BN_free(y);
	EC_POINT_free(pubk);
	EC_GROUP_free(group);
}

EC_POINT * sm2_new_point(uint8_t x_bin[32], uint8_t y_bin[32]){
	EC_KEY *sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
	EC_GROUP *group = EC_KEY_get0_group(sm2_key);
	EC_POINT *pubk = EC_POINT_new(group);
	BIGNUM *x = BN_bin2bn(x_bin, 32, NULL);
	BIGNUM *y = BN_bin2bn(y_bin, 32, NULL);
    EC_POINT_set_affine_coordinates(group, pubk, x, y, NULL);
	// EC_KEY_set_public_key(sm2_key, pubk);
	return pubk;
}

EC_KEY * sm2_public_key_info_from_pem(char *filename){
	EC_KEY *sm2_key;
	
	BIO *file;
	if ((file = BIO_new_file(filename, "r")) == NULL) {
		BIO_free(file);
		error_print();
		return NULL;
	}
	if ((sm2_key = PEM_read_bio_EC_PUBKEY(file, NULL, NULL, NULL)) == NULL) {
		error_print();
		return NULL;
	}
	
	BIO_free(file);
	return sm2_key;
}

EC_KEY * sm2_private_key_info_decrypt_from_pem(char *filename, char *pass){
	EC_KEY *sm2_key;
	
	BIO *file;
	if ((file = BIO_new_file(filename, "r")) == NULL) {
		BIO_free(file);
		error_print();
		return NULL;
	}
	if ((sm2_key = PEM_read_bio_ECPrivateKey(file, NULL, NULL, pass)) == NULL) {
		error_print();
		return NULL;
	}
	BIO_free(file);
	return sm2_key;
}