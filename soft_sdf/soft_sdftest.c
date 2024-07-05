/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <crypto/sdf_error.h>
#include "crypto/sdf.h"
#include "crypto/sdf_ext.h"
#include "crypto/sdf_mem.h"
#include "crypto/sdf_sm2.h"
#include "speed.h"
#include "crypto/sdf_sm4.h"

// sm2模块依赖的头文件
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>

#define TEST_KEK_INDEX		1
#define TEST_SM2_KEY_INDEX	1
#define TEST_SM2_KEY_PASS	"123456"


#define SM2_MIN_PLAINTEXT_SIZE	1 // re-compute SM2_MIN_CIPHERTEXT_SIZE when modify
#define SM2_MAX_PLAINTEXT_SIZE	255 // re-compute SM2_MAX_CIPHERTEXT_SIZE when modify


static unsigned char test_input[16384]={0};
static unsigned char test_output[16384]={0};
void *test_hDeviceHandle = NULL;
void *test_hSessionHandle = NULL;
unsigned char test_ucHash[32];
unsigned int test_uiHashLength = 0;

void *test_hKeyHandle = NULL;
unsigned int test_uiKeyBits = 128;
unsigned int test_uiKEKIndex = TEST_KEK_INDEX;
unsigned char test_pucKey[64];
unsigned int test_uiKeyLength = (unsigned int)sizeof(test_pucKey);
unsigned char test_pucIV[16];
unsigned char test_pucEncData[128];
unsigned int test_EncDataLength = (unsigned int)sizeof(test_pucEncData);

unsigned int test_uiIPKIndex = TEST_SM2_KEY_INDEX;
unsigned char *test_ucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
unsigned int test_uiPwdLength = 6;
unsigned char test_ucEncData[48] = { 1,2,3,4 };
unsigned int test_uiEncDataLength = (unsigned int)sizeof(test_ucEncData);
unsigned char test_ucSigData[32] = { 1,2,3,4 };
unsigned int test_uiSigDataLength = (unsigned int)sizeof(test_ucSigData);
ECCCipher test_eccCipher;
unsigned char test_ucDecData[256];
unsigned int test_uiDecDataLength;
ECCSignature test_eccSignature;

// TODO: move soft_sdf init functions into soft_sdf.c

static int generate_kek(unsigned int uiKEKIndex)
{
	char filename[256];
	uint8_t kek[16];
	FILE *file;

	if (RAND_bytes(kek, sizeof(kek)) != 1) {
		error_print();
		return -1;
	}

	snprintf(filename, sizeof(filename), "kek-%u.key", uiKEKIndex);
	if (!(file = fopen(filename, "wb"))) {
		error_print();
		return -1;
	}
	if (fwrite(kek, 1, sizeof(kek), file) != sizeof(kek)) {
		fclose(file);
		error_print();
		return -1;
	}
	fclose(file);

	return 1;
}

static int generate_sign_key(unsigned int uiKeyIndex, const char *pass)
{
	// SM2_KEY sm2_key;
	// SM2_POINT point;
	EC_POINT *point;

	uint8_t data[32];
	// SM2_SIGNATURE sig;
	uint8_t sig[100];
	int sig_len;
	char filename[256];
	BIO *file;
	int i;
	// if (sm2_key_generate(&sm2_key) != 1) {
	// 	error_print();
	// 	return -1;
	// }
	EC_KEY *sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
	EC_KEY_precompute_mult(sm2_key, NULL);
	EC_KEY_generate_key(sm2_key);
	if (!sm2_key) {
		error_print();
		return -1;
	}
	// EC_KEY_print(stdout, sm2_key, 0);
	// sm2_key_print(stderr, 0, 0, "SDF SignKey", &sm2_key);

	snprintf(filename, sizeof(filename), "sm2sign-%u.pem", uiKeyIndex);
	// if ((file = fopen(filename, "wb")) == NULL) {
	// 	fclose(file);
	// 	error_print();
	// 	return -1;
	// }
	// if (sm2_private_key_info_encrypt_to_pem(&sm2_key, pass, file) != 1) {
	// 	error_print();
	// 	return -1;
	// }
	// fclose(file);

	EVP_CIPHER *enc = EVP_get_cipherbyname("sm4");
	if (!enc)
    {
        printf("EVP_get_cipherbyname failed!\n");
		error_print();
        return -1;
    }
	if ((file = BIO_new_file(filename, "w")) == NULL) {
		BIO_free(file);
		error_print();
		return -1;
	}
	if (!PEM_write_bio_ECPrivateKey(file, sm2_key, enc, NULL, 0, NULL, pass)) {
		error_print();
		return -1;
	}
	BIO_free(file);
	

	snprintf(filename, sizeof(filename), "sm2signpub-%u.pem", uiKeyIndex);
	// if ((file = fopen(filename, "wb")) == NULL) {
	// 	fclose(file);
	// 	error_print();
	// 	return -1;
	// }
	// if (sm2_public_key_info_to_pem(&sm2_key, file) != 1) {
	// 	error_print();
	// 	return -1;
	// }
	// fclose(file);
	if ((file = BIO_new_file(filename, "w")) == NULL) {
		BIO_free(file);
		error_print();
		return -1;
	}
	if (!PEM_write_bio_EC_PUBKEY(file, sm2_key)) {
		error_print();
		return -1;
	}
	BIO_free(file);

	// print public key as ECCrefPublicKey
	// sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point);

	// printf("ECCrefPublicKey eccPublicKey = {\n");
	// printf("256,\n");

	// printf("{\n");
	// for (i = 0; i < 32; i++) {
	// 	printf("0x00,");
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// for (i = 0; i < 32; i++) {
	// 	printf("0x%02x,", point.x[i]);
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// printf("},\n");

	// printf("{\n");
	// for (i = 0; i < 32; i++) {
	// 	printf("0x00,");
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// for (i = 0; i < 32; i++) {
	// 	printf("0x%02x,", point.y[i]);
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// printf("},\n");

	// printf("};\n");



	// print to be signed data
	// rand_bytes(data, sizeof(data));
	// printf("unsigned char ucData[] = {\n");
	// for (i = 0; i < sizeof(data); i++) {
	// 	printf("0x%02x,", data[i]);
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// printf("};\n");

	// sm2_do_sign(&sm2_key, data, &sig);
	sm2_sign(data, 32, sig, &sig_len, sm2_key);

	// print ECCSignature

	// printf("ECCSignature eccSignature = {\n");

	// printf("{\n");
	// for (i = 0; i < 32; i++) {
	// 	printf("0x00,");
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// for (i = 0; i < 32; i++) {
	// 	printf("0x%02x,", sig.r[i]);
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// printf("},\n");

	// printf("{\n");
	// for (i = 0; i < 32; i++) {
	// 	printf("0x00,");
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// for (i = 0; i < 32; i++) {
	// 	printf("0x%02x,", sig.s[i]);
	// 	printf("%s", (i + 1) % 8 ? " " : "\n");
	// }
	// printf("},\n");

	// printf("};\n");
	return 1;
}

// static int generate_enc_key(unsigned int uiKeyIndex, const char *pass)
// {
// 	SM2_KEY sm2_key;
// 	char filename[256];
// 	FILE *file;
// 	size_t i;

// 	if (sm2_key_generate(&sm2_key) != 1) {
// 		error_print();
// 		return -1;
// 	}

// 	snprintf(filename, sizeof(filename), "sm2enc-%u.pem", uiKeyIndex);
// 	if ((file = fopen(filename, "wb")) == NULL) {
// 		fclose(file);
// 		error_print();
// 		return -1;
// 	}
// 	if (sm2_private_key_info_encrypt_to_pem(&sm2_key, pass, file) != 1) {
// 		error_print();
// 		return -1;
// 	}
// 	fclose(file);

// 	snprintf(filename, sizeof(filename), "sm2encpub-%u.pem", uiKeyIndex);
// 	if ((file = fopen(filename, "wb")) == NULL) {
// 		fclose(file);
// 		error_print();
// 		return -1;
// 	}
// 	if (sm2_public_key_info_to_pem(&sm2_key, file) != 1) {
// 		error_print();
// 		return -1;
// 	}
// 	fclose(file);

// 	SM2_POINT point;

// 	// print public key as ECCrefPublicKey
// 	sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point);

// 	printf("ECCrefPublicKey eccPublicKey = {\n");
// 	printf("256,\n");

// 	printf("{\n");
// 	for (i = 0; i < 32; i++) {
// 		printf("0x00,");
// 		printf("%s", (i + 1) % 8 ? " " : "\n");
// 	}
// 	for (i = 0; i < 32; i++) {
// 		printf("0x%02x,", point.x[i]);
// 		printf("%s", (i + 1) % 8 ? " " : "\n");
// 	}
// 	printf("},\n");

// 	printf("{\n");
// 	for (i = 0; i < 32; i++) {
// 		printf("0x00,");
// 		printf("%s", (i + 1) % 8 ? " " : "\n");
// 	}
// 	for (i = 0; i < 32; i++) {
// 		printf("0x%02x,", point.y[i]);
// 		printf("%s", (i + 1) % 8 ? " " : "\n");
// 	}
// 	printf("},\n");

// 	printf("};\n");


// 	// 准备待加密的数据
// 	uint8_t data[48];

// 	rand_bytes(data, sizeof(data));

// 	printf("unsigned char ucData[] = {\n");
// 	for (i = 0; i < sizeof(data); i++) {
// 		printf("0x%02x,", data[i]);
// 		printf("%s", (i + 1) % 8 ? " " : "\n");
// 	}
// 	printf("};\n");


// 	// 现在要加密了
// 	SM2_CIPHERTEXT ciphertext;

// 	sm2_do_encrypt(&sm2_key, data, sizeof(data), &ciphertext);


// 	// 打印CIPHERTEXT

// 	printf("ECCCipher eccCipher = {\n");

// 		printf("{\n");
// 		for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
// 			printf("0x00,");
// 			printf("%s", (i + 1) % 8 ? " " : "\n");
// 		}
// 		for (i = 0; i < 32; i++) {
// 			printf("0x%02x,", ciphertext.point.x[i]);
// 			printf("%s", (i + 1) % 8 ? " " : "\n");
// 		}
// 		printf("},\n");

// 		printf("{\n");
// 		for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
// 			printf("0x00,");
// 			printf("%s", (i + 1) % 8 ? " " : "\n");
// 		}
// 		for (i = 0; i < 32; i++) {
// 			printf("0x%02x,", ciphertext.point.y[i]);
// 			printf("%s", (i + 1) % 8 ? " " : "\n");
// 		}
// 		printf("},\n");

// 		printf("{\n");
// 		for (i = 0; i < 32; i++) {
// 			printf("0x%02x,", ciphertext.hash[i]);
// 			printf("%s", (i + 1) % 8 ? " " : "\n");
// 		}
// 		printf("},\n");

// 		printf("%u,\n", ciphertext.ciphertext_size);

// 		printf("{\n");
// 		for (i = 0; i < ciphertext.ciphertext_size; i++) {
// 			printf("0x%02x,", ciphertext.ciphertext[i]);
// 			printf("%s", (i + 1) % 8 ? " " : "\n");
// 		}
// 		printf("},\n");


// 	printf("};\n");


// 	return 1;
// }

static int generate_enc_key(unsigned int uiKeyIndex, const char *pass)
{
	// SM2_KEY sm2_key;
	// SM2_POINT point;
	EC_POINT *point;

	uint8_t data[32];
	// SM2_SIGNATURE sig;
	uint8_t sig[100];
	int sig_len;
	char filename[256];
	BIO *file;
	int i;

	EC_KEY *sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
	EC_KEY_precompute_mult(sm2_key, NULL);
	EC_KEY_generate_key(sm2_key);
	if (!sm2_key) {
		error_print();
		return -1;
	}

	snprintf(filename, sizeof(filename), "sm2enc-%u.pem", uiKeyIndex);

	EVP_CIPHER *enc = EVP_get_cipherbyname("sm4");
	if (!enc)
    {
        printf("EVP_get_cipherbyname failed!\n");
		error_print();
        return -1;
    }
	if ((file = BIO_new_file(filename, "w")) == NULL) {
		BIO_free(file);
		error_print();
		return -1;
	}
	if (!PEM_write_bio_ECPrivateKey(file, sm2_key, enc, NULL, 0, NULL, pass)) {
		error_print();
		return -1;
	}
	BIO_free(file);
	
	snprintf(filename, sizeof(filename), "sm2encpub-%u.pem", uiKeyIndex);

	if ((file = BIO_new_file(filename, "w")) == NULL) {
		BIO_free(file);
		error_print();
		return -1;
	}
	if (!PEM_write_bio_EC_PUBKEY(file, sm2_key)) {
		error_print();
		return -1;
	}
	BIO_free(file);

	return 1;
}

static int test_SDF_GetDeviceInfo(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	DEVICEINFO deviceInfo;
	int rv;

	rv = SDF_OpenDevice(&hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_OpenSession failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_GetDeviceInfo(hSessionHandle, &deviceInfo);
	if (rv != SDR_OK) {
		printf("SDF_GetDeviceInfo failed with error: 0x%X\n", rv);
		return -1;
	}

	fprintf(stderr, "Device Info:\n");
	fprintf(stderr, "    IssuerName: %s\n", deviceInfo.IssuerName);
	fprintf(stderr, "    DeviceName: %s\n", deviceInfo.DeviceName);
	fprintf(stderr, "    DeviceSerial: %s\n", deviceInfo.DeviceSerial);
	fprintf(stderr, "    DeviceVersion: %u\n", deviceInfo.DeviceVersion);
	fprintf(stderr, "    StandardVersion: %u\n", deviceInfo.StandardVersion);
	fprintf(stderr, "    AsymAlgAbility: 0x%08X 0x%08X\n", deviceInfo.AsymAlgAbility[0], deviceInfo.AsymAlgAbility[1]);
	fprintf(stderr, "    SymAlgAbility:");
	if (deviceInfo.SymAlgAbility & SGD_SM1) fprintf(stderr, " SM1");
	if (deviceInfo.SymAlgAbility & SGD_SM4) fprintf(stderr, " SM4");
	if (deviceInfo.SymAlgAbility & SGD_ZUC) fprintf(stderr, " ZUC");
	if (deviceInfo.SymAlgAbility & SGD_SSF33) fprintf(stderr, " SSF33");
	if (deviceInfo.SymAlgAbility & SGD_ECB) fprintf(stderr, " ECB");
	if (deviceInfo.SymAlgAbility & SGD_CBC) fprintf(stderr, " CBC");
	if (deviceInfo.SymAlgAbility & SGD_CFB) fprintf(stderr, " CFB");
	if (deviceInfo.SymAlgAbility & SGD_OFB) fprintf(stderr, " OFB");
	if (deviceInfo.SymAlgAbility & SGD_MAC) fprintf(stderr, " MAC");
	fprintf(stderr, " (0x%08X)\n", deviceInfo.SymAlgAbility);
	fprintf(stderr, "    HashAlgAbility:");
	if (deviceInfo.HashAlgAbility & SGD_SM3) fprintf(stderr, " SM3");
	if (deviceInfo.HashAlgAbility & SGD_SHA1) fprintf(stderr, " SHA1");
	if (deviceInfo.HashAlgAbility & SGD_SHA256) fprintf(stderr, " SHA256");
	fprintf(stderr, " (0x%08X)\n", deviceInfo.HashAlgAbility);
	fprintf(stderr, "    BufferSize: %u\n", deviceInfo.BufferSize);

	rv = SDF_CloseSession(hSessionHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseSession failed with error: 0x%X\n", rv);
		return -1;
	}

	rv = SDF_CloseDevice(hDeviceHandle);
	if (rv != SDR_OK) {
		printf("SDF_CloseDevice failed with error: 0x%X\n", rv);
		return -1;
	}

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_GenerateRandom(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	int lengths[] = { 1, 8, 128 };
	for (int i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
		unsigned int uiLength = lengths[i];
		unsigned char pucRandom[128] = {0}; // Assuming max length
		unsigned char zeros[sizeof(pucRandom)] = {0};

		ret = SDF_GenerateRandom(hSessionHandle, uiLength, pucRandom);
		if (ret != SDR_OK) {
			fprintf(stderr, "Error: SDF_GenerateRandom: 0x%X\n", ret);
			return -1;
		}

		// Check if the output is not all zeros
		if (memcmp(pucRandom, zeros, uiLength) == 0) {
			error_print();
			return -1;
		}
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// FIXME: check generated public key is not [n-1]G, i.e. -G
int test_SDF_ExportSignPublicKey_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyIndex = TEST_SM2_KEY_INDEX;
	unsigned char *pucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	ECCrefPublicKey eccPublicKey;
	uint8_t zeros[ECCref_MAX_LEN] = {0};
	// SM2_POINT point;
	
	// SM2_Z256_POINT public_key;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenDevice failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenSession failed with error: 0x%X\n", ret);
		return -1;
	}
	ret = SDF_ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, &eccPublicKey);

	if (ret != SDR_OK) {
		printf("SDF_ExportSignPublicKey_ECC failed with error: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	// memcpy(point.x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	// memcpy(point.y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	// if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
	// 	error_print();
	// 	return -1;
	// }

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_SDF_ExportEncPublicKey_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiKeyIndex = TEST_SM2_KEY_INDEX;
	unsigned char *pucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	ECCrefPublicKey eccPublicKey;
	uint8_t zeros[ECCref_MAX_LEN] = {0};
	// SM2_POINT point;
	// SM2_Z256_POINT public_key;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenDevice failed with error: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "SDF_OpenSession failed with error: 0x%X\n", ret);
		return -1;
	}
	ret = SDF_ExportEncPublicKey_ECC(hSessionHandle, uiKeyIndex, &eccPublicKey);
	if (ret != SDR_OK) {
		printf("SDF_ExportEncPublicKey_ECC failed with error: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	// memcpy(point.x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	// memcpy(point.y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	// if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
	// 	error_print();
	// 	return -1;
	// }

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// // FIXME: use format_bytes
// void printECCPublicKey(const ECCrefPublicKey *publicKey)
// {
// 	int i;
// 	printf("ECC Public Key:\n");
// 	printf("Bits: %u\n", publicKey->bits);

// 	printf("X: ");
// 	for (int i = 0; i < ECCref_MAX_LEN; i++) {
// 		printf("%02X", publicKey->x[i]);
// 	}
// 	printf("\n");

// 	printf("Y: ");
// 	for (i = 0; i < ECCref_MAX_LEN; i++) {
// 		printf("%02X", publicKey->y[i]);
// 	}
// 	printf("\n");
// }

// void printECCPrivateKey(const ECCrefPrivateKey *eccRefPrivateKey)
// {
// 	int i;
// 	printf("ECC Private Key:\n");
// 	printf("Bits: %u\n", eccRefPrivateKey->bits);
// 	printf("K Value: ");
// 	for (i = 0; i < ECCref_MAX_LEN; i++) {
// 		printf("%02X", eccRefPrivateKey->K[i]);
// 	}
// 	printf("\n");
// }

// FIXME: check generated public key is not [n-1]G, i.e. -G
static int test_SDF_GenerateKeyPair_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey;
	ECCrefPrivateKey eccPrivateKey;
	int ret;

	EC_KEY *sm2_key;
	EC_POINT *point;
	uint8_t pubk_x[32], pubk_y[32];
	EC_POINT *public_key, *pt;
	EC_GROUP *group;
	BIGNUM *private_key;
	uint8_t zeros[ECCref_MAX_LEN] = {0};

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}
	
	ret = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_1, 256, &eccPublicKey, &eccPrivateKey);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyPair_ECC: 0x%X\n", ret);
		return -1;
	}

	// check public key
	if (eccPublicKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccPublicKey.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	memcpy(pubk_x, eccPublicKey.x + ECCref_MAX_LEN - 32, 32);
	memcpy(pubk_y, eccPublicKey.y + ECCref_MAX_LEN - 32, 32);
	public_key = sm2_new_point(pubk_x, pubk_y);
	if (!public_key) {
		error_print();
		return -1;
	}

	// check private key
	if (eccPrivateKey.bits != 256) {
		error_print();
		return -1;
	}
	if (memcmp(eccPrivateKey.K, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	

	// sm2_z256_from_bytes(private_key, eccPrivateKey.K + ECCref_MAX_LEN - 32);
	// if (sm2_key_set_private_key(&sm2_key, private_key) != 1) {
	// 	error_print();
	// 	return -1;
	// }
	
	sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
	group = EC_KEY_get0_group(sm2_key);
	private_key = sm2_new_bn(eccPrivateKey.K + ECCref_MAX_LEN - 32);
	pt = EC_POINT_new(group);
	EC_POINT_mul(group, pt, private_key, NULL, NULL, NULL);
	if (EC_KEY_set_private_key(sm2_key, private_key) != 1) {
		error_print();
		return -1;
	}
	
	
	// check private/public key
	// if (sm2_z256_point_equ(&sm2_key.public_key, &public_key) != 1) {
	// 	error_print();
	// 	return -1;
	// }
	// 比较 从private计算生成的公钥pt 和 从eccPublicKey读取的公钥public_key
	
	if (EC_POINT_cmp(group, public_key, pt, NULL) != 0) {
		error_print();
		return -1;
	}
	
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_ExternalVerify_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey = {
		256,
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x12, 0xbd, 0x37, 0x95, 0x9d, 0xb3, 0x36,
		0x11, 0x33, 0x04, 0x44, 0x02, 0xfa, 0x83, 0xec,
		0x18, 0x47, 0x1b, 0x5b, 0x2c, 0x98, 0xb5, 0x0e,
		0x49, 0xa3, 0x29, 0x43, 0x92, 0xd1, 0xe5, 0x45,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x31, 0x17, 0xbe, 0x37, 0xef, 0x88, 0x82, 0x2d,
		0xf5, 0x53, 0xc6, 0xe2, 0xf2, 0x67, 0x77, 0x8a,
		0x80, 0xe0, 0xe1, 0xfa, 0x3c, 0x49, 0xd4, 0x8b,
		0xb0, 0xe4, 0xbe, 0xfd, 0x66, 0xbe, 0xcc, 0x4c,
		},
	};
	unsigned char ucData[] = {
		0xac, 0xba, 0xa9, 0x0f, 0xab, 0x42, 0x9f, 0x58,
		0x72, 0x05, 0xeb, 0x4a, 0xb3, 0xa2, 0x16, 0x70,
		0x1a, 0x0d, 0xef, 0xfe, 0x10, 0xea, 0x76, 0x8f,
		0x7d, 0x89, 0x33, 0x7a, 0xcc, 0xbe, 0x9b, 0x9e,
	};
	ECCSignature eccSignature = {
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x50, 0x52, 0x4e, 0xee, 0xa7, 0x6c, 0x91, 0x4e,
		0xd5, 0x75, 0xab, 0xa1, 0x74, 0xcf, 0x34, 0x18,
		0xae, 0xb0, 0x5e, 0x34, 0x29, 0xd5, 0xff, 0x90,
		0x09, 0x93, 0xaf, 0x6b, 0x4d, 0x1c, 0xf5, 0x4f,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x76, 0xf0, 0xba, 0xd1, 0x97, 0x4d, 0x2b, 0xa8,
		0x08, 0x9e, 0xc4, 0x7b, 0x75, 0x06, 0x05, 0x89,
		0x8f, 0xab, 0x60, 0xce, 0xc7, 0x27, 0x98, 0x41,
		0x3e, 0xb4, 0xb6, 0x66, 0x20, 0x52, 0x0c, 0xf4,
		},
	};
	unsigned char saved_byte;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice return 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// verify correct signature
	ret = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccSignature);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ExternalVerify_ECC returned 0x%X\n", ret);
		return -1;
	}

#if ENABLE_TEST_INVALID_INPUT
	// verify invalid signature
	eccSignature.r[32]++;
	fprintf(stderr, "<!--\n");
	ret = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccSignature);
	fprintf(stderr, "-->\n");
	if (ret == SDR_OK) {
		fprintf(stderr, "Error: SDF_ExternalVerify_ECC return SDR_OK on modified signature\n");
		return -1;
	}
	eccSignature.r[32]--;

	// verify modified data
	ucData[0]++;
	fprintf(stderr, "<!--\n");
	ret = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccSignature);
	fprintf(stderr, "-->\n");
	if (ret == SDR_OK) {
		fprintf(stderr, "Error: SDF_ExternalVerify_ECC return SDR_OK on modified data\n");
		return -1;
	}
	ucData[0]--;
#endif

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_ExternalEncrypt_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	ECCrefPublicKey eccPublicKey;
	unsigned char ucData[48];
	ECCCipher eccCipher;
	int ret;

	EC_KEY *sm2_key;
	// SM2_KEY sm2_key;
	// SM2_POINT point;
	uint8_t x[32], y[32];
	// SM2_CIPHERTEXT ciphertext;
	const uint8_t zeros[ECCref_MAX_LEN] = {0};
	uint8_t plaintext[SM2_MAX_PLAINTEXT_SIZE];
	size_t plaintext_len;
	size_t ctext_len;
	uint8_t ctext[SM2_MAX_PLAINTEXT_SIZE];
	uint8_t C1_x[32], C1_y[32], C2[SM2_MAX_PLAINTEXT_SIZE], C3[32];
    int C2_len, C3_len;
	EVP_MD *digest = EVP_sm3();

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// generate SM2_KEY and convert public key to ECCrefPublicKey
	// Note: when testing SDF_ExternalEncrypt_ECC, we should not assume IPK exists
	if ((sm2_key = sm2_key_generate()) == NULL) {
		error_print();
		return -1;
	}
	
	// if (sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point) != 1) {
	// 	error_print();
	// 	return -1;
	// }
	sm2_key_get_public(sm2_key, x, y);

	eccPublicKey.bits = 256;
	memset(eccPublicKey.x, 0, ECCref_MAX_LEN - 32);
	memcpy(eccPublicKey.x + ECCref_MAX_LEN - 32, x, 32);
	memset(eccPublicKey.y, 0, ECCref_MAX_LEN - 32);
	memcpy(eccPublicKey.y + ECCref_MAX_LEN - 32, y, 32);

	// encrypt
	if (RAND_bytes(ucData, sizeof(ucData)) != 1) {
		error_print();
		return -1;
	}
	ret = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, &eccPublicKey, ucData, (unsigned int)sizeof(ucData), &eccCipher);
	if (ret != SDR_OK) {
		error_print();
		return -1;
	}

	// convert ECCCipher to SM2_CIPHERTEXT
	if (memcmp(eccCipher.x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (memcmp(eccCipher.y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return -1;
	}
	if (eccCipher.L > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return -1;
	}
	memcpy(C1_x, eccCipher.x + ECCref_MAX_LEN - 32, 32);
	memcpy(C1_y, eccCipher.y + ECCref_MAX_LEN - 32, 32);
	memcpy(C3, eccCipher.M, 32);
	C2_len = eccCipher.L;
	memcpy(C2, eccCipher.C, eccCipher.L);
	C3_len = 32;
	ctext_len = sizeof(ctext);

	if(sm2_set_ciphertext(ctext, &ctext_len, C1_x, C1_y, C2, C2_len, C3, C3_len) != 1){
		error_print();
		return -1;
	}
	// decrypt and check plaintext
	// if (sm2_do_decrypt(&sm2_key, &ciphertext, plaintext, &plaintext_len) != 1) {
	// 	error_print();
	// 	return -1;
	// }
	plaintext_len = SM2_MAX_PLAINTEXT_SIZE;
	if (sm2_decrypt(sm2_key, digest, ctext, ctext_len, plaintext, &plaintext_len) != 1) {
		error_print();
		return -1;
	}

	if (plaintext_len != sizeof(ucData)) {
		error_print();
		return -1;
	}
	if (memcmp(plaintext, ucData, sizeof(ucData)) != 0) {
		error_print();
		return -1;
	}


	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// void printECCCipher(const ECCCipher *cipher)
// {
// 	printf("ECCCipher:\n");
// 	printf("x: ");
// 	for (int i = 0; i < ECCref_MAX_LEN; ++i) {
// 		printf("%02X ", cipher->x[i]);
// 	}
// 	printf("\n");

// 	printf("y: ");
// 	for (int i = 0; i < ECCref_MAX_LEN; ++i) {
// 		printf("%02X ", cipher->y[i]);
// 	}
// 	printf("\n");

// 	printf("M: ");
// 	for (int i = 0; i < 32; ++i) {
// 		printf("%02X ", cipher->M[i]);
// 	}
// 	printf("\n");

// 	printf("L: %u\n", cipher->L);

// 	printf("C: ");
// 	for (int i = 0; i < cipher->L; ++i) {
// 		printf("%02X ", cipher->C[i]);
// 	}
// 	printf("\n");
// }

int test_SDF_GenerateKeyWithEPK_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	ECCrefPublicKey eccPublicKey = {
		256,
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x12, 0xbd, 0x37, 0x95, 0x9d, 0xb3, 0x36,
		0x11, 0x33, 0x04, 0x44, 0x02, 0xfa, 0x83, 0xec,
		0x18, 0x47, 0x1b, 0x5b, 0x2c, 0x98, 0xb5, 0x0e,
		0x49, 0xa3, 0x29, 0x43, 0x92, 0xd1, 0xe5, 0x45,
		},
		{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x31, 0x17, 0xbe, 0x37, 0xef, 0x88, 0x82, 0x2d,
		0xf5, 0x53, 0xc6, 0xe2, 0xf2, 0x67, 0x77, 0x8a,
		0x80, 0xe0, 0xe1, 0xfa, 0x3c, 0x49, 0xd4, 0x8b,
		0xb0, 0xe4, 0xbe, 0xfd, 0x66, 0xbe, 0xcc, 0x4c,
		},
	};
	ECCCipher eccCipher;
	int ret;


	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, 128, SGD_SM2_3, &eccPublicKey, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_GenerateKeyWithEPK_ECC returned 0x%X\n", ret);
		return -1;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return -1;
	}

	if (SDF_DestroyKey(hSessionHandle, hKeyHandle) != SDR_OK) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_SDF_GenerateKeyWithKEK(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = TEST_KEK_INDEX;
	unsigned char ucKey[64]; // encrypted key with SGD_SM4_CBC
	unsigned int uiKeyLength;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		printf("Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	uiKeyLength = (unsigned int)sizeof(ucKey); // SDF_GenerateKeyWithKEK might check output buffer size

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_CBC, uiKEKIndex, ucKey, &uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyWithKEK: 0x%X\n", ret);
		return -1;
	}
	if (hKeyHandle == NULL) {
		error_print();
		return -1;
	}
	// encrpyted key size should be larger
	if (uiKeyLength < uiKeyBits/8) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	hKeyHandle = NULL;

	ret = SDF_ImportKeyWithKEK(hSessionHandle, SGD_SM4_CBC, uiKEKIndex, ucKey, uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print();
		fprintf(stderr, "Error: SDF_ImportKeyWithKEK: 0x%X\n", ret);
		return -1;
	}
	if (hKeyHandle == NULL) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_Hash(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned char ucData[3] = { 0x61, 0x62, 0x63 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucHash[32];
	unsigned int uiHashLength;
	const unsigned char ucHashResult[32] = {
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
	};
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashInit(hSessionHandle, SGD_SM3, NULL, NULL, 0);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashInit: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashUpdate(hSessionHandle, ucData, uiDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashUpdate: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_HashFinal(hSessionHandle, ucHash, &uiHashLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_HashFinal: 0x%X\n", ret);
		return -1;
	}

	// check correctness
	if (uiHashLength != 32) {
		error_print();
		return -1;
	}
	if (memcmp(ucHash, ucHashResult, 32) != 0) {
		error_print();
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

// TODO: change test vectors
// static int test_SDF_Hash_Z(void)
// {
// 	void *hDeviceHandle = NULL;
// 	void *hSessionHandle = NULL;
// 	ECCrefPublicKey publicKeyRef = {
// 		256,
// 		{
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0xb6, 0xaf, 0x0c, 0xda, 0xba, 0xdc, 0x18, 0xb4,
// 		0x65, 0xf5, 0x3f, 0xc3, 0xde, 0x1e, 0x32, 0x87,
// 		0x89, 0xdc, 0x68, 0xde, 0x92, 0xf1, 0x20, 0xa4,
// 		0x0a, 0x2e, 0xbb, 0xdb, 0xf1, 0xbd, 0xa8, 0x39,
// 		},
// 		{
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 		0x07, 0xff, 0x30, 0x5b, 0x95, 0xf9, 0x94, 0x1a,
// 		0x92, 0x74, 0x36, 0x42, 0x6f, 0xd2, 0xdf, 0xf2,
// 		0xfa, 0xf6, 0x08, 0x79, 0x57, 0x7a, 0x95, 0x96,
// 		0x54, 0xb3, 0xf1, 0x50, 0xba, 0x79, 0xdb, 0x86,
// 		},
// 	};
// 	unsigned char ucID[] = {
// 		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
// 		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
// 	};
// 	unsigned int uiIDLength = 16;
// 	unsigned char ucData[3] = { 0x61, 0x62, 0x63 };
// 	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
// 	unsigned char ucHash[32];
// 	unsigned int uiHashLength;
// 	const unsigned char ucHashResult[32] = {
// 		0x87, 0xb7, 0xd6, 0x24, 0xce, 0x4b, 0xb0, 0x0a,
// 		0xc5, 0x6d, 0xb2, 0xb6, 0xc5, 0x06, 0xd5, 0xfc,
// 		0x9e, 0x38, 0xfd, 0x80, 0xc2, 0x4d, 0x1b, 0x99,
// 		0x1e, 0x8c, 0x38, 0xb3, 0x2b, 0xd6, 0xee, 0x5a,
// 	};
// 	int ret;

// 	ret = SDF_OpenDevice(&hDeviceHandle);
// 	if (ret != SDR_OK) {
// 		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
// 		return -1;
// 	}

// 	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
// 	if (ret != SDR_OK) {
// 		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
// 		return -1;
// 	}

// 	ret = SDF_HashInit(hSessionHandle, SGD_SM3, &publicKeyRef, ucID, uiIDLength);
// 	if (ret != SDR_OK) {
// 		fprintf(stderr, "Error: SDF_HashInit: 0x%X\n", ret);
// 		return -1;
// 	}

// 	ret = SDF_HashUpdate(hSessionHandle, ucData, uiDataLength);
// 	if (ret != SDR_OK) {
// 		fprintf(stderr, "Error: SDF_HashUpdate: 0x%X\n", ret);
// 		return -1;
// 	}

// 	ret = SDF_HashFinal(hSessionHandle, ucHash, &uiHashLength);
// 	if (ret != SDR_OK) {
// 		fprintf(stderr, "Error: SDF_HashFinal: 0x%X\n", ret);
// 		return -1;
// 	}

// 	// check correctness
// 	if (uiHashLength != 32) {
// 		error_print();
// 		return -1;
// 	}
// 	if (memcmp(ucHash, ucHashResult, 32) != 0) {
// 		error_print();
// 		return -1;
// 	}

// 	SDF_CloseSession(hSessionHandle);
// 	SDF_CloseDevice(hDeviceHandle);

// 	printf("%s() ok\n", __FUNCTION__);
// 	return 1;
// }

static int test_SDF_GenerateKeyWithIPK_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *pucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)pucPassword);
	unsigned int uiKeyBits = 128;
	ECCCipher eccCipher;
	unsigned char ucIV[16];
	unsigned char ucData[32];
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucEncData[64];
	unsigned int uiEncDataLength;
	unsigned char ucDecData[64];
	unsigned int uiDecDataLength;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	// generate symmetric key and encrypt
	ret = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, uiIPKIndex, uiKeyBits, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GenerateKeyWithIPK_ECC return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucData, uiDataLength, ucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_Encrypt return 0x%X\n", ret);
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_DestroyKey(hSessionHandle, hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_DestroyKey return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}
	hKeyHandle = NULL;

	// import symmetric key and decrypt
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, pucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiIPKIndex, &eccCipher, &hKeyHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ImportKeyWithISK_ECC return 0x%X\n", ret);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, ucIV, ucEncData, uiEncDataLength, ucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		printf("Error: SDF_Encrypt returned 0x%X\n", ret);
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	if (uiDecDataLength != uiDataLength) {
		fprintf(stderr, "Error: uiDecDataLength != uiDataLength\n");
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}
	if (memcmp(ucDecData, ucData, uiDataLength) != 0) {
		fprintf(stderr, "Error: ucDecData != ucData\n");
		SDF_DestroyKey(hSessionHandle, hKeyHandle);
		SDF_CloseSession(hSessionHandle);
		SDF_CloseDevice(hDeviceHandle);
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);
	return 1;
}

static int test_SDF_Encrypt_SM4_CBC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned char pucKey[16];
	unsigned char pucIV[16];
	unsigned char pucData[32];
	unsigned char pucEncData[64];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucCiphertext[64];

	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *pucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)pucPassword);
	ECCCipher eccCipher;
	int ret;

	{
		char *key = "0123456789abcdeffedcba9876543210";
		char *iv  = "0123456789abcdeffedcba9876543210";
		char *plain = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210";
		char *cipher = "2677f46b09c122cc975533105bd4a22af6125f7275ce552c3a2bbcf533de8a3b"; // ciphertext without padding
		size_t len;

		hex_to_bytes(key, strlen(key), pucKey, &len);
		hex_to_bytes(iv, strlen(iv), pucIV, &len);
		hex_to_bytes(plain, strlen(plain), pucData, &len);
		hex_to_bytes(cipher, strlen(cipher), pucCiphertext, &len);
	}


	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// SDF_ImportKey
	// ! 添加sm2后打开
	// ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, pucKey, sizeof(pucKey), &eccCipher);
	// if (ret != SDR_OK) {
	// 	error_print_msg("SDF library: 0x%08X\n", ret);
	// 	return -1;
	// }
	// ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, pucPassword, uiPwdLength);
	// if (ret != SDR_OK) {
	// 	error_print_msg("SDF library: 0x%08X\n", ret);
	// 	return -1;
	// }
	// ret = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiIPKIndex, &eccCipher, &hKeyHandle);
	// if (ret != SDR_OK) {
	// 	error_print_msg("SDF library: 0x%08X\n", ret);
	// 	return -1;
	// }

	// encrypt
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucData, sizeof(pucData), pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// compare ciphertext-without-padding, compatible with padding
	if (memcmp(pucEncData, pucCiphertext, 32) != 0) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_Encrypt_SM4_ECB(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned char pucKey[16];
	unsigned char pucData[32];
	unsigned char pucEncData[64];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucCiphertext[64];
	unsigned char pucDecData[64];
	unsigned int uiDecDataLength = (unsigned int)sizeof(pucDecData);

	int ret;
	char *key = "0123456789abcdeffedcba9876543210";
	char *plain = "0123456789abcdeffedcba9876543210";
	char *cipher = "681EDF34D206965E86B3E94F536E4246"; 
	size_t len;

	hex_to_bytes(key, strlen(key), pucKey, &len);
	hex_to_bytes(plain, strlen(plain), pucData, &len);
	hex_to_bytes(cipher, strlen(cipher), pucCiphertext, &len);

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret=SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_ECB, NULL, pucKey, NULL, &hKeyHandle);

	// encrypt
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, NULL, pucData, sizeof(pucData), pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	if (memcmp(pucEncData, pucCiphertext, 16) != 0) {
		error_print();
		return -1;
	}

	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, NULL, pucEncData, sizeof(pucEncData), pucDecData, &uiDecDataLength);

	if (memcmp(pucDecData, pucData, 16) != 0) {
		error_print();
		return -1;
	}
	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_Encrypt_ECB(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = TEST_KEK_INDEX;
	unsigned char pucKey[64];
	unsigned int uiKeyLength = (unsigned int)sizeof(pucKey);
	unsigned char pucIV[16];
	unsigned char pucData[32];
	unsigned int uiDataLength = sizeof(pucData);
	unsigned char pucEncData[128];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucDecData[128];
	unsigned int uiDecDataLength = (unsigned int)sizeof(pucDecData);
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_ECB, uiKEKIndex, pucKey, &uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// encrypt and decrypt
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, NULL, pucData, uiDataLength, pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// check SDF_Encrypt do Padding or Not
	/*
	if (uiEncDataLength == uiDataLength) {
		error_puts("SDF implement SM4-CBC without padding");
	} else if (uiEncDataLength == uiDataLength + 16) {
		error_puts("SDF implement SM4-CBC with padding");
	} else {
		error_print();
		return -1;
	}
	*/

	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, NULL, pucEncData, uiEncDataLength, pucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// check
	if (uiDecDataLength != uiDataLength) {
		error_print();
		return -1;
	}
	if (memcmp(pucDecData, pucData, uiDataLength) != 0) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_Encrypt(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiKeyBits = 128;
	unsigned int uiKEKIndex = TEST_KEK_INDEX;
	unsigned char pucKey[64];
	unsigned int uiKeyLength = (unsigned int)sizeof(pucKey);
	unsigned char pucIV[16];
	unsigned char pucData[32];
	unsigned int uiDataLength = sizeof(pucData);
	unsigned char pucEncData[128];
	unsigned int uiEncDataLength = (unsigned int)sizeof(pucEncData);
	unsigned char pucDecData[128];
	unsigned int uiDecDataLength = (unsigned int)sizeof(pucDecData);
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, SGD_SM4_CBC, uiKEKIndex, pucKey, &uiKeyLength, &hKeyHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// encrypt and decrypt
	ret = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucData, uiDataLength, pucEncData, &uiEncDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// check SDF_Encrypt do Padding or Not
	/*
	if (uiEncDataLength == uiDataLength) {
		error_puts("SDF implement SM4-CBC without padding");
	} else if (uiEncDataLength == uiDataLength + 16) {
		error_puts("SDF implement SM4-CBC with padding");
	} else {
		error_print();
		return -1;
	}
	*/

	ret = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pucIV, pucEncData, uiEncDataLength, pucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// check
	if (uiDecDataLength != uiDataLength) {
		error_print();
		return -1;
	}
	if (memcmp(pucDecData, pucData, uiDataLength) != 0) {
		error_print();
		return -1;
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_CalculateMAC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned int uiHMACKeyBits = 256;
	unsigned int uiKeyEncAlgID = SGD_SM4_CBC;
	unsigned int uiKEKIndex = TEST_KEK_INDEX;
	unsigned char ucEncedKey[256];
	unsigned int uiEncedKeyLength = (unsigned int)sizeof(ucEncedKey);
	unsigned int uiMACAlgID = SGD_SM3;
	unsigned char ucData[50] = {0}; // FIXME: 这里给出实际测试数据
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	unsigned char ucMAC[32];
	unsigned int uiMACLength = (unsigned int)sizeof(ucMAC);
	int ret;


	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	// 这个实际上无法测试正确性！因为你都不知道生成的密钥是什么
	//! 添加sm2后打开
	// ret = SDF_GenerateKeyWithKEK(hSessionHandle, uiHMACKeyBits, uiKeyEncAlgID, uiKEKIndex, ucEncedKey, &uiEncedKeyLength, &hKeyHandle);
	// if (ret != SDR_OK) {
	// 	fprintf(stderr, "Error: SDF_GenerateKeyWithKEK returned 0x%X\n", ret);
	// 	return -1;
	// }

	ret = SDF_CalculateMAC(hSessionHandle, hKeyHandle, uiMACAlgID, NULL, ucData, uiDataLength, ucMAC, &uiMACLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_CalculateMAC return 0x%X\n", ret);
		return -1;
	}

	if (uiMACLength != 32) {
	}

	SDF_DestroyKey(hSessionHandle, hKeyHandle);
	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

static int test_SDF_InternalSign_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *ucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)ucPassword);
	unsigned char ucData[32] = { 1,2,3,4 };
	unsigned int uiDataLength = 32;
	ECCSignature eccSignature;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// sign
	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_InternalSign_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	// verify
	ret = SDF_InternalVerify_ECC(hSessionHandle, uiIPKIndex, ucData, uiDataLength, &eccSignature);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;

}

static int test_SDF_InternalEncrypt_ECC(void)
{
	void *hDeviceHandle = NULL;
	void *hSessionHandle = NULL;
	unsigned int uiIPKIndex = TEST_SM2_KEY_INDEX;
	unsigned char *ucPassword = (unsigned char *)TEST_SM2_KEY_PASS;
	unsigned int uiPwdLength = (unsigned int)strlen((char *)ucPassword);
	unsigned char ucData[48] = { 1,2,3,4 };
	unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	ECCCipher eccCipher;
	unsigned char ucDecData[256];
	unsigned int uiDecDataLength;
	int ret;

	ret = SDF_OpenDevice(&hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiIPKIndex, ucPassword, uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight failed with error: 0x%X\n", ret);
		return -1;
	}
	// encrypt
	ret = SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, ucData, uiDataLength, &eccCipher);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_InternalEncrypt_ECC return 0x%X\n", ret);
		return -1;
	}


	// decrypt
	
	
	ret = SDF_InternalDecrypt_ECC(hSessionHandle, uiIPKIndex, SGD_SM2_3, &eccCipher, ucDecData, &uiDecDataLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_InternalDecrypt_ECC return 0x%X\n", ret);
		return -1;
	}

	ret = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiIPKIndex);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_ReleasePrivateKeyAccessRight return 0x%X\n", ret);
		return -1;
	}

	

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);

	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

size_t test_sm3_crypt_loop(size_t size){
	// unsigned char ucData[3] = { 0x61, 0x62, 0x63 };
	// unsigned int uiDataLength = (unsigned int)sizeof(ucData);
	
	int ret;
    size_t count = 0;	
    for (count = 0;  run&count < 0xffffffffffffffff; count++)
    {
        ret = SDF_HashInit(test_hSessionHandle, SGD_SM3, NULL, NULL, 0);
		if (ret != SDR_OK) {
			fprintf(stderr, "Error: SDF_HashInit: 0x%X\n", ret);
			return -1;
		}

		ret = SDF_HashUpdate(test_hSessionHandle, test_input, size);
		if (ret != SDR_OK) {
			fprintf(stderr, "Error: SDF_HashUpdate: 0x%X\n", ret);
			return -1;
		}

		ret = SDF_HashFinal(test_hSessionHandle, test_ucHash, &test_uiHashLength);
		if (ret != SDR_OK) {
			fprintf(stderr, "Error: SDF_HashFinal: 0x%X\n", ret);
			return -1;
		}
    }
    return count;
}

static int test_SDF_Hash_SPEED(void){
	size_t size[6] = {16, 64, 256, 1024, 8192, 16384};
    printf("\nsm3:\n");
	int ret = 0;
	ret = SDF_OpenDevice(&test_hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice: 0x%X\n", ret);
		return -1;
	}

	ret = SDF_OpenSession(test_hDeviceHandle, &test_hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession: 0x%X\n", ret);
		return -1;
	}
    performance_test_enc(test_sm3_crypt_loop, size, 6, 3);

	SDF_CloseSession(test_hSessionHandle);
	SDF_CloseDevice(test_hDeviceHandle);
	printf("\n");
	return 1;
}

size_t test_sm4_cbc_crypt_loop(size_t size){

	int ret;
	size_t count = 0;	
    for (count = 0;  run&count < 0xffffffffffffffff; count++)
    {
        ret = SDF_Encrypt(test_hSessionHandle, test_hKeyHandle, SGD_SM4_CBC, test_pucIV, test_input, size, test_output, &test_EncDataLength);
		if (ret != SDR_OK) {
			error_print_msg("SDF library: 0x%08X\n", ret);
			return -1;
		}
    }

	//printf("%s() ok\n", __FUNCTION__);
    
    return count;
}

static int test_SDF_SM4_Encrypt_SPEED(void){
	size_t size[6] = {16, 64, 256, 1024, 8192, 16384};
    printf("\nsm4:\n");
	int ret;
	ret = SDF_OpenDevice(&test_hDeviceHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}
	ret = SDF_OpenSession(test_hDeviceHandle, &test_hSessionHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}
	ret = SDF_GenerateKeyWithKEK(test_hSessionHandle, test_uiKeyBits, SGD_SM4_CBC, test_uiKEKIndex, test_pucKey, &test_uiKeyLength, &test_hKeyHandle);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}

    performance_test_enc(test_sm4_cbc_crypt_loop, size, 6, 3);

	SDF_DestroyKey(test_hSessionHandle, test_hKeyHandle);
	SDF_CloseSession(test_hSessionHandle);
	SDF_CloseDevice(test_hDeviceHandle);
	printf("\n");
	return 1;
}

size_t test_SDF_InternalEncrypt_ECC_loop(size_t size)  //内部加密
{
	
	int ret;
    size_t count=0;
    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
	// encrypt
	    ret = SDF_InternalEncrypt_ECC(test_hSessionHandle, test_uiIPKIndex, SGD_SM2_3, test_ucEncData, test_uiEncDataLength, &test_eccCipher);
		if (ret != SDR_OK) {
			fprintf(stderr, "Error: SDF_InternalEncrypt_ECC return 0x%X\n", ret);
			return -1;
		}
    }
	printf("%s() ok\n", __FUNCTION__);
	return count;
}

size_t test_SDF_InternalDecrypt_ECC_loop(size_t size)  //内部加密
{

	int ret,count;
    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
	    ret = SDF_InternalDecrypt_ECC(test_hSessionHandle, test_uiIPKIndex, SGD_SM2_3, &test_eccCipher, test_ucDecData, &test_uiDecDataLength);
		if (ret != SDR_OK) {
			fprintf(stderr, "Error: SDF_InternalDecrypt_ECC return 0x%X\n", ret);
		return -1;
	}
    }
	printf("%s() ok\n", __FUNCTION__);
	return count;
}


size_t test_SDF_InternalSign_ECC_loop(size_t size)
{
    size_t count=0;
	int ret;

    
	for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
		ret = SDF_InternalSign_ECC(test_hSessionHandle, test_uiIPKIndex, test_ucSigData, test_uiSigDataLength, &test_eccSignature);
		if (ret != SDR_OK) {
			error_print_msg("SDF library: 0x%08X\n", ret);
			return -1;
		}
		
	}

	

	printf("%s() ok\n", __FUNCTION__);
	return count;

}

size_t test_SDF_InternalVerify_ECC_loop(size_t size)
{
    size_t count=0;
	
	int ret;

	for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
		ret = SDF_InternalVerify_ECC(test_hSessionHandle, test_uiIPKIndex, test_ucSigData, test_uiSigDataLength, &test_eccSignature);
		if (ret != SDR_OK) {
			error_print_msg("SDF library: 0x%08X\n", ret);
			return -1;
		}
	}
	
	printf("%s() ok\n", __FUNCTION__);
	return count;

}

static int SDF_TEST_SM2_PERFTEST_SPEED_ENC(void){
	size_t size=48;
	int ret;
	ret = SDF_OpenDevice(&test_hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}
	ret = SDF_OpenSession(test_hDeviceHandle, &test_hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}
	ret = SDF_GetPrivateKeyAccessRight(test_hSessionHandle, test_uiIPKIndex, test_ucPassword, test_uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight failed with error: 0x%X\n", ret);
		return -1;
	}

	printf("\nSDF_Internal_ECC_Enc_and_Dec:\n");
	performance_test_sv(test_SDF_InternalEncrypt_ECC_loop,test_SDF_InternalDecrypt_ECC_loop,&size,1,10);

	ret = SDF_ReleasePrivateKeyAccessRight(test_hSessionHandle, test_uiIPKIndex);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}	

	ret = SDF_GetPrivateKeyAccessRight(test_hSessionHandle, test_uiIPKIndex, test_ucPassword, test_uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight failed with error: 0x%X\n", ret);
		return -1;
	}
	printf("\nSDF_Internal_ECC_Sign_and_Verify:\n");
    performance_test_sv(test_SDF_InternalSign_ECC_loop,test_SDF_InternalSign_ECC_loop,&size,1,10);

	ret = SDF_ReleasePrivateKeyAccessRight(test_hSessionHandle, test_uiIPKIndex);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}	
	SDF_CloseSession(test_hSessionHandle);
	SDF_CloseDevice(test_hDeviceHandle);
	return 1;
}

static int SDF_TEST_SM2_PERFTEST_SPEED_SIG(void){
	size_t size=48;
	int ret;
	ret = SDF_OpenDevice(&test_hDeviceHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenDevice returned 0x%X\n", ret);
		return -1;
	}
	ret = SDF_OpenSession(test_hDeviceHandle, &test_hSessionHandle);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_OpenSession returned 0x%X\n", ret);
		return -1;
	}

	ret = SDF_GetPrivateKeyAccessRight(test_hSessionHandle, test_uiIPKIndex, test_ucPassword, test_uiPwdLength);
	if (ret != SDR_OK) {
		fprintf(stderr, "Error: SDF_GetPrivateKeyAccessRight failed with error: 0x%X\n", ret);
		return -1;
	}
	printf("\nSDF_Internal_ECC_Sign_and_Verify:\n");
    performance_test_sv(test_SDF_InternalSign_ECC_loop,test_SDF_InternalVerify_ECC_loop,&size,1,10);

	ret = SDF_ReleasePrivateKeyAccessRight(test_hSessionHandle, test_uiIPKIndex);
	if (ret != SDR_OK) {
		error_print_msg("SDF library: 0x%08X\n", ret);
		return -1;
	}	
	SDF_CloseSession(test_hSessionHandle);
	SDF_CloseDevice(test_hDeviceHandle);
	return 1;
}

int main(void)
{
	
	if (generate_kek(TEST_KEK_INDEX) != 1) {
		error_print();
		goto err;
	}
	if (generate_sign_key(TEST_SM2_KEY_INDEX, TEST_SM2_KEY_PASS) != 1) {
		error_print();
		goto err;
	}
	if (generate_enc_key(TEST_SM2_KEY_INDEX, TEST_SM2_KEY_PASS) != 1) {
		error_print();
		goto err;
	}
	

	if (SDF_LoadLibrary("/home/hjc/KeySafe-OpenSSL-1.1.1i/soft_sdf/libsoft_sdf.so", NULL) != SDR_OK) {
		error_print();
		goto err;
	}

	if (test_SDF_GetDeviceInfo() != 1) goto err;
	if (test_SDF_GenerateRandom() != 1) goto err;
	if (test_SDF_Hash() != 1) goto err;
	// if (test_SDF_Hash_Z() != 1) goto err;
	if (test_SDF_GenerateKeyWithKEK() != 1) goto err;
	// if (test_SDF_CalculateMAC() != 1) goto err;
	if (test_SDF_Encrypt_ECB() != 1) goto err;
	if (test_SDF_Encrypt() != 1) goto err;
	//if (test_SDF_Encrypt_SM4_CBC() != 1) goto err;
	//if (test_SDF_Encrypt_SM4_ECB() != 1) goto err;
	if (test_SDF_GenerateKeyPair_ECC() != 1) goto err;
	if (test_SDF_ExportSignPublicKey_ECC() != 1) goto err;
	if (test_SDF_ExportEncPublicKey_ECC() != 1) goto err;
	if (test_SDF_GenerateKeyWithEPK_ECC() != 1) goto err;
	if (test_SDF_GenerateKeyWithIPK_ECC() != 1) goto err;
	if (test_SDF_ExternalVerify_ECC() != 1) goto err;
	if (test_SDF_ExternalEncrypt_ECC() != 1) goto err; //FIXME: test this before any ECCCipher used
	if (test_SDF_InternalSign_ECC() != 1) goto err;
	if (test_SDF_InternalEncrypt_ECC() != 1) goto err;

	// if (test_SDF_Hash_SPEED() != 1) goto err;
	// if (test_SDF_SM4_Encrypt_SPEED() != 1) goto err;
	// if (SDF_TEST_SM2_PERFTEST_SPEED_ENC() != 1) goto err;
	if (SDF_TEST_SM2_PERFTEST_SPEED_SIG() != 1) goto err;

	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	error_print();
	return 1;
}
