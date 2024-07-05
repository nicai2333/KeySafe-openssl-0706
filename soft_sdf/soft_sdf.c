/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <crypto/sdf_sm2.h>
#include <crypto/sdf_sm3.h>
#include <crypto/sdf_sm4.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <crypto/sdf_error.h>
#include "sgd.h"
#include "sdf.h"

#include "crypto/sm2.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#define SDR_GMSSLERR	(SDR_BASE + 0x00000100)

static const uint8_t zeros[ECCref_MAX_LEN - 32] = {0};


#define SOFTSDF_MAX_KEY_SIZE	64

struct SOFTSDF_KEY {
	uint8_t key[SOFTSDF_MAX_KEY_SIZE];
	size_t key_size;
	struct SOFTSDF_KEY *next;
};

typedef struct SOFTSDF_KEY SOFTSDF_KEY;


struct SOFTSDF_CONTAINER {
	unsigned int key_index;
	EC_KEY *sign_key;
	EC_KEY *enc_key;
	struct SOFTSDF_CONTAINER *next;
};
typedef struct SOFTSDF_CONTAINER SOFTSDF_CONTAINER;

struct SOFTSDF_SESSION {
	SOFTSDF_CONTAINER *container_list;
	SOFTSDF_KEY *key_list;
	SM3_AVX_CTX sm3_ctx;
	struct SOFTSDF_SESSION *next;
};
typedef struct SOFTSDF_SESSION SOFTSDF_SESSION;

struct SOFTSDF_DEVICE {
	SOFTSDF_SESSION *session_list;
};
typedef struct SOFTSDF_DEVICE SOFTSDF_DEVICE;

SOFTSDF_DEVICE *deviceHandle = NULL;

#define SM2_MIN_PLAINTEXT_SIZE	1 // re-compute SM2_MIN_CIPHERTEXT_SIZE when modify
#define SM2_MAX_PLAINTEXT_SIZE	255 // re-compute SM2_MAX_CIPHERTEXT_SIZE when modify

#define FILENAME_MAX_LEN 256

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
	

	snprintf(filename, sizeof(filename), "sm2sign-%u.pem", uiKeyIndex);

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


	sm2_sign(data, 32, sig, &sig_len, sm2_key);

	
	return 1;
}

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

int softSDF_CreateDevice(unsigned char *pucPassword, unsigned int uiPwdLength)
{
	if (strlen((char *)pucPassword) != uiPwdLength) {
		error_print();
		return SDR_INARGERR;
	}
	// generate system keypairs
	generate_sign_key(0, (char *)pucPassword);
	generate_enc_key(0, (char *)pucPassword);

	// generate user keypairs
	generate_sign_key(1, (char *)pucPassword);
	generate_enc_key(1, (char *)pucPassword);

	// generate user KEK
	generate_kek(1);

	return SDR_OK;
}

int SDF_OpenDevice(
	void **phDeviceHandle)
{
	if (phDeviceHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (deviceHandle != NULL) {
		error_print();
		return SDR_OPENDEVICE;
	}

	deviceHandle = (SOFTSDF_DEVICE *)malloc(sizeof(SOFTSDF_DEVICE));
	if (deviceHandle == NULL) {
		error_print();
		return SDR_OPENDEVICE;
	}
	memset(deviceHandle, 0, sizeof(SOFTSDF_DEVICE));

	*phDeviceHandle = deviceHandle;
	return SDR_OK;
}

int SDF_CloseDevice(
	void *hDeviceHandle)
{
	if (hDeviceHandle != deviceHandle) {
		error_print();
		return SDR_INARGERR;
	}

	if (deviceHandle != NULL) {
		while (deviceHandle->session_list) {
			if (SDF_CloseSession(deviceHandle->session_list) != SDR_OK) {
				error_print();
			}
		}
	}

	memset(deviceHandle, 0, sizeof(SOFTSDF_DEVICE));
	free(deviceHandle);
	deviceHandle = NULL;

	return SDR_OK;
}


int SDF_OpenSession(
	void *hDeviceHandle,
	void **phSessionHandle)
{
	SOFTSDF_SESSION *session;

	if (hDeviceHandle == NULL || hDeviceHandle != deviceHandle) {
		error_print();
		return SDR_INARGERR;
	}

	if (phSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (!(session = (SOFTSDF_SESSION *)malloc(sizeof(*session)))) {
		error_print();
		return SDR_GMSSLERR;
	}
	memset(session, 0, sizeof(*session));

	// append session to session_list
	if (deviceHandle->session_list == NULL) {
		deviceHandle->session_list = session;
	} else {
		SOFTSDF_SESSION *current = deviceHandle->session_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = session;
	}

	*phSessionHandle = session;
	return SDR_OK;
}

int SDF_CloseSession(
	void *hSessionHandle)
{
	SOFTSDF_SESSION *current_session;
	SOFTSDF_SESSION *prev_session;
	SOFTSDF_CONTAINER *current_container;
	SOFTSDF_CONTAINER *next_container;
	SOFTSDF_KEY *current_key;
	SOFTSDF_KEY *next_key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// find hSessionHandle in session_list
	current_session = deviceHandle->session_list;
	prev_session = NULL;
	while (current_session != NULL && current_session != hSessionHandle) {
		prev_session = current_session;
		current_session = current_session->next;
	}
	if (current_session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// free container_list
	current_container = current_session->container_list;
	while (current_container != NULL) {
		next_container = current_container->next;
		memset(current_container, 0, sizeof(*current_container));
		free(current_container);
		current_container = next_container;
	}

	// free key_list
	current_key = current_session->key_list;
	while (current_key != NULL) {
		next_key = current_key->next;
		memset(current_key, 0, sizeof(*current_key));
		free(current_key);
		current_key = next_key;
	}

	// delete current_session from session_list
	if (prev_session == NULL) {
		deviceHandle->session_list = current_session->next;
	} else {
		prev_session->next = current_session->next;
	}
	memset(current_session, 0, sizeof(*current_session));
	free(current_session);

	return SDR_OK;
}

#define SOFTSDF_DEV_DATE	"20231227"
#define SOFTSDF_DEV_BATCH_NUM	"001"
#define SOFTSDF_DEV_SERIAL_NUM	"00123"
#define SOFTSDF_DEV_SERIAL	SOFTSDF_DEV_DATE \
				SOFTSDF_DEV_BATCH_NUM \
				SOFTSDF_DEV_SERIAL_NUM

int SDF_GetDeviceInfo(
	void *hSessionHandle,
	DEVICEINFO *pstDeviceInfo)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pstDeviceInfo == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	memset(pstDeviceInfo, 0, sizeof(*pstDeviceInfo));
	strncpy((char *)pstDeviceInfo->IssuerName, "SCNU KEYSAFE Project",
		sizeof(pstDeviceInfo->IssuerName));
	strncpy((char *)pstDeviceInfo->DeviceName, "Soft SDF",
		sizeof(pstDeviceInfo->DeviceName));
	strncpy((char *)pstDeviceInfo->DeviceSerial, SOFTSDF_DEV_SERIAL,
		sizeof(pstDeviceInfo->DeviceSerial));
	pstDeviceInfo->DeviceVersion = 1;
	pstDeviceInfo->StandardVersion = 1;
	pstDeviceInfo->AsymAlgAbility[0] = SGD_SM2_1|SGD_SM2_3;
	pstDeviceInfo->AsymAlgAbility[1] = 256;
	pstDeviceInfo->SymAlgAbility = SGD_SM4|SGD_CBC|SGD_MAC;
	pstDeviceInfo->HashAlgAbility = SGD_SM3;
	pstDeviceInfo->BufferSize = 256*1024;

	return SDR_OK;
}

int SDF_GenerateRandom(
	void *hSessionHandle,
	unsigned int uiLength,
	unsigned char *pucRandom)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucRandom == NULL || uiLength == 0) {
		error_puts("Invalid output buffer or length");
		return SDR_INARGERR;
	}
	if (uiLength > 256) {
		error_print();
		return SDR_INARGERR;
	}

	if (RAND_bytes(pucRandom, uiLength) != 1) {
		error_print();
		return SDR_GMSSLERR;
	}

	return SDR_OK;
}

int SDF_GetPrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	unsigned char *pucPassword,
	unsigned int uiPwdLength)
{
	int ret = SDR_OK;
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container = NULL;
	char *pass = NULL;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPassword == NULL || uiPwdLength == 0) {
		error_puts("Invalid password or password length");
		return SDR_INARGERR;
	}
	pass = (char *)malloc(uiPwdLength + 1);
	if (pass == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memcpy(pass, pucPassword, uiPwdLength);
	pass[uiPwdLength] = 0;
	if (strlen(pass) != uiPwdLength) {
		error_print();
		ret = SDR_INARGERR;
		goto end;
	}

	// create container
	container = (SOFTSDF_CONTAINER *)malloc(sizeof(*container));
	if (container == NULL) {
		error_print();
		ret = SDR_NOBUFFER;
		goto end;
	}
	memset(container, 0, sizeof(*container));
	container->key_index = uiKeyIndex;

	// load sign_key
	snprintf(filename, FILENAME_MAX_LEN, "sm2sign-%u.pem", uiKeyIndex);
	// file = fopen(filename, "r");
	// if (file == NULL) {
	// 	perror("Error opening file");
	// 	fprintf(stderr, "open failure %s\n", filename);
	// 	ret = SDR_KEYNOTEXIST;
	// 	goto end;
	// }
	// if (sm2_private_key_info_decrypt_from_pem(&container->sign_key, pass, file) != 1) {
	// 	error_print();
	// 	ret = SDR_GMSSLERR;
	// 	goto end;
	// }
	// fclose(file);
	if ((container->sign_key = sm2_private_key_info_decrypt_from_pem(filename, pass)) == NULL) {
		error_print();
		ret = SDR_GMSSLERR;
		goto end;
	}


	// load enc_key
	snprintf(filename, FILENAME_MAX_LEN, "sm2enc-%u.pem", uiKeyIndex);
	// file = fopen(filename, "r");
	// if (file == NULL) {
	// 	perror("Error opening file");
	// 	ret = SDR_KEYNOTEXIST;
	// 	goto end;
	// }
	// if (sm2_private_key_info_decrypt_from_pem(&container->enc_key, pass, file) != 1) {
	// 	error_print();
	// 	ret = SDR_GMSSLERR;
	// 	goto end;
	// }
	// fclose(file);
	if ((container->enc_key = sm2_private_key_info_decrypt_from_pem(filename, pass)) == NULL) {
		error_print();
		ret = SDR_GMSSLERR;
		goto end;
	}

	// append container to container_list
	if (session->container_list == NULL) {
		session->container_list = container;
	} else {
		SOFTSDF_CONTAINER *current = session->container_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = container;
	}

	container = NULL;
	ret = SDR_OK;
end:
	if (container) {
		memset(container, 0, sizeof(*container));
		free(container);
	}
	if (pass) {
		memset(pass, 0, uiPwdLength);
		free(pass);
	}
	if (file) fclose(file);
	return ret;
}

int SDF_ReleasePrivateKeyAccessRight(
	void *hSessionHandle,
	unsigned int uiKeyIndex)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *current_container;
	SOFTSDF_CONTAINER *prev_container;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// delete container in container_list with uiKeyIndex
	current_container = session->container_list;
	prev_container = NULL;
	while (current_container != NULL && current_container->key_index != uiKeyIndex) {
		prev_container = current_container;
		current_container = current_container->next;
	}
	if (current_container == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (prev_container == NULL) {
		session->container_list = current_container->next;
	} else {
		prev_container->next = current_container->next;
	}
	memset(current_container, 0, sizeof(*current_container));
	free(current_container);

	return SDR_OK;
}

int SDF_ExportSignPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	error_print();
	return SDR_NOTSUPPORT;
}

int SDF_ExportEncPublicKey_RSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey)
{
	error_print();
	return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyPair_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	RSArefPrivateKey *pucPrivateKey)
{
	error_print();
	return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithIPK_RSA(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	error_print();
	return SDR_NOTSUPPORT;
}

int SDF_GenerateKeyWithEPK_RSA(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	error_print();
	return SDR_NOTSUPPORT;
}

int SDF_ImportKeyWithISK_RSA(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	error_print();
	return SDR_NOTSUPPORT;
}

int SDF_ExchangeDigitEnvelopeBaseOnRSA(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDEInput,
	unsigned int uiDELength,
	unsigned char *pucDEOutput,
	unsigned int *puiDELength)
{
	error_print();
	return SDR_NOTSUPPORT;
}

int SDF_ExportSignPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	EC_KEY *sm2_key;
	uint8_t x_bin[32], y_bin[32];
	// SM2_POINT point;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	snprintf(filename, FILENAME_MAX_LEN, "sm2signpub-%u.pem", uiKeyIndex);
	// file = fopen(filename, "rb");
	// if (file == NULL) {
	// 	error_print();
	// 	return SDR_KEYNOTEXIST;
	// }
	// if ((sm2_key = sm2_public_key_info_from_pem(filename)) == NULL) {
	// 	error_print();
	// 	fclose(file);
	// 	return SDR_KEYNOTEXIST;
	// }
	// fclose(file);
	if ((sm2_key = sm2_public_key_info_from_pem(filename)) == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	
	// sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point);
	sm2_key_get_public(sm2_key, x_bin, y_bin);

	pucPublicKey->bits = 256;
	memset(pucPublicKey->x, 0, ECCref_MAX_LEN - 32);
	memcpy(pucPublicKey->x + ECCref_MAX_LEN - 32, x_bin, 32);
	memset(pucPublicKey->y, 0, ECCref_MAX_LEN - 32);
	memcpy(pucPublicKey->y + ECCref_MAX_LEN - 32, y_bin, 32);
	return SDR_OK;
}

int SDF_ExportEncPublicKey_ECC(
	void *hSessionHandle,
	unsigned int uiKeyIndex,
	ECCrefPublicKey *pucPublicKey)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	EC_KEY *sm2_key;
	uint8_t x_bin[32], y_bin[32];
	// SM2_KEY sm2_key;
	// SM2_POINT point;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	snprintf(filename, FILENAME_MAX_LEN, "sm2encpub-%u.pem", uiKeyIndex);
	// file = fopen(filename, "rb");
	// if (file == NULL) {
	// 	error_print();
	// 	return SDR_KEYNOTEXIST;
	// }
	// if (sm2_public_key_info_from_pem(&sm2_key, file) != 1) {
	// 	error_print();
	// 	fclose(file);
	// 	return SDR_KEYNOTEXIST;
	// }
	// fclose(file);
	if ((sm2_key = sm2_public_key_info_from_pem(filename)) == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}

	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&point);
	sm2_key_get_public(sm2_key, x_bin, y_bin);
	pucPublicKey->bits = 256;
	memset(pucPublicKey->x, 0, ECCref_MAX_LEN - 32);
	memcpy(pucPublicKey->x + ECCref_MAX_LEN - 32, x_bin, 32);
	memset(pucPublicKey->y, 0, ECCref_MAX_LEN - 32);
	memcpy(pucPublicKey->y + ECCref_MAX_LEN - 32, x_bin, 32);

	return SDR_OK;
}

int SDF_GenerateKeyPair_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey)
{
	SOFTSDF_SESSION *session;
	EC_KEY *sm2_key;
	EC_POINT *public_key;
	uint8_t prik[32];
	uint8_t pubk_x[32], pubk_y[32];
	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	
	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}

	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiKeyBits != 256) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucPublicKey == NULL || pucPrivateKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// if (sm2_key_generate(&sm2_key) != 1) {
	// 	error_print();
	// 	return SDR_GMSSLERR;
	// }
	if ((sm2_key=sm2_key_generate()) == NULL) {
		error_print();
		return SDR_GMSSLERR;
	}
	
	// sm2_z256_to_bytes(sm2_key.private_key, private_key);
	// sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&public_key);
	sm2_key_get_public(sm2_key, pubk_x, pubk_y);
	
	sm2_key_get_private(sm2_key, prik);
	
	memset(pucPublicKey, 0, sizeof(*pucPublicKey));
	
	pucPublicKey->bits = 256;

	memcpy(pucPublicKey->x + ECCref_MAX_LEN - 32, pubk_x, 32);

	memcpy(pucPublicKey->y + ECCref_MAX_LEN - 32, pubk_y, 32);

	memset(pucPrivateKey, 0, sizeof(*pucPrivateKey));

	pucPrivateKey->bits = 256;

	memcpy(pucPrivateKey->K + ECCref_MAX_LEN - 32, prik, 32);
	
	// 清空内存
	memset(&sm2_key, 0, sizeof(sm2_key));
	memset(prik, 0, sizeof(prik));
	memset(pubk_x, 0, sizeof(pubk_x));
	memset(pubk_y, 0, sizeof(pubk_y));
	
	return SDR_OK;
}

int SDF_GenerateKeyWithIPK_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file;
	EC_KEY *sm2_key;
	// SM2_KEY sm2_key;
	SOFTSDF_KEY *key;
	EVP_MD *digest = EVP_sm3();
	// SM2_CIPHERTEXT ctxt;
	uint8_t ctext[200];
	size_t ctext_len;
	uint8_t C1_x[32], C1_y[32], C2[200], C3[32];
    int C2_len, C3_len;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	
	snprintf(filename, FILENAME_MAX_LEN, "sm2encpub-%u.pem", uiIPKIndex);
	// file = fopen(filename, "rb");
	// if (file == NULL) {
	// 	error_print();
	// 	return SDR_KEYNOTEXIST;
	// }
	// if (sm2_public_key_info_from_pem(&sm2_key, file) != 1) {
	// 	error_print();
	// 	fclose(file);
	// 	return SDR_KEYNOTEXIST;
	// }
	// fclose(file);
	if ((sm2_key = sm2_public_key_info_from_pem(filename)) == NULL) {
		error_print();
		fclose(file);
		return SDR_KEYNOTEXIST;
	}

	if (uiKeyBits%8 != 0 || uiKeyBits/8 > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// generate key
	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));
	if (RAND_bytes(key->key, uiKeyBits/8) != 1) {
		error_print();
		free(key);
		return SDR_GMSSLERR;
	}
	key->key_size = uiKeyBits/8;

	// encrypt key with container
	// if (sm2_do_encrypt(&sm2_key, key->key, key->key_size, &ctxt) != 1) {
	// 	error_print();
	// 	free(key);
	// 	return SDR_GMSSLERR;
	// }
	sm2_ciphertext_size(sm2_key, digest, key->key_size, &ctext_len);
	if (sm2_encrypt(sm2_key, digest, (const uint8_t *)key->key, key->key_size, ctext, &ctext_len) != 1) {
		error_print();
		free(key);
		return SDR_GMSSLERR;
	}
	
	// memset(pucKey, 0, sizeof(*pucKey));
	// memcpy(pucKey->x + ECCref_MAX_LEN - 32, ctxt.point.x, 32);
	// memcpy(pucKey->y + ECCref_MAX_LEN - 32, ctxt.point.y, 32);
	// memcpy(pucKey->M, ctxt.hash, 32);
	// pucKey->L = ctxt.ciphertext_size;
	// memcpy(pucKey->C, ctxt.ciphertext, ctxt.ciphertext_size);
	sm2_get_ciphertext(ctext, ctext_len, C1_x, C1_y, C2, &C2_len, C3, &C3_len);
	memset(pucKey, 0, sizeof(*pucKey));
	memcpy(pucKey->x + ECCref_MAX_LEN - 32, C1_x, 32);
	memcpy(pucKey->y + ECCref_MAX_LEN - 32, C1_y, 32);
	memcpy(pucKey->M, C3, 32);
	pucKey->L = C2_len;
	memcpy(pucKey->C, C2, C2_len);
	
	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_GenerateKeyWithEPK_ECC(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	// SM2_POINT point;
	uint8_t x_bin[32], y_bin[32];
	EC_POINT *public_key;
	// SM2_Z256_POINT public_key;
	// SM2_KEY sm2_key;
	EC_KEY *sm2_key;
	SOFTSDF_KEY *key;
	uint8_t ctext[200];
	size_t ctext_len;
	uint8_t C1_x[32], C1_y[32], C2[200], C3[32];
    int C2_len, C3_len;
	EVP_MD *digest = EVP_sm3();
	// SM2_CIPHERTEXT ctxt;
	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiKeyBits%8 != 0 || uiKeyBits/8 > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey == NULL || pucKey == NULL || phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	// load public key
	// memset(&point, 0, sizeof(point));
	memset(x_bin, 0, sizeof(x_bin));
	memset(y_bin, 0, sizeof(y_bin));
	memcpy(x_bin, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
	memcpy(y_bin, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
	// if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
	// 	error_print();
	// 	return SDR_INARGERR;
	// }
	if (!(public_key = sm2_new_point(x_bin, y_bin))) {
		error_print();
		return SDR_INARGERR;
	}
	sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
	EC_KEY_precompute_mult(sm2_key, NULL);
	if (EC_KEY_set_public_key(sm2_key, public_key) != 1) {
		error_print();
		return SDR_INARGERR;
	}
	// generate key
	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));
	if (RAND_bytes(key->key, uiKeyBits/8) != 1) {
		error_print();
		free(key);
		return SDR_GMSSLERR;
	}
	key->key_size = uiKeyBits/8;
	
	// encrypt key with external public key
	// 获取ctext_len这步不能少

	sm2_ciphertext_size(sm2_key, digest, key->key_size, &ctext_len);
	if (sm2_encrypt(sm2_key, digest, (const uint8_t *)key->key, key->key_size, ctext, &ctext_len) != 1) {
		error_print();
		free(key);
		return SDR_GMSSLERR;
	}
	sm2_get_ciphertext(ctext, ctext_len, C1_x, C1_y, C2, &C2_len, C3, &C3_len);
	memset(pucKey, 0, sizeof(*pucKey));
	memcpy(pucKey->x + ECCref_MAX_LEN - 32, C1_x, 32);
	memcpy(pucKey->y + ECCref_MAX_LEN - 32, C1_y, 32);
	memcpy(pucKey->M, C3, 32);
	pucKey->L = C2_len;
	memcpy(pucKey->C, C2, C2_len);

	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_ImportKeyWithISK_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	// SM2_CIPHERTEXT ctxt;
	SOFTSDF_KEY *key;
	size_t ctext_len;
	uint8_t ctext[200];
	uint8_t C1_x[32], C1_y[32], C2[200], C3[32];
    int C2_len, C3_len;
	EVP_MD *digest = EVP_sm3();

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_puts("Invalid session handle");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	container = session->container_list;
	while (container != NULL && container->key_index != uiISKIndex) {
		container = container->next;
	}
	if (container == NULL) {
		// 没有找到container意味着可能之前没有调用GetPrivateKeyAccess				
		error_print();
		return SDR_INARGERR;
	}

	if (pucKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucKey->L > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucKey->L > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (phKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// create key
	key = (SOFTSDF_KEY *)malloc(sizeof(*key));
	if (key == NULL) {
		error_print();
		return SDR_NOBUFFER;
	}
	memset(key, 0, sizeof(*key));

	// decrypt key
	memset(ctext, 0, sizeof(ctext));
	memcpy(C1_x, pucKey->x + ECCref_MAX_LEN - 32, 32);
	memcpy(C1_y, pucKey->y + ECCref_MAX_LEN - 32, 32);
	memcpy(C3, pucKey->M, 32);
	memcpy(C2, pucKey->C, pucKey->L);
	C2_len = pucKey->L;
	C3_len = 32;
	ctext_len = sizeof(ctext);
	sm2_set_ciphertext(ctext, &ctext_len, C1_x, C1_y, C2, C2_len, C3, C3_len);
    
	// if (sm2_do_decrypt(&container->enc_key, &ctxt, key->key, &key->key_size) != 1) {
	// 	error_print();
	// 	free(key);
	// 	return SDR_GMSSLERR;
	// }
	if (sm2_decrypt(container->enc_key, digest, ctext, ctext_len, key->key, &key->key_size) != 1) {
		error_print();
		free(key);
		return SDR_GMSSLERR;
	}

	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

// int SDF_GenerateAgreementDataWithECC(
// 	void *hSessionHandle,
// 	unsigned int uiISKIndex,
// 	unsigned int uiKeyBits,
// 	unsigned char *pucSponsorID,
// 	unsigned int uiSponsorIDLength,
// 	ECCrefPublicKey *pucSponsorPublicKey,
// 	ECCrefPublicKey *pucSponsorTmpPublicKey,
// 	void **phAgreementHandle)
// {
// 	error_print();
// 	return SDR_NOTSUPPORT;
// }

// int SDF_GenerateKeyWithECC(
// 	void *hSessionHandle,
// 	unsigned char *pucResponseID,
// 	unsigned int uiResponseIDLength,
// 	ECCrefPublicKey *pucResponsePublicKey,
// 	ECCrefPublicKey *pucResponseTmpPublicKey,
// 	void *hAgreementHandle,
// 	void **phKeyHandle)
// {
// 	error_print();
// 	return SDR_NOTSUPPORT;
// }

// int SDF_GenerateAgreementDataAndKeyWithECC(
// 	void *hSessionHandle,
// 	unsigned int uiISKIndex,
// 	unsigned int uiKeyBits,
// 	unsigned char *pucResponseID,
// 	unsigned int uiResponseIDLength,
// 	unsigned char *pucSponsorID,
// 	unsigned int uiSponsorIDLength,
// 	ECCrefPublicKey *pucSponsorPublicKey,
// 	ECCrefPublicKey *pucSponsorTmpPublicKey,
// 	ECCrefPublicKey *pucResponsePublicKey,
// 	ECCrefPublicKey *pucResponseTmpPublicKey,
// 	void **phKeyHandle)
// {
// 	error_print();
// 	return SDR_NOTSUPPORT;
// }

// int SDF_ExchangeDigitEnvelopeBaseOnECC(
// 	void *hSessionHandle,
// 	unsigned int uiKeyIndex,
// 	unsigned int uiAlgID,
// 	ECCrefPublicKey *pucPublicKey,
// 	ECCCipher *pucEncDataIn,
// 	ECCCipher *pucEncDataOut)
// {
// 	error_print();
// 	return SDR_NOTSUPPORT;
// }

int SDF_GenerateKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiKeyBits,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int *puiKeyLength,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file;
	uint8_t kek[16];
	uint8_t *iv;
	uint8_t *enced;
	size_t enced_len,pad_len = 0;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}
	printf("test\n");

	if (hSessionHandle == NULL) {
		error_print();
		printf("test1\n");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		printf("test2\n");
		return SDR_INARGERR;
	}

	if (uiKeyBits % 8 != 0 || uiKeyBits/8 > SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		printf("test3\n");
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM4_CBC && uiAlgID != SGD_SM4_ECB) {
		error_print();
		printf("test4\n");
		return SDR_INARGERR;
	}

	if(uiAlgID == SGD_SM4_CBC){
		EVP_CIPHER_CTX *sm4_cbc_ctx;
		// load KEK file with index
		snprintf(filename, FILENAME_MAX_LEN, "kek-%u.key", uiKEKIndex);
		file = fopen(filename, "rb");
		if (file == NULL) {
			fprintf(stderr, "open file: %s\n", filename);
			error_print();
			return SDR_KEYNOTEXIST;
		}

		size_t rlen;
		if ((rlen = fread(kek, 1, sizeof(kek), file)) != sizeof(kek)) {

			printf("rlen = %zu\n", rlen);
			perror("fread");
			error_print();
			fclose(file);
			return SDR_INARGERR;
		}
		fclose(file);

		if (pucKey == NULL || puiKeyLength == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		if (phKeyHandle == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		// generate key
		key = (SOFTSDF_KEY *)malloc(sizeof(SOFTSDF_KEY));
		if (key == NULL) {
			error_print();
			return SDR_GMSSLERR;
		}
		memset(key, 0, sizeof(*key));

		iv = pucKey;
		enced = pucKey + SM4_BLOCK_SIZE;

		if (RAND_bytes(iv, SM4_BLOCK_SIZE) != 1) {
			error_print();
			return SDR_GMSSLERR;
		}

		key->key_size = uiKeyBits/8;
		if (RAND_bytes(key->key, key->key_size) != 1) {
			error_print();
			free(key);
			return SDR_GMSSLERR;
		}
		sm4_cbc_ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit(sm4_cbc_ctx,EVP_sm4_cbc(),kek,iv);
		EVP_CIPHER_CTX_set_padding(sm4_cbc_ctx, 0);
		if (EVP_EncryptUpdate(sm4_cbc_ctx, enced, &enced_len, key->key, key->key_size) != 1) {
			error_print();
			// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_free(sm4_cbc_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		if (EVP_EncryptFinal(sm4_cbc_ctx, enced+enced_len, &pad_len) != 1) {
			error_print();
			// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_free(sm4_cbc_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		EVP_CIPHER_CTX_free(sm4_cbc_ctx);
		// ! 不一定够长
		*puiKeyLength = 16 + enced_len;

		// append key to key_list
		if (session->key_list == NULL) {
			session->key_list = key;
		} else {
			SOFTSDF_KEY *current = session->key_list;
			while (current->next != NULL) {
				current = current->next;
			}
			current->next = key;
		}

		*phKeyHandle = key;
		return SDR_OK;
	}

	if(uiAlgID == SGD_SM4_ECB){
		EVP_CIPHER_CTX *sm4_ecb_ctx;
		// load KEK file with index
		snprintf(filename, FILENAME_MAX_LEN, "kek-%u.key", uiKEKIndex);
		file = fopen(filename, "rb");
		if (file == NULL) {
			fprintf(stderr, "open file: %s\n", filename);
			error_print();
			return SDR_KEYNOTEXIST;
		}

		size_t rlen;
		if ((rlen = fread(kek, 1, sizeof(kek), file)) != sizeof(kek)) {

			printf("rlen = %zu\n", rlen);
			perror("fread");
			error_print();
			fclose(file);
			printf("test5\n");
			return SDR_INARGERR;
		}
		fclose(file);

		if (pucKey == NULL || puiKeyLength == NULL) {
			error_print();
			printf("test6\n");
			return SDR_INARGERR;
		}

		if (phKeyHandle == NULL) {
			error_print();
			printf("test7\n");
			return SDR_INARGERR;
		}

		// generate key
		key = (SOFTSDF_KEY *)malloc(sizeof(SOFTSDF_KEY));
		if (key == NULL) {
			error_print();
			return SDR_GMSSLERR;
		}
		memset(key, 0, sizeof(*key));

		iv = pucKey;
		enced = pucKey + SM4_BLOCK_SIZE;

		if (RAND_bytes(iv, SM4_BLOCK_SIZE) != 1) {
			error_print();
			return SDR_GMSSLERR;
		}

		key->key_size = uiKeyBits/8;
		if (RAND_bytes(key->key, key->key_size) != 1) {
			error_print();
			free(key);
			return SDR_GMSSLERR;
		}
		sm4_ecb_ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit(sm4_ecb_ctx,EVP_sm4_ecb(),kek,iv);
		EVP_CIPHER_CTX_set_padding(sm4_ecb_ctx, 0);
		if (EVP_EncryptUpdate(sm4_ecb_ctx, enced, &enced_len, key->key, key->key_size) != 1) {
			error_print();
			// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_free(sm4_ecb_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		if (EVP_EncryptFinal(sm4_ecb_ctx, enced+enced_len, &pad_len) != 1) {
			error_print();
			// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_free(sm4_ecb_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		EVP_CIPHER_CTX_free(sm4_ecb_ctx);
		// ! 不一定够长
		*puiKeyLength = 16 + enced_len;

		// append key to key_list
		if (session->key_list == NULL) {
			session->key_list = key;
		} else {
			SOFTSDF_KEY *current = session->key_list;
			while (current->next != NULL) {
				current = current->next;
			}
			current->next = key;
		}

		*phKeyHandle = key;
		return SDR_OK;
	}
}

int SDF_ImportKeyWithKEK(
	void *hSessionHandle,
	unsigned int uiAlgID,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength,
	void **phKeyHandle)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file;
	uint8_t kek[16];
	const uint8_t *iv;
	const uint8_t *enced;
	EVP_CIPHER_CTX *sm4_cbc_ctx;
	size_t enced_len,pad_len = 0;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM4_CBC) {
		error_print();
		return SDR_INARGERR;
	}

	// load KEK file with index
	snprintf(filename, FILENAME_MAX_LEN, "kek-%u.key", uiKEKIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (fread(kek, 1, sizeof(kek), file) != sizeof(kek)) {
		error_print();
		fclose(file);
		return SDR_INARGERR;
	}
	fclose(file);


	// decrypt SM4-CBC encrypted pucKey
	if (pucKey == NULL || uiKeyLength <= SM4_BLOCK_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiKeyLength > SM4_BLOCK_SIZE + SOFTSDF_MAX_KEY_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	key = (SOFTSDF_KEY *)malloc(sizeof(SOFTSDF_KEY));
	if (key == NULL) {
		error_print();
		return SDR_GMSSLERR;
	}
	memset(key, 0, sizeof(*key));

	iv = pucKey;
	enced = pucKey + SM4_BLOCK_SIZE;
	enced_len = uiKeyLength - SM4_BLOCK_SIZE;
	
	
	sm4_cbc_ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit(sm4_cbc_ctx,EVP_sm4_cbc(),kek,iv);
	// ! 不知道解密还要不要
	EVP_CIPHER_CTX_set_padding(sm4_cbc_ctx, 0);
	if (EVP_DecryptUpdate(sm4_cbc_ctx, key->key, &key->key_size, enced, enced_len) != 1) {
		error_print();
		// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
		EVP_CIPHER_CTX_free(sm4_cbc_ctx);
		free(key);
		return SDR_GMSSLERR;
	}
	if (EVP_DecryptFinal(sm4_cbc_ctx, key->key + key->key_size, &pad_len) != 1) {
		error_print();
		// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
		EVP_CIPHER_CTX_free(sm4_cbc_ctx);
		free(key);
		return SDR_GMSSLERR;
	}
	EVP_CIPHER_CTX_free(sm4_cbc_ctx);

	// append key to key_list
	if (session->key_list == NULL) {
		session->key_list = key;
	} else {
		SOFTSDF_KEY *current = session->key_list;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = key;
	}

	*phKeyHandle = key;
	return SDR_OK;
}

int SDF_DestroyKey(
	void *hSessionHandle,
	void *hKeyHandle)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *current;
	SOFTSDF_KEY *prev;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	current = session->key_list;
	{
		assert(current != NULL);
	}
	prev = NULL;
	while (current != NULL && current != (SOFTSDF_KEY *)hKeyHandle) {
		prev = current;
		current = current->next;
	}
	if (current == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if (prev == NULL) {
		session->key_list = current->next;
	} else {
		prev->next = current->next;
	}
	memset(current, 0, sizeof(SOFTSDF_KEY));
	free(current);

	return SDR_OK;
}

// int SDF_ExternalPublicKeyOperation_RSA(
// 	void *hSessionHandle,
// 	RSArefPublicKey *pucPublicKey,
// 	unsigned char *pucDataInput,
// 	unsigned int uiInputLength,
// 	unsigned char *pucDataOutput,
// 	unsigned int *puiOutputLength)
// {
// 	error_print();
// 	return SDR_NOTSUPPORT;
// }

// int SDF_ExternalPrivateKeyOperation_RSA(
// 	void *hSessionHandle,
// 	RSArefPrivateKey *pucPrivateKey,
// 	unsigned char *pucDataInput,
// 	unsigned int uiInputLength,
// 	unsigned char *pucDataOutput,
// 	unsigned int *puiOutputLength)
// {
// 	error_print();
// 	return SDR_NOTSUPPORT;
// }

// int SDF_InternalPrivateKeyOperation_RSA(
// 	void *hSessionHandle,
// 	unsigned int uiKeyIndex,
// 	unsigned char *pucDataInput,
// 	unsigned int uiInputLength,
// 	unsigned char *pucDataOutput,
// 	unsigned int *puiOutputLength)
// {
// 	error_print();
// 	return SDR_NOTSUPPORT;
// }

int SDF_ExternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature)
{
	SOFTSDF_SESSION *session;
	// SM2_POINT point;
	// SM2_Z256_POINT public_key;
	// SM2_KEY sm2_key;
	// SM2_SIGNATURE sig;
	EC_KEY *sm2_key;
	EC_POINT *public_key;
	uint8_t x[32], y[32];
	unsigned int i;
	uint8_t r[32], s[32], sig_bin[200];
	int sig_len;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_1) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey->bits != 256) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key
	// memset(&point, 0, sizeof(point));
	// memcpy(point.x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
	// memcpy(point.y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
	// if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
	// 	error_print();
	// 	return -1;
	// }
	// if (sm2_key_set_public_key(&sm2_key, &public_key) != 1) {
	// 	error_print();
	// 	return SDR_INARGERR;
	// }
	// memset(&point, 0, sizeof(point));
	memcpy(x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
	memcpy(y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
	if ((public_key = sm2_new_point(x, y)) == NULL) {
		error_print();
		return -1;
	}
	sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
	EC_KEY_precompute_mult(sm2_key, NULL);
	if (EC_KEY_set_public_key(sm2_key, public_key) != 1) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucDataInput == NULL || uiInputLength != 32) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucSignature == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucSignature->r[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucSignature->s[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}

	memcpy(r, pucSignature->r + ECCref_MAX_LEN - 32, 32);
	memcpy(s, pucSignature->s + ECCref_MAX_LEN - 32, 32);
	sm2_sig_set(sig_bin, &sig_len, r, s);
	if (sm2_verify(pucDataInput, 32, sig_bin, sig_len, sm2_key) != 1) {
		error_print();
		return SDR_VERIFYERR;
	}

	return SDR_OK;
}

int SDF_InternalSign_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	// SM2_SIGNATURE sig;
	uint8_t sig[100], r[32], s[32];
	int sig_len;


	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// find container with key index
	container = session->container_list;
	while (container != NULL && container->key_index != uiISKIndex) {
		container = container->next;
	}
	if (container == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucData == NULL || uiDataLength != SM3_DIGEST_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucSignature == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (sm2_sign(pucData, 32, sig, &sig_len, container->sign_key) != 1) {
		error_print();
		return SDR_GMSSLERR;
	}
	sm2_sig_get(sig, sig_len, r, s);
	memset(pucSignature, 0, sizeof(*pucSignature));
	memcpy(pucSignature->r + ECCref_MAX_LEN - 32, r, 32);
	memcpy(pucSignature->s + ECCref_MAX_LEN - 32, s, 32);

	return SDR_OK;
}

int SDF_InternalVerify_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	EC_KEY *sm2_key;
	// SM2_KEY sm2_key;
	// SM2_SIGNATURE sig;
	unsigned int i;
	uint8_t r[32], s[32], sig[100];
	int sig_len;
	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key from file
	snprintf(filename, FILENAME_MAX_LEN, "sm2signpub-%u.pem", uiIPKIndex);
	if ((sm2_key = sm2_public_key_info_from_pem(filename)) == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}

	if (pucData == NULL || uiDataLength != SM3_DIGEST_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucSignature == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucSignature->r[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucSignature->s[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}

	memcpy(r, pucSignature->r + ECCref_MAX_LEN - 32, 32);
	memcpy(s, pucSignature->s + ECCref_MAX_LEN - 32, 32);
	sm2_sig_set(sig, &sig_len, r, s);
	if (sm2_verify(pucData, 32, sig, sig_len, sm2_key) != 1) {
		error_print();
		return SDR_VERIFYERR;
	}

	return SDR_OK;
}

int SDF_ExternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	SOFTSDF_SESSION *session;
	// SM2_POINT point;
	// SM2_Z256_POINT public_key;
	// SM2_KEY sm2_key;
	// SM2_CIPHERTEXT ctxt;
	uint8_t ctext[SM2_MAX_PLAINTEXT_SIZE];
	size_t ctext_len;
	EVP_MD *digest = EVP_sm3();
	unsigned int i;
	uint8_t x[32], y[32];
	EC_POINT *public_key;
	EC_KEY *sm2_key;
	uint8_t C1_x[32], C1_y[32], C2[200], C3[32];
    int C2_len, C3_len;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucPublicKey->bits != 256) {
		error_print();
		return SDR_INARGERR;
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucPublicKey->x[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}
	for (i = 0; i < ECCref_MAX_LEN - 32; i++) {
		if (pucPublicKey->y[i] != 0) {
			error_print();
			return SDR_INARGERR;
		}
	}

	// parse public key
	// memset(&point, 0, sizeof(point));
	memcpy(x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
	memcpy(y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
	if ((public_key = sm2_new_point(x, y)) == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	// if (sm2_key_set_public_key(&sm2_key, &public_key) != 1) {
	// 	error_print();
	// 	return SDR_INARGERR;
	// }
	sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
	EC_KEY_precompute_mult(sm2_key, NULL);
	if (EC_KEY_set_public_key(sm2_key, public_key) != 1) {
		error_print();
		return SDR_INARGERR;
	}

	if (!pucData) {
		error_print();
		return SDR_INARGERR;
	}

	if(uiDataLength <=0 || uiDataLength > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	sm2_ciphertext_size(sm2_key, digest, uiDataLength, &ctext_len);
	if (sm2_encrypt(sm2_key, digest, (const uint8_t *)pucData, uiDataLength, ctext, &ctext_len) != 1) {
		error_print();
		return SDR_GMSSLERR;
	}
	sm2_get_ciphertext(ctext, ctext_len, C1_x, C1_y, C2, &C2_len, C3, &C3_len);
	
	memset(pucEncData, 0, sizeof(*pucEncData));
	memcpy(pucEncData->x + ECCref_MAX_LEN - 32, C1_x, 32);
	memcpy(pucEncData->y + ECCref_MAX_LEN - 32, C1_y, 32);
	memcpy(pucEncData->M, C3, 32);
	pucEncData->L = C2_len;
	memcpy(pucEncData->C, C2, C2_len);
	return SDR_OK;
}

int SDF_Encrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	size_t outlen,pad_len = 0;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}

	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	key = session->key_list;
	while (key != NULL && key != (SOFTSDF_KEY *)hKeyHandle) {
		key = key->next;
	}

	if (key == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	
	if (key->key_size < SM4_BLOCK_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	
	if (uiAlgID != SGD_SM4_CBC && uiAlgID != SGD_SM4_ECB) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID == SGD_SM4_CBC){
		EVP_CIPHER_CTX *sm4_cbc_ctx;
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		if (pucData == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		if (puiEncDataLength == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		// FIXME: calculate *puiEncDataLength if pucEncData is NULL
		if (pucEncData == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		sm4_cbc_ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit(sm4_cbc_ctx,EVP_sm4_cbc(),key->key,pucIV);

		EVP_CIPHER_CTX_set_padding(sm4_cbc_ctx, 0);
		if (EVP_EncryptUpdate(sm4_cbc_ctx, pucEncData, &outlen, pucData, uiDataLength) != 1) {
			error_print();
			// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_free(sm4_cbc_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		if (EVP_EncryptFinal(sm4_cbc_ctx, pucEncData + outlen, &pad_len) != 1) {
			error_print();
			// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_free(sm4_cbc_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		EVP_CIPHER_CTX_free(sm4_cbc_ctx);

		*puiEncDataLength = (unsigned int)outlen;
		return SDR_OK;
	}

	if (uiAlgID == SGD_SM4_ECB){
		EVP_CIPHER_CTX *sm4_ecb_ctx;

		if (pucData == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		if (puiEncDataLength == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		if (pucEncData == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		sm4_ecb_ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit(sm4_ecb_ctx,EVP_sm4_ecb(),key->key,NULL);
		EVP_CIPHER_CTX_set_padding(sm4_ecb_ctx, 0);
		if (EVP_EncryptUpdate(sm4_ecb_ctx, pucEncData, &outlen, pucData, uiDataLength) != 1) {
			error_print();
			EVP_CIPHER_CTX_free(sm4_ecb_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		if (EVP_EncryptFinal(sm4_ecb_ctx, pucEncData + outlen, &pad_len) != 1) {
			error_print();
			EVP_CIPHER_CTX_free(sm4_ecb_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		EVP_CIPHER_CTX_free(sm4_ecb_ctx);

		*puiEncDataLength = (unsigned int)outlen;
		return SDR_OK;
	}
}

int SDF_Decrypt(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;
	size_t outlen,pad_len = 0;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		printf("test10\n");
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		printf("test11\n");
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		printf("test12\n");
		return SDR_INARGERR;
	}
	key = session->key_list;
	while (key != NULL && key != (SOFTSDF_KEY *)hKeyHandle) {
		key = key->next;
	}
	if (key == NULL) {
		error_print();
		printf("test13\n");
		return SDR_INARGERR;
	}
	if (key->key_size < SM4_BLOCK_SIZE) {
		error_print();
		printf("test14\n");
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM4_CBC && uiAlgID != SGD_SM4_ECB) {
		error_print();
		printf("test15\n");
		return SDR_INARGERR;
	}

	if (uiAlgID == SGD_SM4_CBC) {
		EVP_CIPHER_CTX *sm4_cbc_ctx;
		if (pucIV == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		if (pucEncData == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		if (puiDataLength == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		// FIXME: calculate *puiDataLength if pucData is NULL
		if (pucData == NULL) {
			error_print();
			return SDR_INARGERR;
		}

		sm4_cbc_ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(sm4_cbc_ctx,EVP_sm4_cbc(),key->key,pucIV);
		// ! 不知道解密还要不要
		EVP_CIPHER_CTX_set_padding(sm4_cbc_ctx, 0);
		if (EVP_DecryptUpdate(sm4_cbc_ctx, pucData, &outlen, pucEncData, uiEncDataLength) != 1) {
			error_print();
			// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_free(sm4_cbc_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		if (EVP_DecryptFinal(sm4_cbc_ctx, pucData + outlen, &pad_len) != 1) {
			error_print();
			// memset(&sm4_cbc_ctx, 0, sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_free(sm4_cbc_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		EVP_CIPHER_CTX_free(sm4_cbc_ctx);

		*puiDataLength = (unsigned int)outlen;
		return SDR_OK;
	}

	if (uiAlgID == SGD_SM4_ECB) {
		EVP_CIPHER_CTX *sm4_ecb_ctx;
		if (pucEncData == NULL) {
			error_print();
			printf("test16\n");
			return SDR_INARGERR;
		}

		if (puiDataLength == NULL) {
			error_print();
			printf("test17\n");
			return SDR_INARGERR;
		}

		if (pucData == NULL) {
			error_print();
			printf("test18\n");
			return SDR_INARGERR;
		}

		sm4_ecb_ctx = EVP_CIPHER_CTX_new();
		EVP_DecryptInit(sm4_ecb_ctx,EVP_sm4_ecb(),key->key,NULL);
		EVP_CIPHER_CTX_set_padding(sm4_ecb_ctx, 0);
		if (EVP_DecryptUpdate(sm4_ecb_ctx, pucData, &outlen, pucEncData, uiEncDataLength) != 1) {
			error_print();

			EVP_CIPHER_CTX_free(sm4_ecb_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		if (EVP_DecryptFinal(sm4_ecb_ctx, pucData + outlen, &pad_len) != 1) {
			error_print();

			EVP_CIPHER_CTX_free(sm4_ecb_ctx);
			free(key);
			return SDR_GMSSLERR;
		}
		EVP_CIPHER_CTX_free(sm4_ecb_ctx);

		*puiDataLength = (unsigned int)outlen;
		return SDR_OK;
	}
}

int SDF_CalculateMAC(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucMAC,
	unsigned int *puiMACLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_KEY *key;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (hKeyHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	key = session->key_list;
	while (key != NULL && key != (SOFTSDF_KEY *)hKeyHandle) {
		key = key->next;
	}
	if (key == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucIV != NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucData == NULL || uiDataLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}

	if (puiMACLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID == SGD_SM3) {
		SM3_HMAC_CTX hmac_ctx;

		if (key->key_size < 12) {
			error_print();
			return SDR_INARGERR;
		}

		*puiMACLength = SM3_HMAC_SIZE;

		if (!pucMAC) {
			return SDR_OK;
		}

		sm3_hmac_init(&hmac_ctx, key->key, key->key_size);
		sm3_hmac_update(&hmac_ctx, pucData, uiDataLength);
		sm3_hmac_finish(&hmac_ctx, pucMAC);

		memset(&hmac_ctx, 0, sizeof(hmac_ctx));

	} else if (uiAlgID == SGD_SM4_MAC) {
		SM4_CBC_MAC_CTX cbc_mac_ctx;

		if (key->key_size < SM4_BLOCK_SIZE) {
			error_print();
			return SDR_INARGERR;
		}
		*puiMACLength = SM4_CBC_MAC_SIZE;

		if (!pucMAC) {
			return SDR_OK;
		}

		sm4_cbc_mac_init(&cbc_mac_ctx, key->key);
		sm4_cbc_mac_update(&cbc_mac_ctx, pucData, uiDataLength);
		sm4_cbc_mac_finish(&cbc_mac_ctx, pucMAC);

		memset(&cbc_mac_ctx, 0, sizeof(cbc_mac_ctx));

	} else {
		error_print();
		return SDR_INARGERR;
	}

	return SDR_OK;
}

int SDF_HashInit(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength)
{
	SOFTSDF_SESSION *session;
	
	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (uiAlgID != SGD_SM3) {
		error_print();
		return SDR_INARGERR;
	}

	// FIXME: check step or return SDR_STEPERR;
	sm3_avx_init(&session->sm3_ctx);

	if (pucPublicKey != NULL) {
		uint8_t x[32], y[32];
		EC_POINT *public_key;
		EC_KEY *sm2_key;
		EVP_MD *digest = EVP_sm3();
		// SM2_POINT point;
		// SM2_Z256_POINT public_key;
		uint8_t z[32];

		if (pucID == NULL || uiIDLength <= 0) {
			error_print();
			return SDR_INARGERR;
		}

		// memset(&point, 0, sizeof(point));
		// memcpy(point.x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
		// memcpy(point.y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
		// if (sm2_z256_point_from_bytes(&public_key, (uint8_t *)&point) != 1) {
		// 	error_print();
		// 	return SDR_INARGERR;
		// }
		// if (sm2_compute_z(z, &public_key, (const char *)pucID, uiIDLength) != 1) {
		// 	error_print();
		// 	return SDR_GMSSLERR;
		// }
		memset(x, 0, sizeof(x));
		memset(y, 0, sizeof(y));
		memcpy(x, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
		memcpy(y, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
		if ((public_key = sm2_new_point(x, y)) == NULL) {
			error_print();
			return SDR_INARGERR;
		}
		sm2_key = EC_KEY_new_by_curve_name(NID_sm2);
		EC_KEY_precompute_mult(sm2_key, NULL);
		if (EC_KEY_set_public_key(sm2_key, public_key) != 1) {
			error_print();
			return SDR_INARGERR;
		}
		if (sm2_compute_z_digest(z, digest, (const char *)pucID, uiIDLength, sm2_key) != 1) {
			error_print();
			return SDR_GMSSLERR;
		}
		sm3_avx_update(&session->sm3_ctx, z, sizeof(z));

		EC_KEY_free(sm2_key);
		EC_POINT_free(public_key);
	}
	return SDR_OK;
}

int SDF_HashUpdate(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int uiDataLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucData == NULL || uiDataLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}

	sm3_avx_update(&session->sm3_ctx, pucData, uiDataLength);

	return SDR_OK;
}

int SDF_HashFinal(void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength)
{
	SOFTSDF_SESSION *session;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucHash == NULL || puiHashLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	sm3_avx_final(pucHash, &session->sm3_ctx);

	*puiHashLength = SM3_DIGEST_SIZE;
	return SDR_OK;
}

int SDF_CreateFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiFileSize)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	uint8_t buf[1024] = {0};
	size_t i;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucFileName == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiNameLen <= 0 || uiNameLen >= FILENAME_MAX_LEN - 5) {
		error_print();
		return SDR_INARGERR;
	}
	memcpy(filename, pucFileName, uiNameLen);
	filename[uiNameLen] = 0;
	if (strlen(filename) != uiNameLen) {
		error_print();
		return SDR_INARGERR;
	}
	strcat(filename, ".file");

	if (uiFileSize > 64 * 1024) {
		error_print();
		return SDR_INARGERR;
	}

	file = fopen(filename, "wb");
	if (file == NULL) {
		error_puts("Failed to create file");
		return SDR_GMSSLERR;
	}
	for (i = 0; i < uiFileSize/sizeof(buf); i++) {
		fwrite(buf, 1, sizeof(buf), file);
	}
	fwrite(buf, 1, uiFileSize % sizeof(buf), file);
	fclose(file);

	return SDR_OK;
}

int SDF_ReadFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int *puiReadLength,
	unsigned char *pucBuffer)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	size_t bytesRead;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucFileName == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiNameLen <= 0 || uiNameLen >= FILENAME_MAX_LEN - 5) {
		error_print();
		return SDR_INARGERR;
	}
	memcpy(filename, pucFileName, uiNameLen);
	filename[uiNameLen] = 0;
	if (strlen(filename) != uiNameLen) {
		error_print();
		return SDR_INARGERR;
	}
	strcat(filename, ".file");

	if (puiReadLength == NULL || *puiReadLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucBuffer == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_GMSSLERR;
	}
	if (fseek(file, uiOffset, SEEK_SET) != 0) {
		fclose(file);
		error_print();
		return SDR_GMSSLERR;
	}
	bytesRead = fread(pucBuffer, 1, *puiReadLength, file);
	if (bytesRead == 0) {
		error_print();
		fclose(file);
		return SDR_GMSSLERR;
	}
	fclose(file);

	*puiReadLength = bytesRead;
	return SDR_OK;
}

int SDF_WriteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int uiWriteLength,
	unsigned char *pucBuffer)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	size_t bytesWritten;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucFileName == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiNameLen <= 0 || uiNameLen >= FILENAME_MAX_LEN - 5) {
		error_print();
		return SDR_INARGERR;
	}
	memcpy(filename, pucFileName, uiNameLen);
	filename[uiNameLen] = 0;
	if (strlen(filename) != uiNameLen) {
		error_print();
		return SDR_INARGERR;
	}
	strcat(filename, ".file");

	if (uiWriteLength <= 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiWriteLength > 64 * 1024) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucBuffer == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	file = fopen(filename, "wb");
	if (file == NULL) {
		error_print();
		return SDR_GMSSLERR;
	}
	if (fseek(file, uiOffset, SEEK_SET) != 0) {
		error_print();
		fclose(file);
		return SDR_GMSSLERR;
	}
	bytesWritten = fwrite(pucBuffer, 1, uiWriteLength, file);
	if (bytesWritten != uiWriteLength) {
		error_print();
		fclose(file);
		return SDR_GMSSLERR;
	}
	fclose(file);

	return SDR_OK;
}

int SDF_DeleteFile(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (hSessionHandle == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucFileName == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiNameLen <= 0 || uiNameLen >= FILENAME_MAX_LEN - 5) {
		error_print();
		return SDR_INARGERR;
	}
	memcpy(filename, pucFileName, uiNameLen);
	filename[uiNameLen] = 0;
	if (strlen(filename) != uiNameLen) {
		error_print();
		return SDR_INARGERR;
	}
	strcat(filename, ".file");

	if (remove(filename) != 0) {
		error_print();
		return SDR_GMSSLERR;
	}

	return SDR_OK;
}

int SDF_InternalEncrypt_ECC(
	void *hSessionHandle,
	unsigned int uiIPKIndex,
	unsigned int uiAlgID,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCCipher *pucEncData)
{
	SOFTSDF_SESSION *session;
	char filename[FILENAME_MAX_LEN];
	FILE *file = NULL;
	EC_KEY *sm2_key;
	uint8_t ctext[200];
	size_t ctext_len;
	uint8_t C1_x[32], C1_y[32], C2[200], C3[32];
    int C2_len, C3_len;
	EVP_MD *digest = EVP_sm3();
	// SM2_KEY sm2_key;
	// SM2_CIPHERTEXT ciphertext;

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key by uiISKIndex
	snprintf(filename, FILENAME_MAX_LEN, "sm2encpub-%u.pem", uiIPKIndex);
	file = fopen(filename, "rb");
	if (file == NULL) {
		error_print();
		return SDR_KEYNOTEXIST;
	}
	if ((sm2_key = sm2_public_key_info_from_pem(filename)) == NULL) {
		error_print();
		fclose(file);
		return SDR_KEYNOTEXIST;
	}
	fclose(file);

	// check uiAlgID
	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_ALGNOTSUPPORT;
	}

	if (pucData == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (uiDataLength > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucEncData == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// encrypt
	// if (sm2_encrypt(&sm2_key, pucData, uiDataLength, &ciphertext) != 1) {
	// 	error_print();
	// 	return SDR_PKOPERR;
	// }
	sm2_ciphertext_size(sm2_key, digest, uiDataLength, &ctext_len);
	if (sm2_encrypt(sm2_key, digest, (const uint8_t *)pucData, uiDataLength, ctext, &ctext_len) != 1) {
		error_print();
		return SDR_GMSSLERR;
	}
	sm2_get_ciphertext(ctext, ctext_len, C1_x, C1_y, C2, &C2_len, C3, &C3_len);

	memset(pucEncData->x, 0, ECCref_MAX_LEN - 32);
	memcpy(pucEncData->x + ECCref_MAX_LEN - 32, C1_x, 32);
	memset(pucEncData->y, 0, ECCref_MAX_LEN - 32);
	memcpy(pucEncData->y + ECCref_MAX_LEN - 32, C1_y, 32);
	memcpy(pucEncData->M, C3, 32);
	memcpy(pucEncData->C, C2, C2_len);
	pucEncData->L = (unsigned int)C2_len;

	return SDR_OK;
}

int SDF_InternalDecrypt_ECC(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	unsigned int uiAlgID,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int *puiDataLength)
{
	SOFTSDF_SESSION *session;
	SOFTSDF_CONTAINER *container;
	// SM2_CIPHERTEXT ciphertext;
	size_t plaintext_len = 256;
	uint8_t ctext[200];
	size_t ctext_len;
	uint8_t C1_x[32], C1_y[32], C2[200], C3[32];
    int C2_len, C3_len;
	EVP_MD *digest = EVP_sm3();

	if (deviceHandle == NULL) {
		error_print();
		return SDR_STEPERR;
	}

	if (!hSessionHandle) {
		error_print();
		return SDR_INARGERR;
	}
	session = deviceHandle->session_list;
	while (session != NULL && session != hSessionHandle) {
		session = session->next;
	}
	if (session == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// load public key by uiISKIndex
	container = session->container_list;
	while (container != NULL && container->key_index != uiISKIndex) {
		container = container->next;
	}
	if (container == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	// check uiAlgID
	if (uiAlgID != SGD_SM2_3) {
		error_print();
		return SDR_ALGNOTSUPPORT;
	}

	// check ciphertext
	if (pucEncData == NULL) {
		error_print();
		return SDR_INARGERR;
	}
	if (pucEncData->L > SM2_MAX_PLAINTEXT_SIZE) {
		error_print();
		return SDR_INARGERR;
	}

	// convert ECCCipher to SM2_CIPHERTEXT
	if (memcmp(pucEncData->x, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return SDR_INARGERR;
	}
	if (memcmp(pucEncData->y, zeros, ECCref_MAX_LEN - 32) != 0) {
		error_print();
		return SDR_INARGERR;
	}
	memcpy(C1_x, pucEncData->x + ECCref_MAX_LEN - 32, 32);
	memcpy(C1_y, pucEncData->y + ECCref_MAX_LEN - 32, 32);
	memcpy(C3, pucEncData->M, 32);
	memcpy(C2, pucEncData->C, pucEncData->L);
	C2_len = pucEncData->L;
	C3_len = 32;
	ctext_len = sizeof(ctext);
	sm2_set_ciphertext(ctext, &ctext_len, C1_x, C1_y, C2, C2_len, C3, C3_len);

	if (puiDataLength == NULL) {
		error_print();
		return SDR_INARGERR;
	}

	if (pucData == NULL) {
		*puiDataLength = pucEncData->L;
		return SDR_OK;
	}

	// if (sm2_do_decrypt(&container->enc_key, &ciphertext, pucData, &plaintext_len) != 1) {
	// 	error_print();
	// 	return SDR_PKOPERR;
	// }
	if (sm2_decrypt(container->enc_key, digest, ctext, ctext_len, pucData, &plaintext_len) != 1) {
		printf("%s: error...\n", __func__);
		error_print();
		return SDR_PKOPERR;
	}
	*puiDataLength = (unsigned int)plaintext_len;
	return SDR_OK;
}

// int SDF_InternalPublicKeyOperation_RSA(
// 	void *hSessionHandle,
// 	unsigned int uiKeyIndex,
// 	unsigned char *pucDataInput,
// 	unsigned int uiInputLength,
// 	unsigned char *pucDataOutput,
// 	unsigned int *puiOutputLength)
// {
// 	error_print();
// 	return SDR_NOTSUPPORT;
// }
