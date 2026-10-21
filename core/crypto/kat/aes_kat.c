// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "aes_kat.h"
#include "aes_kat_vectors.h"
#include "common/buffer_util.h"

/**
 * Self test function for AES-CBC encrypt algorithm. Uses NIST defined test vectors
 *
 * @param aes - AES-CBC engine.
 *
 * @return 0 on success, error code otherwise
 */
int aes_cbc_kat_run_self_test_encrypt_aes256 (const struct aes_cbc_engine *aes)
{
	int status;
	int clear_status;
	uint8_t ciphertext[AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN];

	if (aes == NULL) {
		return AES_CBC_ENGINE_INVALID_ARGUMENT;
	}

	status = aes->set_key (aes, AES_CBC_KAT_VECTORS_256_KEY, AES_CBC_KAT_VECTORS_256_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes->encrypt_data (aes, AES_CBC_KAT_VECTORS_PLAINTEXT,
		AES_CBC_KAT_VECTORS_PLAINTEXT_LEN, AES_CBC_KAT_VECTORS_IV, ciphertext, sizeof (ciphertext),
		NULL);
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (AES_CBC_KAT_VECTORS_CIPHERTEXT, ciphertext,
		AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN);
	if (status != 0) {
		status = AES_CBC_ENGINE_SELF_TEST_FAILED;
	}

exit:
	buffer_zeroize (ciphertext, sizeof (ciphertext));

	clear_status = aes->clear_key (aes);
	if ((status == 0) && (clear_status != 0)) {
		status = clear_status;
	}

	return status;
}

/**
 * Self test function for AES-CBC decrypt algorithm. Uses NIST defined test vectors
 *
 * @param aes - AES-CBC engine.
 *
 * @return 0 on success, error code otherwise
 */
int aes_cbc_kat_run_self_test_decrypt_aes256 (const struct aes_cbc_engine *aes)
{
	int status;
	int clear_status;
	uint8_t plaintext[AES_CBC_KAT_VECTORS_PLAINTEXT_LEN];

	if (aes == NULL) {
		return AES_CBC_ENGINE_INVALID_ARGUMENT;
	}

	status = aes->set_key (aes, AES_CBC_KAT_VECTORS_256_KEY, AES_CBC_KAT_VECTORS_256_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes->decrypt_data (aes, AES_CBC_KAT_VECTORS_CIPHERTEXT,
		AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN, AES_CBC_KAT_VECTORS_IV, plaintext, sizeof (plaintext),
		NULL);
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (AES_CBC_KAT_VECTORS_PLAINTEXT, plaintext,
		AES_CBC_KAT_VECTORS_PLAINTEXT_LEN);
	if (status != 0) {
		status = AES_CBC_ENGINE_SELF_TEST_FAILED;
	}

exit:
	buffer_zeroize (plaintext, sizeof (plaintext));
	clear_status = aes->clear_key (aes);
	if ((status == 0) && (clear_status != 0)) {
		status = clear_status;
	}

	return status;
}

/**
 * Self test function for AES-ECB encrypt algorithm. Uses NIST defined test vectors
 *
 * @param aes - AES-ECB engine.
 *
 * @return 0 on success, error code otherwise
 */
int aes_ecb_kat_run_self_test_encrypt_aes256 (const struct aes_ecb_engine *aes)
{
	int status;
	int clear_status;
	uint8_t ciphertext[AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN];

	if (aes == NULL) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	status = aes->set_key (aes, AES_ECB_KAT_VECTORS_256_KEY, AES_ECB_KAT_VECTORS_256_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes->encrypt_data (aes, AES_ECB_KAT_VECTORS_PLAINTEXT,
		AES_ECB_KAT_VECTORS_PLAINTEXT_LEN, ciphertext, sizeof (ciphertext));
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (AES_ECB_KAT_VECTORS_CIPHERTEXT, ciphertext,
		AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN);
	if (status != 0) {
		status = AES_ECB_ENGINE_SELF_TEST_FAILED;
	}

exit:
	buffer_zeroize (ciphertext, sizeof (ciphertext));
	clear_status = aes->clear_key (aes);
	if ((status == 0) && (clear_status != 0)) {
		status = clear_status;
	}

	return status;
}

/**
 * Self test function for AES-ECB decrypt algorithm. Uses NIST defined test vectors
 *
 * @param aes - AES-ECB engine.
 *
 * @return 0 on success, error code otherwise
 */
int aes_ecb_kat_run_self_test_decrypt_aes256 (const struct aes_ecb_engine *aes)
{
	int status;
	int clear_status;
	uint8_t plaintext[AES_ECB_KAT_VECTORS_PLAINTEXT_LEN];

	if (aes == NULL) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	status = aes->set_key (aes, AES_ECB_KAT_VECTORS_256_KEY, AES_ECB_KAT_VECTORS_256_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes->decrypt_data (aes, AES_ECB_KAT_VECTORS_CIPHERTEXT,
		AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN, plaintext, sizeof (plaintext));
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (AES_ECB_KAT_VECTORS_PLAINTEXT, plaintext,
		AES_ECB_KAT_VECTORS_PLAINTEXT_LEN);
	if (status != 0) {
		status = AES_ECB_ENGINE_SELF_TEST_FAILED;
	}

exit:
	buffer_zeroize (plaintext, sizeof (plaintext));
	clear_status = aes->clear_key (aes);
	if ((status == 0) && (clear_status != 0)) {
		status = clear_status;
	}

	return status;
}

/**
 * Self test function for AES-GCM encrypt algorithm. Uses NIST defined test vectors
 *
 * @param aes - AES-GCM engine.
 *
 * @return 0 on success, error code otherwise
 */
int aes_gcm_kat_run_self_test_encrypt_aes256 (const struct aes_gcm_engine *aes)
{
	int status;
	int clear_status;
	uint8_t ciphertext[AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN];
	uint8_t tag[AES_GCM_KAT_VECTORS_TAG_LEN];

	if (aes == NULL) {
		return AES_GCM_ENGINE_INVALID_ARGUMENT;
	}

	status = aes->set_key (aes, AES_GCM_KAT_VECTORS_256_KEY, AES_GCM_KAT_VECTORS_256_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes->encrypt_data (aes, AES_GCM_KAT_VECTORS_PLAINTEXT,
		AES_GCM_KAT_VECTORS_PLAINTEXT_LEN, AES_GCM_KAT_VECTORS_IV, AES_GCM_KAT_VECTORS_IV_LEN,
		ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (AES_GCM_KAT_VECTORS_CIPHERTEXT, ciphertext,
		AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN);
	if (status != 0) {
		status = AES_GCM_ENGINE_SELF_TEST_FAILED;
		goto exit;
	}

	status = buffer_compare (AES_GCM_KAT_VECTORS_TAG, tag, AES_GCM_KAT_VECTORS_TAG_LEN);
	if (status != 0) {
		status = AES_GCM_ENGINE_SELF_TEST_FAILED;
	}

exit:
	buffer_zeroize (ciphertext, sizeof (ciphertext));
	buffer_zeroize (tag, sizeof (tag));

	clear_status = aes->clear_key (aes);
	if ((status == 0) && (clear_status != 0)) {
		status = clear_status;
	}

	return status;
}


/**
 * Self test function for AES-GCM decrypt algorithm. Uses NIST defined test vectors
 *
 * @param aes - AES-GCM engine.
 *
 * @return 0 on success, error code otherwise
 */
int aes_gcm_kat_run_self_test_decrypt_aes256 (const struct aes_gcm_engine *aes)
{
	int status;
	int clear_status;
	uint8_t plaintext[AES_GCM_KAT_VECTORS_PLAINTEXT_LEN];

	if (aes == NULL) {
		return AES_GCM_ENGINE_INVALID_ARGUMENT;
	}

	status = aes->set_key (aes, AES_GCM_KAT_VECTORS_256_KEY, AES_GCM_KAT_VECTORS_256_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes->decrypt_data (aes, AES_GCM_KAT_VECTORS_CIPHERTEXT,
		AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN, AES_GCM_KAT_VECTORS_TAG, AES_GCM_KAT_VECTORS_IV,
		AES_GCM_KAT_VECTORS_IV_LEN, plaintext, sizeof (plaintext));
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (AES_GCM_KAT_VECTORS_PLAINTEXT, plaintext,
		AES_GCM_KAT_VECTORS_PLAINTEXT_LEN);
	if (status != 0) {
		status = AES_GCM_ENGINE_SELF_TEST_FAILED;
	}

exit:
	buffer_zeroize (plaintext, sizeof (plaintext));

	clear_status = aes->clear_key (aes);
	if ((status == 0) && (clear_status != 0)) {
		status = clear_status;
	}

	return status;
}

/**
 * Self test function for AES-XTS encrypt algorithm. Uses NIST defined test vectors
 *
 * @param aes - AES-XTS engine.
 *
 * @return 0 on success, error code otherwise
 */
int aes_xts_kat_run_self_test_encrypt_aes256 (const struct aes_xts_engine *aes)
{
	int status;
	int clear_status;
	uint8_t ciphertext[AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN];

	if (aes == NULL) {
		return AES_XTS_ENGINE_INVALID_ARGUMENT;
	}

	status = aes->set_key (aes, AES_XTS_KAT_VECTORS_256_KEY, AES_XTS_KAT_VECTORS_256_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes->encrypt_data (aes, AES_XTS_KAT_VECTORS_PLAINTEXT,
		AES_XTS_KAT_VECTORS_PLAINTEXT_LEN, AES_XTS_KAT_VECTORS_UNIQUE_DATA, ciphertext,
		sizeof (ciphertext));
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (AES_XTS_KAT_VECTORS_CIPHERTEXT, ciphertext,
		AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN);
	if (status != 0) {
		status = AES_XTS_ENGINE_SELF_TEST_FAILED;
	}

exit:
	buffer_zeroize (ciphertext, sizeof (ciphertext));
	clear_status = aes->clear_key (aes);
	if ((status == 0) && (clear_status != 0)) {
		status = clear_status;
	}

	return status;
}

/**
 * Self test function for AES-XTS decrypt algorithm. Uses NIST defined test vectors
 *
 * @param aes - AES-XTS engine.
 *
 * @return 0 on success, error code otherwise
 */
int aes_xts_kat_run_self_test_decrypt_aes256 (const struct aes_xts_engine *aes)
{
	int status;
	int clear_status;
	uint8_t plaintext[AES_XTS_KAT_VECTORS_PLAINTEXT_LEN];

	if (aes == NULL) {
		return AES_XTS_ENGINE_INVALID_ARGUMENT;
	}

	status = aes->set_key (aes, AES_XTS_KAT_VECTORS_256_KEY, AES_XTS_KAT_VECTORS_256_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes->decrypt_data (aes, AES_XTS_KAT_VECTORS_CIPHERTEXT,
		AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN, AES_XTS_KAT_VECTORS_UNIQUE_DATA, plaintext,
		sizeof (plaintext));
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (AES_XTS_KAT_VECTORS_PLAINTEXT, plaintext,
		AES_XTS_KAT_VECTORS_PLAINTEXT_LEN);
	if (status != 0) {
		status = AES_XTS_ENGINE_SELF_TEST_FAILED;
	}

exit:
	buffer_zeroize (plaintext, sizeof (plaintext));
	clear_status = aes->clear_key (aes);
	if ((status == 0) && (clear_status != 0)) {
		status = clear_status;
	}

	return status;
}
