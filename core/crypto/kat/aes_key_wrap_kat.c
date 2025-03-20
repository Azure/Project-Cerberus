// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "aes_key_wrap_kat.h"
#include "aes_key_wrap_kat_vectors.h"
#include "common/buffer_util.h"


/**
 * Run a Known Answer Test (KAT) for AES Key Wrap using AES-256.
 *
 * @param aes_kw The key wrap instance to test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int aes_key_wrap_kat_run_self_test_wrap_aes256 (const struct aes_key_wrap_interface *aes_kw)
{
	uint8_t wrapped[AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN] = {0};
	int status;
	int clear_status;

	if (aes_kw == NULL) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	status = aes_kw->set_kek (aes_kw, AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes_kw->wrap (aes_kw, AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN, wrapped, sizeof (wrapped));
	if (status != 0) {
		goto exit;
	}

	if (buffer_compare (wrapped, AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED, sizeof (wrapped)) != 0) {
		status = AES_KEY_WRAP_SELF_TEST_FAILED;
	}

exit:
	clear_status = aes_kw->clear_kek (aes_kw);
	if ((clear_status != 0) && (status == 0)) {
		status = clear_status;
	}

	buffer_zeroize (wrapped, sizeof (wrapped));

	return status;
}

/**
 * Run a Known Answer Test (KAT) for AES Key Unwrap using AES-256.
 *
 * @param aes_kw The key wrap instance to test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int aes_key_wrap_kat_run_self_test_unwrap_aes256 (const struct aes_key_wrap_interface *aes_kw)
{
	uint8_t data[AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN] = {0};
	size_t length = sizeof (data);
	int status;
	int clear_status;

	if (aes_kw == NULL) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	status = aes_kw->set_kek (aes_kw, AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes_kw->unwrap (aes_kw, AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN, data, &length);
	if (status != 0) {
		goto exit;
	}

	if (length != AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN) {
		status = AES_KEY_WRAP_SELF_TEST_FAILED;
	}
	else if (buffer_compare (data, AES_KEY_WRAP_KAT_VECTORS_KW_DATA, length) != 0) {
		status = AES_KEY_WRAP_SELF_TEST_FAILED;
	}

exit:
	clear_status = aes_kw->clear_kek (aes_kw);
	if ((clear_status != 0) && (status == 0)) {
		status = clear_status;
	}

	buffer_zeroize (data, sizeof (data));

	return status;
}

/**
 * Run a Known Answer Test (KAT) for AES Key Wrap with Padding using AES-256.
 *
 * @param aes_kwp The key wrap instance to test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (
	const struct aes_key_wrap_interface *aes_kwp)
{
	uint8_t wrapped[AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN] = {0};
	int status;
	int clear_status;

	if (aes_kwp == NULL) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	status = aes_kwp->set_kek (aes_kwp, AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes_kwp->wrap (aes_kwp, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN, wrapped, sizeof (wrapped));
	if (status != 0) {
		goto exit;
	}

	if (buffer_compare (wrapped, AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED, sizeof (wrapped)) != 0) {
		status = AES_KEY_WRAP_SELF_TEST_FAILED;
	}

exit:
	clear_status = aes_kwp->clear_kek (aes_kwp);
	if ((clear_status != 0) && (status == 0)) {
		status = clear_status;
	}

	buffer_zeroize (wrapped, sizeof (wrapped));

	return status;
}

/**
 * Run a Known Answer Test (KAT) for AES Key Unwrap with Padding using AES-256.
 *
 * @param aes_kwp The key wrap instance to test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (
	const struct aes_key_wrap_interface *aes_kwp)
{
	uint8_t
		data[AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN)] = {0};
	size_t length = sizeof (data);
	int status;
	int clear_status;

	if (aes_kwp == NULL) {
		return AES_KEY_WRAP_INVALID_ARGUMENT;
	}

	status = aes_kwp->set_kek (aes_kwp, AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN);
	if (status != 0) {
		return status;
	}

	status = aes_kwp->unwrap (aes_kwp, AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN, data, &length);
	if (status != 0) {
		goto exit;
	}

	if (length != AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN) {
		status = AES_KEY_WRAP_SELF_TEST_FAILED;
	}
	else if (buffer_compare (data, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA, length) != 0) {
		status = AES_KEY_WRAP_SELF_TEST_FAILED;
	}

exit:
	clear_status = aes_kwp->clear_kek (aes_kwp);
	if ((clear_status != 0) && (status == 0)) {
		status = clear_status;
	}

	buffer_zeroize (data, sizeof (data));

	return status;
}
