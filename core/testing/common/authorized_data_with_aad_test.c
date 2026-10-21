// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/authorized_data_with_aad.h"
#include "common/authorized_data_with_aad_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("authorized_data_with_aad");


/**
 * Construct authorized data for testing.
 *
 * @param token The authorization token to add to the payload.
 * @param token_length Length of the token data.
 * @param aad The AAD to add to the payload.
 * @param aad_length Length of the AAD.
 * @param signature The authorizing signature for the data.
 * @param sig_length Length of the signature data.
 * @param payload Output for the authorized data payload.  This is assumed large enough for all the
 * specified data.
 * @param length Output for the total payload length.
 */
static void authorized_data_with_aad_testing_construct_payload (const uint8_t *token,
	size_t token_length, const uint8_t *aad, size_t aad_length, const uint8_t *signature,
	size_t sig_length, uint8_t *payload, size_t *length)
{
	uint8_t *pos = payload;

	*length = 0;

	memcpy (pos, &token_length, 2);
	pos += 2;
	*length += 2;

	memcpy (pos, &aad_length, 2);
	pos += 2;
	*length += 2;

	if (token != NULL) {
		memcpy (pos, token, token_length);
		pos += token_length;
		*length += token_length;
	}

	if (aad != NULL) {
		memcpy (pos, aad, aad_length);
		pos += aad_length;
		*length += aad_length;
	}

	if (signature != NULL) {
		memcpy (pos, signature, sig_length);
		*length += sig_length;
	}
}


/*******************
 * Test cases
 *******************/

static void authorized_data_with_aad_test_init (CuTest *test)
{
	struct authorized_data_with_aad auth;
	int status;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.base_data.get_token_offset);
	CuAssertPtrNotNull (test, auth.base_data.get_authenticated_data);
	CuAssertPtrNotNull (test, auth.base_data.get_authenticated_data_length);

	CuAssertPtrNotNull (test, auth.base_sig.get_signature);
	CuAssertPtrNotNull (test, auth.base_sig.get_signature_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = authorized_data_with_aad_init (NULL);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);
}

static void authorized_data_with_aad_test_static_init (CuTest *test)
{
	struct authorized_data_with_aad auth = authorized_data_with_aad_static_init ();

	TEST_START;

	CuAssertPtrNotNull (test, auth.base_data.get_token_offset);
	CuAssertPtrNotNull (test, auth.base_data.get_authenticated_data);
	CuAssertPtrNotNull (test, auth.base_data.get_authenticated_data_length);

	CuAssertPtrNotNull (test, auth.base_sig.get_signature);
	CuAssertPtrNotNull (test, auth.base_sig.get_signature_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_release_null (CuTest *test)
{
	TEST_START;

	authorized_data_with_aad_release (NULL);
}

static void authorized_data_with_aad_test_get_token_offset (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length, &token_offset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, token_offset);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length, &token_offset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, token_offset);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_no_auth_token (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length, &token_offset);
	CuAssertIntEquals (test, AUTH_DATA_NO_AUTH_TOKEN, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_no_auth_token_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length, NULL, aad_length,
		ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length, &token_offset);
	CuAssertIntEquals (test, AUTH_DATA_NO_AUTH_TOKEN, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_static_init (CuTest *test)
{
	struct authorized_data_with_aad auth = authorized_data_with_aad_static_init ();
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length, &token_offset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, token_offset);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_null (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_token_offset (NULL, data, length, &token_offset);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base_data.get_token_offset (&auth.base_data, NULL, length, &token_offset);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length, NULL);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_no_header (CuTest *test)
{
	struct authorized_data_with_aad auth;
	uint8_t data[4 - 1] = {0};
	size_t length = sizeof (data);
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length, &token_offset);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_payload_too_short (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length - 1, &token_offset);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_payload_too_short_no_auth_token (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length - 1, &token_offset);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_token_offset_payload_too_short_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t token_offset = 0x55;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_token_offset (&auth.base_data, data, length - 1, &token_offset);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, &out_aad,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length], out_aad);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, &out_aad,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, out_aad);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_no_auth_token (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, &out_aad,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length], out_aad);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_no_auth_token_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length, NULL, aad_length,
		ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, &out_aad,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, out_aad);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_no_signature (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, &out_aad,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length], out_aad);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_static_init (CuTest *test)
{
	struct authorized_data_with_aad auth = authorized_data_with_aad_static_init ();
	const size_t token_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_512, token_length,
		HASH_TESTING_FULL_BLOCK_1024, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, &out_aad,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length], out_aad);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_null (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (NULL, data, length, &out_aad, &out_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base_data.get_authenticated_data (&auth.base_data, NULL, length, &out_aad,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, NULL,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, &out_aad, NULL);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_no_header (CuTest *test)
{
	struct authorized_data_with_aad auth;
	uint8_t data[4 - 1] = {0};
	size_t length = sizeof (data);
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length, &out_aad,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_payload_too_short (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, 4 + token_length,
		&out_aad, &out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length - 1, &out_aad,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_payload_too_short_no_auth_token (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length - 1, &out_aad,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_payload_too_short_no_aad (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *out_aad = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data (&auth.base_data, data, length - 1, &out_aad,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length_no_auth_token (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length_no_auth_token_no_aad (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length, NULL, aad_length,
		ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length_static_init (CuTest *test)
{
	struct authorized_data_with_aad auth = authorized_data_with_aad_static_init ();
	const size_t token_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_512, token_length,
		HASH_TESTING_FULL_BLOCK_1024, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length,
		&out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, aad_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length_null (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (NULL, data, length, &out_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, NULL, length,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length, NULL);
	CuAssertIntEquals (test, AUTH_DATA_INVALID_ARGUMENT, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length_no_header (CuTest *test)
{
	struct authorized_data_with_aad auth;
	uint8_t data[4 - 1] = {0};
	size_t length = sizeof (data);
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length_payload_too_short (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length - 1,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void
authorized_data_with_aad_test_get_authenticated_data_length_payload_too_short_no_auth_token (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length - 1,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_authenticated_data_length_payload_too_short_no_aad (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, NULL, sig_length, data, &length);

	status = auth.base_data.get_authenticated_data_length (&auth.base_data, data, length - 1,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, &signature, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length + aad_length], signature);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, &signature, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length + aad_length], signature);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_no_auth_token (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, &signature, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length + aad_length], signature);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_no_auth_token_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length, NULL, aad_length,
		ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, &signature, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length + aad_length], signature);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_static_init (CuTest *test)
{
	struct authorized_data_with_aad auth = authorized_data_with_aad_static_init ();
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC384_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC384_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, &signature, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &data[4 + token_length + aad_length], signature);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_null (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature (NULL, data, length, &signature, &out_length);
	CuAssertIntEquals (test, AUTH_SIGNATURE_INVALID_ARGUMENT, status);

	status = auth.base_sig.get_signature (&auth.base_sig, NULL, length, &signature, &out_length);
	CuAssertIntEquals (test, AUTH_SIGNATURE_INVALID_ARGUMENT, status);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, NULL, &out_length);
	CuAssertIntEquals (test, AUTH_SIGNATURE_INVALID_ARGUMENT, status);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, &signature, NULL);
	CuAssertIntEquals (test, AUTH_SIGNATURE_INVALID_ARGUMENT, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_no_header (CuTest *test)
{
	struct authorized_data_with_aad auth;
	uint8_t data[4 - 1] = {0};
	size_t length = sizeof (data);
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, &signature, &out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_no_signature (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length, &signature, &out_length);
	CuAssertIntEquals (test, AUTH_SIGNATURE_NO_SIGNATURE, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_payload_too_short (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length - 1, &signature,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_payload_too_short_no_auth_token (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length - 1, &signature,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_payload_too_short_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	const uint8_t *signature = data;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, NULL, sig_length, data, &length);

	status = auth.base_sig.get_signature (&auth.base_sig, data, length - 1, &signature,
		&out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_no_auth_token (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (NULL, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_no_auth_token_no_aad (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_static_init (CuTest *test)
{
	struct authorized_data_with_aad auth = authorized_data_with_aad_static_init ();
	const size_t token_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t sig_length = ECC384_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_512, token_length,
		HASH_TESTING_FULL_BLOCK_1024, aad_length, ECC384_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sig_length, out_length);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_null (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = ECC_SIG_TEST_LEN;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (NULL, data, length, &out_length);
	CuAssertIntEquals (test, AUTH_SIGNATURE_INVALID_ARGUMENT, status);

	status = auth.base_sig.get_signature_length (&auth.base_sig, NULL, length, &out_length);
	CuAssertIntEquals (test, AUTH_SIGNATURE_INVALID_ARGUMENT, status);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length, NULL);
	CuAssertIntEquals (test, AUTH_SIGNATURE_INVALID_ARGUMENT, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_no_header (CuTest *test)
{
	struct authorized_data_with_aad auth;
	uint8_t data[4 - 1] = {0};
	size_t length = sizeof (data);
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length, &out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_no_signature (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length, &out_length);
	CuAssertIntEquals (test, AUTH_SIGNATURE_NO_SIGNATURE, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_payload_too_short (CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, NULL, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length - 1, &out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_payload_too_short_no_auth_token (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = 0;
	const size_t aad_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		HASH_TESTING_FULL_BLOCK_512, aad_length, ECC_SIGNATURE_TEST, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length - 1, &out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}

static void authorized_data_with_aad_test_get_signature_length_payload_too_short_no_aad (
	CuTest *test)
{
	struct authorized_data_with_aad auth;
	const size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t aad_length = 0;
	const size_t sig_length = 0;
	uint8_t data[4 + token_length + aad_length + sig_length];
	size_t length;
	int status;
	size_t out_length = 0xaa;

	TEST_START;

	status = authorized_data_with_aad_init (&auth);
	CuAssertIntEquals (test, 0, status);

	authorized_data_with_aad_testing_construct_payload (HASH_TESTING_FULL_BLOCK_1024, token_length,
		NULL, aad_length, NULL, sig_length, data, &length);

	status = auth.base_sig.get_signature_length (&auth.base_sig, data, length - 1, &out_length);
	CuAssertIntEquals (test, AUTH_DATA_BAD, status);

	authorized_data_with_aad_release (&auth);
}


// *INDENT-OFF*
TEST_SUITE_START (authorized_data_with_aad);

TEST (authorized_data_with_aad_test_init);
TEST (authorized_data_with_aad_test_init_null);
TEST (authorized_data_with_aad_test_static_init);
TEST (authorized_data_with_aad_test_release_null);
TEST (authorized_data_with_aad_test_get_token_offset);
TEST (authorized_data_with_aad_test_get_token_offset_no_aad);
TEST (authorized_data_with_aad_test_get_token_offset_no_auth_token);
TEST (authorized_data_with_aad_test_get_token_offset_no_auth_token_no_aad);
TEST (authorized_data_with_aad_test_get_token_offset_static_init);
TEST (authorized_data_with_aad_test_get_token_offset_null);
TEST (authorized_data_with_aad_test_get_token_offset_no_header);
TEST (authorized_data_with_aad_test_get_token_offset_payload_too_short);
TEST (authorized_data_with_aad_test_get_token_offset_payload_too_short_no_auth_token);
TEST (authorized_data_with_aad_test_get_token_offset_payload_too_short_no_aad);
TEST (authorized_data_with_aad_test_get_authenticated_data);
TEST (authorized_data_with_aad_test_get_authenticated_data_no_aad);
TEST (authorized_data_with_aad_test_get_authenticated_data_no_auth_token);
TEST (authorized_data_with_aad_test_get_authenticated_data_no_auth_token_no_aad);
TEST (authorized_data_with_aad_test_get_authenticated_data_no_signature);
TEST (authorized_data_with_aad_test_get_authenticated_data_static_init);
TEST (authorized_data_with_aad_test_get_authenticated_data_null);
TEST (authorized_data_with_aad_test_get_authenticated_data_no_header);
TEST (authorized_data_with_aad_test_get_authenticated_data_payload_too_short);
TEST (authorized_data_with_aad_test_get_authenticated_data_payload_too_short_no_auth_token);
TEST (authorized_data_with_aad_test_get_authenticated_data_payload_too_short_no_aad);
TEST (authorized_data_with_aad_test_get_authenticated_data_length);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_no_aad);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_no_auth_token);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_no_auth_token_no_aad);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_static_init);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_null);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_no_header);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_payload_too_short);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_payload_too_short_no_auth_token);
TEST (authorized_data_with_aad_test_get_authenticated_data_length_payload_too_short_no_aad);
TEST (authorized_data_with_aad_test_get_signature);
TEST (authorized_data_with_aad_test_get_signature_no_aad);
TEST (authorized_data_with_aad_test_get_signature_no_auth_token);
TEST (authorized_data_with_aad_test_get_signature_no_auth_token_no_aad);
TEST (authorized_data_with_aad_test_get_signature_static_init);
TEST (authorized_data_with_aad_test_get_signature_null);
TEST (authorized_data_with_aad_test_get_signature_no_header);
TEST (authorized_data_with_aad_test_get_signature_no_signature);
TEST (authorized_data_with_aad_test_get_signature_payload_too_short);
TEST (authorized_data_with_aad_test_get_signature_payload_too_short_no_auth_token);
TEST (authorized_data_with_aad_test_get_signature_payload_too_short_no_aad);
TEST (authorized_data_with_aad_test_get_signature_length);
TEST (authorized_data_with_aad_test_get_signature_length_no_aad);
TEST (authorized_data_with_aad_test_get_signature_length_no_auth_token);
TEST (authorized_data_with_aad_test_get_signature_length_no_auth_token_no_aad);
TEST (authorized_data_with_aad_test_get_signature_length_static_init);
TEST (authorized_data_with_aad_test_get_signature_length_null);
TEST (authorized_data_with_aad_test_get_signature_length_no_header);
TEST (authorized_data_with_aad_test_get_signature_length_no_signature);
TEST (authorized_data_with_aad_test_get_signature_length_payload_too_short);
TEST (authorized_data_with_aad_test_get_signature_length_payload_too_short_no_auth_token);
TEST (authorized_data_with_aad_test_get_signature_length_payload_too_short_no_aad);

TEST_SUITE_END;
// *INDENT-ON*
