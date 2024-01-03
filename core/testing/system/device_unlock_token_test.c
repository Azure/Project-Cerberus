// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "asn1/asn1_util.h"
#include "system/device_unlock_token.h"
#include "system/device_unlock_token_static.h"
#include "testing/mock/cmd_interface/cmd_device_mock.h"
#include "testing/mock/common/auth_token_mock.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("device_unlock_token");


/**
 * A device UUID value for use in test tokens.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_UUID[16] = {
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

const size_t DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN = sizeof (DEVICE_UNLOCK_TOKEN_TESTING_UUID);

/**
 * A device UUID value padding with zeros for use in test tokens.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED[16] = {
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

const size_t DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED_LEN = 8;	/* Only represent the valid data. */

/**
 * An unlock counter value for use in test tokens.  The counter represents an unlocked state.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED[] = {
	0xff,0xff,0x1f,0x00,0x00,0x00,0x00,0x00
};

/**
 * An unlock counter value for use in test tokens.  The counter represents the locked value
 * corresponding to DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LOCKED[] = {
	0xff,0xff,0x3f,0x00,0x00,0x00,0x00,0x00
};

/**
 * An unlock counter value for use in test tokens.  The counter represents the unlocked value
 * corresponding to DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LOCKED.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LOCKED_UNLOCKED[] = {
	0xff,0xff,0x7f,0x00,0x00,0x00,0x00,0x00
};

const size_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN =
	sizeof (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED);

/**
 * An unlock counter value for use in test tokens.  The counter represents a locked state.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED[] = {
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

/**
 * An unlock counter value for use in test tokens.  The counter represents the unlocked value
 * corresponding to DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_UNLOCKED[] = {
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

const size_t DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN =
	sizeof (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED);

/**
 * A nonce for use in test tokens.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_NONCE[32] = {
	0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
	0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};

const size_t DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN = sizeof (DEVICE_UNLOCK_TOKEN_TESTING_NONCE);

/**
 * An unlock policy to use for test authorized data.
 */
const uint8_t DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY[] = {
	0x6d,0x91,0x51,0xb9,0xf8,0x84,0xf5,0x95,0x51,0xf4,0x76,0xe5,0x25,0x69,0x86,0xa6,
	0x53,0xd4,0xa4,0x68,0xf2,0x81,0x41,0xed,0x95,0x47,0x21,0xf2,0xcd,0x02,0x05,0x4d,
	0xf0,0x43,0x87,0x38,0x19,0x45,0x45,0xed,0x70,0x23,0x41,0x73,0xac,0x49,0x88,0xb7
};

const size_t DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN =
	sizeof (DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY);


/**
 * Dependencies for testing the device unlock token handler.
 */
struct device_unlock_token_testing {
	struct auth_token_mock auth;			/**< Mock for authorization token handling. */
	struct cmd_device_mock uuid;			/**< Mock for UUID retrieval. */
	struct device_unlock_token test;		/**< Unlock token handler under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param token Testing dependencies to initialize.
 */
static void device_unlock_token_testing_init_dependencies (CuTest *test,
	struct device_unlock_token_testing *token)
{
	int status;

	status = auth_token_mock_init (&token->auth);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&token->uuid);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param token Testing dependencies to release.
 */
static void device_unlock_token_testing_release_dependencies (CuTest *test,
	struct device_unlock_token_testing *token)
{
	int status;

	status = auth_token_mock_validate_and_release (&token->auth);
	status |= cmd_device_mock_validate_and_release (&token->uuid);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a device unlock token handler for testing.
 *
 * @param test The test framework.
 * @param token Testing components to initialize.
 * @param oid The OID to use in the tokens.
 * @param oid_length Length of the OID.
 * @param counter_length Length of the unlock counter data.
 * @param auth_hash Hash algorithm for authentication.
 */
static void device_unlock_token_testing_init (CuTest *test,
	struct device_unlock_token_testing *token, const uint8_t *oid, size_t oid_length,
	size_t counter_length, enum hash_type auth_hash)
{
	int status;

	device_unlock_token_testing_init_dependencies (test, token);

	status = device_unlock_token_init (&token->test, &token->auth.base, &token->uuid.base, oid,
		oid_length, counter_length, auth_hash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param token Testing components to release.
 * @param test_token The test handler to release.
 */
static void device_unlock_token_testing_release (CuTest *test,
	struct device_unlock_token_testing *token, struct device_unlock_token *test_token)
{
	device_unlock_token_release (test_token);
	device_unlock_token_testing_release_dependencies (test, token);
}

/**
 * Build an unlock token for testing.
 *
 * @param oid The raw OID to use in the token.  This will be DER encoded.
 * @param oid_len Length of the OID data.
 * @param uuid The UUID to use in the token.  This will always be 16 bytes.
 * @param counter The unlock counter to use in the token.
 * @param counter_len Length of the unlock counter.
 * @param nonce The nonce to use in the token.  This will always be 32 bytes.
 * @param signature The token signature.
 * @param sig_len Length of the token signature.
 * @param token Output for the constructed token.  This must be large enough for all the token data.
 */
void device_unlock_token_testing_build_token (const uint8_t *oid, size_t oid_len,
	const uint8_t *uuid, const uint8_t *counter, size_t counter_len, const uint8_t *nonce,
	const uint8_t *signature, size_t sig_len, uint8_t *token)
{
	uint8_t *pos = token;

	/* DER encode OID */
	*pos++ = 0x06;
	*pos++ = oid_len;

	memcpy (pos, oid, oid_len);
	pos += oid_len;

	*(uint16_t*) pos = 1;
	pos += 2;

	memcpy (pos, uuid, DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN);
	pos += DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN;

	*pos++ = counter_len;

	memcpy (pos, counter, counter_len);
	pos += counter_len;

	memcpy (pos, nonce, DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN);
	pos += DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN;

	memcpy (pos, signature, sig_len);
}

/**
 * Build authorized unlock data for testing.
 *
 * @param token The unlock token data to include.
 * @param token_len Length of the token data.
 * @param policy The unlock policy data to include.
 * @param policy_len Length of the unlock policy.
 * @param signature Authorization signature.
 * @param sig_len Length of the signature.
 * @param auth_data Output for the constructed data. This must be large enough for all the included
 * data.
 *
 * @return Length of the authorized data.
 */
size_t device_unlock_token_testing_build_authorized_data (const uint8_t *token, size_t token_len,
	const uint8_t *policy, size_t policy_len, const uint8_t *signature, size_t sig_len,
	uint8_t *auth_data)
{
	uint8_t *pos = auth_data;

	*(uint16_t*) pos = token_len;
	pos += 2;

	memcpy (pos, token, token_len);
	pos += token_len;

	*(uint16_t*) pos = policy_len;
	pos += 2;

	memcpy (pos, policy, policy_len);
	pos += policy_len;

	memcpy (pos, signature, sig_len);

	return 2 + token_len + 2 + policy_len + sig_len;
}

/**
 * Allocate memory and build an unlock token.  The unlock counter can be specified, but the rest of
 * token data will be statically defined using the following:
 * - RIOT_CORE_DEVICE_ID_OID
 * - DEVICE_UNLOCK_TOKEN_TESTING_UUID
 * - DEVICE_UNLOCK_TOKEN_TESTING_NONCE
 * - ECC384_SIGNATURE_TEST (for token signature)
 *
 * @param test The test framework.
 * @param counter The unlock counter to use in the token.
 * @param counter_len Length of the unlock counter.
 * @param token Output for the dynamically allocated unlock token.  This must be freed by the
 * caller.
 * @param length Output for the length of the unlock token.
 * @param context_length Optional output for the length of the unlock context data in the token.
 */
void device_unlock_token_testing_allocate_token (CuTest *test, const uint8_t *counter,
	size_t counter_len, uint8_t **token, size_t *length, size_t *context_length)
{
	size_t token_context = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + counter_len;
	size_t token_length = token_context + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;

	*token = platform_malloc (token_length);
	CuAssertPtrNotNull (test, token);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, counter, counter_len, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, *token);

	*length = token_length;

	if (context_length) {
		*context_length = token_context;
	}
}

/**
 * Allocate memory and build authorized unlock data.  The unlock counter can be specified, but the
 * rest of the unlock data will be statically defined using the following:
 * - RIOT_CORE_DEVICE_ID_OID
 * - DEVICE_UNLOCK_TOKEN_TESTING_UUID
 * - DEVICE_UNLOCK_TOKEN_TESTING_NONCE
 * - ECC384_SIGNATURE_TEST (for token signature)
 * - DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY
 * - ECC384_SIGNATURE_TEST2 (for unlock data signature)
 *
 * @param test The test framework.
 * @param counter The unlock counter to use in the token.
 * @param counter_len Length of the unlock counter.
 * @param extra_space The amount of additional space to allocate after the unlock data.  This can be
 * 0 if no extra space is needed.
 * @param auth_data Output for the dynamically allocated authorized unlock data.  This must be freed
 * by the caller.
 * @param length Output for the length of the unlock data, excluding extra allocated space.
 * @param token_offset Optional output for the offset in the data where the token data starts.
 * @param policy_offset Optional output for the offset in the data where the unlock policy data
 * starts.
 */
void device_unlock_token_testing_allocate_authorized_data (CuTest *test, const uint8_t *counter,
	size_t counter_len, size_t extra_space, uint8_t **auth_data, size_t *length,
	size_t *token_offset, size_t *policy_offset)
{
	size_t auth_data_length = 2 + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN;
	uint8_t *token;
	size_t token_length;

	device_unlock_token_testing_allocate_token (test, counter, counter_len, &token, &token_length,
		NULL);
	auth_data_length += token_length;

	*auth_data = platform_malloc (auth_data_length + extra_space);
	CuAssertPtrNotNull (test, *auth_data);

	device_unlock_token_testing_build_authorized_data (token, token_length,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC384_SIG_TEST2_LEN, *auth_data);

	*length = auth_data_length;

	if (token_offset) {
		*token_offset = 2;
	}

	if (policy_offset) {
		*policy_offset = 2 + token_length + 2;
	}

	platform_free (token);
}


/*******************
 * Test cases
 *******************/

static void device_unlock_token_test_init (CuTest *test)
{
	struct device_unlock_token_testing token;
	int status;

	TEST_START;

	device_unlock_token_testing_init_dependencies (test, &token);

	status = device_unlock_token_init (&token.test, &token.auth.base, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_init_null (CuTest *test)
{
	struct device_unlock_token_testing token;
	int status;

	TEST_START;

	device_unlock_token_testing_init_dependencies (test, &token);

	status = device_unlock_token_init (NULL, &token.auth.base, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_init (&token.test, NULL, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_init (&token.test, &token.auth.base, NULL,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_init (&token.test, &token.auth.base, &token.uuid.base,
		NULL, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_init (&token.test, &token.auth.base, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_init (&token.test, &token.auth.base, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		0, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	device_unlock_token_testing_release_dependencies (test, &token);
}

static void device_unlock_token_test_static_init (CuTest *test)
{
	struct device_unlock_token_testing token;
	struct device_unlock_token test_static = device_unlock_token_static_init (&token.auth.base,
		&token.uuid.base, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);

	TEST_START;

	device_unlock_token_testing_init_dependencies (test, &token);

	device_unlock_token_testing_release (test, &token, &test_static);
}

static void device_unlock_token_test_release_null (CuTest *test)
{
	TEST_START;

	device_unlock_token_release (NULL);
}

static void device_unlock_token_test_get_counter_length (CuTest *test)
{
	struct device_unlock_token_testing token;
	size_t length;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	length = device_unlock_token_get_counter_length (&token.test);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, length);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_get_counter_length_longer_counter (CuTest *test)
{
	struct device_unlock_token_testing token;
	size_t length;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN,
		HASH_TYPE_SHA256);

	length = device_unlock_token_get_counter_length (&token.test);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, length);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_get_counter_length_static_init (CuTest *test)
{
	struct device_unlock_token_testing token;
	struct device_unlock_token test_static = device_unlock_token_static_init (&token.auth.base,
		&token.uuid.base, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	size_t length;

	TEST_START;

	device_unlock_token_testing_init_dependencies (test, &token);

	length = device_unlock_token_get_counter_length (&test_static);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, length);

	device_unlock_token_testing_release (test, &token, &test_static);
}

static void device_unlock_token_test_get_counter_length_null (CuTest *test)
{
	struct device_unlock_token_testing token;
	size_t length;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	length = device_unlock_token_get_counter_length (NULL);
	CuAssertIntEquals (test, 0, length);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	const uint8_t *token_data_ptr = token_data;
	int status;
	uint8_t out[sizeof (token_data) * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.auth.mock, token.auth.base.new_token, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token_data, context_length), MOCK_ARG (context_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&token.auth.mock, 2, &token_data_ptr, sizeof (token_data_ptr),
		-1);
	status |= mock_expect_output (&token.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (token_data), status);

	status = testing_validate_array (token_data, out, sizeof (token_data));
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_longer_oid (CuTest *test)
{
	struct device_unlock_token_testing token;
	uint8_t oid[RIOT_CORE_DEVICE_ID_OID_LEN + 4];
	const size_t context_length = 2 + sizeof (oid) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	const uint8_t *token_data_ptr = token_data;
	int status;
	uint8_t out[sizeof (token_data) * 2];

	TEST_START;

	memcpy (oid, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN);
	oid[RIOT_CORE_DEVICE_ID_OID_LEN] = 0x11;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 1] = 0x22;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 2] = 0x33;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 3] = 0x44;

	device_unlock_token_testing_init (test, &token, oid, sizeof (oid),
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (oid, sizeof (oid), DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.auth.mock, token.auth.base.new_token, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token_data, context_length), MOCK_ARG (context_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&token.auth.mock, 2, &token_data_ptr, sizeof (token_data_ptr),
		-1);
	status |= mock_expect_output (&token.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (token_data), status);

	status = testing_validate_array (token_data, out, sizeof (token_data));
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_longer_counter (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	const uint8_t *token_data_ptr = token_data;
	int status;
	uint8_t out[sizeof (token_data) * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.auth.mock, token.auth.base.new_token, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token_data, context_length), MOCK_ARG (context_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&token.auth.mock, 2, &token_data_ptr, sizeof (token_data_ptr),
		-1);
	status |= mock_expect_output (&token.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_generate (&token.test, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_LOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (token_data), status);

	status = testing_validate_array (token_data, out, sizeof (token_data));
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_short_uuid (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	const uint8_t *token_data_ptr = token_data;
	int status;
	uint8_t out[sizeof (token_data) * 2];

	TEST_START;

	memset (out, 0xff, sizeof (out));

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED_LEN, 1);

	status |= mock_expect (&token.auth.mock, token.auth.base.new_token, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token_data, context_length), MOCK_ARG (context_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&token.auth.mock, 2, &token_data_ptr, sizeof (token_data_ptr),
		-1);
	status |= mock_expect_output (&token.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (token_data), status);

	status = testing_validate_array (token_data, out, sizeof (token_data));
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_static_init (CuTest *test)
{
	struct device_unlock_token_testing token;
	struct device_unlock_token test_static = device_unlock_token_static_init (&token.auth.base,
		&token.uuid.base, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	const uint8_t *token_data_ptr = token_data;
	int status;
	uint8_t out[sizeof (token_data) * 2];

	TEST_START;

	device_unlock_token_testing_init_dependencies (test, &token);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.auth.mock, token.auth.base.new_token, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token_data, context_length), MOCK_ARG (context_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&token.auth.mock, 2, &token_data_ptr, sizeof (token_data_ptr),
		-1);
	status |= mock_expect_output (&token.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_generate (&test_static,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (token_data), status);

	status = testing_validate_array (token_data, out, sizeof (token_data));
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &test_static);
}

static void device_unlock_token_test_generate_null (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	int status;
	uint8_t out[token_length * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	status = device_unlock_token_generate (NULL,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_generate (&token.test,
		NULL,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, NULL, sizeof (out));
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_small_counter (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	int status;
	uint8_t out[token_length * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN - 1, out, context_length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_COUNTER, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_large_counter (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	int status;
	uint8_t out[token_length * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + 1, out, context_length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_COUNTER, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_small_buffer_less_than_context_data (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	int status;
	uint8_t out[token_length * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, context_length - 1);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_SMALL_BUFFER, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_small_buffer_less_than_token_data (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	const uint8_t *token_data_ptr = token_data;
	int status;
	uint8_t out[sizeof (token_data) * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.auth.mock, token.auth.base.new_token, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (token_data, context_length), MOCK_ARG (context_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&token.auth.mock, 2, &token_data_ptr, sizeof (token_data_ptr),
		-1);
	status |= mock_expect_output (&token.auth.mock, 3, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, token_length - 1);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_SMALL_BUFFER, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_oid_too_long (CuTest *test)
{
	struct device_unlock_token_testing token;
	uint8_t oid[128];
	const size_t context_length = 2 + sizeof (oid) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	int status;
	uint8_t out[token_length * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, oid, sizeof (oid),
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, ASN1_UTIL_OUT_OF_RANGE, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_uuid_error (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	int status;
	uint8_t out[sizeof (token_data) * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		CMD_DEVICE_UUID_BUFFER_TOO_SMALL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, CMD_DEVICE_UUID_BUFFER_TOO_SMALL, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_generate_token_error (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	int status;
	uint8_t out[sizeof (token_data) * 2];

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.auth.mock, token.auth.base.new_token, &token.auth,
		AUTH_TOKEN_BUILD_FAILED, MOCK_ARG_PTR_CONTAINS (token_data, context_length),
		MOCK_ARG (context_length), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_generate (&token.test,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, out, sizeof (out));
	CuAssertIntEquals (test, AUTH_TOKEN_BUILD_FAILED, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	memset (auth_data, 0, auth_length);

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = mock_expect (&token.auth.mock, token.auth.base.verify_data, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, auth_length), MOCK_ARG (auth_length), MOCK_ARG (2),
		MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN), MOCK_ARG (HASH_TYPE_SHA256));
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_authenicate (&token.test, auth_data, auth_length);
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_sha384 (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	memset (auth_data, 0, auth_length);

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA384);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = mock_expect (&token.auth.mock, token.auth.base.verify_data, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, auth_length), MOCK_ARG (auth_length), MOCK_ARG (2),
		MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN), MOCK_ARG (HASH_TYPE_SHA384));
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_authenicate (&token.test, auth_data, auth_length);
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_longer_policy (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t policy_length = DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + 10;
	const size_t auth_length = 2 + token_length + 2 + policy_length + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t unlock_policy[policy_length];
	uint8_t auth_data[auth_length];
	int status;
	size_t i;

	TEST_START;

	memset (auth_data, 0, auth_length);
	for (i = 0; i < sizeof (unlock_policy); i++) {
		unlock_policy[i] = ~i;
	}

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		unlock_policy, policy_length, ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = mock_expect (&token.auth.mock, token.auth.base.verify_data, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, auth_length), MOCK_ARG (auth_length), MOCK_ARG (2),
		MOCK_ARG (2 + policy_length), MOCK_ARG (HASH_TYPE_SHA256));
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_authenicate (&token.test, auth_data, auth_length);
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_static_init (CuTest *test)
{
	struct device_unlock_token_testing token;
	struct device_unlock_token test_static = device_unlock_token_static_init (&token.auth.base,
		&token.uuid.base, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	memset (auth_data, 0, auth_length);

	device_unlock_token_testing_init_dependencies (test, &token);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = mock_expect (&token.auth.mock, token.auth.base.verify_data, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, auth_length), MOCK_ARG (auth_length), MOCK_ARG (2),
		MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN), MOCK_ARG (HASH_TYPE_SHA256));
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_authenicate (&test_static, auth_data, auth_length);
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &test_static);
}

static void device_unlock_token_test_authenticate_static_init_sha384 (CuTest *test)
{
	struct device_unlock_token_testing token;
	struct device_unlock_token test_static = device_unlock_token_static_init (&token.auth.base,
		&token.uuid.base, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA384);
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	memset (auth_data, 0, auth_length);

	device_unlock_token_testing_init_dependencies (test, &token);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = mock_expect (&token.auth.mock, token.auth.base.verify_data, &token.auth, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, auth_length), MOCK_ARG (auth_length), MOCK_ARG (2),
		MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN), MOCK_ARG (HASH_TYPE_SHA384));
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_authenicate (&test_static, auth_data, auth_length);
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &test_static);
}

static void device_unlock_token_test_authenticate_null (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_authenicate (NULL, auth_data, auth_length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_authenicate (&token.test, NULL, auth_length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_short_data_no_token_length (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_authenicate (&token.test, auth_data, 0);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	status = device_unlock_token_authenicate (&token.test, auth_data, 1);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_short_data_token (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_authenicate (&token.test, auth_data, 2 + token_length - 1);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_short_data_policy_length (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_authenicate (&token.test, auth_data, 2 + token_length + 2 - 1);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_short_data_policy (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_authenicate (&token.test, auth_data,
		2 + token_length + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN - 1);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_verify_error (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	memset (auth_data, 0, auth_length);

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = mock_expect (&token.auth.mock, token.auth.base.verify_data, &token.auth,
		AUTH_TOKEN_CHECK_FAILED, MOCK_ARG_PTR_CONTAINS (auth_data, auth_length),
		MOCK_ARG (auth_length), MOCK_ARG (2),
		MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN), MOCK_ARG (HASH_TYPE_SHA256));
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_authenicate (&token.test, auth_data, auth_length);
	CuAssertIntEquals (test, AUTH_TOKEN_CHECK_FAILED, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_authenticate_token_not_valid (CuTest *test)
{
	struct device_unlock_token_testing token;
	const size_t context_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 + DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN;
	const size_t token_length = context_length + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN;
	const size_t auth_length = 2 + token_length + 2 +
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + ECC384_SIG_TEST2_LEN;
	uint8_t token_data[token_length];
	uint8_t auth_data[auth_length];
	int status;

	TEST_START;

	memset (auth_data, 0, auth_length);

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	device_unlock_token_testing_build_authorized_data (token_data, sizeof (token_data),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = mock_expect (&token.auth.mock, token.auth.base.verify_data, &token.auth,
		AUTH_TOKEN_NOT_VALID, MOCK_ARG_PTR_CONTAINS (auth_data, auth_length),
		MOCK_ARG (auth_length), MOCK_ARG (2),
		MOCK_ARG (2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN), MOCK_ARG (HASH_TYPE_SHA256));
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_authenicate (&token.test, auth_data, auth_length);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_invalidate (CuTest *test)
{
	struct device_unlock_token_testing token;
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	status = mock_expect (&token.auth.mock, token.auth.base.invalidate, &token.auth, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_invalidate (&token.test);
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_invalidate_static_init (CuTest *test)
{
	struct device_unlock_token_testing token;
	struct device_unlock_token test_static = device_unlock_token_static_init (&token.auth.base,
		&token.uuid.base, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, HASH_TYPE_SHA256);
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	status = mock_expect (&token.auth.mock, token.auth.base.invalidate, &token.auth, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_invalidate (&test_static);
	CuAssertIntEquals (test, 0, status);

	device_unlock_token_testing_release (test, &token, &test_static);
}

static void device_unlock_token_test_invalidate_null (CuTest *test)
{
	struct device_unlock_token_testing token;
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	status = device_unlock_token_invalidate (NULL);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_invalidate_error (CuTest *test)
{
	struct device_unlock_token_testing token;
	int status;

	TEST_START;

	device_unlock_token_testing_init (test, &token, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		HASH_TYPE_SHA256);

	status = mock_expect (&token.auth.mock, token.auth.base.invalidate, &token.auth,
		AUTH_TOKEN_INVALIDATE_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_unlock_token_invalidate (&token.test);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALIDATE_FAILED, status);

	device_unlock_token_testing_release (test, &token, &token.test);
}

static void device_unlock_token_test_get_unlock_counter (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, sizeof (auth_data), &counter,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, counter);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, length);

	status = testing_validate_array (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED, counter, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_unlock_counter_longer_oid (CuTest *test)
{
	uint8_t oid[RIOT_CORE_DEVICE_ID_OID_LEN + 4];
	uint8_t token[2 + sizeof (oid) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	memcpy (oid, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN);
	oid[RIOT_CORE_DEVICE_ID_OID_LEN] = 0x11;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 1] = 0x22;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 2] = 0x33;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 3] = 0x44;

	device_unlock_token_testing_build_token (oid, sizeof (oid), DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, sizeof (auth_data), &counter,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, counter);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, length);

	status = testing_validate_array (DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED, counter, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_unlock_counter_longer_counter (CuTest *test)
{
	uint8_t unlock_counter[DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN * 4];
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		sizeof (unlock_counter) + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	memset (unlock_counter, 0xff, sizeof (unlock_counter));
	memcpy (unlock_counter, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, unlock_counter, sizeof (unlock_counter),
		DEVICE_UNLOCK_TOKEN_TESTING_NONCE, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, sizeof (auth_data), &counter,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, counter);
	CuAssertIntEquals (test, sizeof (unlock_counter), length);

	status = testing_validate_array (unlock_counter, counter, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_unlock_counter_null (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (NULL, sizeof (auth_data), &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_get_unlock_counter (auth_data, sizeof (auth_data), NULL, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_get_unlock_counter (auth_data, sizeof (auth_data), &counter, NULL);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_no_token_length (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, 0, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	status = device_unlock_token_get_unlock_counter (auth_data, 1, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_token (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, 2 + sizeof (token) - 1, &counter,
		&length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_no_der (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	auth_length = device_unlock_token_testing_build_authorized_data (token, 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_oid_more_than_length (
	CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token, 2 + 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_oid (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN - 1, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN, ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN,
		auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_version (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 - 1, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN, ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN,
		auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_uuid (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN - 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_counter_len (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 - 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_no_counter (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_counter_short_data_counter (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *counter = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
			DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN - 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_counter (auth_data, auth_length, &counter, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, sizeof (auth_data), &nonce, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN, length);

	status = testing_validate_array (DEVICE_UNLOCK_TOKEN_TESTING_NONCE, nonce, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_nonce_longer_oid (CuTest *test)
{
	uint8_t oid[RIOT_CORE_DEVICE_ID_OID_LEN + 4];
	uint8_t token[2 + sizeof (oid) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	memcpy (oid, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN);
	oid[RIOT_CORE_DEVICE_ID_OID_LEN] = 0x11;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 1] = 0x22;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 2] = 0x33;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 3] = 0x44;

	device_unlock_token_testing_build_token (oid, sizeof (oid), DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, sizeof (auth_data), &nonce, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN, length);

	status = testing_validate_array (DEVICE_UNLOCK_TOKEN_TESTING_NONCE, nonce, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_nonce_longer_counter (CuTest *test)
{
	uint8_t unlock_counter[DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN * 4];
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		sizeof (unlock_counter) + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	memset (unlock_counter, 0xff, sizeof (unlock_counter));
	memcpy (unlock_counter, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN);

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, unlock_counter, sizeof (unlock_counter),
		DEVICE_UNLOCK_TOKEN_TESTING_NONCE, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, sizeof (auth_data), &nonce, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN, length);

	status = testing_validate_array (DEVICE_UNLOCK_TOKEN_TESTING_NONCE, nonce, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_nonce_null (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (NULL, sizeof (auth_data), &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_get_nonce (auth_data, sizeof (auth_data), NULL, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_get_nonce (auth_data, sizeof (auth_data), &nonce, NULL);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);
}

static void device_unlock_token_test_get_nonce_short_data_no_token_length (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, 0, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	status = device_unlock_token_get_nonce (auth_data, 1, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_token (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, 2 + sizeof (token) - 1, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_no_der (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token, 0,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	auth_length = device_unlock_token_testing_build_authorized_data (token, 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_oid_more_than_length (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token, 2 + 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_oid (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN - 1, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN, ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN,
		auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_version (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 - 1, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN, ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN,
		auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_uuid (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN - 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_counter_len (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 - 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_no_counter (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_counter (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
			DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN - 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_no_nonce (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
			DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_nonce_short_data_nonce (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	size_t auth_length;
	int status;
	const uint8_t *nonce = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	auth_length = device_unlock_token_testing_build_authorized_data (token,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
			DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN +
			DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN - 1,
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_nonce (auth_data, auth_length, &nonce, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_policy (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (auth_data, sizeof (auth_data), &policy,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, policy);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN, length);

	status = testing_validate_array (DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, policy, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_unlock_policy_longer_token (CuTest *test)
{
	uint8_t oid[RIOT_CORE_DEVICE_ID_OID_LEN + 4];
	uint8_t token[2 + sizeof (oid) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;

	TEST_START;

	memcpy (oid, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN);
	oid[RIOT_CORE_DEVICE_ID_OID_LEN] = 0x11;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 1] = 0x22;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 2] = 0x33;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 3] = 0x44;

	device_unlock_token_testing_build_token (oid, sizeof (oid), DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (auth_data, sizeof (auth_data), &policy,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, policy);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN, length);

	status = testing_validate_array (DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, policy, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_unlock_policy_longer_policy (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t unlock_policy[DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN + 10];
	uint8_t auth_data[2 + sizeof (token) + 2 + sizeof (unlock_policy) + ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (unlock_policy); i++) {
		unlock_policy[i] = ~i;
	}

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token), unlock_policy,
		sizeof (unlock_policy), ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (auth_data, sizeof (auth_data), &policy,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, policy);
	CuAssertIntEquals (test, sizeof (unlock_policy), length);

	status = testing_validate_array (unlock_policy, policy, length);
	CuAssertIntEquals (test, 0, status);
}

static void device_unlock_token_test_get_unlock_policy_null (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (NULL, sizeof (auth_data), &policy,
		&length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_get_unlock_policy (auth_data, sizeof (auth_data), NULL,
		&length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = device_unlock_token_get_unlock_policy (auth_data, sizeof (auth_data), &policy,
		NULL);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT, status);
}

static void device_unlock_token_test_get_unlock_policy_short_data_no_token_length (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (auth_data, 0, &policy, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);

	status = device_unlock_token_get_unlock_policy (auth_data, 1, &policy, &length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_policy_short_data_token (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (auth_data, 2 + sizeof (token) - 1, &policy,
		&length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_policy_short_data_policy_length (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (auth_data, 2 + sizeof (token) + 2 - 1, &policy,
		&length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_policy_short_data_no_policy (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (auth_data, 2 + sizeof (token) + 2, &policy,
		&length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}

static void device_unlock_token_test_get_unlock_policy_short_data_policy (CuTest *test)
{
	uint8_t token[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + 1 +
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN + DEVICE_UNLOCK_TOKEN_TESTING_NONCE_LEN +
		ECC384_SIG_TEST_LEN];
	uint8_t auth_data[2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN +
		ECC384_SIG_TEST2_LEN];
	int status;
	const uint8_t *policy = NULL;
	size_t length;

	TEST_START;

	device_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED,
		DEVICE_UNLOCK_TOKEN_TESTING_COUNTER_UNLOCKED_LEN, DEVICE_UNLOCK_TOKEN_TESTING_NONCE,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token);

	device_unlock_token_testing_build_authorized_data (token, sizeof (token),
		DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY, DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN,
		ECC384_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, auth_data);

	status = device_unlock_token_get_unlock_policy (auth_data,
		2 + sizeof (token) + 2 + DEVICE_UNLOCK_TOKEN_TESTING_UNLOCK_POLICY_LEN - 1, &policy,
			&length);
	CuAssertIntEquals (test, DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA, status);
}


TEST_SUITE_START (device_unlock_token);

TEST (device_unlock_token_test_init);
TEST (device_unlock_token_test_init_null);
TEST (device_unlock_token_test_static_init);
TEST (device_unlock_token_test_release_null);
TEST (device_unlock_token_test_get_counter_length);
TEST (device_unlock_token_test_get_counter_length_longer_counter);
TEST (device_unlock_token_test_get_counter_length_static_init);
TEST (device_unlock_token_test_get_counter_length_null);
TEST (device_unlock_token_test_generate);
TEST (device_unlock_token_test_generate_longer_oid);
TEST (device_unlock_token_test_generate_longer_counter);
TEST (device_unlock_token_test_generate_short_uuid);
TEST (device_unlock_token_test_generate_static_init);
TEST (device_unlock_token_test_generate_null);
TEST (device_unlock_token_test_generate_small_counter);
TEST (device_unlock_token_test_generate_large_counter);
TEST (device_unlock_token_test_generate_small_buffer_less_than_context_data);
TEST (device_unlock_token_test_generate_small_buffer_less_than_token_data);
TEST (device_unlock_token_test_generate_oid_too_long);
TEST (device_unlock_token_test_generate_uuid_error);
TEST (device_unlock_token_test_generate_token_error);
TEST (device_unlock_token_test_authenticate);
TEST (device_unlock_token_test_authenticate_sha384);
TEST (device_unlock_token_test_authenticate_longer_policy);
TEST (device_unlock_token_test_authenticate_static_init);
TEST (device_unlock_token_test_authenticate_static_init_sha384);
TEST (device_unlock_token_test_authenticate_null);
TEST (device_unlock_token_test_authenticate_short_data_no_token_length);
TEST (device_unlock_token_test_authenticate_short_data_token);
TEST (device_unlock_token_test_authenticate_short_data_policy_length);
TEST (device_unlock_token_test_authenticate_short_data_policy);
TEST (device_unlock_token_test_authenticate_verify_error);
TEST (device_unlock_token_test_authenticate_token_not_valid);
TEST (device_unlock_token_test_invalidate);
TEST (device_unlock_token_test_invalidate_static_init);
TEST (device_unlock_token_test_invalidate_null);
TEST (device_unlock_token_test_invalidate_error);
TEST (device_unlock_token_test_get_unlock_counter);
TEST (device_unlock_token_test_get_unlock_counter_longer_oid);
TEST (device_unlock_token_test_get_unlock_counter_longer_counter);
TEST (device_unlock_token_test_get_unlock_counter_null);
TEST (device_unlock_token_test_get_unlock_counter_short_data_no_token_length);
TEST (device_unlock_token_test_get_unlock_counter_short_data_token);
TEST (device_unlock_token_test_get_unlock_counter_short_data_no_der);
TEST (device_unlock_token_test_get_unlock_counter_short_data_oid_more_than_length);
TEST (device_unlock_token_test_get_unlock_counter_short_data_oid);
TEST (device_unlock_token_test_get_unlock_counter_short_data_version);
TEST (device_unlock_token_test_get_unlock_counter_short_data_uuid);
TEST (device_unlock_token_test_get_unlock_counter_short_data_counter_len);
TEST (device_unlock_token_test_get_unlock_counter_short_data_no_counter);
TEST (device_unlock_token_test_get_unlock_counter_short_data_counter);
TEST (device_unlock_token_test_get_nonce);
TEST (device_unlock_token_test_get_nonce_longer_oid);
TEST (device_unlock_token_test_get_nonce_longer_counter);
TEST (device_unlock_token_test_get_nonce_null);
TEST (device_unlock_token_test_get_nonce_short_data_no_token_length);
TEST (device_unlock_token_test_get_nonce_short_data_token);
TEST (device_unlock_token_test_get_nonce_short_data_no_der);
TEST (device_unlock_token_test_get_nonce_short_data_oid_more_than_length);
TEST (device_unlock_token_test_get_nonce_short_data_oid);
TEST (device_unlock_token_test_get_nonce_short_data_version);
TEST (device_unlock_token_test_get_nonce_short_data_uuid);
TEST (device_unlock_token_test_get_nonce_short_data_counter_len);
TEST (device_unlock_token_test_get_nonce_short_data_no_counter);
TEST (device_unlock_token_test_get_nonce_short_data_counter);
TEST (device_unlock_token_test_get_nonce_short_data_no_nonce);
TEST (device_unlock_token_test_get_nonce_short_data_nonce);
TEST (device_unlock_token_test_get_unlock_policy);
TEST (device_unlock_token_test_get_unlock_policy_longer_token);
TEST (device_unlock_token_test_get_unlock_policy_longer_policy);
TEST (device_unlock_token_test_get_unlock_policy_null);
TEST (device_unlock_token_test_get_unlock_policy_short_data_no_token_length);
TEST (device_unlock_token_test_get_unlock_policy_short_data_token);
TEST (device_unlock_token_test_get_unlock_policy_short_data_policy_length);
TEST (device_unlock_token_test_get_unlock_policy_short_data_no_policy);
TEST (device_unlock_token_test_get_unlock_policy_short_data_policy);

TEST_SUITE_END;
