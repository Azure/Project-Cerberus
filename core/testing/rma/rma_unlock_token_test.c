// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/buffer_util.h"
#include "rma/rma_unlock_token.h"
#include "rma/rma_unlock_token_static.h"
#include "testing/mock/cmd_interface/cmd_device_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/riot/riot_core_testing.h"
#include "testing/system/device_unlock_token_testing.h"


TEST_SUITE_LABEL ("rma_unlock_token");


/**
 * Dependencies for testing the device unlock token handler.
 */
struct rma_unlock_token_testing {
	HASH_TESTING_ENGINE hash;						/**< Hash engine for testing. */
	struct hash_engine_mock hash_mock;				/**< Mock for the hash engine. */
	struct signature_verification_mock authority;	/**< Mock for authority signature verification. */
	struct cmd_device_mock uuid;					/**< Mock for UUID retrieval. */
	struct rma_unlock_token test;					/**< RMA token handler under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param token Testing dependencies to initialize.
 */
static void rma_unlock_token_testing_init_dependencies (CuTest *test,
	struct rma_unlock_token_testing *token)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&token->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&token->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&token->authority);
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
static void rma_unlock_token_testing_release_dependencies (CuTest *test,
	struct rma_unlock_token_testing *token)
{
	int status;

	status = hash_mock_validate_and_release (&token->hash_mock);
	status |= signature_verification_mock_validate_and_release (&token->authority);
	status |= cmd_device_mock_validate_and_release (&token->uuid);

	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&token->hash);
}

/**
 * Initialize a RMA unlock token handler for testing.
 *
 * @param test The test framework.
 * @param token Testing components to initialize.
 * @param auth_hash Hash algorithm for authentication.
 * @param oid The OID to use in the tokens.
 * @param oid_length Length of the OID.
 * @param dice Hash of the DICE key in the token.
 * @param dice_length Length of the DICE key hash.
 */
static void rma_unlock_token_testing_init (CuTest *test, struct rma_unlock_token_testing *token,
	enum hash_type auth_hash, const uint8_t *oid, size_t oid_length, const uint8_t *dice,
	size_t dice_length)
{
	int status;

	rma_unlock_token_testing_init_dependencies (test, token);

	status = rma_unlock_token_init (&token->test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token->authority.base, &token->hash.base, auth_hash, &token->uuid.base, oid, oid_length,
		dice, dice_length);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param token Testing components to release.
 */
static void rma_unlock_token_testing_release (CuTest *test, struct rma_unlock_token_testing *token)
{
	rma_unlock_token_release (&token->test);
	rma_unlock_token_testing_release_dependencies (test, token);
}

/**
 * Build an unlock token for testing.
 *
 * @param oid The raw OID to use in the token.  This will be DER encoded.
 * @param oid_len Length of the OID data.
 * @param uuid The UUID to use in the token.  This will always be 16 bytes.
 * @param dice_hash The DICE key hash to use in the token.
 * @param dice_len Length of the DICE key hash.
 * @param signature The token signature.
 * @param sig_len Length of the token signature.
 * @param token Output for the constructed token.  This must be large enough for all the token data.
 */
void rma_unlock_token_testing_build_token (const uint8_t *oid, size_t oid_len,
	const uint8_t *uuid, const uint8_t *dice_hash, size_t dice_len, const uint8_t *signature,
	size_t sig_len, uint8_t *token)
{
	uint8_t *pos = token;

	/* DER encode OID */
	*pos++ = 0x06;
	*pos++ = oid_len;

	memcpy (pos, oid, oid_len);
	pos += oid_len;

	buffer_unaligned_write16 ((uint16_t*) pos, 1);
	pos += 2;

	buffer_unaligned_write32 ((uint32_t*) pos, 0x52545354);
	pos += 4;

	memcpy (pos, uuid, DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN);
	pos += DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN;

	memcpy (pos, dice_hash, dice_len);
	pos += dice_len;

	memcpy (pos, signature, sig_len);
}


/*******************
 * Test cases
 *******************/

static void rma_unlock_token_test_init (CuTest *test)
{
	struct rma_unlock_token_testing token;
	int status;

	TEST_START;

	rma_unlock_token_testing_init_dependencies (test, &token);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, token.test.authenticate);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_init_null (CuTest *test)
{
	struct rma_unlock_token_testing token;
	int status;

	TEST_START;

	rma_unlock_token_testing_init_dependencies (test, &token);

	status = rma_unlock_token_init (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, NULL, ECC_PUBKEY_DER_LEN,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, 0,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token.authority.base, NULL, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, NULL,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		NULL, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, 0, ECC_PUBKEY2_SHA256,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, NULL,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = rma_unlock_token_init (&token.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
		RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
		0);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	rma_unlock_token_testing_release_dependencies (test, &token);
}

static void rma_unlock_token_test_static_init (CuTest *test)
{
	struct rma_unlock_token_testing token = {
		.test = rma_unlock_token_static_init (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
			&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
			RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
			SHA256_HASH_LENGTH)
	};

	TEST_START;

	CuAssertPtrNotNull (test, token.test.authenticate);

	rma_unlock_token_testing_init_dependencies (test, &token);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_release_null (CuTest *test)
{
	TEST_START;

	rma_unlock_token_release (NULL);
}

static void rma_unlock_token_test_authenticate (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&token.authority.mock, token.authority.base.verify_signature,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, 0, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_sha384 (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA384_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA384, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA384, SHA384_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA384, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha384 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&token.authority.mock, token.authority.base.verify_signature,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, 0, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_sha512 (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA512_HASH_LENGTH;
	const size_t token_length = signed_length + ECC521_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA512, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA512, SHA512_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA512, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha512 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&token.authority.mock, token.authority.base.verify_signature,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN),
		MOCK_ARG (ECC521_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, 0, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_longer_oid (CuTest *test)
{
	struct rma_unlock_token_testing token;
	uint8_t oid[RIOT_CORE_DEVICE_ID_OID_LEN + 4];
	const size_t signed_length = 2 + sizeof (oid) + 2 + 4 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN +
		SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	memcpy (oid, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN);
	oid[RIOT_CORE_DEVICE_ID_OID_LEN] = 0x11;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 1] = 0x22;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 2] = 0x33;
	oid[RIOT_CORE_DEVICE_ID_OID_LEN + 3] = 0x44;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, oid, sizeof (oid),
		ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (oid, sizeof (oid), DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN,
		token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&token.authority.mock, token.authority.base.verify_signature,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, 0, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_short_uuid (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_PADDED_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&token.authority.mock, token.authority.base.verify_signature,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, 0, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_static_init (CuTest *test)
{
	struct rma_unlock_token_testing token = {
		.test = rma_unlock_token_static_init (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
			&token.authority.base, &token.hash.base, HASH_TYPE_SHA256, &token.uuid.base,
			RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256,
			SHA256_HASH_LENGTH)
	};
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init_dependencies (test, &token);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&token.authority.mock, token.authority.base.verify_signature,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, 0, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_null (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (NULL, token_data, token_length);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	status = token.test.authenticate (&token.test, NULL, token_length);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_INVALID_ARGUMENT, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_get_uuid_error (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		CMD_DEVICE_UUID_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, CMD_DEVICE_UUID_FAILED, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_short_data_no_der (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, 0);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, 1);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_short_data_oid (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, 2 + RIOT_CORE_DEVICE_ID_OID_LEN - 1);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_mismatch_short_oid_length (CuTest *test)
{
	struct rma_unlock_token_testing token;
	uint8_t oid[RIOT_CORE_DEVICE_ID_OID_LEN - 1];
	const size_t signed_length = 2 + sizeof (oid) + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	memcpy (oid, RIOT_CORE_DEVICE_ID_OID, sizeof (oid));

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (oid, sizeof (oid), DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN,
		token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_DEVICE_MISMATCH, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_mismatch_oid (CuTest *test)
{
	struct rma_unlock_token_testing token;
	uint8_t oid[RIOT_CORE_DEVICE_ID_OID_LEN];
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	memcpy (oid, RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN);
	oid[2] ^= 0x55;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (oid, sizeof (oid), DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN,
		token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_DEVICE_MISMATCH, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_short_data_version (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 - 1);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_mismatch_version (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);
	token_data[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 1] = 0xf0;	/* Change the format version. */

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_short_data_magic_number (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 - 1);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_mismatch_magic_number (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);
	token_data[2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 1] ^= 0x55;	/* Change the magic number. */

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_short_data_uuid (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN - 1);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_mismatch_uuid (CuTest *test)
{
	struct rma_unlock_token_testing token;
	uint8_t uuid[DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN];
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	memcpy (uuid, DEVICE_UNLOCK_TOKEN_TESTING_UUID, DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN);
	uuid[4] ^= 0x55;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		uuid, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN,
		token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_DEVICE_MISMATCH, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_short_data_device_id_hash (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data,
		2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 + DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN +
			SHA256_HASH_LENGTH - 1);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_mismatch_device_id_hash (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY3_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_DEVICE_MISMATCH, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_unknown_signature_hash (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, (enum hash_type) 10, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_verification_key_error (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_bad_signature (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&token.authority.mock, token.authority.base.verify_signature,
		&token.authority, SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	rma_unlock_token_testing_release (test, &token);
}

static void rma_unlock_token_test_authenticate_signature_verify_error (CuTest *test)
{
	struct rma_unlock_token_testing token;
	const size_t signed_length = 2 + RIOT_CORE_DEVICE_ID_OID_LEN + 2 + 4 +
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN + SHA256_HASH_LENGTH;
	const size_t token_length = signed_length + ECC384_SIG_TEST_LEN;
	uint8_t token_data[token_length];
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	rma_unlock_token_testing_init (test, &token, HASH_TYPE_SHA256, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH);

	rma_unlock_token_testing_build_token (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID, ECC_PUBKEY2_SHA256, SHA256_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, token_data);

	status = token.hash.base.calculate_sha256 (&token.hash.base, token_data, signed_length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&token.uuid.mock, token.uuid.base.get_uuid, &token.uuid,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN));
	status |= mock_expect_output (&token.uuid.mock, 0, DEVICE_UNLOCK_TOKEN_TESTING_UUID,
		DEVICE_UNLOCK_TOKEN_TESTING_UUID_LEN, 1);

	status |= mock_expect (&token.authority.mock, token.authority.base.set_verification_key,
		&token.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&token.authority.mock, token.authority.base.verify_signature,
		&token.authority, SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN),
		MOCK_ARG (ECC384_SIG_TEST_LEN));

	CuAssertIntEquals (test, 0, status);

	status = token.test.authenticate (&token.test, token_data, token_length);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	rma_unlock_token_testing_release (test, &token);
}


TEST_SUITE_START (rma_unlock_token);

TEST (rma_unlock_token_test_init);
TEST (rma_unlock_token_test_init_null);
TEST (rma_unlock_token_test_static_init);
TEST (rma_unlock_token_test_release_null);
TEST (rma_unlock_token_test_authenticate);
TEST (rma_unlock_token_test_authenticate_sha384);
TEST (rma_unlock_token_test_authenticate_sha512);
TEST (rma_unlock_token_test_authenticate_longer_oid);
TEST (rma_unlock_token_test_authenticate_short_uuid);
TEST (rma_unlock_token_test_authenticate_static_init);
TEST (rma_unlock_token_test_authenticate_null);
TEST (rma_unlock_token_test_authenticate_get_uuid_error);
TEST (rma_unlock_token_test_authenticate_short_data_no_der);
TEST (rma_unlock_token_test_authenticate_short_data_oid);
TEST (rma_unlock_token_test_authenticate_mismatch_short_oid_length);
TEST (rma_unlock_token_test_authenticate_mismatch_oid);
TEST (rma_unlock_token_test_authenticate_short_data_version);
TEST (rma_unlock_token_test_authenticate_mismatch_version);
TEST (rma_unlock_token_test_authenticate_short_data_magic_number);
TEST (rma_unlock_token_test_authenticate_mismatch_magic_number);
TEST (rma_unlock_token_test_authenticate_short_data_uuid);
TEST (rma_unlock_token_test_authenticate_mismatch_uuid);
TEST (rma_unlock_token_test_authenticate_short_data_device_id_hash);
TEST (rma_unlock_token_test_authenticate_mismatch_device_id_hash);
TEST (rma_unlock_token_test_authenticate_unknown_signature_hash);
TEST (rma_unlock_token_test_authenticate_verification_key_error);
TEST (rma_unlock_token_test_authenticate_bad_signature);
TEST (rma_unlock_token_test_authenticate_signature_verify_error);

TEST_SUITE_END;
