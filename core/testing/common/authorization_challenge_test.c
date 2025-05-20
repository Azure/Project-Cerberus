// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/authorization_challenge.h"
#include "common/authorization_challenge_static.h"
#include "testing/crypto/hash_testing.h"
#include "testing/mock/common/auth_token_mock.h"
#include "testing/mock/common/authorized_data_mock.h"


TEST_SUITE_LABEL ("authorization_challenge");


/**
 * Dependencies for testing authorization that requires a authenticated challenge.
 */
struct authorization_challenge_testing {
	struct auth_token_mock token;				/**< Mock for the authorization token. */
	struct authorized_data_mock data;			/**< Mock for the authorized data parser. */
	struct authorization_challenge_state state;	/**< Variable context for the authorization manager. */
	struct authorization_challenge test;		/**< Authorization manager under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to initialize.
 */
static void authorization_challenge_testing_init_dependencies (CuTest *test,
	struct authorization_challenge_testing *auth)
{
	int status;

	status = auth_token_mock_init (&auth->token);
	CuAssertIntEquals (test, 0, status);

	status = authorized_data_mock_init (&auth->data);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to release all testing dependencies.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to release.
 */
static void authorization_challenge_testing_release_dependencies (CuTest *test,
	struct authorization_challenge_testing *auth)
{
	int status;

	status = auth_token_mock_validate_and_release (&auth->token);
	status |= authorized_data_mock_validate_and_release (&auth->data);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an authentication manager for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies.
 * @param auth_hash The token authenticating hash to use.
 */
static void authorization_challenge_testing_init (CuTest *test,
	struct authorization_challenge_testing *auth, enum hash_type auth_hash)
{
	int status;

	authorization_challenge_testing_init_dependencies (test, auth);

	status = authorization_challenge_init (&auth->test, &auth->state, &auth->token.base,
		&auth->data.base, auth_hash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an authentication manager for testing that includes a token tag.
 *
 * @param test The test framework.
 * @param auth Testing dependencies.
 * @param auth_hash The token authenticating hash to use.
 * @param tag Tag value to include in the tokens.
 */
static void authorization_challenge_testing_init_with_tag (CuTest *test,
	struct authorization_challenge_testing *auth, enum hash_type auth_hash, uint32_t tag)
{
	int status;

	authorization_challenge_testing_init_dependencies (test, auth);

	status = authorization_challenge_init_with_tag (&auth->test, &auth->state, &auth->token.base,
		&auth->data.base, auth_hash, tag);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static authentication manager for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies.
 */
static void authorization_challenge_testing_init_static (CuTest *test,
	struct authorization_challenge_testing *auth)
{
	int status;

	authorization_challenge_testing_init_dependencies (test, auth);

	status = authorization_challenge_init_state (&auth->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release authentication test components.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to release.
 */
static void authorization_challenge_testing_release (CuTest *test,
	struct authorization_challenge_testing *auth)
{
	authorization_challenge_release (&auth->test);
	authorization_challenge_testing_release_dependencies (test, auth);
}


/*******************
 * Test cases
 *******************/

static void authorization_challenge_test_init (CuTest *test)
{
	struct authorization_challenge_testing auth;
	int status;

	TEST_START;

	authorization_challenge_testing_init_dependencies (test, &auth);

	status = authorization_challenge_init (&auth.test, &auth.state, &auth.token.base,
		&auth.data.base, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.test.base.authorize);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_init_null (CuTest *test)
{
	struct authorization_challenge_testing auth;
	int status;

	TEST_START;

	authorization_challenge_testing_init_dependencies (test, &auth);

	status = authorization_challenge_init (NULL, &auth.state, &auth.token.base, &auth.data.base,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init (&auth.test, NULL, &auth.token.base, &auth.data.base,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init (&auth.test, &auth.state, NULL, &auth.data.base,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init (&auth.test, &auth.state, &auth.token.base, NULL,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	authorization_challenge_testing_release_dependencies (test, &auth);
}

static void authorization_challenge_test_init_with_tag (CuTest *test)
{
	struct authorization_challenge_testing auth;
	int status;

	TEST_START;

	authorization_challenge_testing_init_dependencies (test, &auth);

	status = authorization_challenge_init_with_tag (&auth.test, &auth.state, &auth.token.base,
		&auth.data.base, HASH_TYPE_SHA256, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.test.base.authorize);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_init_with_tag_null (CuTest *test)
{
	struct authorization_challenge_testing auth;
	int status;

	TEST_START;

	authorization_challenge_testing_init_dependencies (test, &auth);

	status = authorization_challenge_init_with_tag (NULL, &auth.state, &auth.token.base,
		&auth.data.base, HASH_TYPE_SHA256, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_with_tag (&auth.test, NULL, &auth.token.base,
		&auth.data.base, HASH_TYPE_SHA256, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_with_tag (&auth.test, &auth.state, NULL, &auth.data.base,
		HASH_TYPE_SHA256, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_with_tag (&auth.test, &auth.state, &auth.token.base, NULL,
		HASH_TYPE_SHA256, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	authorization_challenge_testing_release_dependencies (test, &auth);
}

static void authorization_challenge_test_static_init (CuTest *test)
{
	struct authorization_challenge_testing auth = {
		.test = authorization_challenge_static_init (&auth.state, &auth.token.base, &auth.data.base,
			HASH_TYPE_SHA384)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, auth.test.base.authorize);

	authorization_challenge_testing_init_dependencies (test, &auth);

	status = authorization_challenge_init_state (&auth.test);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_static_init_null (CuTest *test)
{
	struct authorization_challenge_testing auth;
	struct authorization_challenge null_state = authorization_challenge_static_init (NULL,
		&auth.token.base, &auth.data.base, HASH_TYPE_SHA384);
	struct authorization_challenge null_token =
		authorization_challenge_static_init (&auth.state, NULL, &auth.data.base, HASH_TYPE_SHA384);
	struct authorization_challenge null_data =
		authorization_challenge_static_init (&auth.state, &auth.token.base, NULL, HASH_TYPE_SHA384);
	int status;

	TEST_START;

	authorization_challenge_testing_init_dependencies (test, &auth);

	status = authorization_challenge_init_state (NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_state (&null_state);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_state (&null_token);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_state (&null_data);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	authorization_challenge_testing_release_dependencies (test, &auth);
}

static void authorization_challenge_test_static_init_with_tag (CuTest *test)
{
	struct authorization_challenge_testing auth = {
		.test = authorization_challenge_static_init_with_tag (&auth.state, &auth.token.base,
			&auth.data.base, HASH_TYPE_SHA384, 2)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, auth.test.base.authorize);

	authorization_challenge_testing_init_dependencies (test, &auth);

	status = authorization_challenge_init_state (&auth.test);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_static_init_with_tag_null (CuTest *test)
{
	struct authorization_challenge_testing auth;
	struct authorization_challenge null_state = authorization_challenge_static_init_with_tag (NULL,
		&auth.token.base, &auth.data.base, HASH_TYPE_SHA384, 2);
	struct authorization_challenge null_token =
		authorization_challenge_static_init_with_tag (&auth.state, NULL, &auth.data.base,
		HASH_TYPE_SHA384, 3);
	struct authorization_challenge null_data =
		authorization_challenge_static_init_with_tag (&auth.state, &auth.token.base, NULL,
		HASH_TYPE_SHA384, 3);
	int status;

	TEST_START;

	authorization_challenge_testing_init_dependencies (test, &auth);

	status = authorization_challenge_init_state (NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_state (&null_state);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_state (&null_token);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_state (&null_data);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	authorization_challenge_testing_release_dependencies (test, &auth);
}

static void authorization_challenge_test_release_null (CuTest *test)
{
	TEST_START;

	authorization_challenge_release (NULL);
}

static void authorization_challenge_test_authorize_new_token (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_512;
	size_t data_len = HASH_TESTING_FULL_BLOCK_512_LEN;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.token.mock, 2, &token_data, sizeof (token_data), -1);
	status |= mock_expect_output (&auth.token.mock, 3, &data_len, sizeof (data_len), -1);

	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	status = auth.test.base.authorize (&auth.test.base, &out_token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, out_token);
	CuAssertIntEquals (test, HASH_TESTING_FULL_BLOCK_512_LEN, length);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, out_token, length);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_new_token_with_tag (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_512;
	size_t data_len = HASH_TESTING_FULL_BLOCK_512_LEN;
	uint32_t tag = 5;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_with_tag (test, &auth, HASH_TYPE_SHA256, tag);

	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (&tag, sizeof (tag)), MOCK_ARG (sizeof (tag)),
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.token.mock, 2, &token_data, sizeof (token_data), -1);
	status |= mock_expect_output (&auth.token.mock, 3, &data_len, sizeof (data_len), -1);

	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	status = auth.test.base.authorize (&auth.test.base, &out_token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, out_token);
	CuAssertIntEquals (test, HASH_TESTING_FULL_BLOCK_512_LEN, length);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, out_token, length);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_new_token_static_init (CuTest *test)
{
	struct authorization_challenge_testing auth = {
		.test = authorization_challenge_static_init (&auth.state, &auth.token.base, &auth.data.base,
			HASH_TYPE_SHA256)
	};
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_512;
	size_t data_len = HASH_TESTING_FULL_BLOCK_512_LEN;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_static (test, &auth);

	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.token.mock, 2, &token_data, sizeof (token_data), -1);
	status |= mock_expect_output (&auth.token.mock, 3, &data_len, sizeof (data_len), -1);

	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	status = auth.test.base.authorize (&auth.test.base, &out_token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, out_token);
	CuAssertIntEquals (test, HASH_TESTING_FULL_BLOCK_512_LEN, length);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, out_token, length);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_new_token_static_init_with_tag (CuTest *test)
{
	uint32_t tag = 8;
	struct authorization_challenge_testing auth = {
		.test = authorization_challenge_static_init_with_tag (&auth.state, &auth.token.base,
			&auth.data.base, HASH_TYPE_SHA256, tag)
	};
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_512;
	size_t data_len = HASH_TESTING_FULL_BLOCK_512_LEN;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_static (test, &auth);

	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (&tag, sizeof (tag)), MOCK_ARG (sizeof (tag)),
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.token.mock, 2, &token_data, sizeof (token_data), -1);
	status |= mock_expect_output (&auth.token.mock, 3, &data_len, sizeof (data_len), -1);

	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	status = auth.test.base.authorize (&auth.test.base, &out_token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, out_token);
	CuAssertIntEquals (test, HASH_TESTING_FULL_BLOCK_512_LEN, length);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, out_token, length);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	size_t token_offset = 10;
	size_t aad_length = 20;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA256));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_sha384 (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_2048;
	size_t data_len = HASH_TESTING_FULL_BLOCK_2048_LEN;
	size_t token_offset = 16;
	size_t aad_length = 32;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA384);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA384));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_with_tag (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	size_t token_offset = 10;
	size_t aad_length = 20;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_with_tag (test, &auth, HASH_TYPE_SHA256, 4);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA256));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_with_tag_sha384 (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_2048;
	size_t data_len = HASH_TESTING_FULL_BLOCK_2048_LEN;
	size_t token_offset = 16;
	size_t aad_length = 32;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_with_tag (test, &auth, HASH_TYPE_SHA384, 4);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA384));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_static_init (CuTest *test)
{
	struct authorization_challenge_testing auth = {
		.test = authorization_challenge_static_init (&auth.state, &auth.token.base, &auth.data.base,
			HASH_TYPE_SHA256)
	};
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	size_t token_offset = 10;
	size_t aad_length = 20;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_static (test, &auth);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA256));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_static_init_sha384 (CuTest *test)
{
	struct authorization_challenge_testing auth = {
		.test = authorization_challenge_static_init (&auth.state, &auth.token.base, &auth.data.base,
			HASH_TYPE_SHA384)
	};
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_2048;
	size_t data_len = HASH_TESTING_FULL_BLOCK_2048_LEN;
	size_t token_offset = 16;
	size_t aad_length = 32;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_static (test, &auth);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA384));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_static_init_with_tag (CuTest *test)
{
	struct authorization_challenge_testing auth = {
		.test = authorization_challenge_static_init_with_tag (&auth.state, &auth.token.base,
			&auth.data.base, HASH_TYPE_SHA256, 6)
	};
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	size_t token_offset = 10;
	size_t aad_length = 20;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_static (test, &auth);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA256));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_static_init_with_tag_sha384 (
	CuTest *test)
{
	struct authorization_challenge_testing auth = {
		.test = authorization_challenge_static_init_with_tag (&auth.state, &auth.token.base,
			&auth.data.base, HASH_TYPE_SHA384, 6)
	};
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_2048;
	size_t data_len = HASH_TESTING_FULL_BLOCK_2048_LEN;
	size_t token_offset = 16;
	size_t aad_length = 32;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init_static (test, &auth);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_2048_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA384));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, 0, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_null (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *out_token = NULL;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = auth.test.base.authorize (NULL, &out_token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = auth.test.base.authorize (&auth.test.base, NULL, &length);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = auth.test.base.authorize (&auth.test.base, &out_token, NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_new_token_error (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token,
		AUTH_TOKEN_BUILD_FAILED, MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR_PTR (NULL),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	status = auth.test.base.authorize (&auth.test.base, &out_token, &length);
	CuAssertIntEquals (test, AUTH_TOKEN_BUILD_FAILED, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_token_offset_error (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data,
		AUTH_DATA_TOKEN_OFFSET_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, AUTH_DATA_TOKEN_OFFSET_FAILED, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_aad_length_error (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	size_t token_offset = 10;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, AUTH_DATA_AAD_LENGTH_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, AUTH_DATA_AAD_LENGTH_FAILED, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_error (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	size_t token_offset = 10;
	size_t aad_length = 20;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token,
		AUTH_TOKEN_CHECK_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA256));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, AUTH_TOKEN_CHECK_FAILED, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_not_valid (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	size_t token_offset = 10;
	size_t aad_length = 20;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token,
		AUTH_TOKEN_NOT_VALID,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA256));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}

static void authorization_challenge_test_authorize_verify_token_invalidate_error (CuTest *test)
{
	struct authorization_challenge_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t data_len = HASH_TESTING_FULL_BLOCK_1024_LEN;
	size_t token_offset = 10;
	size_t aad_length = 20;
	const uint8_t *out_token;
	size_t length;
	int status;

	TEST_START;

	authorization_challenge_testing_init (test, &auth, HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_token_offset, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &token_offset, sizeof (token_offset), -1);

	status |= mock_expect (&auth.data.mock, auth.data.base.get_authenticated_data_length,
		&auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.token.mock, auth.token.base.verify_data, &auth.token, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN), MOCK_ARG (token_offset), MOCK_ARG (aad_length),
		MOCK_ARG (HASH_TYPE_SHA256));

	status |= mock_expect (&auth.token.mock, auth.token.base.invalidate, &auth.token,
		AUTH_TOKEN_INVALIDATE_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token_data, &data_len);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALIDATE_FAILED, status);

	/* Verify mutex has been released. */
	status = mock_expect (&auth.token.mock, auth.token.base.new_token, &auth.token, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	out_token = NULL;
	auth.test.base.authorize (&auth.test.base, &out_token, &length);

	authorization_challenge_testing_release (test, &auth);
}


// *INDENT-OFF*
TEST_SUITE_START (authorization_challenge);

TEST (authorization_challenge_test_init);
TEST (authorization_challenge_test_init_null);
TEST (authorization_challenge_test_init_with_tag);
TEST (authorization_challenge_test_init_with_tag_null);
TEST (authorization_challenge_test_static_init);
TEST (authorization_challenge_test_static_init_null);
TEST (authorization_challenge_test_static_init_with_tag);
TEST (authorization_challenge_test_static_init_with_tag_null);
TEST (authorization_challenge_test_release_null);
TEST (authorization_challenge_test_authorize_new_token);
TEST (authorization_challenge_test_authorize_new_token_with_tag);
TEST (authorization_challenge_test_authorize_new_token_static_init);
TEST (authorization_challenge_test_authorize_new_token_static_init_with_tag);
TEST (authorization_challenge_test_authorize_verify_token);
TEST (authorization_challenge_test_authorize_verify_token_sha384);
TEST (authorization_challenge_test_authorize_verify_token_with_tag);
TEST (authorization_challenge_test_authorize_verify_token_with_tag_sha384);
TEST (authorization_challenge_test_authorize_verify_token_static_init);
TEST (authorization_challenge_test_authorize_verify_token_static_init_sha384);
TEST (authorization_challenge_test_authorize_verify_token_static_init_with_tag);
TEST (authorization_challenge_test_authorize_verify_token_static_init_with_tag_sha384);
TEST (authorization_challenge_test_authorize_null);
TEST (authorization_challenge_test_authorize_new_token_error);
TEST (authorization_challenge_test_authorize_verify_token_token_offset_error);
TEST (authorization_challenge_test_authorize_verify_token_aad_length_error);
TEST (authorization_challenge_test_authorize_verify_token_error);
TEST (authorization_challenge_test_authorize_verify_token_not_valid);
TEST (authorization_challenge_test_authorize_verify_token_invalidate_error);

TEST_SUITE_END;
// *INDENT-ON*
