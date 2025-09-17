// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "common/unused.h"
#include "spdm/spdm_persistent_context_static.h"

TEST_SUITE_LABEL ("spdm_persistent_context");


/**
 * Dependencies for testing SPDM persistent context for GSRAM storage.
 */
struct spdm_persistent_context_testing {
	struct spdm_persistent_context_state state;	/**< Internal state for the context. */
	struct spdm_persistent_context context;
};


/**
 * Initialize all dependencies for testing
 *
 * @param test The test framework
 * @param testing Testing dependencies
 */
static void spdm_persistent_context_testing_init_dependencies (CuTest *test,
	struct spdm_persistent_context_testing *testing)
{
	UNUSED (test);
	UNUSED (testing);
}

/**
 * Release all dependencies and validate all mocks
 *
 * @param test The test framework
 * @param testing Testing dependencies
 */
static void spdm_persistent_context_testing_release_dependencies (CuTest *test,
	struct spdm_persistent_context_testing *testing)
{
	UNUSED (test);
	UNUSED (testing);
}

/**
 * Initialize GSRAM stored SPDM permanent context for testing
 *
 * @param test The test framework
 * @param testing Testing components to initialize
 */
static void spdm_persistent_context_testing_init (CuTest *test,
	struct spdm_persistent_context_testing *testing)
{
	int status;

	spdm_persistent_context_testing_init_dependencies (test, testing);

	status = spdm_persistent_context_init (&testing->context, &testing->state);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release GSRAM stored Manticore SPDM permanent context and validate all mocks
 *
 * @param test The test framework
 * @param testing Testing components to release
 */
static void spdm_persistent_context_testing_release (CuTest *test,
	struct spdm_persistent_context_testing *testing)
{
	spdm_persistent_context_release (&testing->context);
	spdm_persistent_context_testing_release_dependencies (test, testing);
}


/*******************
 * Test cases
 *******************/

static void spdm_persistent_context_test_init (CuTest *test)
{
	struct spdm_persistent_context_testing testing;

	TEST_START;

	spdm_persistent_context_testing_init (test, &testing);

	CuAssertPtrNotNull (test, testing.context.base.get_responder_state);
	CuAssertPtrNotNull (test, testing.context.base.get_secure_session_manager_state);
	CuAssertPtrNotNull (test, testing.context.base.unlock);

	spdm_persistent_context_testing_release (test, &testing);
}

static void spdm_persistent_context_test_init_static (CuTest *test)
{
	struct spdm_persistent_context_testing testing = {
		.context = spdm_persistent_context_static_init (&testing.state),
	};

	TEST_START;

	spdm_persistent_context_testing_init_dependencies (test, &testing);

	CuAssertPtrNotNull (test, testing.context.base.get_responder_state);
	CuAssertPtrNotNull (test, testing.context.base.get_secure_session_manager_state);
	CuAssertPtrNotNull (test, testing.context.base.unlock);

	spdm_persistent_context_testing_release (test, &testing);
}

static void spdm_persistent_context_test_init_null (CuTest *test)
{
	struct spdm_persistent_context_testing testing;
	int status;

	TEST_START;

	spdm_persistent_context_testing_init_dependencies (test, &testing);

	status = spdm_persistent_context_init (NULL, &testing.state);
	CuAssertIntEquals (test, SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT, status);

	status = spdm_persistent_context_init (&testing.context, NULL);
	CuAssertIntEquals (test, SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT, status);

	spdm_persistent_context_testing_release (test, &testing);
}

static void spdm_persistent_context_test_get_responder_state (CuTest *test)
{
	struct spdm_persistent_context_testing testing;
	struct spdm_responder_state *state = NULL;
	int status;

	TEST_START;

	spdm_persistent_context_testing_init (test, &testing);

	status = testing.context.base.get_responder_state (&testing.context.base, &state);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &testing.state.responder_state, state);

	state = NULL;
	status = testing.context.base.get_responder_state (&testing.context.base, &state);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &testing.state.responder_state, state);

	spdm_persistent_context_testing_release (test, &testing);
}

static void spdm_persistent_context_test_get_responder_state_null (CuTest *test)
{
	struct spdm_persistent_context_testing testing;
	struct spdm_responder_state *state = NULL;
	int status;

	TEST_START;

	spdm_persistent_context_testing_init (test, &testing);

	status = testing.context.base.get_responder_state (NULL, &state);
	CuAssertIntEquals (test, SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT, status);

	status = testing.context.base.get_responder_state (&testing.context.base, NULL);
	CuAssertIntEquals (test, SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT, status);

	spdm_persistent_context_testing_release (test, &testing);
}

static void spdm_persistent_context_test_get_secure_session_manager_state (
	CuTest *test)
{
	struct spdm_persistent_context_testing testing;
	struct spdm_secure_session_manager_persistent_state *state = NULL;
	int status;

	TEST_START;

	spdm_persistent_context_testing_init (test, &testing);

	status = testing.context.base.get_secure_session_manager_state (&testing.context.base, &state);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &testing.state.ssm_state, state);

	state = NULL;
	status = testing.context.base.get_secure_session_manager_state (&testing.context.base, &state);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &testing.state.ssm_state, state);

	spdm_persistent_context_testing_release (test, &testing);
}

static void spdm_persistent_context_test_get_secure_session_manager_state_null (
	CuTest *test)
{
	struct spdm_persistent_context_testing testing;
	struct spdm_secure_session_manager_persistent_state *state = NULL;
	int status;

	TEST_START;

	spdm_persistent_context_testing_init (test, &testing);

	status = testing.context.base.get_secure_session_manager_state (NULL, &state);
	CuAssertIntEquals (test, SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT, status);

	status = testing.context.base.get_secure_session_manager_state (&testing.context.base, NULL);
	CuAssertIntEquals (test, SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT, status);

	spdm_persistent_context_testing_release (test, &testing);
}

static void spdm_persistent_context_test_unlock (CuTest *test)
{
	struct spdm_persistent_context_testing testing;
	struct spdm_responder_state *state = NULL;
	int status;

	TEST_START;

	spdm_persistent_context_testing_init (test, &testing);

	status = testing.context.base.get_responder_state (&testing.context.base, &state);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &testing.state.responder_state, state);

	testing.context.base.unlock (&testing.context.base);

	spdm_persistent_context_testing_release (test, &testing);
}

static void spdm_persistent_context_test_unlock_null (CuTest *test)
{
	struct spdm_persistent_context_testing testing;

	TEST_START;

	spdm_persistent_context_testing_init (test, &testing);

	testing.context.base.unlock (NULL);

	spdm_persistent_context_testing_release (test, &testing);
}

// *INDENT-OFF*
TEST_SUITE_START (spdm_persistent_context);

TEST (spdm_persistent_context_test_init);
TEST (spdm_persistent_context_test_init_static);
TEST (spdm_persistent_context_test_init_null);
TEST (spdm_persistent_context_test_get_responder_state);
TEST (spdm_persistent_context_test_get_responder_state_null);
TEST (spdm_persistent_context_test_get_secure_session_manager_state);
TEST (spdm_persistent_context_test_get_secure_session_manager_state_null);
TEST (spdm_persistent_context_test_unlock);
TEST (spdm_persistent_context_test_unlock_null);

TEST_SUITE_END;
// *INDENT-ON*
