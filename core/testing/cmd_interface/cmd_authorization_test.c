// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "cmd_interface/cerberus_protocol_optional_commands.h"
#include "cmd_interface/cmd_authorization.h"
#include "cmd_interface/cmd_authorization_static.h"
#include "common/array_size.h"
#include "testing/crypto/hash_testing.h"
#include "testing/mock/common/authorization_mock.h"
#include "testing/mock/common/authorized_execution_mock.h"


TEST_SUITE_LABEL ("cmd_authorization");


/**
 * Dependencies for testing the command authorization handler.
 */
struct cmd_authorization_testing {
	struct authorization_mock bypass;				/**< Mock for revert bypass authorization. */
	struct authorized_execution_mock bypass_op;		/**< Mock for the revert bypass operation. */
	struct authorization_mock defaults;				/**< Mock for factory default authorization. */
	struct authorized_execution_mock defaults_op;	/**< Mock for the factory default operation. */
	struct authorization_mock platform;				/**< Mock for platform config authorization. */
	struct authorized_execution_mock platform_op;	/**< Mock for the platform config operation. */
	struct authorization_mock components;			/**< Mock for component config authorization. */
	struct authorized_execution_mock components_op;	/**< Mock for the component config operation. */
	struct authorization_mock intrusion;			/**< Mock for intrusion authorization. */
	struct authorized_execution_mock intrusion_op;	/**< Mock for the intrusion operation. */
	struct cmd_authorization_operation op_list[5];	/**< List of supported operations. */
	struct cmd_authorization test;					/**< Command authorization handler under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to initialize.
 */
static void cmd_authorization_testing_init_dependencies (CuTest *test,
	struct cmd_authorization_testing *auth)
{
	int status;

	status = authorization_mock_init (&auth->bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->bypass_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[0].id = CERBERUS_PROTOCOL_REVERT_BYPASS;
	auth->op_list[0].authorization = &auth->bypass.base;
	auth->op_list[0].execution = &auth->bypass_op.base;

	status = authorization_mock_init (&auth->defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->defaults_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[1].id = CERBERUS_PROTOCOL_FACTORY_RESET;
	auth->op_list[1].authorization = &auth->defaults.base;
	auth->op_list[1].execution = &auth->defaults_op.base;

	status = authorization_mock_init (&auth->platform);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->platform_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[2].id = CERBERUS_PROTOCOL_CLEAR_PCD;
	auth->op_list[2].authorization = &auth->platform.base;
	auth->op_list[2].execution = &auth->platform_op.base;

	status = authorization_mock_init (&auth->components);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->components_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[3].id = CERBERUS_PROTOCOL_CLEAR_CFM;
	auth->op_list[3].authorization = &auth->components.base;
	auth->op_list[3].execution = &auth->components_op.base;

	status = authorization_mock_init (&auth->intrusion);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->intrusion_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[4].id = CERBERUS_PROTOCOL_RESET_INTRUSION;
	auth->op_list[4].authorization = &auth->intrusion.base;
	auth->op_list[4].execution = &auth->intrusion_op.base;
}

/**
 * Helper to release all testing dependencies.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to release.
 */
static void cmd_authorization_testing_release_dependencies (CuTest *test,
	struct cmd_authorization_testing *auth)
{
	int status;

	status = authorization_mock_validate_and_release (&auth->bypass);
	status |= authorized_execution_mock_validate_and_release (&auth->bypass_op);

	status |= authorization_mock_validate_and_release (&auth->defaults);
	status |= authorized_execution_mock_validate_and_release (&auth->defaults_op);

	status |= authorization_mock_validate_and_release (&auth->platform);
	status |= authorized_execution_mock_validate_and_release (&auth->platform_op);

	status |= authorization_mock_validate_and_release (&auth->components);
	status |= authorized_execution_mock_validate_and_release (&auth->components_op);

	status |= authorization_mock_validate_and_release (&auth->intrusion);
	status |= authorized_execution_mock_validate_and_release (&auth->intrusion_op);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a command authorization handler for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies.
 */
static void cmd_authorization_testing_init (CuTest *test, struct cmd_authorization_testing *auth)
{
	int status;

	cmd_authorization_testing_init_dependencies (test, auth);

	status = cmd_authorization_init (&auth->test, auth->op_list, ARRAY_SIZE (auth->op_list));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release command authorization handler test components.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to release.
 */
static void cmd_authorization_testing_release (CuTest *test, struct cmd_authorization_testing *auth)
{
	cmd_authorization_release (&auth->test);
	cmd_authorization_testing_release_dependencies (test, auth);
}


/*******************
 * Test cases
 *******************/

static void authorization_allowed_test_operation_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth;
	struct cmd_authorization_operation operation1 =
		cmd_authorization_operation_static_init (12, &auth.bypass.base, &auth.bypass_op.base);
	struct cmd_authorization_operation operation2 =
		cmd_authorization_operation_static_init (20, &auth.defaults.base, &auth.defaults_op.base);

	TEST_START;

	CuAssertIntEquals (test, 12, operation1.id);
	CuAssertPtrEquals (test, &auth.bypass.base, (void*) operation1.authorization);
	CuAssertPtrEquals (test, &auth.bypass_op.base, (void*) operation1.execution);

	CuAssertIntEquals (test, 20, operation2.id);
	CuAssertPtrEquals (test, &auth.defaults.base, (void*) operation2.authorization);
	CuAssertPtrEquals (test, &auth.defaults_op.base, (void*) operation2.execution);
}

static void authorization_allowed_test_init (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = cmd_authorization_init (&auth.test, auth.op_list, ARRAY_SIZE (auth.op_list));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.test.authorize_operation);
	CuAssertPtrNotNull (test, auth.test.authorize_revert_bypass);
	CuAssertPtrNotNull (test, auth.test.authorize_reset_defaults);
	CuAssertPtrNotNull (test, auth.test.authorize_clear_platform_config);
	CuAssertPtrNotNull (test, auth.test.authorize_clear_component_manifests);
	CuAssertPtrNotNull (test, auth.test.authorize_reset_intrusion);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_init_no_operations (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = cmd_authorization_init (&auth.test, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_init_null (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = cmd_authorization_init (NULL, auth.op_list, ARRAY_SIZE (auth.op_list));
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	status = cmd_authorization_init (&auth.test, NULL, ARRAY_SIZE (auth.op_list));
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	cmd_authorization_testing_release_dependencies (test, &auth);
}

static void authorization_allowed_test_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};

	TEST_START;

	CuAssertPtrNotNull (test, auth.test.authorize_operation);
	CuAssertPtrNotNull (test, auth.test.authorize_revert_bypass);
	CuAssertPtrNotNull (test, auth.test.authorize_reset_defaults);
	CuAssertPtrNotNull (test, auth.test.authorize_clear_platform_config);
	CuAssertPtrNotNull (test, auth.test.authorize_clear_component_manifests);
	CuAssertPtrNotNull (test, auth.test.authorize_reset_intrusion);

	cmd_authorization_testing_init_dependencies (test, &auth);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_authorization_release (NULL);
}

static void authorization_allowed_test_authorize_operation (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	const struct authorized_execution *execution = (void*) &length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length,
		&execution);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth.op_list[0].execution, (void*) execution);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_operation_last (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	const struct authorized_execution *execution = (void*) &length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.intrusion.mock, auth.intrusion.base.authorize, &auth.intrusion, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[4].id, &token, &length,
		&execution);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth.op_list[4].execution, (void*) execution);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_operation_no_authorization (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	const struct authorized_execution *execution = (void*) &length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	/* Remove authorization for an operation. */
	auth.op_list[2].authorization = NULL;

	status = auth.test.authorize_operation (&auth.test, auth.op_list[2].id, &token, &length,
		&execution);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertPtrEquals (test, NULL, (void*) execution);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_operation_challenge (CuTest *test)
{
	struct cmd_authorization_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	int status;
	const uint8_t *token;
	size_t length;
	const struct authorized_execution *execution = (void*) &length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.defaults.mock, auth.defaults.base.authorize, &auth.defaults,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	status |= mock_expect_output (&auth.defaults.mock, 0, &token_data, sizeof (token_data), -1);
	status |= mock_expect_output (&auth.defaults.mock, 1, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[1].id, &token, &length,
		&execution);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrEquals (test, (void*) token_data, (void*) token);
	CuAssertIntEquals (test, HASH_TESTING_FULL_BLOCK_1024_LEN, length);
	CuAssertPtrEquals (test, NULL, (void*) execution);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_1024, token, length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_operation_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};
	int status;
	const uint8_t *token;
	size_t length;
	const struct authorized_execution *execution = (void*) &length;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length,
		&execution);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth.op_list[0].execution, (void*) execution);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_operation_null (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	const struct authorized_execution *execution = (void*) &length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_operation (NULL, auth.op_list[0].id, &token, &length, &execution);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, (void*) execution);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length, NULL);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_operation_unsupported (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	const struct authorized_execution *execution = (void*) &length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_operation (&auth.test, 15, &token, &length, &execution);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_UNSUPPORTED_OP, status);
	CuAssertPtrEquals (test, NULL, (void*) execution);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_operation_authorize_error (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	const struct authorized_execution *execution = (void*) &length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass,
		AUTHORIZATION_AUTHORIZE_FAILED, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length,
		&execution);
	CuAssertIntEquals (test, AUTHORIZATION_AUTHORIZE_FAILED, status);
	CuAssertPtrEquals (test, NULL, (void*) execution);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_revert_bypass (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_revert_bypass (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_revert_bypass_no_authorization (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	/* Disable revert bypass. */
	auth.op_list[0].authorization = NULL;

	status = auth.test.authorize_revert_bypass (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_revert_bypass_challenge (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_revert_bypass (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_revert_bypass_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_revert_bypass (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_revert_bypass_null (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_revert_bypass (NULL, &token, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_defaults (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.defaults.mock, auth.defaults.base.authorize, &auth.defaults, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_reset_defaults (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_defaults_no_authorization (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	/* Disable reset defaults. */
	auth.op_list[1].authorization = NULL;

	status = auth.test.authorize_reset_defaults (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_defaults_challenge (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.defaults.mock, auth.defaults.base.authorize, &auth.defaults,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_reset_defaults (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_defaults_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.defaults.mock, auth.defaults.base.authorize, &auth.defaults, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_reset_defaults (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_defaults_null (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_reset_defaults (NULL, &token, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_platform_config (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.platform.mock, auth.platform.base.authorize, &auth.platform, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_clear_platform_config (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_platform_config_no_authorization (
	CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	/* Disable platform config. */
	auth.op_list[2].authorization = NULL;

	status = auth.test.authorize_clear_platform_config (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_platform_config_challenge (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.platform.mock, auth.platform.base.authorize, &auth.platform,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_clear_platform_config (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_platform_config_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.platform.mock, auth.platform.base.authorize, &auth.platform, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_clear_platform_config (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_platform_config_null (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_clear_platform_config (NULL, &token, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_component_manifests (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.components.mock, auth.components.base.authorize, &auth.components,
		0, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_clear_component_manifests (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_component_manifests_no_authorization (
	CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	/* Disable component config. */
	auth.op_list[3].authorization = NULL;

	status = auth.test.authorize_clear_component_manifests (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_component_manifests_challenge (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.components.mock, auth.components.base.authorize, &auth.components,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_clear_component_manifests (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_component_manifests_static_init (
	CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.components.mock, auth.components.base.authorize, &auth.components,
		0, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_clear_component_manifests (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_clear_component_manifests_null (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_clear_component_manifests (NULL, &token, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_intrusion (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.intrusion.mock, auth.intrusion.base.authorize, &auth.intrusion, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_reset_intrusion (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_intrusion_no_authorization (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	/* Disable reset intrusion. */
	auth.op_list[4].authorization = NULL;

	status = auth.test.authorize_reset_intrusion (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_intrusion_challenge (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.intrusion.mock, auth.intrusion.base.authorize, &auth.intrusion,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_reset_intrusion (&auth.test, &token, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_intrusion_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.intrusion.mock, auth.intrusion.base.authorize, &auth.intrusion, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_reset_intrusion (&auth.test, &token, &length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void authorization_allowed_test_authorize_reset_intrusion_null (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_reset_intrusion (NULL, &token, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	cmd_authorization_testing_release (test, &auth);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_authorization);

TEST (authorization_allowed_test_operation_static_init);
TEST (authorization_allowed_test_init);
TEST (authorization_allowed_test_init_no_operations);
TEST (authorization_allowed_test_init_null);
TEST (authorization_allowed_test_static_init);
TEST (authorization_allowed_test_release_null);
TEST (authorization_allowed_test_authorize_operation);
TEST (authorization_allowed_test_authorize_operation_last);
TEST (authorization_allowed_test_authorize_operation_no_authorization);
TEST (authorization_allowed_test_authorize_operation_challenge);
TEST (authorization_allowed_test_authorize_operation_static_init);
TEST (authorization_allowed_test_authorize_operation_null);
TEST (authorization_allowed_test_authorize_operation_unsupported);
TEST (authorization_allowed_test_authorize_operation_authorize_error);
TEST (authorization_allowed_test_authorize_revert_bypass);
TEST (authorization_allowed_test_authorize_revert_bypass_no_authorization);
TEST (authorization_allowed_test_authorize_revert_bypass_challenge);
TEST (authorization_allowed_test_authorize_revert_bypass_static_init);
TEST (authorization_allowed_test_authorize_revert_bypass_null);
TEST (authorization_allowed_test_authorize_reset_defaults);
TEST (authorization_allowed_test_authorize_reset_defaults_no_authorization);
TEST (authorization_allowed_test_authorize_reset_defaults_challenge);
TEST (authorization_allowed_test_authorize_reset_defaults_static_init);
TEST (authorization_allowed_test_authorize_reset_defaults_null);
TEST (authorization_allowed_test_authorize_clear_platform_config);
TEST (authorization_allowed_test_authorize_clear_platform_config_no_authorization);
TEST (authorization_allowed_test_authorize_clear_platform_config_challenge);
TEST (authorization_allowed_test_authorize_clear_platform_config_static_init);
TEST (authorization_allowed_test_authorize_clear_platform_config_null);
TEST (authorization_allowed_test_authorize_clear_component_manifests);
TEST (authorization_allowed_test_authorize_clear_component_manifests_no_authorization);
TEST (authorization_allowed_test_authorize_clear_component_manifests_challenge);
TEST (authorization_allowed_test_authorize_clear_component_manifests_static_init);
TEST (authorization_allowed_test_authorize_clear_component_manifests_null);
TEST (authorization_allowed_test_authorize_reset_intrusion);
TEST (authorization_allowed_test_authorize_reset_intrusion_no_authorization);
TEST (authorization_allowed_test_authorize_reset_intrusion_challenge);
TEST (authorization_allowed_test_authorize_reset_intrusion_static_init);
TEST (authorization_allowed_test_authorize_reset_intrusion_null);

TEST_SUITE_END;
// *INDENT-ON*
