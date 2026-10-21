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
#include "testing/mock/common/authorized_data_mock.h"
#include "testing/mock/common/authorized_execution_mock.h"


TEST_SUITE_LABEL ("cmd_authorization");


/**
 * Dependencies for testing the command authorization handler.
 */
struct cmd_authorization_testing {
	struct authorization_mock bypass;				/**< Mock for revert bypass authorization. */
	struct authorized_data_mock bypass_data;		/**< Mock for revert bypass data parsing. */
	struct authorized_execution_mock bypass_op;		/**< Mock for the revert bypass operation. */
	struct authorization_mock defaults;				/**< Mock for factory default authorization. */
	struct authorized_data_mock defaults_data;		/**< Mock for factory default data parsing. */
	struct authorized_execution_mock defaults_op;	/**< Mock for the factory default operation. */
	struct authorization_mock platform;				/**< Mock for platform config authorization. */
	struct authorized_data_mock platform_data;		/**< Mock for platform config data parsing. */
	struct authorized_execution_mock platform_op;	/**< Mock for the platform config operation. */
	struct authorization_mock components;			/**< Mock for component config authorization. */
	struct authorized_data_mock components_data;	/**< Mock for component config data parsing. */
	struct authorized_execution_mock components_op;	/**< Mock for the component config operation. */
	struct authorization_mock intrusion;			/**< Mock for intrusion authorization. */
	struct authorized_data_mock intrusion_data;		/**< Mock for intrusion data parsing. */
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

	status = authorized_data_mock_init (&auth->bypass_data);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->bypass_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[0].id = CERBERUS_PROTOCOL_REVERT_BYPASS;
	auth->op_list[0].authorization = &auth->bypass.base;
	auth->op_list[0].data = &auth->bypass_data.base;
	auth->op_list[0].execution = &auth->bypass_op.base;

	status = authorization_mock_init (&auth->defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorized_data_mock_init (&auth->defaults_data);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->defaults_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[1].id = CERBERUS_PROTOCOL_FACTORY_RESET;
	auth->op_list[1].authorization = &auth->defaults.base;
	auth->op_list[1].data = &auth->defaults_data.base;
	auth->op_list[1].execution = &auth->defaults_op.base;

	status = authorization_mock_init (&auth->platform);
	CuAssertIntEquals (test, 0, status);

	status = authorized_data_mock_init (&auth->platform_data);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->platform_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[2].id = CERBERUS_PROTOCOL_CLEAR_PCD;
	auth->op_list[2].authorization = &auth->platform.base;
	auth->op_list[2].data = &auth->platform_data.base;
	auth->op_list[2].execution = &auth->platform_op.base;

	status = authorization_mock_init (&auth->components);
	CuAssertIntEquals (test, 0, status);

	status = authorized_data_mock_init (&auth->components_data);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->components_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[3].id = CERBERUS_PROTOCOL_CLEAR_CFM;
	auth->op_list[3].authorization = &auth->components.base;
	auth->op_list[3].data = &auth->components_data.base;
	auth->op_list[3].execution = &auth->components_op.base;

	status = authorization_mock_init (&auth->intrusion);
	CuAssertIntEquals (test, 0, status);

	status = authorized_data_mock_init (&auth->intrusion_data);
	CuAssertIntEquals (test, 0, status);

	status = authorized_execution_mock_init (&auth->intrusion_op);
	CuAssertIntEquals (test, 0, status);

	auth->op_list[4].id = CERBERUS_PROTOCOL_RESET_INTRUSION;
	auth->op_list[4].authorization = &auth->intrusion.base;
	auth->op_list[4].data = &auth->intrusion_data.base;
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
	status |= authorized_data_mock_validate_and_release (&auth->bypass_data);
	status |= authorized_execution_mock_validate_and_release (&auth->bypass_op);

	status |= authorization_mock_validate_and_release (&auth->defaults);
	status |= authorized_data_mock_validate_and_release (&auth->defaults_data);
	status |= authorized_execution_mock_validate_and_release (&auth->defaults_op);

	status |= authorization_mock_validate_and_release (&auth->platform);
	status |= authorized_data_mock_validate_and_release (&auth->platform_data);
	status |= authorized_execution_mock_validate_and_release (&auth->platform_op);

	status |= authorization_mock_validate_and_release (&auth->components);
	status |= authorized_data_mock_validate_and_release (&auth->components_data);
	status |= authorized_execution_mock_validate_and_release (&auth->components_op);

	status |= authorization_mock_validate_and_release (&auth->intrusion);
	status |= authorized_data_mock_validate_and_release (&auth->intrusion_data);
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

static void cmd_authorization_test_operation_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth;
	struct cmd_authorization_operation operation1 = cmd_authorization_operation_static_init (12,
		&auth.bypass.base, &auth.bypass_data.base, &auth.bypass_op.base);
	struct cmd_authorization_operation operation2 = cmd_authorization_operation_static_init (20,
		&auth.defaults.base, &auth.defaults_data.base, &auth.defaults_op.base);

	TEST_START;

	CuAssertIntEquals (test, 12, operation1.id);
	CuAssertPtrEquals (test, &auth.bypass.base, (void*) operation1.authorization);
	CuAssertPtrEquals (test, &auth.bypass_data.base, (void*) operation1.data);
	CuAssertPtrEquals (test, &auth.bypass_op.base, (void*) operation1.execution);

	CuAssertIntEquals (test, 20, operation2.id);
	CuAssertPtrEquals (test, &auth.defaults.base, (void*) operation2.authorization);
	CuAssertPtrEquals (test, &auth.defaults_data.base, (void*) operation2.data);
	CuAssertPtrEquals (test, &auth.defaults_op.base, (void*) operation2.execution);
}

static void cmd_authorization_test_init (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = cmd_authorization_init (&auth.test, auth.op_list, ARRAY_SIZE (auth.op_list));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.test.authorize_operation);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_init_no_operations (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;

	TEST_START;

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = cmd_authorization_init (&auth.test, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_init_null (CuTest *test)
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

static void cmd_authorization_test_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};

	TEST_START;

	CuAssertPtrNotNull (test, auth.test.authorize_operation);

	cmd_authorization_testing_init_dependencies (test, &auth);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_authorization_release (NULL);
}

static void cmd_authorization_test_authorize_operation (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const uint8_t *aad = &token[HASH_TESTING_FULL_BLOCK_1024_LEN / 2];
	size_t aad_length = HASH_TESTING_FULL_BLOCK_1024_LEN / 2;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));

	status |= mock_expect (&auth.bypass_data.mock, auth.bypass_data.base.get_authenticated_data,
		&auth.bypass_data, 0, MOCK_ARG_PTR (token), MOCK_ARG (length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.bypass_data.mock, 2, &aad, sizeof (aad), -1);
	status |= mock_expect_output (&auth.bypass_data.mock, 3, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.bypass_op.mock, auth.bypass_op.base.validate_data, &auth.bypass_op,
		0, MOCK_ARG_PTR_CONTAINS (aad, aad_length), MOCK_ARG (aad_length));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth.op_list[0].execution, (void*) op_context.execution);
	CuAssertPtrEquals (test, (void*) aad, (void*) op_context.data);
	CuAssertIntEquals (test, aad_length, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_no_authenticated_data (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.intrusion.mock, auth.intrusion.base.authorize, &auth.intrusion, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));

	status |= mock_expect (&auth.intrusion_op.mock, auth.intrusion_op.base.validate_data,
		&auth.intrusion_op, 0, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	/* Remove the data parser for an operation. */
	auth.op_list[4].data = NULL;

	status = auth.test.authorize_operation (&auth.test, auth.op_list[4].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth.op_list[4].execution, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_no_authorization (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	/* Remove authorization for an operation. */
	auth.op_list[2].authorization = NULL;

	status = auth.test.authorize_operation (&auth.test, auth.op_list[2].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_no_execution (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_2048;
	size_t length = HASH_TESTING_FULL_BLOCK_2048_LEN;
	const uint8_t *aad = &token[HASH_TESTING_FULL_BLOCK_2048_LEN / 2];
	size_t aad_length = HASH_TESTING_FULL_BLOCK_2048_LEN / 2;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.defaults.mock, auth.defaults.base.authorize, &auth.defaults, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));

	status |= mock_expect (&auth.defaults_data.mock, auth.defaults_data.base.get_authenticated_data,
		&auth.defaults_data, 0, MOCK_ARG_PTR (token), MOCK_ARG (length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.defaults_data.mock, 2, &aad, sizeof (aad), -1);
	status |= mock_expect_output (&auth.defaults_data.mock, 3, &aad_length, sizeof (aad_length),
		-1);

	CuAssertIntEquals (test, 0, status);

	/* Remove execution for an operation. */
	auth.op_list[1].execution = NULL;

	status = auth.test.authorize_operation (&auth.test, auth.op_list[1].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, (void*) aad, (void*) op_context.data);
	CuAssertIntEquals (test, aad_length, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_challenge (CuTest *test)
{
	struct cmd_authorization_testing auth;
	const uint8_t *token_data = HASH_TESTING_FULL_BLOCK_1024;
	size_t token_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	int status;
	const uint8_t *token = NULL;
	size_t length;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.defaults.mock, auth.defaults.base.authorize, &auth.defaults,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	status |= mock_expect_output (&auth.defaults.mock, 0, &token_data, sizeof (token_data), -1);
	status |= mock_expect_output (&auth.defaults.mock, 1, &token_length, sizeof (token_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[1].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrEquals (test, (void*) token_data, (void*) token);
	CuAssertIntEquals (test, HASH_TESTING_FULL_BLOCK_1024_LEN, length);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_1024, token, length);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_null_token_authorized (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = NULL;
	size_t length = 0;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.platform.mock, auth.platform.base.authorize, &auth.platform, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));

	status |= mock_expect (&auth.platform_op.mock, auth.platform_op.base.validate_data,
		&auth.platform_op, 0, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[2].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth.op_list[2].execution, (void*) op_context.execution);
	CuAssertPtrEquals (test, (void*) NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_static_init (CuTest *test)
{
	struct cmd_authorization_testing auth = {
		.test = cmd_authorization_static_init (auth.op_list, ARRAY_SIZE (auth.op_list))
	};
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const uint8_t *aad = &token[HASH_TESTING_FULL_BLOCK_1024_LEN / 2];
	size_t aad_length = HASH_TESTING_FULL_BLOCK_1024_LEN / 2;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.components.mock, auth.components.base.authorize, &auth.components,
		0, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));

	status |= mock_expect (&auth.components_data.mock,
		auth.components_data.base.get_authenticated_data, &auth.components_data, 0,
		MOCK_ARG_PTR (token), MOCK_ARG (length), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.components_data.mock, 2, &aad, sizeof (aad), -1);
	status |= mock_expect_output (&auth.components_data.mock, 3, &aad_length, sizeof (aad_length),
		-1);

	status |= mock_expect (&auth.components_op.mock, auth.components_op.base.validate_data,
		&auth.components_op, 0, MOCK_ARG_PTR_CONTAINS (aad, aad_length), MOCK_ARG (aad_length));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[3].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth.op_list[3].execution, (void*) op_context.execution);
	CuAssertPtrEquals (test, (void*) aad, (void*) op_context.data);
	CuAssertIntEquals (test, aad_length, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_null (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_operation (NULL, auth.op_list[0].id, &token, &length, &op_context);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	memset (&op_context, 0xaa, sizeof (op_context));

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, NULL, &length,
		&op_context);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	memset (&op_context, 0xaa, sizeof (op_context));

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, NULL,
		&op_context);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length, NULL);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_unsupported (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = auth.test.authorize_operation (&auth.test, 15, &token, &length, &op_context);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_UNSUPPORTED_OP, status);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_authorize_error (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass,
		AUTHORIZATION_AUTHORIZE_FAILED, MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, AUTHORIZATION_AUTHORIZE_FAILED, status);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_authenticated_data_error (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));

	status |= mock_expect (&auth.bypass_data.mock, auth.bypass_data.base.get_authenticated_data,
		&auth.bypass_data, AUTH_DATA_GET_AAD_FAILED, MOCK_ARG_PTR (token), MOCK_ARG (length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, AUTH_DATA_GET_AAD_FAILED, status);
	CuAssertPtrEquals (test, NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}

static void cmd_authorization_test_authorize_operation_validate_data_error (CuTest *test)
{
	struct cmd_authorization_testing auth;
	int status;
	const uint8_t *token = HASH_TESTING_FULL_BLOCK_1024;
	size_t length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const uint8_t *aad = &token[HASH_TESTING_FULL_BLOCK_1024_LEN / 2];
	size_t aad_length = HASH_TESTING_FULL_BLOCK_1024_LEN / 2;
	struct cmd_authorization_operation_context op_context;

	TEST_START;

	memset (&op_context, 0xaa, sizeof (op_context));

	cmd_authorization_testing_init (test, &auth);

	status = mock_expect (&auth.bypass.mock, auth.bypass.base.authorize, &auth.bypass, 0,
		MOCK_ARG_PTR (&token), MOCK_ARG_PTR (&length));

	status |= mock_expect (&auth.bypass_data.mock, auth.bypass_data.base.get_authenticated_data,
		&auth.bypass_data, 0, MOCK_ARG_PTR (token), MOCK_ARG (length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.bypass_data.mock, 2, &aad, sizeof (aad), -1);
	status |= mock_expect_output (&auth.bypass_data.mock, 3, &aad_length, sizeof (aad_length), -1);

	status |= mock_expect (&auth.bypass_op.mock, auth.bypass_op.base.validate_data, &auth.bypass_op,
		AUTHORIZED_EXECUTION_CHECK_DATA_FAILED, MOCK_ARG_PTR_CONTAINS (aad, aad_length),
		MOCK_ARG (aad_length));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.authorize_operation (&auth.test, auth.op_list[0].id, &token, &length,
		&op_context);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_CHECK_DATA_FAILED, status);
	CuAssertPtrEquals (test, (void*) NULL, (void*) op_context.execution);
	CuAssertPtrEquals (test, (void*) NULL, (void*) op_context.data);
	CuAssertIntEquals (test, 0, op_context.data_length);

	cmd_authorization_testing_release (test, &auth);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_authorization);

TEST (cmd_authorization_test_operation_static_init);
TEST (cmd_authorization_test_init);
TEST (cmd_authorization_test_init_no_operations);
TEST (cmd_authorization_test_init_null);
TEST (cmd_authorization_test_static_init);
TEST (cmd_authorization_test_release_null);
TEST (cmd_authorization_test_authorize_operation);
TEST (cmd_authorization_test_authorize_operation_no_authenticated_data);
TEST (cmd_authorization_test_authorize_operation_no_authorization);
TEST (cmd_authorization_test_authorize_operation_no_execution);
TEST (cmd_authorization_test_authorize_operation_challenge);
TEST (cmd_authorization_test_authorize_operation_null_token_authorized);
TEST (cmd_authorization_test_authorize_operation_static_init);
TEST (cmd_authorization_test_authorize_operation_null);
TEST (cmd_authorization_test_authorize_operation_unsupported);
TEST (cmd_authorization_test_authorize_operation_authorize_error);
TEST (cmd_authorization_test_authorize_operation_authenticated_data_error);
TEST (cmd_authorization_test_authorize_operation_validate_data_error);

TEST_SUITE_END;
// *INDENT-ON*
