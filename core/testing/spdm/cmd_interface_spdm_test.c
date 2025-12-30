// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "spdm/cmd_interface_spdm.h"
#include "spdm/spdm_commands.h"
#include "spdm/spdm_protocol.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"


TEST_SUITE_LABEL ("cmd_interface_spdm");


/**
 * Dependencies for testing the SPDM command interface.
 */
struct cmd_interface_spdm_testing {
	struct cmd_interface_spdm handler;	/**< Command handler instance. */
};


/**
 * Helper function to setup the SPDM command interface.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 * @param add_observer Flag indicating whether to register observer for SPDM response notifications.
 */
static void setup_cmd_interface_spdm_mock_test (CuTest *test,
	struct cmd_interface_spdm_testing *cmd)
{
	int status;

	status = cmd_interface_spdm_init (&cmd->handler);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release the SPDM command interface instance.
 *
 * @param test The test framework.
 * @param cmd The testing instance to release.
 */
static void complete_cmd_interface_spdm_mock_test (CuTest *test,
	struct cmd_interface_spdm_testing *cmd)
{
	cmd_interface_spdm_deinit (&cmd->handler);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_spdm_test_init (CuTest *test)
{
	struct cmd_interface_spdm interface;
	int status;

	TEST_START;

	status = cmd_interface_spdm_init (&interface);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, interface.base.process_request);
	CuAssertPtrNotNull (test, interface.base.process_response);

	cmd_interface_spdm_deinit (&interface);
}

static void cmd_interface_spdm_test_init_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = cmd_interface_spdm_init (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void cmd_interface_spdm_test_deinit_invalid_arg (CuTest *test)
{
	TEST_START;

	cmd_interface_spdm_deinit (NULL);
}

static void cmd_interface_spdm_test_process_request (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_spdm);

TEST (cmd_interface_spdm_test_init);
TEST (cmd_interface_spdm_test_init_invalid_arg);
TEST (cmd_interface_spdm_test_deinit_invalid_arg);
TEST (cmd_interface_spdm_test_process_request);
TEST (cmd_interface_spdm_test_process_response);

TEST_SUITE_END;
// *INDENT-ON*
