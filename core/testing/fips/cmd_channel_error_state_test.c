// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "testing.h"
#include "fips/cmd_channel_error_state.h"
#include "fips/cmd_channel_error_state_static.h"
#include "testing/mock/cmd_interface/cmd_channel_mock.h"


TEST_SUITE_LABEL ("cmd_channel_error_state");


/**
 * Dependencies for testing a command channel interposer for FIPS error state handling.
 */
struct cmd_channel_error_state_testing {
	struct cmd_channel_mock channel;			/**< Mock for the interposed channel. */
	struct cmd_channel_error_state_state state;	/**< Variable context for the interposer. */
	struct cmd_channel_error_state test;		/**< Interposer instance under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param interposer Testing dependencies to initialize.
 */
static void cmd_channel_error_state_testing_init_dependencies (CuTest *test,
	struct cmd_channel_error_state_testing *interposer)
{
	int status;

	status = cmd_channel_mock_init (&interposer->channel, 4);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param interposer Testing dependencies to release.
 */
static void cmd_channel_error_state_testing_release_dependencies (CuTest *test,
	struct cmd_channel_error_state_testing *interposer)
{
	int status;

	status = cmd_channel_mock_validate_and_release (&interposer->channel);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an error state channel interposer for testing.
 *
 * @param test The test framework.
 * @param interposer Testing components to initialize.
 */
static void cmd_channel_error_state_testing_init (CuTest *test,
	struct cmd_channel_error_state_testing *interposer)
{
	int status;

	cmd_channel_error_state_testing_init_dependencies (test, interposer);

	status = cmd_channel_error_state_init (&interposer->test, &interposer->state,
		&interposer->channel.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static error state channel interposer for testing.
 *
 * @param test The test framework.
 * @param interposer Testing components to initialize.
 */
static void cmd_channel_error_state_testing_init_static (CuTest *test,
	struct cmd_channel_error_state_testing *interposer)
{
	int status;

	cmd_channel_error_state_testing_init_dependencies (test, interposer);

	status = cmd_channel_error_state_init_state (&interposer->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param interposer Testing components to release.
 */
static void cmd_channel_error_state_testing_release (CuTest *test,
	struct cmd_channel_error_state_testing *interposer)
{
	cmd_channel_error_state_release (&interposer->test);
	cmd_channel_error_state_testing_release_dependencies (test, interposer);
}


/*******************
 * Test cases
 *******************/

static void cmd_channel_error_state_test_init (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;

	TEST_START;

	cmd_channel_error_state_testing_init_dependencies (test, &interposer);

	status = cmd_channel_error_state_init (&interposer.test, &interposer.state,
		&interposer.channel.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, interposer.test.base_channel.receive_packet);
	CuAssertPtrNotNull (test, interposer.test.base_channel.send_packet);

	CuAssertPtrNotNull (test, interposer.test.base_entry.enter_error_state);

	status = cmd_channel_get_id (&interposer.test.base_channel);
	CuAssertIntEquals (test, 4, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_init_null (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;

	TEST_START;

	cmd_channel_error_state_testing_init_dependencies (test, &interposer);

	status = cmd_channel_error_state_init (NULL, &interposer.state, &interposer.channel.base);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_error_state_init (&interposer.test, NULL, &interposer.channel.base);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_error_state_init (&interposer.test, &interposer.state, NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	cmd_channel_error_state_testing_release_dependencies (test, &interposer);
}

static void cmd_channel_error_state_test_static_init (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer = {
		.test = cmd_channel_error_state_static_init (&interposer.state, &interposer.channel.base, 3)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, interposer.test.base_channel.receive_packet);
	CuAssertPtrNotNull (test, interposer.test.base_channel.send_packet);

	CuAssertPtrNotNull (test, interposer.test.base_entry.enter_error_state);

	cmd_channel_error_state_testing_init_dependencies (test, &interposer);

	status = cmd_channel_error_state_init_state (&interposer.test);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_get_id (&interposer.test.base_channel);
	CuAssertIntEquals (test, 3, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_static_init_null (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	struct cmd_channel_error_state null_state =
		cmd_channel_error_state_static_init ((struct cmd_channel_error_state_state*) NULL,
		&interposer.channel.base, 3);
	struct cmd_channel_error_state null_channel =
		cmd_channel_error_state_static_init (&interposer.state, NULL, 3);
	int status;

	TEST_START;

	cmd_channel_error_state_testing_init_dependencies (test, &interposer);

	status = cmd_channel_error_state_init_state (NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_error_state_init_state (&null_state);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_error_state_init_state (&null_channel);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	cmd_channel_error_state_testing_release_dependencies (test, &interposer);
}

static void cmd_channel_error_state_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_channel_error_state_release (NULL);
}

static void cmd_channel_error_state_test_receive_packet (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;
	struct cmd_packet pkt;
	int timeout = 100;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	status = mock_expect (&interposer.channel.mock, interposer.channel.base.receive_packet,
		&interposer.channel, 0, MOCK_ARG_PTR (&pkt), MOCK_ARG (timeout));
	CuAssertIntEquals (test, 0, status);

	status = interposer.test.base_channel.receive_packet (&interposer.test.base_channel, &pkt,
		timeout);
	CuAssertIntEquals (test, 0, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_receive_packet_in_error_state (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;
	struct cmd_packet pkt;
	int timeout = 200;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	status = mock_expect (&interposer.channel.mock, interposer.channel.base.receive_packet,
		&interposer.channel, 0, MOCK_ARG_PTR (&pkt), MOCK_ARG (timeout));
	CuAssertIntEquals (test, 0, status);

	/* Enter error state. */
	interposer.test.base_entry.enter_error_state (&interposer.test.base_entry, NULL);

	status = interposer.test.base_channel.receive_packet (&interposer.test.base_channel, &pkt,
		timeout);
	CuAssertIntEquals (test, 0, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_receive_packet_static_init (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer = {
		.test = cmd_channel_error_state_static_init (&interposer.state, &interposer.channel.base, 3)
	};
	int status;
	struct cmd_packet pkt;
	int timeout = 100;

	TEST_START;

	cmd_channel_error_state_testing_init_static (test, &interposer);

	status = mock_expect (&interposer.channel.mock, interposer.channel.base.receive_packet,
		&interposer.channel, 0, MOCK_ARG_PTR (&pkt), MOCK_ARG (timeout));
	CuAssertIntEquals (test, 0, status);

	status = interposer.test.base_channel.receive_packet (&interposer.test.base_channel, &pkt,
		timeout);
	CuAssertIntEquals (test, 0, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_receive_packet_static_init_in_error_state (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer = {
		.test = cmd_channel_error_state_static_init (&interposer.state, &interposer.channel.base, 3)
	};
	int status;
	struct cmd_packet pkt;
	int timeout = 100;

	TEST_START;

	cmd_channel_error_state_testing_init_static (test, &interposer);

	status = mock_expect (&interposer.channel.mock, interposer.channel.base.receive_packet,
		&interposer.channel, 0, MOCK_ARG_PTR (&pkt), MOCK_ARG (timeout));
	CuAssertIntEquals (test, 0, status);

	/* Enter error state. */
	interposer.test.base_entry.enter_error_state (&interposer.test.base_entry, NULL);

	status = interposer.test.base_channel.receive_packet (&interposer.test.base_channel, &pkt,
		timeout);
	CuAssertIntEquals (test, 0, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_receive_packet_null (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;
	struct cmd_packet pkt;
	int timeout = 100;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	status = interposer.test.base_channel.receive_packet (NULL, &pkt, timeout);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_receive_packet_error (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;
	struct cmd_packet pkt;
	int timeout = 100;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	status = mock_expect (&interposer.channel.mock, interposer.channel.base.receive_packet,
		&interposer.channel, CMD_CHANNEL_RX_FAILED, MOCK_ARG_PTR (&pkt), MOCK_ARG (timeout));
	CuAssertIntEquals (test, 0, status);

	status = interposer.test.base_channel.receive_packet (&interposer.test.base_channel, &pkt,
		timeout);
	CuAssertIntEquals (test, CMD_CHANNEL_RX_FAILED, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_send_packet (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;
	struct cmd_packet pkt;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	status = mock_expect (&interposer.channel.mock, interposer.channel.base.send_packet,
		&interposer.channel, 0, MOCK_ARG_PTR (&pkt));
	CuAssertIntEquals (test, 0, status);

	status = interposer.test.base_channel.send_packet (&interposer.test.base_channel, &pkt);
	CuAssertIntEquals (test, 0, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_send_packet_in_error_state (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;
	struct cmd_packet pkt;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	/* Enter error state. */
	interposer.test.base_entry.enter_error_state (&interposer.test.base_entry, NULL);

	status = interposer.test.base_channel.send_packet (&interposer.test.base_channel, &pkt);
	CuAssertIntEquals (test, 0, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_send_packet_static_init (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer = {
		.test = cmd_channel_error_state_static_init (&interposer.state, &interposer.channel.base, 3)
	};
	int status;
	struct cmd_packet pkt;

	TEST_START;

	cmd_channel_error_state_testing_init_static (test, &interposer);

	status = mock_expect (&interposer.channel.mock, interposer.channel.base.send_packet,
		&interposer.channel, 0, MOCK_ARG_PTR (&pkt));
	CuAssertIntEquals (test, 0, status);

	status = interposer.test.base_channel.send_packet (&interposer.test.base_channel, &pkt);
	CuAssertIntEquals (test, 0, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_send_packet_static_init_in_error_state (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer = {
		.test = cmd_channel_error_state_static_init (&interposer.state, &interposer.channel.base, 3)
	};
	int status;
	struct cmd_packet pkt;

	TEST_START;

	cmd_channel_error_state_testing_init_static (test, &interposer);

	/* Enter error state. */
	interposer.test.base_entry.enter_error_state (&interposer.test.base_entry, NULL);

	status = interposer.test.base_channel.send_packet (&interposer.test.base_channel, &pkt);
	CuAssertIntEquals (test, 0, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_send_packet_null (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;
	struct cmd_packet pkt;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	status = interposer.test.base_channel.send_packet (NULL, &pkt);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = interposer.test.base_channel.send_packet (&interposer.test.base_channel, NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_send_packet_error (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;
	int status;
	struct cmd_packet pkt;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	status = mock_expect (&interposer.channel.mock, interposer.channel.base.send_packet,
		&interposer.channel, CMD_CHANNEL_TX_FAILED, MOCK_ARG_PTR (&pkt));
	CuAssertIntEquals (test, 0, status);

	status = interposer.test.base_channel.send_packet (&interposer.test.base_channel, &pkt);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	cmd_channel_error_state_testing_release (test, &interposer);
}

static void cmd_channel_error_state_test_enter_error_state_null (CuTest *test)
{
	struct cmd_channel_error_state_testing interposer;

	TEST_START;

	cmd_channel_error_state_testing_init (test, &interposer);

	interposer.test.base_entry.enter_error_state (NULL, NULL);

	cmd_channel_error_state_testing_release (test, &interposer);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_channel_error_state);

TEST (cmd_channel_error_state_test_init);
TEST (cmd_channel_error_state_test_init_null);
TEST (cmd_channel_error_state_test_static_init);
TEST (cmd_channel_error_state_test_static_init_null);
TEST (cmd_channel_error_state_test_release_null);
TEST (cmd_channel_error_state_test_receive_packet);
TEST (cmd_channel_error_state_test_receive_packet_in_error_state);
TEST (cmd_channel_error_state_test_receive_packet_static_init);
TEST (cmd_channel_error_state_test_receive_packet_static_init_in_error_state);
TEST (cmd_channel_error_state_test_receive_packet_null);
TEST (cmd_channel_error_state_test_receive_packet_error);
TEST (cmd_channel_error_state_test_send_packet);
TEST (cmd_channel_error_state_test_send_packet_in_error_state);
TEST (cmd_channel_error_state_test_send_packet_static_init);
TEST (cmd_channel_error_state_test_send_packet_static_init_in_error_state);
TEST (cmd_channel_error_state_test_send_packet_null);
TEST (cmd_channel_error_state_test_send_packet_error);
TEST (cmd_channel_error_state_test_enter_error_state_null);

TEST_SUITE_END;
// *INDENT-ON*
