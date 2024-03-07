// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "pcisig/tdisp/cmd_interface_tdisp_responder_static.h"
#include "pcisig/tdisp/tdisp_driver.h"
#include "pcisig/tdisp/tdisp_commands.h"
#include "testing/mock/pcisig/tdisp/tdisp_driver_mock.h"
#include "common/array_size.h"
#include "pcisig/doe/doe_base_protocol.h"


TEST_SUITE_LABEL ("cmd_interface_tdisp_responder");

#define TDISP_SUPPORTED_VERSION_MAX_COUNT		1

/**
 * Dependencies for testing.
 */
struct cmd_interface_tdisp_responder_testing {
	struct cmd_interface_tdisp_responder tdisp_responder;		/**< TDISP responder interface. */
	struct tdisp_driver_interface_mock tdisp_driver_mock;		/**< TDISP driver mock. */
	uint8_t version_num[TDISP_SUPPORTED_VERSION_MAX_COUNT];		/**< Version number entries. */
	struct tdisp_state tdisp_state;								/**< TDISP state. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to initialize.
 */
static void cmd_interface_tdisp_responder_testing_init_dependencies (CuTest *test,
	struct cmd_interface_tdisp_responder_testing *testing)
{
	int status;

	status = tdisp_driver_interface_mock_init (&testing->tdisp_driver_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to release all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to release.
 */
static void cmd_interface_tdisp_responder_testing_release_dependencies (CuTest *test,
	struct cmd_interface_tdisp_responder_testing *testing)
{
	int status;

	status = tdisp_driver_interface_mock_validate_and_release (&testing->tdisp_driver_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the TDISP responder interface for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to initialize.
 */
static void cmd_interface_tdisp_responder_testing_init (CuTest *test,
	struct cmd_interface_tdisp_responder_testing *testing)
{
	int status;
	uint8_t version_num[TDISP_SUPPORTED_VERSION_MAX_COUNT] = { TDISP_VERSION_1_0 };

	memcpy (testing->version_num, version_num, sizeof (version_num));

	cmd_interface_tdisp_responder_testing_init_dependencies (test, testing);

	status = cmd_interface_tdisp_responder_init (&testing->tdisp_responder, &testing->tdisp_state,
		&testing->tdisp_driver_mock.base, testing->version_num, ARRAY_SIZE (testing->version_num));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release the TDISP responder interface after testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to release.
 */
static void cmd_interface_tdisp_responder_testing_release (CuTest *test,
	struct cmd_interface_tdisp_responder_testing *testing)
{
	cmd_interface_tdisp_responder_release (&testing->tdisp_responder);

	cmd_interface_tdisp_responder_testing_release_dependencies (test, testing);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_tdisp_responder_test_static_init (CuTest *test)
{
	struct cmd_interface_tdisp_responder_testing testing;
	int status;
	const struct cmd_interface_tdisp_responder tdisp_responder =
		cmd_interface_tdisp_responder_static_init (&testing.tdisp_state, 
		&testing.tdisp_driver_mock.base, testing.version_num, TDISP_SUPPORTED_VERSION_MAX_COUNT);

	TEST_START;

	cmd_interface_tdisp_responder_testing_init_dependencies (test, &testing);

	status = cmd_interface_tdisp_responder_init_state (&tdisp_responder);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, tdisp_responder.base.process_request);

	CuAssertPtrNotNull (test, tdisp_responder.base.process_response);
	CuAssertPtrNotNull (test, tdisp_responder.base.generate_error_packet);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_static_init_invalid_param (CuTest *test)
{
	int status;

	const struct cmd_interface_tdisp_responder tdisp_responder =
		cmd_interface_tdisp_responder_static_init (NULL,
			(struct tdisp_driver*) (0xDEADBEEF), (uint8_t*) (0x12345678),
			TDISP_SUPPORTED_VERSION_MAX_COUNT);

	const struct cmd_interface_tdisp_responder tdisp_responder2 =
		cmd_interface_tdisp_responder_static_init (
			(struct tdisp_state*) (0xBAADF00D), NULL, (uint8_t*) (0x12345678),
			TDISP_SUPPORTED_VERSION_MAX_COUNT);

	const struct cmd_interface_tdisp_responder tdisp_responder3 =
		cmd_interface_tdisp_responder_static_init (
			(struct tdisp_state*) (0xBAADF00D),
			(struct tdisp_driver*) (0xDEADBEEF), NULL, TDISP_SUPPORTED_VERSION_MAX_COUNT);

	const struct cmd_interface_tdisp_responder tdisp_responder4 =
		cmd_interface_tdisp_responder_static_init (
			(struct tdisp_state*) (0xBAADF00D),
			(struct tdisp_driver*) (0xDEADBEEF), (uint8_t*) (0x12345678), 0);

	TEST_START;

	status = cmd_interface_tdisp_responder_init_state (NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init_state (&tdisp_responder);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init_state (&tdisp_responder2);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init_state (&tdisp_responder3);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init_state (&tdisp_responder4);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);
}

static void cmd_interface_tdisp_responder_test_init (CuTest *test)
{
	struct cmd_interface_tdisp_responder_testing testing;
	int status;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init_dependencies (test, &testing);

	status = cmd_interface_tdisp_responder_init (&testing.tdisp_responder, &testing.tdisp_state,
		&testing.tdisp_driver_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, testing.tdisp_responder.base.process_request);
	CuAssertPtrNotNull (test, testing.tdisp_responder.base.process_response);
	CuAssertPtrNotNull (test, testing.tdisp_responder.base.generate_error_packet);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_init_invalid_param (CuTest *test)
{
	int status;
	struct cmd_interface_tdisp_responder tdisp_responder;

	TEST_START;

	status = cmd_interface_tdisp_responder_init (NULL,
		(struct tdisp_state*) (0xBAADF00D),
		(struct tdisp_driver*) (0xDEADBEEF),
		(uint8_t*) (0x12345678), TDISP_SUPPORTED_VERSION_MAX_COUNT);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&tdisp_responder, NULL,
		(struct tdisp_driver*) (0xDEADBEEF), (uint8_t*) (0x12345678),
		TDISP_SUPPORTED_VERSION_MAX_COUNT);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&tdisp_responder,
		(struct tdisp_state*) (0xBAADF00D), NULL, (uint8_t*) (0x12345678),
		TDISP_SUPPORTED_VERSION_MAX_COUNT);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&tdisp_responder,
		(struct tdisp_state*) (0xBAADF00D),
		(struct tdisp_driver*) (0xDEADBEEF), NULL, TDISP_SUPPORTED_VERSION_MAX_COUNT);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&tdisp_responder,
		(struct tdisp_state*) (0xBAADF00D),
		(struct tdisp_driver*) (0xDEADBEEF), (uint8_t*) (0x12345678), 0);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);
}

static void cmd_interface_tdisp_responder_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_tdisp_responder_release (NULL);
}

static void cmd_interface_tdisp_responder_test_process_request_get_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_version_response *resp = (struct tdisp_version_response*) buf;
	struct cmd_interface_msg request;
	size_t version_length;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;
	version_length = tdisp_responder->version_num_count * sizeof (uint8_t);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_get_version_request);
	request.length = request.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id = 0;

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_version_response) + version_length, request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_VERSION, resp->header.message_type);
	CuAssertIntEquals (test, 0, resp->header.interface_id.function_id);
	CuAssertIntEquals (test, tdisp_responder->version_num_count, resp->version_num_count);
	CuAssertIntEquals (test, 0, memcmp (resp + 1, testing.version_num, version_length));

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_invalid_params (CuTest *test)
{
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	status = tdisp_responder->base.process_request (NULL, (struct cmd_interface_msg*) 0xBAADF00D);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_responder->base.process_request ((const struct cmd_interface*) 0xDEADBEEF,
		NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_unsupported_message_type (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_version_request *rq = (struct tdisp_get_version_request*) buf;
	struct tdisp_error_response *error_response = (struct tdisp_error_response*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_get_version_request);
	request.length = request.payload_length;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = UINT8_MAX;
	rq->header.interface_id.function_id = 0;

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_error_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, error_response, request.payload);
	CuAssertIntEquals (test, TDISP_VERSION_1_0, error_response->header.version);
	CuAssertIntEquals (test, TDISP_ERROR_CODE_UNSUPPORTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, TDISP_ERROR, error_response->header.message_type);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_payload_lt_min_length (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_header) - 1;
	request.length = request.payload_length;

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_MSG_SIZE, status);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_response (CuTest *test)
{
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	status = tdisp_responder->base.process_response ((const struct cmd_interface*) 0xDEADBEEF,
		(struct cmd_interface_msg*) 0xBAADB00F);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_generate_error_packet (CuTest *test)
{
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	status = tdisp_responder->base.generate_error_packet ((const struct cmd_interface*) 0xDEADBEEF,
		(struct cmd_interface_msg*) 0xBAADB00F, 0, 0, 0);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

TEST_SUITE_START (cmd_interface_tdisp_responder);

TEST (cmd_interface_tdisp_responder_test_static_init);
TEST (cmd_interface_tdisp_responder_test_static_init_invalid_param);
TEST (cmd_interface_tdisp_responder_test_init);
TEST (cmd_interface_tdisp_responder_test_init_invalid_param);
TEST (cmd_interface_tdisp_responder_test_release_null);
TEST (cmd_interface_tdisp_responder_test_process_request_get_version);
TEST (cmd_interface_tdisp_responder_test_process_request_invalid_params);
TEST (cmd_interface_tdisp_responder_test_process_request_payload_lt_min_length);
TEST (cmd_interface_tdisp_responder_test_process_request_unsupported_message_type);
TEST (cmd_interface_tdisp_responder_test_process_response);
TEST (cmd_interface_tdisp_responder_test_generate_error_packet);

TEST_SUITE_END;
