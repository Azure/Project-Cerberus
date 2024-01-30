// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "spdm/cmd_interface_spdm_responder_static.h"
#include "spdm/spdm_commands.h"
#include "common/array_size.h"
#include "pcisig/doe/doe_base_protocol.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/spdm/spdm_transcript_manager_mock.h"


TEST_SUITE_LABEL ("cmd_interface_spdm_responder");


/**
 * Dependencies for testing.
 */
struct cmd_interface_spdm_responder_testing {
	struct cmd_interface_spdm_responder spdm_responder;				/**< The SPDM responder being tested. */
	struct spdm_state spdm_responder_state;							/**< The SPDM responder state. */
	struct spdm_transcript_manager_state state;						/**< The transcript manager state. */
	struct spdm_transcript_manager_mock transcript_manager_mock;	/**< The transcript manager. */
	struct spdm_transcript_manager_state transcript_manager_state; 	/**< The transcript manager state. */
	struct hash_engine_mock hash_engine_mock;						/**< Mock hash engine for the responder. */
	struct spdm_version_num_entry version_num[SPDM_MAX_MINOR_VERSION];	/**< Version number entries. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to initialize.
 */
void cmd_interface_spdm_responder_testing_init_dependencies (CuTest *test,
	struct cmd_interface_spdm_responder_testing *testing)
{
	int status;
	struct spdm_version_num_entry version_num[SPDM_MAX_MINOR_VERSION] =
		{ {1, 1, 0, 0}, {1, 2, 0, 0} };

	memcpy (testing->version_num, version_num, sizeof (version_num));

	status = spdm_transcript_manager_mock_init (&testing->transcript_manager_mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&testing->hash_engine_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
void cmd_interface_spdm_responder_testing_release_dependencies (CuTest *test,
	struct cmd_interface_spdm_responder_testing *testing)
{
	int status;
	status = spdm_transcript_manager_mock_validate_and_release (
		&testing->transcript_manager_mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&testing->hash_engine_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the SPDM responder for testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to initialize.
 */
static void cmd_interface_spdm_responder_testing_init (CuTest *test,
	struct cmd_interface_spdm_responder_testing *testing)
{
	int status;

	cmd_interface_spdm_responder_testing_init_dependencies (test, testing);

	status = cmd_interface_spdm_responder_init (&testing->spdm_responder,
		&testing->spdm_responder_state, &testing->transcript_manager_mock.base,
		&testing->hash_engine_mock.base, testing->version_num,
		ARRAY_SIZE (testing->version_num));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release SPDM responder and validate all mocks.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
static void cmd_interface_spdm_responder_testing_release (CuTest *test,
	struct cmd_interface_spdm_responder_testing *testing)
{
	cmd_interface_spdm_responder_deinit (&testing->spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, testing);
}

/*******************
 * Test cases
 *******************/

static void cmd_interface_spdm_responder_test_static_init (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num));

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, spdm_responder.base.process_request);
	CuAssertPtrNotNull (test, spdm_responder.base.process_response);
	CuAssertPtrNotNull (test, spdm_responder.base.generate_error_packet);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_invalid_arg (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (NULL,
			(struct spdm_transcript_manager*) 0xDEADBEEF, (struct hash_engine*) 0xBAADF00D, 
			(struct spdm_version_num_entry*) 0xBADDCAFE, 2);

	struct cmd_interface_spdm_responder spdm_responder2 =
		cmd_interface_spdm_responder_static_init ((struct spdm_state*) 0xDEADBEEF, NULL,
			(struct hash_engine*) 0xBAADF00D, (struct spdm_version_num_entry*) 0xBADDCAFE, 2);

	struct cmd_interface_spdm_responder spdm_responder3 =
		cmd_interface_spdm_responder_static_init ((struct spdm_state*) 0xBAADF00D,
			(struct spdm_transcript_manager*) 0xDEADBEEF, NULL,
			(struct spdm_version_num_entry*) 0xBADDCAFE, 3);

	struct cmd_interface_spdm_responder spdm_responder4 =
		cmd_interface_spdm_responder_static_init ((struct spdm_state*) 0xDEADBEEF,
			(struct spdm_transcript_manager*) 0xBAADF00D, (struct hash_engine*) 0xCAFEB0BA,
			NULL, 2);

	struct cmd_interface_spdm_responder spdm_responder5 =
		cmd_interface_spdm_responder_static_init ((struct spdm_state*) 0xDEADBEEF,
			(struct spdm_transcript_manager*) 0xBAADF00D, (struct hash_engine*) 0xCAFEB0BA,
			(struct spdm_version_num_entry*) 0xBADDCAFE, 0);

	TEST_START;

	/* state = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder3);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder4);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num_count = 0 */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder5);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);
}

static void cmd_interface_spdm_responder_test_init (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, testing.spdm_responder.base.process_request);
	CuAssertPtrNotNull (test, testing.spdm_responder.base.process_response);
	CuAssertPtrNotNull (test, testing.spdm_responder.base.generate_error_packet);

	cmd_interface_spdm_responder_deinit (&testing.spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_init_invalid_arg (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	/* spdm_responder = NULL */
	status = cmd_interface_spdm_responder_init (NULL, &testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, &testing.hash_engine_mock.base,
		testing.version_num, ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* state = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder, NULL,
		&testing.transcript_manager_mock.base, &testing.hash_engine_mock.base,
		testing.version_num, ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, NULL, &testing.hash_engine_mock.base,
		testing.version_num, ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, NULL,
		testing.version_num, ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, NULL, ARRAY_SIZE (testing.version_num));

	/* version_num_count = 0 */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, 0);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	uint8_t expected_buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct spdm_get_version_request rq = {0};
	struct spdm_get_version_response *resp = (struct spdm_get_version_response*) buf;
	struct spdm_get_version_response *expected_rsp =
		(struct spdm_get_version_response*) expected_buf;
	struct cmd_interface_msg request;
	size_t version_count = SPDM_MAX_MINOR_VERSION - SPDM_MIN_MINOR_VERSION + 1;
	size_t version_length = version_count * sizeof (struct spdm_version_num_entry);
	struct spdm_version_num_entry *version_num =
		spdm_get_version_resp_version_table (expected_rsp);
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	resp = (struct spdm_get_version_response*) buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_version_request);
	request.length = request.payload_length;

	rq.header.spdm_minor_version = 0;
	rq.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.header.req_rsp_code = SPDM_REQUEST_GET_VERSION;
	rq.reserved = 0;
	rq.reserved2 = 0;
	memcpy (request.payload, &rq, sizeof (struct spdm_get_version_request));

	expected_rsp->header.spdm_minor_version = 0;
	expected_rsp->header.spdm_major_version = 1;
	expected_rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;
	expected_rsp->reserved = 0;
	expected_rsp->reserved2 = 0;
	expected_rsp->reserved3 = 0;
	expected_rsp->version_num_entry_count = version_count;
	memcpy (version_num, testing.version_num,
		sizeof (struct spdm_version_num_entry) * ARRAY_SIZE (testing.version_num));

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset,
		&testing.transcript_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (&rq, sizeof (struct spdm_get_version_request)),
		MOCK_ARG (sizeof (struct spdm_get_version_request)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (expected_rsp, sizeof (struct spdm_get_version_request) +
			version_length),
		MOCK_ARG (sizeof (struct spdm_get_version_response) + version_length),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (*resp) + version_length, request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, 0, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_VERSION, resp->header.req_rsp_code);
	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 0, resp->reserved2);
	CuAssertIntEquals (test, 0, resp->reserved3);
	CuAssertIntEquals (test, 2, resp->version_num_entry_count);

	version_num = spdm_get_version_resp_version_table (resp);
	status = memcmp (version_num, testing.version_num,
		sizeof (struct spdm_version_num_entry) * ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, 0, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_version_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct spdm_error_response *error_response = (struct spdm_error_response*) buf;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_version_request) - 1;
	request.length = request.payload_length;

	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;
	rq->reserved = 0;
	rq->reserved2 = 0;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, error_response->header.spdm_major_version);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_invalid_arg (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	/* intf = NULL */
	status = testing.spdm_responder.base.process_request (NULL,
		(struct cmd_interface_msg*) (0xDEADBEEF));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* request = NULL */
	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_short_payload (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_protocol_header) - 1;
	request.length = request.payload_length;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_PAYLOAD_TOO_SHORT, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_unsupported_major_version (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_version_request);
	request.length = request.payload_length;

	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION + 1;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;
	rq->reserved = 0;
	rq->reserved2 = 0;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_NOT_INTEROPERABLE, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_unsupported_request_code (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_spdm_responder_testing testing;
	struct spdm_error_response *error_response = (struct spdm_error_response*) buf;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_version_request);
	request.length = request.payload_length;

	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = -1;
	rq->reserved = 0;
	rq->reserved2 = 0;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_UNSUPPORTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, error_response->header.spdm_major_version);
	CuAssertIntEquals (test, 0, error_response->header.spdm_minor_version);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_response (
	CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	status = testing.spdm_responder.base.process_response (
		(const struct cmd_interface*)(0xDEADBEEF), (struct cmd_interface_msg*)(0xBAADF00D));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_generate_error_packet (
	CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	status = testing.spdm_responder.base.generate_error_packet (
		(const struct cmd_interface*)(0xDEADBEEF), (struct cmd_interface_msg*)(0xBAADF00D),
		-1, -1, -1);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

TEST_SUITE_START (cmd_interface_spdm_responder);

TEST (cmd_interface_spdm_responder_test_static_init);
TEST (cmd_interface_spdm_responder_test_static_init_invalid_arg);
TEST (cmd_interface_spdm_responder_test_init);
TEST (cmd_interface_spdm_responder_test_init_invalid_arg);
TEST (cmd_interface_spdm_responder_test_process_request_get_version);
TEST (cmd_interface_spdm_responder_test_process_request_get_version_fail);
TEST (cmd_interface_spdm_responder_test_process_request_invalid_arg);
TEST (cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_short_payload);
TEST (cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_unsupported_major_version);
TEST (cmd_interface_spdm_responder_test_process_request_unsupported_request_code);
TEST (cmd_interface_spdm_responder_test_process_response);
TEST (cmd_interface_spdm_responder_test_generate_error_packet);

TEST_SUITE_END;



