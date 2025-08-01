// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "common/array_size.h"
#include "pcisig/doe/doe_base_protocol.h"
#include "pcisig/tdisp/cmd_interface_tdisp_responder_static.h"
#include "pcisig/tdisp/tdisp_commands.h"
#include "pcisig/tdisp/tdisp_driver.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/pcisig/tdisp/tdisp_driver_mock.h"
#include "testing/mock/pcisig/tdisp/tdisp_tdi_context_manager_mock.h"


TEST_SUITE_LABEL ("cmd_interface_tdisp_responder");

#define TDISP_SUPPORTED_VERSION_MAX_COUNT		1

/**
 * Dependencies for testing.
 */
struct cmd_interface_tdisp_responder_testing {
	struct cmd_interface_tdisp_responder tdisp_responder;			/**< TDISP responder interface. */
	struct tdisp_driver_interface_mock tdisp_driver_mock;			/**< TDISP driver mock. */
	uint8_t version_num[TDISP_SUPPORTED_VERSION_MAX_COUNT];			/**< Version number entries. */
	struct tdisp_tdi_context_manager_mock tdi_context_manager_mock;	/**< Mock TDI context manager. */
	struct rng_engine_mock rng_mock;								/**< Mock RNG engine. */
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

	status = tdisp_tdi_context_manager_mock_init (&testing->tdi_context_manager_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&testing->rng_mock);
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

	status = rng_mock_validate_and_release (&testing->rng_mock);
	CuAssertIntEquals (test, 0, status);

	status =
		tdisp_tdi_context_manager_mock_validate_and_release (&testing->tdi_context_manager_mock);
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
	uint8_t version_num[TDISP_SUPPORTED_VERSION_MAX_COUNT] = {TDISP_VERSION_1_0};

	memcpy (testing->version_num, version_num, sizeof (version_num));

	cmd_interface_tdisp_responder_testing_init_dependencies (test, testing);

	status = cmd_interface_tdisp_responder_init (&testing->tdisp_responder,
		&testing->tdi_context_manager_mock.base, &testing->tdisp_driver_mock.base,
		testing->version_num, ARRAY_SIZE (testing->version_num), &testing->rng_mock.base);
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
	const struct cmd_interface_tdisp_responder tdisp_responder =
		cmd_interface_tdisp_responder_static_init (&testing.tdi_context_manager_mock.base,
		&testing.tdisp_driver_mock.base, testing.version_num, TDISP_SUPPORTED_VERSION_MAX_COUNT,
		&testing.rng_mock.base);

	TEST_START;

	cmd_interface_tdisp_responder_testing_init_dependencies (test, &testing);

	CuAssertPtrNotNull (test, tdisp_responder.base.process_request);
	CuAssertPtrNotNull (test, tdisp_responder.base.process_response);

	cmd_interface_tdisp_responder_release (&tdisp_responder);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}


static void cmd_interface_tdisp_responder_test_init (CuTest *test)
{
	struct cmd_interface_tdisp_responder_testing testing;
	int status;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init_dependencies (test, &testing);

	status = cmd_interface_tdisp_responder_init (&testing.tdisp_responder,
		&testing.tdi_context_manager_mock.base, &testing.tdisp_driver_mock.base,
		testing.version_num, ARRAY_SIZE (testing.version_num), &testing.rng_mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, testing.tdisp_responder.base.process_request);
	CuAssertPtrNotNull (test, testing.tdisp_responder.base.process_response);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_init_invalid_param (CuTest *test)
{
	int status;
	struct cmd_interface_tdisp_responder_testing testing;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	status = cmd_interface_tdisp_responder_init (NULL, &testing.tdi_context_manager_mock.base,
		&testing.tdisp_driver_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		&testing.rng_mock.base);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&testing.tdisp_responder, NULL,
		&testing.tdisp_driver_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		&testing.rng_mock.base);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&testing.tdisp_responder,
		&testing.tdi_context_manager_mock.base, NULL, testing.version_num,
		ARRAY_SIZE (testing.version_num), &testing.rng_mock.base);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&testing.tdisp_responder,
		&testing.tdi_context_manager_mock.base, &testing.tdisp_driver_mock.base, NULL,
		ARRAY_SIZE (testing.version_num), &testing.rng_mock.base);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&testing.tdisp_responder,
		&testing.tdi_context_manager_mock.base, &testing.tdisp_driver_mock.base,
		testing.version_num, 0, &testing.rng_mock.base);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_tdisp_responder_init (&testing.tdisp_responder,
		&testing.tdi_context_manager_mock.base, &testing.tdisp_driver_mock.base,
		testing.version_num, ARRAY_SIZE (testing.version_num), NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_tdisp_responder_release (NULL);
}

static void cmd_interface_tdisp_responder_test_process_request_no_encrypt (CuTest *test)
{
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.is_encrypted = false;

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_SECURE_SPDM_REQUIRED, status);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
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
	request.is_encrypted = true;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_VERSION;
	rq->header.interface_id.function_id.value = 0;

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_function_index, &testing.tdisp_driver_mock.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_version_response) + version_length,
		request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_VERSION, resp->header.message_type);
	CuAssertIntEquals (test, 0, resp->header.interface_id.function_id.value);
	CuAssertIntEquals (test, tdisp_responder->version_num_count, resp->version_num_count);
	CuAssertIntEquals (test, 0, memcmp (resp + 1, testing.version_num, version_length));

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_get_capabilities (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_capabilities_request *rq = (struct tdisp_get_capabilities_request*) buf;
	struct tdisp_get_capabilities_request rq_copy;
	struct tdisp_capabilities_response *resp = (struct tdisp_capabilities_response*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;
	struct tdisp_responder_capabilities expected_rsp_caps = {0};

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_get_capabilities_request);
	request.length = request.payload_length;
	request.is_encrypted = true;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_CAPABILITIES;
	rq->header.interface_id.function_id.value = 0;
	rq->req_caps.tsm_caps = rand ();

	expected_rsp_caps.dsm_caps = rand ();
	memset (expected_rsp_caps.req_msg_supported, 0, sizeof (expected_rsp_caps.req_msg_supported));
	expected_rsp_caps.req_msg_supported[0] = 0xFE;
	expected_rsp_caps.lock_interface_flags_supported = rand ();
	expected_rsp_caps.dev_addr_width = rand ();
	expected_rsp_caps.num_req_this = rand ();
	expected_rsp_caps.num_req_all = rand ();

	memcpy (&rq_copy, rq, sizeof (rq_copy));
	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_tdisp_capabilities, &testing.tdisp_driver_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&rq_copy.req_caps, sizeof (struct tdisp_requester_capabilities)),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &expected_rsp_caps,
		sizeof (struct tdisp_responder_capabilities), -1);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_capabilities_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_CAPABILITIES, resp->header.message_type);
	CuAssertIntEquals (test, 0, resp->header.interface_id.function_id.value);
	CuAssertIntEquals (test, 0,
		memcmp (&expected_rsp_caps, &resp->rsp_caps, sizeof (struct tdisp_responder_capabilities)));

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_lock_interface (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct tdisp_lock_interface_request *rq = (struct tdisp_lock_interface_request*) buf;
	struct tdisp_lock_interface_request rq_copy;
	struct tdisp_lock_interface_response *resp = (struct tdisp_lock_interface_response*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;
	uint8_t i;
	uint32_t function_id;
	uint8_t expected_nonce[TDISP_START_INTERFACE_NONCE_SIZE];

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_lock_interface_request);
	request.length = request.payload_length;
	request.is_encrypted = true;

	function_id = rand ();
	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_LOCK_INTERFACE;
	rq->header.interface_id.function_id.value = function_id;
	rq->lock_interface_param.default_stream_id = rand ();
	rq->lock_interface_param.mmio_reporting_offset = rand ();
	rq->lock_interface_param.bind_p2p_address_mask = rand ();

	for (i = 0; i < TDISP_START_INTERFACE_NONCE_SIZE; i++) {
		expected_nonce[i] = rand ();
	}
	status = mock_expect (&testing.rng_mock.mock, testing.rng_mock.base.generate_random_buffer,
		&testing.rng_mock, 0, MOCK_ARG (TDISP_START_INTERFACE_NONCE_SIZE), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.rng_mock.mock, 1, expected_nonce,
		TDISP_START_INTERFACE_NONCE_SIZE, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_function_index, &testing.tdisp_driver_mock.base, 0,
		MOCK_ARG (function_id & 0xffff), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &function_id,
		sizeof (function_id), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.tdi_context_manager_mock.mock,
		testing.tdi_context_manager_mock.base.get_tdi_context,
		&testing.tdi_context_manager_mock.base, 0, MOCK_ARG (function_id), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.tdi_context_manager_mock.mock,
		testing.tdi_context_manager_mock.base.set_start_nonce,
		&testing.tdi_context_manager_mock.base, 0, MOCK_ARG (function_id),
		MOCK_ARG_PTR_CONTAINS (expected_nonce, sizeof (expected_nonce)),
		MOCK_ARG (sizeof (expected_nonce)));

	memcpy (&rq_copy, rq, sizeof (rq_copy));
	status |= mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.lock_interface_request, &testing.tdisp_driver_mock, 0,
		MOCK_ARG (function_id),
		MOCK_ARG_PTR_CONTAINS (&rq_copy.lock_interface_param,
		sizeof (struct tdisp_lock_interface_param)));

	CuAssertIntEquals (test, 0, status);

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_lock_interface_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_LOCK_INTERFACE, resp->header.message_type);
	CuAssertIntEquals (test, function_id, resp->header.interface_id.function_id.value);
	CuAssertIntEquals (test, 0,
		memcmp (&expected_nonce, &resp->start_interface_nonce, TDISP_START_INTERFACE_NONCE_SIZE));

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_get_device_interface_report (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_device_interface_report_request *rq =
		(struct tdisp_get_device_interface_report_request*) buf;
	struct tdisp_device_interface_report_response *resp =
		(struct tdisp_device_interface_report_response*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;
	size_t i;
	uint32_t function_id;
	uint8_t expected_device_report[1024];
	uint16_t expected_report_length;
	uint16_t expected_remainder_length;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_get_device_interface_report_request);
	request.length = request.payload_length;
	request.is_encrypted = true;

	function_id = rand ();
	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_DEVICE_INTERFACE_REPORT;
	rq->header.interface_id.function_id.value = function_id;
	rq->offset = rand ();
	rq->length = rand ();

	for (i = 0; i < sizeof (expected_device_report); i++) {
		expected_device_report[i] = rand ();
	}
	expected_report_length = rand ();
	expected_remainder_length = rand ();

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_function_index, &testing.tdisp_driver_mock.base, 0,
		MOCK_ARG (function_id & 0xffff), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &function_id,
		sizeof (function_id), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_device_interface_report, &testing.tdisp_driver_mock, 0,
		MOCK_ARG (function_id), MOCK_ARG (rq->offset), MOCK_ARG (rq->length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 3, &expected_report_length,
		sizeof (expected_report_length), -1);
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 4, expected_device_report,
		sizeof (expected_device_report), -1);
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 5, &expected_remainder_length,
		sizeof (expected_remainder_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct tdisp_device_interface_report_response) + resp->portion_length,
		request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_DEVICE_INTERFACE_REPORT, resp->header.message_type);
	CuAssertIntEquals (test, function_id, resp->header.interface_id.function_id.value);
	CuAssertIntEquals (test, expected_report_length, resp->portion_length);
	CuAssertIntEquals (test, expected_remainder_length, resp->remainder_length);
	CuAssertIntEquals (test, 0,
		memcmp (expected_device_report, (resp + 1),	sizeof (expected_device_report)));

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_get_device_interface_state (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_get_device_interface_state_request *rq =
		(struct tdisp_get_device_interface_state_request*) buf;
	struct tdisp_device_interface_state_response *resp =
		(struct tdisp_device_interface_state_response*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;
	uint32_t function_id;
	uint8_t expected_tdi_state;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_get_device_interface_state_request);
	request.length = request.payload_length;
	request.is_encrypted = true;

	function_id = rand ();
	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE;
	rq->header.interface_id.function_id.value = function_id;

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_function_index, &testing.tdisp_driver_mock.base, 0,
		MOCK_ARG (function_id & 0xffff), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &function_id,
		sizeof (function_id), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_device_interface_state, &testing.tdisp_driver_mock, 0,
		MOCK_ARG (function_id), MOCK_ARG_NOT_NULL);

	expected_tdi_state = rand ();
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &expected_tdi_state,
		sizeof (expected_tdi_state), 0);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_device_interface_state_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_GET_DEVICE_INTERFACE_STATE, resp->header.message_type);
	CuAssertIntEquals (test, function_id, resp->header.interface_id.function_id.value);
	CuAssertIntEquals (test, expected_tdi_state, resp->tdi_state);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_start_interface (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_start_interface_request *rq = (struct tdisp_start_interface_request*) buf;
	struct tdisp_start_interface_response *resp = (struct tdisp_start_interface_response*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;
	uint32_t function_id;
	uint8_t nonce[TDISP_START_INTERFACE_NONCE_SIZE];
	uint8_t i;
	struct tdisp_tdi_context tdi_context = {};

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_start_interface_request);
	request.length = request.payload_length;
	request.is_encrypted = true;

	function_id = rand ();
	for (i = 0; i < TDISP_START_INTERFACE_NONCE_SIZE; i++) {
		nonce[i] = rand ();
	}

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_START_INTERFACE;
	rq->header.interface_id.function_id.value = function_id;
	memcpy (rq->start_interface_nonce, nonce, TDISP_START_INTERFACE_NONCE_SIZE);

	memcpy (tdi_context.start_interface_nonce, nonce, TDISP_START_INTERFACE_NONCE_SIZE);
	tdi_context.tdi_context_mask = TDISP_TDI_CONTEXT_MASK_NONCE;

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_function_index, &testing.tdisp_driver_mock.base, 0,
		MOCK_ARG (function_id & 0xffff), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &function_id,
		sizeof (function_id), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.start_interface_request, &testing.tdisp_driver_mock,	0,
		MOCK_ARG (function_id));

	status |= mock_expect (&testing.tdi_context_manager_mock.mock,
		testing.tdi_context_manager_mock.base.get_tdi_context,
		&testing.tdi_context_manager_mock.base, 0, MOCK_ARG (function_id),
		MOCK_ARG (TDISP_TDI_CONTEXT_MASK_NONCE), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.tdi_context_manager_mock.mock, 2, &tdi_context,
		sizeof (tdi_context), -1);

	CuAssertIntEquals (test, 0, status);

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_start_interface_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_START_INTERFACE, resp->header.message_type);
	CuAssertIntEquals (test, function_id, resp->header.interface_id.function_id.value);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_stop_interface (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct tdisp_stop_interface_request *rq = (struct tdisp_stop_interface_request*) buf;
	struct tdisp_stop_interface_response *resp = (struct tdisp_stop_interface_response*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;
	uint32_t function_id;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct tdisp_stop_interface_request);
	request.length = request.payload_length;
	request.is_encrypted = true;

	function_id = rand ();
	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = TDISP_REQUEST_STOP_INTERFACE;
	rq->header.interface_id.function_id.value = function_id;

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.get_function_index, &testing.tdisp_driver_mock.base, 0,
		MOCK_ARG (function_id & 0xffff), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.tdisp_driver_mock.mock, 1, &function_id,
		sizeof (function_id), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.tdisp_driver_mock.mock,
		testing.tdisp_driver_mock.base.stop_interface_request, &testing.tdisp_driver_mock, 0,
		MOCK_ARG (function_id));

	CuAssertIntEquals (test, 0, status);

	status = tdisp_responder->base.process_request (&tdisp_responder->base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct tdisp_start_interface_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, TDISP_CURRENT_VERSION, resp->header.version);
	CuAssertIntEquals (test, TDISP_RESPONSE_STOP_INTERFACE, resp->header.message_type);
	CuAssertIntEquals (test, function_id, resp->header.interface_id.function_id.value);

	cmd_interface_tdisp_responder_testing_release (test, &testing);
}

static void cmd_interface_tdisp_responder_test_process_request_invalid_params (CuTest *test)
{
	int status;
	struct cmd_interface_tdisp_responder *tdisp_responder;
	struct cmd_interface_tdisp_responder_testing testing;
	struct cmd_interface_msg request;

	TEST_START;

	cmd_interface_tdisp_responder_testing_init (test, &testing);

	tdisp_responder = &testing.tdisp_responder;

	status = tdisp_responder->base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT, status);

	status = tdisp_responder->base.process_request (&tdisp_responder->base, NULL);
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
	request.is_encrypted = true;

	rq->header.version = TDISP_CURRENT_VERSION;
	rq->header.message_type = UINT8_MAX;
	rq->header.interface_id.function_id.value = 0;

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
	request.is_encrypted = true;

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

#ifdef CMD_ENABLE_ISSUE_REQUEST
	status = tdisp_responder->base.process_response ((const struct cmd_interface*) 0xDEADBEEF,
		(struct cmd_interface_msg*) 0xBAADB00F);
	CuAssertIntEquals (test, CMD_INTERFACE_TDISP_RESPONDER_UNSUPPORTED_OPERATION, status);
#else
	UNUSED (status);
#endif
	cmd_interface_tdisp_responder_testing_release (test, &testing);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_tdisp_responder);

TEST (cmd_interface_tdisp_responder_test_static_init);
TEST (cmd_interface_tdisp_responder_test_init);
TEST (cmd_interface_tdisp_responder_test_init_invalid_param);
TEST (cmd_interface_tdisp_responder_test_release_null);
TEST (cmd_interface_tdisp_responder_test_process_request_no_encrypt);
TEST (cmd_interface_tdisp_responder_test_process_request_get_version);
TEST (cmd_interface_tdisp_responder_test_process_request_get_capabilities);
TEST (cmd_interface_tdisp_responder_test_process_request_lock_interface);
TEST (cmd_interface_tdisp_responder_test_process_request_get_device_interface_report);
TEST (cmd_interface_tdisp_responder_test_process_request_get_device_interface_state);
TEST (cmd_interface_tdisp_responder_test_process_request_start_interface);
TEST (cmd_interface_tdisp_responder_test_process_request_stop_interface);
TEST (cmd_interface_tdisp_responder_test_process_request_invalid_params);
TEST (cmd_interface_tdisp_responder_test_process_request_payload_lt_min_length);
TEST (cmd_interface_tdisp_responder_test_process_request_unsupported_message_type);
TEST (cmd_interface_tdisp_responder_test_process_response);

TEST_SUITE_END;
// *INDENT-ON*
