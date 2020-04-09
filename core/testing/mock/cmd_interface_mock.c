// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include <stdint.h>
#include "platform_io.h"
#include "cmd_interface_mock.h"
#include "testing.h"


static int cmd_interface_mock_process_request (struct cmd_interface *intf,
	struct cmd_interface_request *request)
{
	struct cmd_interface_mock *mock = (struct cmd_interface_mock*) intf;

	if ((mock == NULL) || (request == NULL)) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_mock_process_request, intf, MOCK_ARG_CALL (request));
}

static int cmd_interface_mock_issue_request (struct cmd_interface *intf, uint8_t command_id,
	void *request_params, uint8_t *buf, int buf_len)
{
	struct cmd_interface_mock *mock = (struct cmd_interface_mock*) intf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_mock_issue_request, intf, MOCK_ARG_CALL (command_id),
		MOCK_ARG_CALL (request_params), MOCK_ARG_CALL (buf), MOCK_ARG_CALL (buf_len));
}

static int cmd_interface_mock_func_arg_count (void *func)
{
	if (func == cmd_interface_mock_issue_request) {
		return 4;
	}
	else if (func == cmd_interface_mock_process_request) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cmd_interface_mock_func_name_map (void *func)
{
	if (func == cmd_interface_mock_process_request) {
		return "process_request";
	}
	else if (func == cmd_interface_mock_issue_request) {
		return "issue_request";
	}
	else {
		return "unknown";
	}
}

static const char* cmd_interface_mock_arg_name_map (void *func, int arg)
{
	if (func == cmd_interface_mock_process_request) {
		switch (arg) {
			case 0:
				return "request";
		}
	}
	else if (func == cmd_interface_mock_issue_request) {
		switch (arg) {
			case 0:
				return "command_id";

			case 1:
				return "request_params";

			case 2:
				return "buf";

			case 3:
				return "buf_len";
		}
	}

	return "unknown";
}

/**
 * Initialize mock interface instance
 *
 * @param mock Mock interface instance to initialize
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_mock_init (struct cmd_interface_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cmd_interface_mock));

	status = mock_init (&mock->mock);

	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cmd_interface");

	mock->base.process_request = cmd_interface_mock_process_request;
	mock->base.issue_request = cmd_interface_mock_issue_request;

	mock->mock.func_arg_count = cmd_interface_mock_func_arg_count;
	mock->mock.func_name_map = cmd_interface_mock_func_name_map;
	mock->mock.arg_name_map = cmd_interface_mock_arg_name_map;

	return 0;
}

/**
 * Release resources used by an cmd_interface mock instance
 *
 * @param mock Mock interface instance to release
 */
void cmd_interface_mock_release (struct cmd_interface_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that all expectations were met then release the mock instance
 *
 * @param mock The mock to validate and release
 *
 * @return Validation status, 0 if expectations met or 1 if not.
 */
int cmd_interface_mock_validate_and_release (struct cmd_interface_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cmd_interface_mock_release (mock);
	}

	return status;
}

/**
 * Custom validation routine for validating cmd_interface_request arguments.
 *
 * @param arg_info Argument information from the mock for error messages.
 * @param expected The expected request contents.
 * @param actual The actual request contents.
 *
 * @return 0 if the request contained the expected information or 1 if not.
 */
int cmd_interface_mock_validate_request (const char *arg_info, void *expected, void *actual)
{
	struct cmd_interface_request *req_expected = (struct cmd_interface_request*) expected;
	struct cmd_interface_request *req_actual = (struct cmd_interface_request*) actual;
	int fail = 0;

	if (req_expected->source_eid != req_actual->source_eid) {
		platform_printf ("%sUnexpected source EID: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, req_expected->source_eid, req_actual->source_eid);
		fail |= 1;
	}

	if (req_expected->target_eid != req_actual->target_eid) {
		platform_printf ("%sUnexpected target EID: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, req_expected->target_eid, req_actual->target_eid);
		fail |= 1;
	}

	if (req_expected->length != req_actual->length) {
		platform_printf ("%sUnexpected request length: expected=0x%lx, actual=0x%lx" NEWLINE,
			arg_info, req_expected->length, req_actual->length);
		fail |= 1;
	}

	if (req_expected->max_response != req_actual->max_response) {
		platform_printf ("%sUnexpected max response length: expected=0x%lx, actual=0x%lx" NEWLINE,
			arg_info, req_expected->max_response, req_actual->max_response);
		fail |= 1;
	}

	if (req_expected->channel_id != req_actual->channel_id) {
		platform_printf ("%sUnexpected request channel: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, req_expected->channel_id, req_actual->channel_id);
		fail |= 1;
	}

	fail |= testing_validate_array_prefix (req_expected->data, req_actual->data,
		req_expected->length, arg_info);

	return fail;
}
