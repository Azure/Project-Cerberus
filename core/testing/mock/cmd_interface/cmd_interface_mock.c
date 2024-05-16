// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "cmd_interface_mock.h"
#include "platform_io.h"
#include "testing.h"


static int cmd_interface_mock_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	struct cmd_interface_mock *mock = (struct cmd_interface_mock*) intf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_mock_process_request, intf,
		MOCK_ARG_PTR_CALL (request));
}

static int cmd_interface_mock_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	struct cmd_interface_mock *mock = (struct cmd_interface_mock*) intf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_mock_process_response, intf,
		MOCK_ARG_PTR_CALL (response));
}

static int cmd_interface_mock_generate_error_packet (const struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set)
{
	struct cmd_interface_mock *mock = (struct cmd_interface_mock*) intf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_mock_generate_error_packet, intf,
		MOCK_ARG_PTR_CALL (request), MOCK_ARG_CALL (error_code), MOCK_ARG_CALL (error_data),
		MOCK_ARG_CALL (cmd_set));
}

static int cmd_interface_mock_func_arg_count (void *func)
{
	if (func == cmd_interface_mock_generate_error_packet) {
		return 4;
	}
	else if ((func == cmd_interface_mock_process_request) ||
		(func == cmd_interface_mock_process_response)) {
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
	else if (func == cmd_interface_mock_process_response) {
		return "process_response";
	}
	else if (func == cmd_interface_mock_generate_error_packet) {
		return "generate_error_packet";
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
	else if (func == cmd_interface_mock_process_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == cmd_interface_mock_generate_error_packet) {
		switch (arg) {
			case 0:
				return "request";

			case 1:
				return "error_code";

			case 2:
				return "error_data";

			case 3:
				return "cmd_set";
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
	mock->base.process_response = cmd_interface_mock_process_response;
	mock->base.generate_error_packet = cmd_interface_mock_generate_error_packet;

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
 * Custom validation routine for validating cmd_interface_msg arguments.
 *
 * @param arg_info Argument information from the mock for error messages.
 * @param expected The expected request contents.
 * @param actual The actual request contents.
 *
 * @return 0 if the request contained the expected information or 1 if not.
 */
int cmd_interface_mock_validate_request (const char *arg_info, void *expected, void *actual)
{
	struct cmd_interface_msg *req_expected = (struct cmd_interface_msg*) expected;
	struct cmd_interface_msg *req_actual = (struct cmd_interface_msg*) actual;
	int fail = 0;

	if (req_expected->source_eid != req_actual->source_eid) {
		platform_printf ("%sUnexpected source EID: expected=0x%x, actual=0x%x" NEWLINE, arg_info,
			req_expected->source_eid, req_actual->source_eid);
		fail |= 1;
	}

	if (req_expected->source_addr != req_actual->source_addr) {
		platform_printf ("%sUnexpected source address: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, req_expected->source_addr, req_actual->source_addr);
		fail |= 1;
	}

	if (req_expected->target_eid != req_actual->target_eid) {
		platform_printf ("%sUnexpected target EID: expected=0x%x, actual=0x%x" NEWLINE, arg_info,
			req_expected->target_eid, req_actual->target_eid);
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

	if (req_expected->is_encrypted != req_actual->is_encrypted) {
		platform_printf ("%sUnexpected encrypted flag: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, req_expected->is_encrypted, req_actual->is_encrypted);
		fail |= 1;
	}

	if (req_expected->crypto_timeout != req_actual->crypto_timeout) {
		platform_printf ("%sUnexpected crypto timeout: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, req_expected->crypto_timeout, req_actual->crypto_timeout);
		fail |= 1;
	}

	if (req_expected->channel_id != req_actual->channel_id) {
		platform_printf ("%sUnexpected request channel: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, req_expected->channel_id, req_actual->channel_id);
		fail |= 1;
	}

	/* Don't compare payload pointers directly since they won't match.  But the offset from the base
	 * data pointer should be the same. */
	if ((req_expected->payload == NULL) && (req_actual->payload != NULL)) {
		platform_printf ("%sUnexpected payload pointer: expected=%p, actual=%p" NEWLINE, arg_info,
			req_expected->payload, req_actual->payload);
		fail |= 1;
	}
	else {
		size_t diff_expected = req_expected->payload - req_expected->data;
		size_t diff_actual = req_actual->payload - req_actual->data;

		if (diff_expected != diff_actual) {
			platform_printf ("%sUnexpected payload offset: expected=0x%x, actual=0x%x" NEWLINE,
				arg_info, diff_expected, diff_actual);
			fail |= 1;
		}
	}

	if (req_expected->payload_length != req_actual->payload_length) {
		platform_printf ("%sUnexpected payload length: expected=0x%lx, actual=0x%lx" NEWLINE,
			arg_info, req_expected->payload_length, req_actual->payload_length);
		fail |= 1;
	}

	fail |= testing_validate_array_prefix (req_expected->data, req_actual->data,
		req_expected->length, arg_info);

	return fail;
}

/**
 * Copy the data present in a command request structure.
 *
 * @param req_orig The original data that will be copied.
 * @param req_copy The destination for the data.
 */
static void cmd_interface_mock_copy_request_data (const struct cmd_interface_msg *req_orig,
	struct cmd_interface_msg *req_copy)
{
	size_t payload_offset;

	if (req_copy->data != NULL) {
		if (req_copy->payload == NULL) {
			/* If there is no payload set, just copy the data. */
			memcpy (req_copy->data, req_orig->data, req_orig->length);
		}
		else {
			/* Copy from the beginning of the data buffer to the end of the payload and set the
			 * payload pointer to the right location. */
			payload_offset = req_orig->payload - req_orig->data;
			memcpy (req_copy->data, req_orig->data, req_orig->payload_length + payload_offset);
			req_copy->payload = &req_copy->data[payload_offset];
		}
	}
}

/**
 * Allocate memory and perform a deep copy of the command request structure for validation.
 *
 * @param expected The expectation context for the argument to save.
 * @param call The calling context for the argument to save.
 */
void cmd_interface_mock_save_request (const struct mock_arg *expected, struct mock_arg *call)
{
	struct cmd_interface_msg *req_orig;
	struct cmd_interface_msg *req_copy;

	call->ptr_value = platform_malloc (expected->ptr_value_len);

	if (call->ptr_value != NULL) {
		call->ptr_value_len = expected->ptr_value_len;
		memcpy (call->ptr_value, (void*) ((uintptr_t) call->value), call->ptr_value_len);

		req_orig = (struct cmd_interface_msg*) ((uintptr_t) call->value);
		req_copy = (struct cmd_interface_msg*) call->ptr_value;

		req_copy->data = platform_malloc (req_orig->length);
		cmd_interface_mock_copy_request_data (req_orig, req_copy);
	}
}

/**
 * Free a copied request structure.
 *
 * @param arg The request structure to free.
 */
void cmd_interface_mock_free_request (void *arg)
{
	struct cmd_interface_msg *req = arg;

	if (req) {
		platform_free (req->data);
		platform_free (req);
	}
}

/**
 * Deep copy request data into an output parameter.
 *
 * @param expected The expectation context for the argument to copy.
 * @param call The calling context to copy into.
 * @param out_len Buffer space available in the function argument.
 */
void cmd_interface_mock_copy_request (const struct mock_arg *expected, struct mock_arg *call,
	size_t out_len)
{
	const struct cmd_interface_msg *req_orig = expected->out_data;
	struct cmd_interface_msg *req_copy = (struct cmd_interface_msg*) ((uintptr_t) call->value);
	void *data_tmp = req_copy->data;

	memcpy ((void*) ((uintptr_t) call->value), expected->out_data, out_len);

	req_copy->data = data_tmp;
	cmd_interface_mock_copy_request_data (req_orig, req_copy);
}

/**
 * Allocate memory and deep copy data for an expectation argument.
 *
 * @param arg_data The data to copy into the expectation argument.
 * @param arg_length The length of the data to copy.
 * @param arg_save The argument buffer to copy the data to.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
int cmd_interface_mock_duplicate_request (const void *arg_data, size_t arg_length, void **arg_save)
{
	const struct cmd_interface_msg *req_orig = arg_data;
	struct cmd_interface_msg *req_copy;

	if (arg_length != sizeof (struct cmd_interface_msg)) {
		return MOCK_BAD_ARG_LENGTH;
	}

	*arg_save = platform_malloc (arg_length);
	if (*arg_save == NULL) {
		return MOCK_NO_MEMORY;
	}

	memcpy (*arg_save, arg_data, arg_length);

	req_copy = (struct cmd_interface_msg*) *arg_save;
	req_copy->data = platform_malloc (req_orig->length);
	if (req_copy->data == NULL) {
		platform_free (*arg_save);
		*arg_save = NULL;

		return MOCK_NO_MEMORY;
	}

	cmd_interface_mock_copy_request_data (req_orig, req_copy);

	return 0;
}
