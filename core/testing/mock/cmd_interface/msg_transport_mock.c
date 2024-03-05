// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include <stdint.h>
#include "msg_transport_mock.h"


static int msg_transport_mock_get_max_message_overhead (const struct msg_transport *transport,
	uint8_t dest_id)
{
	struct msg_transport_mock *mock = (struct msg_transport_mock*) transport;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, msg_transport_mock_get_max_message_overhead, transport,
		MOCK_ARG_CALL (dest_id));
}

static int msg_transport_mock_get_max_message_payload_length (const struct msg_transport *transport,
	uint8_t dest_id)
{
	struct msg_transport_mock *mock = (struct msg_transport_mock*) transport;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, msg_transport_mock_get_max_message_payload_length, transport,
		MOCK_ARG_CALL (dest_id));
}

static int msg_transport_mock_get_max_encapsulated_message_length (
	const struct msg_transport *transport, uint8_t dest_id)
{
	struct msg_transport_mock *mock = (struct msg_transport_mock*) transport;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, msg_transport_mock_get_max_encapsulated_message_length, transport,
		MOCK_ARG_CALL (dest_id));
}

static int msg_transport_mock_send_request_message (const struct msg_transport *transport,
	struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response)
{
	struct msg_transport_mock *mock = (struct msg_transport_mock*) transport;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, msg_transport_mock_send_request_message, transport,
		MOCK_ARG_PTR_CALL (request), MOCK_ARG_CALL (timeout_ms), MOCK_ARG_PTR_CALL (response));
}

static int msg_transport_mock_func_arg_count (void *func)
{
	if (func == msg_transport_mock_send_request_message) {
		return 3;
	}
	else if ((func == msg_transport_mock_get_max_message_overhead) ||
		(func == msg_transport_mock_get_max_message_payload_length) ||
		(func == msg_transport_mock_get_max_encapsulated_message_length)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* msg_transport_mock_func_name_map (void *func)
{
	if (func == msg_transport_mock_get_max_message_overhead) {
		return "get_max_message_overhead";
	}
	else if (func == msg_transport_mock_get_max_message_payload_length) {
		return "get_max_message_payload_length";
	}
	else if (func == msg_transport_mock_get_max_encapsulated_message_length) {
		return "get_max_encapsulated_message_length";
	}
	else if (func == msg_transport_mock_send_request_message) {
		return "send_request_message";
	}
	else {
		return "unknown";
	}
}

static const char* msg_transport_mock_arg_name_map (void *func, int arg)
{
	if (func == msg_transport_mock_send_request_message) {
		switch (arg) {
			case 0:
				return "request";

			case 1:
				return "timeout_ms";

			case 2:
				return "response";
		}
	}
	else if (func == msg_transport_mock_get_max_message_overhead) {
		switch (arg) {
			case 0:
				return "dest_id";
		}
	}
	else if (func == msg_transport_mock_get_max_message_payload_length) {
		switch (arg) {
			case 0:
				return "dest_id";
		}
	}
	else if (func == msg_transport_mock_get_max_encapsulated_message_length) {
		switch (arg) {
			case 0:
				return "dest_id";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a message transport.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int msg_transport_mock_init (struct msg_transport_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct msg_transport_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "msg_transport");

	mock->base.get_max_message_overhead = msg_transport_mock_get_max_message_overhead;
	mock->base.get_max_message_payload_length = msg_transport_mock_get_max_message_payload_length;
	mock->base.get_max_encapsulated_message_length =
		msg_transport_mock_get_max_encapsulated_message_length;
	mock->base.send_request_message = msg_transport_mock_send_request_message;

	mock->mock.func_arg_count = msg_transport_mock_func_arg_count;
	mock->mock.func_name_map = msg_transport_mock_func_name_map;
	mock->mock.arg_name_map = msg_transport_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock message transport.
 *
 * @param mock The mock to release.
 */
void msg_transport_mock_release (struct msg_transport_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int msg_transport_mock_validate_and_release (struct msg_transport_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		msg_transport_mock_release (mock);
	}

	return status;
}
