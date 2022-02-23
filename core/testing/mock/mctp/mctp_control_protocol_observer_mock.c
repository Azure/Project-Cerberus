// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cmd_interface/cmd_interface.h"
#include "mctp_control_protocol_observer_mock.h"


static void mctp_control_protocol_observer_mock_on_set_eid_request (
	struct mctp_control_protocol_observer *observer)
{
	struct mctp_control_protocol_observer_mock *mock =
		(struct mctp_control_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, mctp_control_protocol_observer_mock_on_set_eid_request,
		observer);
}

static void mctp_control_protocol_observer_mock_on_get_message_type_response (
	struct mctp_control_protocol_observer *observer, struct cmd_interface_msg *response)
{
	struct mctp_control_protocol_observer_mock *mock =
		(struct mctp_control_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, mctp_control_protocol_observer_mock_on_get_message_type_response,
		observer, MOCK_ARG_CALL (response));
}

static void mctp_control_protocol_observer_mock_on_get_routing_table_entries_response (
	struct mctp_control_protocol_observer *observer, struct cmd_interface_msg *response)
{
	struct mctp_control_protocol_observer_mock *mock =
		(struct mctp_control_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock,
		mctp_control_protocol_observer_mock_on_get_routing_table_entries_response, observer,
		MOCK_ARG_CALL (response));
}

static void mctp_control_protocol_observer_mock_on_get_vendor_def_msg_response (
	struct mctp_control_protocol_observer *observer, struct cmd_interface_msg *response)
{
	struct mctp_control_protocol_observer_mock *mock =
		(struct mctp_control_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock,
		mctp_control_protocol_observer_mock_on_get_vendor_def_msg_response, observer,
		MOCK_ARG_CALL (response));
}

static int mctp_control_protocol_observer_mock_func_arg_count (void *func)
{
	if ((func == mctp_control_protocol_observer_mock_on_get_message_type_response) ||
		(func == mctp_control_protocol_observer_mock_on_get_routing_table_entries_response) ||
		(func == mctp_control_protocol_observer_mock_on_get_vendor_def_msg_response)) {
		return 1;
	}

	return 0;
}

static const char* mctp_control_protocol_observer_mock_func_name_map (void *func)
{
	if (func == mctp_control_protocol_observer_mock_on_set_eid_request) {
		return "on_set_eid_request";
	}
	else if (func == mctp_control_protocol_observer_mock_on_get_message_type_response) {
		return "on_get_message_type_response";
	}
	else if (func == mctp_control_protocol_observer_mock_on_get_routing_table_entries_response) {
		return "on_get_routing_table_entries_response";
	}
	else if (func == mctp_control_protocol_observer_mock_on_get_vendor_def_msg_response) {
		return "on_get_vendor_def_msg_response";
	}
	else {
		return "unknown";
	}
}

static const char* mctp_control_protocol_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == mctp_control_protocol_observer_mock_on_get_message_type_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == mctp_control_protocol_observer_mock_on_get_routing_table_entries_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == mctp_control_protocol_observer_mock_on_get_vendor_def_msg_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for receiving Cerberus protocol notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int mctp_control_protocol_observer_mock_init (struct mctp_control_protocol_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct mctp_control_protocol_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "mctp_control_protocol_observer");

	mock->base.on_set_eid_request = mctp_control_protocol_observer_mock_on_set_eid_request;
	mock->base.on_get_message_type_response =
		mctp_control_protocol_observer_mock_on_get_message_type_response;
	mock->base.on_get_routing_table_entries_response =
		mctp_control_protocol_observer_mock_on_get_routing_table_entries_response;
	mock->base.on_get_vendor_def_msg_response =
		mctp_control_protocol_observer_mock_on_get_vendor_def_msg_response;

	mock->mock.func_arg_count = mctp_control_protocol_observer_mock_func_arg_count;
	mock->mock.func_name_map = mctp_control_protocol_observer_mock_func_name_map;
	mock->mock.arg_name_map = mctp_control_protocol_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a MCTP protocol observer mock.
 *
 * @param mock The mock to release.
 */
void mctp_control_protocol_observer_mock_release (struct mctp_control_protocol_observer_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int mctp_control_protocol_observer_mock_validate_and_release (
		struct mctp_control_protocol_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		mctp_control_protocol_observer_mock_release (mock);
	}

	return status;
}
