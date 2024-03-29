// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "mctp_notifier_interface_mock.h"


static int mctp_notifier_interface_mock_send_notification_request (
	const struct mctp_notifier_interface *interface, uint8_t *payload, size_t payload_len)
{
	struct mctp_notifier_interface_mock *mock = (struct mctp_notifier_interface_mock*) interface;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mctp_notifier_interface_mock_send_notification_request, interface,
		MOCK_ARG_PTR_CALL (payload), MOCK_ARG_CALL (payload_len));
}

static int mctp_notifier_interface_mock_register_listener (
	const struct mctp_notifier_interface *interface, uint8_t dest_id)
{
	struct mctp_notifier_interface_mock *mock = (struct mctp_notifier_interface_mock*) interface;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mctp_notifier_interface_mock_register_listener, interface,
		MOCK_ARG_CALL (dest_id));
}

static int mctp_notifier_interface_mock_force_register_listener (
	const struct mctp_notifier_interface *interface, uint8_t dest_id)
{
	struct mctp_notifier_interface_mock *mock = (struct mctp_notifier_interface_mock*) interface;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mctp_notifier_interface_mock_force_register_listener, interface,
		MOCK_ARG_CALL (dest_id));
}

static int mctp_notifier_interface_mock_deregister_listener (
	const struct mctp_notifier_interface *interface, uint8_t dest_id)
{
	struct mctp_notifier_interface_mock *mock = (struct mctp_notifier_interface_mock*) interface;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, mctp_notifier_interface_mock_deregister_listener, interface,
		MOCK_ARG_CALL (dest_id));
}

static int mctp_notifier_interface_mock_func_arg_count (void *func)
{
	if ((func == mctp_notifier_interface_mock_register_listener) ||
		(func == mctp_notifier_interface_mock_force_register_listener) ||
		(func == mctp_notifier_interface_mock_deregister_listener)) {
		return 1;
	}
	else if (func == mctp_notifier_interface_mock_send_notification_request) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* mctp_notifier_interface_mock_func_name_map (void *func)
{
	if (func == mctp_notifier_interface_mock_send_notification_request) {
		return "send_notification_request";
	}
	else if (func == mctp_notifier_interface_mock_register_listener) {
		return "register_listener";
	}
	else if (func == mctp_notifier_interface_mock_force_register_listener) {
		return "force_register_listener";
	}
	else if (func == mctp_notifier_interface_mock_deregister_listener) {
		return "deregister_listener";
	}
	else {
		return "unknown";
	}
}

static const char* mctp_notifier_interface_mock_arg_name_map (void *func, int arg)
{
	if (func == mctp_notifier_interface_mock_send_notification_request) {
		switch (arg) {
			case 0:
				return "payload";

			case 1:
				return "payload_len";
		}
	}
	else if (func == mctp_notifier_interface_mock_register_listener) {
		switch (arg) {
			case 0:
				return "dest_id";
		}
	}
	else if (func == mctp_notifier_interface_mock_force_register_listener) {
		switch (arg) {
			case 0:
				return "dest_id";
		}
	}
	else if (func == mctp_notifier_interface_mock_deregister_listener) {
		switch (arg) {
			case 0:
				return "dest_id";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a mctp notifier interface.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int mctp_notifier_interface_mock_init (struct mctp_notifier_interface_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct mctp_notifier_interface_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "mctp_notifier");

	mock->base.send_notification_request = mctp_notifier_interface_mock_send_notification_request;
	mock->base.register_listener = mctp_notifier_interface_mock_register_listener;
	mock->base.force_register_listener = mctp_notifier_interface_mock_force_register_listener;
	mock->base.deregister_listener = mctp_notifier_interface_mock_deregister_listener;

	mock->mock.func_arg_count = mctp_notifier_interface_mock_func_arg_count;
	mock->mock.func_name_map = mctp_notifier_interface_mock_func_name_map;
	mock->mock.arg_name_map = mctp_notifier_interface_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock mctp notifier interface.
 *
 * @param mock The mock to release.
 */
void mctp_notifier_interface_mock_release (struct mctp_notifier_interface_mock *mock)
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
int mctp_notifier_interface_mock_validate_and_release (struct mctp_notifier_interface_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		mctp_notifier_interface_mock_release (mock);
	}

	return status;
}
