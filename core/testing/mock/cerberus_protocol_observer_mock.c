// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cmd_interface/cmd_interface.h"
#include "cerberus_protocol_observer_mock.h"


static void cerberus_protocol_observer_mock_on_get_digest_response (
	struct cerberus_protocol_observer *observer, struct cmd_interface_msg *response)
{
	struct cerberus_protocol_observer_mock *mock = 
		(struct cerberus_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cerberus_protocol_observer_mock_on_get_digest_response, observer, 
		MOCK_ARG_CALL (response));
}

static void cerberus_protocol_observer_mock_on_get_certificate_response (
	struct cerberus_protocol_observer *observer, struct cmd_interface_msg *response)
{
	struct cerberus_protocol_observer_mock *mock = 
		(struct cerberus_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cerberus_protocol_observer_mock_on_get_certificate_response, 
		observer, MOCK_ARG_CALL (response));
}

static void cerberus_protocol_observer_mock_on_challenge_response (
	struct cerberus_protocol_observer *observer, struct cmd_interface_msg *response)
{
	struct cerberus_protocol_observer_mock *mock = 
		(struct cerberus_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cerberus_protocol_observer_mock_on_challenge_response, 
		observer, MOCK_ARG_CALL (response));
}

static int cerberus_protocol_observer_mock_func_arg_count (void *func)
{
	if ((func == cerberus_protocol_observer_mock_on_challenge_response) || 
		(func == cerberus_protocol_observer_mock_on_get_digest_response) || 
		(func == cerberus_protocol_observer_mock_on_get_certificate_response)) {
		return 1;
	}
	return 0;
}

static const char* cerberus_protocol_observer_mock_func_name_map (void *func)
{
	if (func == cerberus_protocol_observer_mock_on_get_digest_response) {
		return "on_get_digest_response";
	}
	else if (func == cerberus_protocol_observer_mock_on_get_certificate_response) {
		return "on_get_certificate_response";
	}
	else if (func == cerberus_protocol_observer_mock_on_challenge_response) {
		return "on_challenge_response";
	}
	else {
		return "unknown";
	}
}

static const char* cerberus_protocol_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == cerberus_protocol_observer_mock_on_get_digest_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == cerberus_protocol_observer_mock_on_get_certificate_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == cerberus_protocol_observer_mock_on_challenge_response) {
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
int cerberus_protocol_observer_mock_init (struct cerberus_protocol_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cerberus_protocol_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cerberus_protocol_observer");

	mock->base.on_get_digest_response = cerberus_protocol_observer_mock_on_get_digest_response;
	mock->base.on_get_certificate_response = 
		cerberus_protocol_observer_mock_on_get_certificate_response;
	mock->base.on_challenge_response = cerberus_protocol_observer_mock_on_challenge_response;

	mock->mock.func_arg_count = cerberus_protocol_observer_mock_func_arg_count;
	mock->mock.func_name_map = cerberus_protocol_observer_mock_func_name_map;
	mock->mock.arg_name_map = cerberus_protocol_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a Cerberus protocol observer mock.
 *
 * @param mock The mock to release.
 */
void cerberus_protocol_observer_mock_release (struct cerberus_protocol_observer_mock *mock)
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
int cerberus_protocol_observer_mock_validate_and_release (
	struct cerberus_protocol_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cerberus_protocol_observer_mock_release (mock);
	}

	return status;
}
