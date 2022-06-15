// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cmd_interface/cmd_interface.h"
#include "spdm_protocol_observer_mock.h"


static void spdm_protocol_observer_mock_on_get_version_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct spdm_protocol_observer_mock *mock =
		(struct spdm_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_observer_mock_on_get_version_response, observer,
		MOCK_ARG_CALL (response));
}

static void spdm_protocol_observer_mock_on_get_capabilities_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct spdm_protocol_observer_mock *mock =
		(struct spdm_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_observer_mock_on_get_capabilities_response,
		observer, MOCK_ARG_CALL (response));
}

static void spdm_protocol_observer_mock_on_negotiate_algorithms_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct spdm_protocol_observer_mock *mock =
		(struct spdm_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_observer_mock_on_negotiate_algorithms_response,
		observer, MOCK_ARG_CALL (response));
}

static void spdm_protocol_observer_mock_on_get_digests_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct spdm_protocol_observer_mock *mock =
		(struct spdm_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_observer_mock_on_get_digests_response,
		observer, MOCK_ARG_CALL (response));
}

static void spdm_protocol_observer_mock_on_get_certificate_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct spdm_protocol_observer_mock *mock =
		(struct spdm_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_observer_mock_on_get_certificate_response,
		observer, MOCK_ARG_CALL (response));
}

static void spdm_protocol_observer_mock_on_challenge_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct spdm_protocol_observer_mock *mock =
		(struct spdm_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_observer_mock_on_challenge_response,
		observer, MOCK_ARG_CALL (response));
}

static void spdm_protocol_observer_mock_on_get_measurements_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct spdm_protocol_observer_mock *mock =
		(struct spdm_protocol_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_protocol_observer_mock_on_get_measurements_response,
		observer, MOCK_ARG_CALL (response));
}

static int spdm_protocol_observer_mock_func_arg_count (void *func)
{
	if ((func == spdm_protocol_observer_mock_on_get_version_response) ||
		(func == spdm_protocol_observer_mock_on_get_capabilities_response) ||
		(func == spdm_protocol_observer_mock_on_negotiate_algorithms_response) ||
		(func == spdm_protocol_observer_mock_on_get_digests_response) ||
		(func == spdm_protocol_observer_mock_on_get_certificate_response) ||
		(func == spdm_protocol_observer_mock_on_challenge_response) ||
		(func == spdm_protocol_observer_mock_on_get_measurements_response)) {
		return 1;
	}
	return 0;
}

static const char* spdm_protocol_observer_mock_func_name_map (void *func)
{
	if (func == spdm_protocol_observer_mock_on_get_version_response) {
		return "on_get_version_response";
	}
	else if (func == spdm_protocol_observer_mock_on_get_capabilities_response) {
		return "on_get_capabilities_response";
	}
	else if (func == spdm_protocol_observer_mock_on_negotiate_algorithms_response) {
		return "on_negotiate_algorithms_response";
	}
	else if (func == spdm_protocol_observer_mock_on_get_digests_response) {
		return "on_get_digests_response";
	}
	else if (func == spdm_protocol_observer_mock_on_get_certificate_response) {
		return "on_get_certificate_response";
	}
	else if (func == spdm_protocol_observer_mock_on_challenge_response) {
		return "on_challenge_response";
	}
	else if (func == spdm_protocol_observer_mock_on_get_measurements_response) {
		return "on_get_measurements_response";
	}
	else {
		return "unknown";
	}
}

static const char* spdm_protocol_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == spdm_protocol_observer_mock_on_get_version_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == spdm_protocol_observer_mock_on_get_capabilities_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == spdm_protocol_observer_mock_on_negotiate_algorithms_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == spdm_protocol_observer_mock_on_get_digests_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == spdm_protocol_observer_mock_on_get_certificate_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == spdm_protocol_observer_mock_on_challenge_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == spdm_protocol_observer_mock_on_get_measurements_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for receiving SPDM protocol notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int spdm_protocol_observer_mock_init (struct spdm_protocol_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct spdm_protocol_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "spdm_protocol_observer");

	mock->mock.func_arg_count = spdm_protocol_observer_mock_func_arg_count;
	mock->mock.func_name_map = spdm_protocol_observer_mock_func_name_map;
	mock->mock.arg_name_map = spdm_protocol_observer_mock_arg_name_map;

	mock->base.on_spdm_get_version_response = spdm_protocol_observer_mock_on_get_version_response;
	mock->base.on_spdm_get_capabilities_response =
		spdm_protocol_observer_mock_on_get_capabilities_response;
	mock->base.on_spdm_negotiate_algorithms_response =
		spdm_protocol_observer_mock_on_negotiate_algorithms_response;
	mock->base.on_spdm_get_digests_response = spdm_protocol_observer_mock_on_get_digests_response;
	mock->base.on_spdm_get_certificate_response =
		spdm_protocol_observer_mock_on_get_certificate_response;
	mock->base.on_spdm_challenge_response = spdm_protocol_observer_mock_on_challenge_response;
	mock->base.on_spdm_get_measurements_response =
		spdm_protocol_observer_mock_on_get_measurements_response;

	return 0;
}

/**
 * Release the resources used by a SPDM protocol observer mock.
 *
 * @param mock The mock to release.
 */
void spdm_protocol_observer_mock_release (struct spdm_protocol_observer_mock *mock)
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
int spdm_protocol_observer_mock_validate_and_release (
	struct spdm_protocol_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		spdm_protocol_observer_mock_release (mock);
	}

	return status;
}
