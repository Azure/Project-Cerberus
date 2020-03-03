// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_io.h"
#include "cmd_channel_mock.h"
#include "testing.h"


static int cmd_channel_mock_receive_packet (struct cmd_channel *channel, struct cmd_packet *packet,
	int ms_timeout)
{
	struct cmd_channel_mock *mock = (struct cmd_channel_mock*) channel;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_channel_mock_receive_packet, channel, MOCK_ARG_CALL (packet),
		MOCK_ARG_CALL (ms_timeout));
}

static int cmd_channel_mock_send_packet (struct cmd_channel *channel, struct cmd_packet *packet)
{
	struct cmd_channel_mock *mock = (struct cmd_channel_mock*) channel;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_channel_mock_send_packet, channel, MOCK_ARG_CALL (packet));
}

static int cmd_channel_mock_func_arg_count (void *func)
{
	if (func == cmd_channel_mock_receive_packet) {
		return 2;
	}
	if (func == cmd_channel_mock_send_packet) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cmd_channel_mock_func_name_map (void *func)
{
	if (func == cmd_channel_mock_receive_packet) {
		return "receive_packet";
	}
	else if (func == cmd_channel_mock_send_packet) {
		return "send_packet";
	}
	else {
		return "unknown";
	}
}

static const char* cmd_channel_mock_arg_name_map (void *func, int arg)
{
	if (func == cmd_channel_mock_receive_packet) {
		switch (arg) {
			case 0:
				return "packet";
			case 1:
				return "ms_timeout";
		}
	}
	else if (func == cmd_channel_mock_send_packet) {
		switch (arg) {
			case 0:
				return "packet";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a command channel.
 *
 * @param mock The mock to initialize.
 * @param id An ID for the command channel.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int cmd_channel_mock_init (struct cmd_channel_mock *mock, int id)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cmd_channel_mock));

	status = cmd_channel_init (&mock->base, id);
	if (status != 0) {
		return status;
	}

	status = mock_init (&mock->mock);
	if (status != 0) {
		cmd_channel_release (&mock->base);
		return status;
	}

	mock_set_name (&mock->mock, "cmd_channel");

	mock->base.receive_packet = cmd_channel_mock_receive_packet;
	mock->base.send_packet = cmd_channel_mock_send_packet;

	mock->mock.func_arg_count = cmd_channel_mock_func_arg_count;
	mock->mock.func_name_map = cmd_channel_mock_func_name_map;
	mock->mock.arg_name_map = cmd_channel_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a command channel mock.
 *
 * @param mock The mock to release.
 */
void cmd_channel_mock_release (struct cmd_channel_mock *mock)
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
int cmd_channel_mock_validate_and_release (struct cmd_channel_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cmd_channel_mock_release (mock);
	}

	return status;
}

/**
 * Custom validation routine for validating cmd_packet arguments.
 *
 * @param arg_info Argument information from the mock for error messages.
 * @param expected The expected packet contents.
 * @param actual The actual packet contents.
 *
 * @return 0 if the packet contained the expected information or 1 if not.
 */
int cmd_channel_mock_validate_packet (const char *arg_info, void *expected, void *actual)
{
	struct cmd_packet *pkt_expected = (struct cmd_packet*) expected;
	struct cmd_packet *pkt_actual = (struct cmd_packet*) actual;
	int fail = 0;

	if (pkt_expected->dest_addr != pkt_actual->dest_addr) {
		platform_printf ("%sUnexpected destination address: expected=0x%x, actual=0x%x" NEWLINE,
			arg_info, pkt_expected->dest_addr, pkt_actual->dest_addr);
		fail |= 1;
	}

	if (pkt_expected->state != pkt_actual->state) {
		platform_printf ("%sUnexpected packet state: expected=%d, actual=%d" NEWLINE, arg_info,
			pkt_expected->state, pkt_actual->state);
		fail |= 1;
	}

	if (pkt_expected->timeout_valid != pkt_actual->timeout_valid) {
		platform_printf ("%sUnexpected timeout flag: expected=%d, actual=%d" NEWLINE, arg_info,
			pkt_expected->timeout_valid, pkt_actual->timeout_valid);
		fail |= 1;
	}

	if (pkt_expected->pkt_size != pkt_actual->pkt_size) {
		platform_printf ("%sUnexpected packet length: expected=0x%lx, actual=0x%lx" NEWLINE, arg_info,
			pkt_expected->pkt_size, pkt_actual->pkt_size);
		fail |= 1;
	}

	fail |= testing_validate_array_prefix (pkt_expected->data, pkt_actual->data,
		pkt_expected->pkt_size, arg_info);

	return fail;
}
