// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface_tdisp_responder.h"
#include "tdisp_commands.h"
#include "common/unused.h"


int cmd_interface_tdisp_responder_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	int status = 0;
	const struct cmd_interface_tdisp_responder *tdisp_responder =
		(const struct cmd_interface_tdisp_responder*) intf;
	const struct tdisp_header *tdisp_request;

	if ((tdisp_responder == NULL) || (request == NULL)) {
		status = CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	if (request->payload_length < sizeof (struct tdisp_header)) {
		status = CMD_INTERFACE_TDISP_RESPONDER_INVALID_MSG_SIZE;
		goto exit;
	}
	tdisp_request = (const struct tdisp_header*) request->payload;

	/* [TODO] If possible, consolidate error response generation in this function. */
	switch (tdisp_request->message_type) {
		case TDISP_REQUEST_GET_VERSION:
			status = tdisp_get_version (tdisp_responder->state, tdisp_responder->version_num,
				tdisp_responder->version_num_count, request);
			break;

		case TDISP_REQUEST_GET_CAPABILITIES:
			status = tdisp_get_capabilities (tdisp_responder->tdisp_driver, request);
			break;

		case TDISP_REQUEST_LOCK_INTERFACE:
			status = tdisp_lock_interface (tdisp_responder->state, tdisp_responder->tdisp_driver,
				tdisp_responder->rng_engine, request);
			break;

		case TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE:
			status = tdisp_get_device_interface_state (tdisp_responder->state,
				tdisp_responder->tdisp_driver, request);
			break;

		case TDISP_REQUEST_START_INTERFACE:
			status = tdisp_start_interface (tdisp_responder->state, tdisp_responder->tdisp_driver,
				request);
			break;

		default:
			tdisp_generate_error_response (request, TDISP_VERSION_1_0, 0,
				TDISP_ERROR_CODE_UNSUPPORTED_REQUEST, 0);
			break;
	}

exit:
	return status;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
int cmd_interface_tdisp_responder_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	UNUSED (intf);
	UNUSED (response);

	return CMD_INTERFACE_TDISP_RESPONDER_UNSUPPORTED_OPERATION;
}
#endif

int cmd_interface_tdisp_responder_generate_error_packet (const struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set)
{
	UNUSED (intf);
	UNUSED (request);
	UNUSED (error_code);
	UNUSED (error_data);
	UNUSED (cmd_set);

	return CMD_INTERFACE_TDISP_RESPONDER_UNSUPPORTED_OPERATION;
}

/**
 * Initialize the TDISP responder instance.
 *
 * @param tdisp_responder TDISP responder instance to initialize.
 * @param tdisp_state TDISP state to use for the responder instance.
 * @param tdisp_driver TDISP driver to use for programming the TDISP registers.
 * @param version_num Supported TDISP version number array.
 * @param version_num_count Number of version number(s) in the array.
 * @param rng_engine Random number generator engine.
 *
 * @return 0 if the TDISP responder instance was initialized successfully or an error code.
 */
int cmd_interface_tdisp_responder_init (struct cmd_interface_tdisp_responder *tdisp_responder,
	struct tdisp_state *tdisp_state, struct tdisp_driver *tdisp_driver,
	const uint8_t *version_num, uint8_t version_num_count, struct rng_engine *rng_engine)
{
	int status = 0;

	if (tdisp_responder == NULL) {
		status = CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	memset (tdisp_responder, 0, sizeof (struct cmd_interface_tdisp_responder));

	tdisp_responder->tdisp_driver = tdisp_driver;
	tdisp_responder->version_num = version_num;
	tdisp_responder->version_num_count = version_num_count;
	tdisp_responder->state = tdisp_state;
	tdisp_responder->rng_engine = rng_engine;

	tdisp_responder->base.process_request = cmd_interface_tdisp_responder_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	tdisp_responder->base.process_response = cmd_interface_tdisp_responder_process_response;
#endif
	tdisp_responder->base.generate_error_packet =
		cmd_interface_tdisp_responder_generate_error_packet;

	/* Initialize the state. */
	status = cmd_interface_tdisp_responder_init_state (tdisp_responder);

exit:
	return status;
}

/**
 * Initialize the state of the TDISP responder instance.
 *
 * @param tdisp_responder TDISP responder instance to initialize.
 *
 * @return 0 if the TDISP responder state was initialized successfully or an error code.
 */
int cmd_interface_tdisp_responder_init_state (
	const struct cmd_interface_tdisp_responder *tdisp_responder)
{
	int status;

	if ((tdisp_responder == NULL) || (tdisp_responder->tdisp_driver == NULL) ||
		(tdisp_responder->version_num == NULL) || (tdisp_responder->version_num_count == 0) ||
		(tdisp_responder->rng_engine == NULL)) {
		status = CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	status = tdisp_init_state (tdisp_responder->state);
	if (status != 0) {
		goto exit;
	}

exit:
	return status;
}

/**
 * Release the resources used by the TDISP responder instance.
 *
 * @param tdisp_interface TDISP responder instance to release.
 */
void cmd_interface_tdisp_responder_release (
	const struct cmd_interface_tdisp_responder *tdisp_interface)
{
	UNUSED (tdisp_interface);
}


