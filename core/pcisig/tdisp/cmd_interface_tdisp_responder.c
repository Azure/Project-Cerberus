// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_interface_tdisp_responder.h"
#include "tdisp_commands.h"
#include "cmd_interface/cmd_interface.h"
#include "common/array_size.h"
#include "common/unused.h"

//#define TDISP_RESPONDER_DEBUG_SPEW

#ifdef TDISP_RESPONDER_DEBUG_SPEW
#include "platform_io_api.h"
#endif

/**
 * TDISP supported messages
 */
static const uint8_t tdisp_supported_messages[] = {
	TDISP_REQUEST_GET_VERSION,
	TDISP_REQUEST_GET_CAPABILITIES,
	TDISP_REQUEST_LOCK_INTERFACE,
	TDISP_REQUEST_GET_DEVICE_INTERFACE_REPORT,
	TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE,
	TDISP_REQUEST_START_INTERFACE,
	TDISP_REQUEST_STOP_INTERFACE,
};


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

	if (request->is_encrypted == false) {
		status = CMD_INTERFACE_TDISP_RESPONDER_SECURE_SPDM_REQUIRED;
		goto exit;
	}

	if (request->payload_length < sizeof (struct tdisp_header)) {
		status = CMD_INTERFACE_TDISP_RESPONDER_INVALID_MSG_SIZE;
		goto exit;
	}
	tdisp_request = (const struct tdisp_header*) request->payload;

#ifdef TDISP_RESPONDER_DEBUG_SPEW
	platform_printf ("TDISP: Request code 0x%x\n", tdisp_request->message_type);
#endif

	/* [TODO] If possible, consolidate error response generation in this function. */
	switch (tdisp_request->message_type) {
		case TDISP_REQUEST_GET_VERSION:
#ifdef TDISP_RESPONDER_DEBUG_SPEW
			platform_printf ("TDISP: TDISP_REQUEST_GET_VERSION\n");
#endif
			status = tdisp_get_version (tdisp_responder->tdisp_driver, tdisp_responder->version_num,
				tdisp_responder->version_num_count, request);
			break;

		case TDISP_REQUEST_GET_CAPABILITIES:
#ifdef TDISP_RESPONDER_DEBUG_SPEW
			platform_printf ("TDISP: TDISP_REQUEST_GET_CAPABILITIES\n");
#endif
			status = tdisp_get_capabilities (tdisp_responder->tdisp_driver,
				tdisp_supported_messages, ARRAY_SIZE (tdisp_supported_messages), request);
			break;

		case TDISP_REQUEST_LOCK_INTERFACE:
#ifdef TDISP_RESPONDER_DEBUG_SPEW
			platform_printf ("TDISP: TDISP_REQUEST_LOCK_INTERFACE\n");
#endif
			status = tdisp_lock_interface (tdisp_responder->tdi_context_manager,
				tdisp_responder->tdisp_driver, tdisp_responder->rng_engine, request);
			break;

		case TDISP_REQUEST_GET_DEVICE_INTERFACE_REPORT:
#ifdef TDISP_RESPONDER_DEBUG_SPEW
			platform_printf ("TDISP: TDISP_REQUEST_GET_DEVICE_INTERFACE_REPORT\n");
#endif
			status = tdisp_get_device_interface_report (tdisp_responder->tdisp_driver, request);
			break;

		case TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE:
#ifdef TDISP_RESPONDER_DEBUG_SPEW
			platform_printf ("TDISP: TDISP_REQUEST_GET_DEVICE_INTERFACE_STATE\n");
#endif
			status = tdisp_get_device_interface_state (tdisp_responder->tdisp_driver, request);
			break;

		case TDISP_REQUEST_START_INTERFACE:
#ifdef TDISP_RESPONDER_DEBUG_SPEW
			platform_printf ("TDISP: TDISP_REQUEST_START_INTERFACE\n");
#endif
			status = tdisp_start_interface (tdisp_responder->tdi_context_manager,
				tdisp_responder->tdisp_driver, request);
			break;

		case TDISP_REQUEST_STOP_INTERFACE:
#ifdef TDISP_RESPONDER_DEBUG_SPEW
			platform_printf ("TDISP: TDISP_REQUEST_STOP_INTERFACE\n");
#endif
			status = tdisp_stop_interface (tdisp_responder->tdisp_driver, request);
			break;

		default:
#ifdef TDISP_RESPONDER_DEBUG_SPEW
			platform_printf ("TDISP: UNKNOWN\n");
#endif
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

/**
 * Initialize the TDISP responder instance.
 *
 * @param tdisp_responder TDISP responder instance to initialize.
 * @param tdi_context_manager TDISP TDI context manager.
 * @param tdisp_driver TDISP driver to use for programming the TDISP registers.
 * @param version_num Supported TDISP version number array.
 * @param version_num_count Number of version number(s) in the array.
 * @param rng_engine Random number generator engine.
 *
 * @return 0 if the TDISP responder instance was initialized successfully or an error code.
 */
int cmd_interface_tdisp_responder_init (struct cmd_interface_tdisp_responder *tdisp_responder,
	const struct tdisp_tdi_context_manager *tdi_context_manager, struct tdisp_driver *tdisp_driver,
	const uint8_t *version_num, uint8_t version_num_count, const struct rng_engine *rng_engine)
{
	int status = 0;

	if ((tdisp_responder == NULL) || (tdi_context_manager == NULL) ||
		(tdisp_driver == NULL) || (version_num == NULL) || (version_num_count == 0) ||
		(rng_engine == NULL)) {
		status = CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	memset (tdisp_responder, 0, sizeof (struct cmd_interface_tdisp_responder));

	tdisp_responder->tdisp_driver = tdisp_driver;
	tdisp_responder->tdi_context_manager = tdi_context_manager;
	tdisp_responder->version_num = version_num;
	tdisp_responder->version_num_count = version_num_count;
	tdisp_responder->rng_engine = rng_engine;

	tdisp_responder->base.process_request = cmd_interface_tdisp_responder_process_request;
#ifdef CMD_ENABLE_ISSUE_REQUEST
	tdisp_responder->base.process_response = cmd_interface_tdisp_responder_process_response;
#endif

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
