// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "cmd_interface_spdm.h"
#include "spdm_state.h"

/**
 * Initialize the SPDM responder state for handling any SPDM requests and keeping SPDM
 * connection state
 *
 * @param state SPDM state.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int spdm_responder_init_state (struct spdm_responder_state *state)
{
	int status = 0;

	if (state == NULL) {
		status = CMD_HANDLER_SPDM_INVALID_ARGUMENT;
		goto exit;
	}

	memset (state, 0, sizeof (struct spdm_responder_state));

	/* Initialize the state. */
	state->connection_info.connection_state = SPDM_CONNECTION_STATE_NOT_STARTED;
	state->response_state = SPDM_RESPONSE_STATE_NORMAL;

exit:

	return status;
}
