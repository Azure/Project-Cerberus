// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "cmd_channel_error_state_with_exit.h"
#include "common/type_cast.h"
#include "common/unused.h"


int cmd_channel_error_state_with_exit_exit_error_state (
	const struct error_state_exit_interface *exit)
{
	const struct cmd_channel_error_state_with_exit *interposer =
		TO_DERIVED_TYPE (exit, const struct cmd_channel_error_state_with_exit, base_exit);

	if (exit == NULL) {
		return ERROR_STATE_EXIT_INVALID_ARGUMENT;
	}

	interposer->base.state->drop_tx_packets = false;

	return 0;
}

/**
 * Initialize a command channel interposer that can supress output from the channel when in the FIPS
 * error state.
 *
 * It's possible for this interposer to both enter and exit the error state.
 *
 * @param interposer The channel interposer to initialize.
 * @param state Variable context for the interposer.  This must be uninitialized.
 * @param channel The command channel to interpose.
 *
 * @return 0 if the channel interposer was initialized successfully or an error code.
 */
int cmd_channel_error_state_with_exit_init (struct cmd_channel_error_state_with_exit *interposer,
	struct cmd_channel_error_state_state *state, const struct cmd_channel *channel)
{
	int status;

	if (interposer == NULL) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	status = cmd_channel_error_state_init (&interposer->base, state, channel);
	if (status == 0) {
		interposer->base_exit.exit_error_state = cmd_channel_error_state_with_exit_exit_error_state;
	}

	return status;
}

/**
 * Initialize only the variable state for a FIPS error state channel interposer that supports
 * exiting the error state.  The rest of the instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param interposer The channel interposer that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int cmd_channel_error_state_with_exit_init_state (
	const struct cmd_channel_error_state_with_exit *interposer)
{
	if (interposer == NULL) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	return cmd_channel_error_state_init_state (&interposer->base);
}

/**
 * Release the resources used by a FIPS error state channel interposer that supports exiting the
 * error state.
 *
 * @param interposer The channel interposer to release.
 */
void cmd_channel_error_state_with_exit_release (
	const struct cmd_channel_error_state_with_exit *interposer)
{
	if (interposer != NULL) {
		cmd_channel_error_state_release (&interposer->base);
	}
}
