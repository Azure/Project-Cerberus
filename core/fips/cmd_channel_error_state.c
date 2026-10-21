// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "cmd_channel_error_state.h"
#include "common/type_cast.h"
#include "common/unused.h"


int cmd_channel_error_state_receive_packet (const struct cmd_channel *channel,
	struct cmd_packet *packet, int ms_timeout)
{
	const struct cmd_channel_error_state *interposer =
		TO_DERIVED_TYPE (channel, const struct cmd_channel_error_state, base_channel);

	if (channel == NULL) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	return interposer->channel->receive_packet (interposer->channel, packet, ms_timeout);
}

int cmd_channel_error_state_send_packet (const struct cmd_channel *channel,
	const struct cmd_packet *packet)
{
	const struct cmd_channel_error_state *interposer =
		TO_DERIVED_TYPE (channel, const struct cmd_channel_error_state, base_channel);

	if ((channel == NULL) || (packet == NULL)) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	if (!interposer->state->drop_tx_packets) {
		return interposer->channel->send_packet (interposer->channel, packet);
	}
	else {
		/* Silently drop outbound packets when in the error state. */
	}

	return 0;
}

void cmd_channel_error_state_enter_error_state (const struct error_state_entry_interface *entry,
	const struct debug_log_entry_info *error_log)
{
	const struct cmd_channel_error_state *interposer =
		TO_DERIVED_TYPE (entry, const struct cmd_channel_error_state, base_entry);

	UNUSED (error_log);

	if (entry == NULL) {
		return;
	}

	interposer->state->drop_tx_packets = true;
}

/**
 * Initialize a command channel interposer that can supress output from the channel when in the FIPS
 * error state.
 *
 * It will not be possible to exit the error state without a device reset.
 *
 * @param interposer The channel interposer to initialize.
 * @param state Variable context for the interposer.  This must be uninitialized.
 * @param channel The command channel to interpose.
 *
 * @return 0 if the channel interposer was initialized successfully or an error code.
 */
int cmd_channel_error_state_init (struct cmd_channel_error_state *interposer,
	struct cmd_channel_error_state_state *state, const struct cmd_channel *channel)
{
	int status;

	if ((interposer == NULL) || (state == NULL)) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	memset (interposer, 0, sizeof (*interposer));
	memset (state, 0, sizeof (*state));

	/* Match the ID of the existing channel, since this is meant to be externally invisible. */
	status = cmd_channel_get_id (channel);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = cmd_channel_init (&interposer->base_channel, &state->base, status);
	if (status != 0) {
		return status;
	}

	interposer->base_channel.receive_packet = cmd_channel_error_state_receive_packet;
	interposer->base_channel.send_packet = cmd_channel_error_state_send_packet;

	interposer->base_entry.enter_error_state = cmd_channel_error_state_enter_error_state;

	interposer->state = state;
	interposer->channel = channel;

	return 0;
}

/**
 * Initialize only the variable state for a FIPS error state channel interposer.  The rest of the
 * instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param interposer The channel interposer that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int cmd_channel_error_state_init_state (const struct cmd_channel_error_state *interposer)
{
	if ((interposer == NULL) || (interposer->state == NULL) || (interposer->channel == NULL)) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	memset (interposer->state, 0, sizeof (*interposer->state));

	return cmd_channel_init_state (&interposer->base_channel);
}

/**
 * Release the resources used by a FIPS error state channel interposer.
 *
 * @param interposer The channel interposer to release.
 */
void cmd_channel_error_state_release (const struct cmd_channel_error_state *interposer)
{
	if (interposer) {
		cmd_channel_release (&interposer->base_channel);
	}
}
