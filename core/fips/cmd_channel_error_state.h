// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_ERROR_STATE_H_
#define CMD_CHANNEL_ERROR_STATE_H_

#include <stdbool.h>
#include "cmd_interface/cmd_channel.h"
#include "fips/error_state_entry_interface.h"


/**
 * Variable context for the error state command channel interposer.
 */
struct cmd_channel_error_state_state {
	struct cmd_channel_state base;	/**< Variable context for the base type. */
	bool drop_tx_packets;			/**< Flag indicating that outbound packets should be dropped. */
};

/**
 * Interposer for a command channel to block output while in the FIPS error state.
 *
 * This version can only enter the error state.  Exiting would require a device reset.
 */
struct cmd_channel_error_state {
	struct cmd_channel base_channel;				/**< Base command channel instance. */
	struct error_state_entry_interface base_entry;	/**< Base error state API for entry. */
	struct cmd_channel_error_state_state *state;	/**< Variable context for the channel. */
	const struct cmd_channel *channel;				/**< Interposed command channel. */
};


int cmd_channel_error_state_init (struct cmd_channel_error_state *interposer,
	struct cmd_channel_error_state_state *state, const struct cmd_channel *channel);
int cmd_channel_error_state_init_state (const struct cmd_channel_error_state *interposer);
void cmd_channel_error_state_release (const struct cmd_channel_error_state *interposer);


#endif	/* CMD_CHANNEL_ERROR_STATE_H_ */
