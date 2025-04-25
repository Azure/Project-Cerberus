// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_ERROR_STATE_WITH_EXIT_H_
#define CMD_CHANNEL_ERROR_STATE_WITH_EXIT_H_

#include "fips/cmd_channel_error_state.h"
#include "fips/error_state_exit_interface.h"


/**
 * Interposer for a command channel to block output while in the FIPS error state.
 *
 * This version supports exiting from error state at run-time.
 */
struct cmd_channel_error_state_with_exit {
	struct cmd_channel_error_state base;			/**< Base error state handling instance. */
	struct error_state_exit_interface base_exit;	/**< Base error state API for exit. */
};


int cmd_channel_error_state_with_exit_init (struct cmd_channel_error_state_with_exit *interposer,
	struct cmd_channel_error_state_state *state, const struct cmd_channel *channel);
int cmd_channel_error_state_with_exit_init_state (
	const struct cmd_channel_error_state_with_exit *interposer);
void cmd_channel_error_state_with_exit_release (
	const struct cmd_channel_error_state_with_exit *interposer);


#endif	/* CMD_CHANNEL_ERROR_STATE_WITH_EXIT_H_ */
