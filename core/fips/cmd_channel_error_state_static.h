// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_ERROR_STATE_STATIC_H_
#define CMD_CHANNEL_ERROR_STATE_STATIC_H_

#include "cmd_channel_error_state.h"
#include "cmd_interface/cmd_channel_static.h"


/* Internal functions declared to allow for static initialization. */
int cmd_channel_error_state_receive_packet (const struct cmd_channel *channel,
	struct cmd_packet *packet, int ms_timeout);
int cmd_channel_error_state_send_packet (const struct cmd_channel *channel,
	const struct cmd_packet *packet);

void cmd_channel_error_state_enter_error_state (const struct error_state_entry_interface *entry,
	const struct debug_log_entry_info *error_log);


/**
 * Constant initializer for the error state entry API.
 */
#define	CMD_CHANNEL_ERROR_STATE_ENTRY_API_INIT  { \
		.enter_error_state = cmd_channel_error_state_enter_error_state, \
	}


/**
 * Initialize a static instance of a command channel interposer that can supress output from the
 * channel when in the FIPS error state.  This can be a constant instance.
 *
 * It will not be possible to exit the error state without a device reset.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the channel error state handler.
 * @param channel_ptr The command channel to interpose.
 * @param id_arg ID assigned to the command channel being interposed.
 */
#define	cmd_channel_error_state_static_init(state_ptr, channel_ptr, id_arg)	{ \
		.base_channel = cmd_channel_static_init (&(state_ptr)->base, \
			cmd_channel_error_state_receive_packet, cmd_channel_error_state_send_packet, id_arg), \
		.base_entry = CMD_CHANNEL_ERROR_STATE_ENTRY_API_INIT, \
		.state = state_ptr, \
		.channel = channel_ptr, \
	}


#endif	/* CMD_CHANNEL_ERROR_STATE_STATIC_H_ */
