// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_ERROR_STATE_WITH_EXIT_STATIC_H_
#define CMD_CHANNEL_ERROR_STATE_WITH_EXIT_STATIC_H_

#include "cmd_channel_error_state_static.h"
#include "cmd_channel_error_state_with_exit.h"


/* Internal functions declared to allow for static initialization. */
int cmd_channel_error_state_with_exit_exit_error_state (
	const struct error_state_exit_interface *exit);


/**
 * Constant initializer for the error state exit API.
 */
#define	CMD_CHANNEL_ERROR_STATE_WITH_EXIT_API_INIT  { \
		.exit_error_state = cmd_channel_error_state_with_exit_exit_error_state, \
	}


/**
 * Initialize a static instance of a command channel interposer that can supress output from the
 * channel when in the FIPS error state.  This can be a constant instance.
 *
 * It's possible for this interposer to both enter and exit the error state.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the channel error state handler.
 * @param channel_ptr The command channel to interpose.
 * @param id_arg ID assigned to the command channel being interposed.
 */
#define	cmd_channel_error_state_with_exit_static_init(state_ptr, channel_ptr, id_arg)	{ \
		.base = cmd_channel_error_state_static_init (state_ptr, channel_ptr, id_arg), \
		.base_exit = CMD_CHANNEL_ERROR_STATE_WITH_EXIT_API_INIT, \
	}


#endif	/* CMD_CHANNEL_ERROR_STATE_WITH_EXIT_STATIC_H_ */
