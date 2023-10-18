// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_STATIC_H_
#define CMD_CHANNEL_STATIC_H_

#include "cmd_interface/cmd_channel.h"


/* Static initializer API for derived types. */

/**
 * Initialize a static instance of a base command channel context.  This is not a top level API
 * and must only be called by an implementation API.  This does not initialize the state context
 * which must be initialized by a top level API that calls cmd_channel_init_state.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the command channel.
 * @param recv_func The command channel packet receive handler.
 * @param send_func The command channel packet send handler.
 * @param chan_id The command channel ID for the instance.
 */
#define cmd_channel_static_init(state_ptr, recv_func, send_func, chan_id) { \
		.receive_packet = recv_func, \
		.send_packet = send_func, \
		.state = state_ptr, \
		.id = chan_id, \
	}


#endif /* CMD_CHANNEL_STATIC_H_ */
