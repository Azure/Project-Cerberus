// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_HANDLER_STATIC_H_
#define CMD_CHANNEL_HANDLER_STATIC_H_

#include "platform_api.h"
#include "cmd_interface/cmd_channel_handler.h"


/* Internal functions declared to allow for static initialization. */
void cmd_channel_handler_prepare (const struct periodic_task_handler *handler);
const platform_clock* cmd_channel_handler_get_next_execution (
	const struct periodic_task_handler *handler);
void cmd_channel_handler_execute (const struct periodic_task_handler *handler);


/**
 * Constant initializer for the the prepare operation.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_CHANNEL_HANDLER_PREPARE_API		.prepare = cmd_channel_handler_prepare,
#define	CMD_CHANNEL_HANDLER_NOTIFY_EID(x)	.use_bridge_eid = (x),
#else
#define	CMD_CHANNEL_HANDLER_PREPARE_API
#define	CMD_CHANNEL_HANDLER_NOTIFY_EID(x)
#endif

/**
 * Constant initializer for the command handling task API.
 */
#define	CMD_CHANNEL_HANDLER_API_INIT  { \
		CMD_CHANNEL_HANDLER_PREPARE_API \
		.get_next_execution = cmd_channel_handler_get_next_execution, \
		.execute = cmd_channel_handler_execute \
	}


/**
 * Initialize a static instance of a handler for commands received from a command channel.  This can
 * be a constant instance.
 *
 * When sending MCTP requests is enabled, the MCTP bridge will be notified using the configured
 * bridge EID.
 *
 * There is no validation done on the arguments.
 *
 * @param channel_ptr The command channel for sending and receiving packets.
 * @param mctp_ptr The MCTP protocol handler to use for packet processing.
 * @param mctp_control_ptr The MCTP control message transport instance.
 */
#define	cmd_channel_handler_static_init(channel_ptr, mctp_ptr, mctp_control_ptr)	{ \
		.base = CMD_CHANNEL_HANDLER_API_INIT, \
		.channel = channel_ptr, \
		.mctp = mctp_ptr, \
		.mctp_control = mctp_control_ptr, \
		CMD_CHANNEL_HANDLER_NOTIFY_EID (true) \
	}

/**
 * Initialize a static instance of a handler for commands received from a command channel.  This can
 * be a constant instance.
 *
 * When sending MCTP requests is enabled, the MCTP bridge will be notified using the NULL EID.
 *
 * There is no validation done on the arguments.
 *
 * @param channel_ptr The command channel for sending and receiving packets.
 * @param mctp_ptr The MCTP protocol handler to use for packet processing.
 * @param mctp_control_ptr The MCTP control message transport instance.
 */
#define	cmd_channel_handler_static_init_notify_null_eid(channel_ptr, mctp_ptr, mctp_control_ptr)	{ \
		.base = CMD_CHANNEL_HANDLER_API_INIT, \
		.channel = channel_ptr, \
		.mctp = mctp_ptr, \
		.mctp_control = mctp_control_ptr, \
		CMD_CHANNEL_HANDLER_NOTIFY_EID (false) \
	}


#endif	/* CMD_CHANNEL_HANDLER_STATIC_H_ */
