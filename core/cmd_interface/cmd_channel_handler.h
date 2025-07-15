// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_HANDLER_H_
#define CMD_CHANNEL_HANDLER_H_

#include <stdbool.h>
#include "cmd_interface/cmd_channel.h"
#include "mctp/mctp_interface.h"
#include "system/periodic_task.h"


/**
 * Handler for processing received commands from a command channel.
 */
struct cmd_channel_handler {
	struct periodic_task_handler base;	/**< Base interface for task integration. */
	const struct cmd_channel *channel;	/**< Command channel for receiving messages. */
	const struct mctp_interface *mctp;	/**< MCTP protocol layer. */
#ifdef CMD_ENABLE_ISSUE_REQUEST
	bool use_bridge_eid;				/**< Flag to indicate the bridge EID should be notified. */
#endif
};


int cmd_channel_handler_init (struct cmd_channel_handler *handler,
	const struct cmd_channel *channel, const struct mctp_interface *mctp);
int cmd_channel_handler_init_notify_null_eid (struct cmd_channel_handler *handler,
	const struct cmd_channel *channel, const struct mctp_interface *mctp);
void cmd_channel_handler_release (const struct cmd_channel_handler *handler);


/* This module will be treated as an extension of the command channel and use CMD_CHANNEL_* error
 * codes. */


#endif	/* CMD_CHANNEL_HANDLER_H_ */
