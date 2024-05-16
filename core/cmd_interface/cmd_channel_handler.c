// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_channel_handler.h"
#include "common/unused.h"


#ifdef CMD_ENABLE_ISSUE_REQUEST
void cmd_channel_handler_prepare (const struct periodic_task_handler *handler)
{
	const struct cmd_channel_handler *cmd = (const struct cmd_channel_handler*) handler;

	mctp_interface_send_discovery_notify (cmd->mctp, 0, NULL);
}
#endif

const platform_clock* cmd_channel_handler_get_next_execution (
	const struct periodic_task_handler *handler)
{
	UNUSED (handler);

	return NULL;
}

void cmd_channel_handler_execute (const struct periodic_task_handler *handler)
{
	const struct cmd_channel_handler *cmd = (const struct cmd_channel_handler*) handler;

	/* Errors are handled and logged within this call, so there is no need to check the return
	 * value. */
	cmd_channel_receive_and_process (cmd->channel, cmd->mctp, -1);
}

/**
 * Initialize a handler for receiving and processing commands from a command channel.
 *
 * @param handler The command handler to initialize.
 * @param channel The command channel for sending and receiving packets.
 * @param mctp The MCTP protocol handler to use for packet processing.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int cmd_channel_handler_init (struct cmd_channel_handler *handler,
	const struct cmd_channel *channel, const struct mctp_interface *mctp)
{
	if ((handler == NULL) || (channel == NULL) || (mctp == NULL)) {
		return CMD_CHANNEL_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct cmd_channel_handler));

#ifdef CMD_ENABLE_ISSUE_REQUEST
	handler->base.prepare = cmd_channel_handler_prepare;
#endif
	handler->base.get_next_execution = cmd_channel_handler_get_next_execution;
	handler->base.execute = cmd_channel_handler_execute;

	handler->channel = channel;
	handler->mctp = mctp;

	return 0;
}

/**
 * Release the resources used for handling received commands.
 *
 * @param handler The command handler to release.
 */
void cmd_channel_handler_release (const struct cmd_channel_handler *handler)
{
	UNUSED (handler);
}
