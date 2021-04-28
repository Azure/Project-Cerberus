// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "mctp_cmd_task.h"


/**
 * MCTP command loop
 *
 * @param data Pointer to MCTP command task instance
 *
 */
static void mctp_cmd_task_loop (void *data)
{
	struct mctp_cmd_task *task = (struct mctp_cmd_task*) data;

	while (1) {
		cmd_channel_receive_and_process (task->channel, task->mctp, -1);
	}
}

/**
 * Initialize and start the task to process received MCTP messages.
 *
 * @param task The MCTP command task to initialize.
 * @param channel The command channel for sending and receiving packets.
 * @param mctp The MCTP protocol handler to use for packet processing.
 * @param priority The priority level for running the command task.
 * @param stack_words The size of the command task stack.  The stack size is measured in words.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int mctp_cmd_task_init (struct mctp_cmd_task *task, struct cmd_channel *channel,
	struct mctp_interface *mctp, int priority, uint16_t stack_words)
{
	int status;

	if ((task == NULL) || (channel == NULL) || (mctp == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct mctp_cmd_task));

	task->channel = channel;
	task->mctp = mctp;

	status = xTaskCreate (mctp_cmd_task_loop, "MCTP_LOOP", stack_words, task, priority,
		&task->cmd_loop_task);
	if (status != pdPASS) {
		return status;
	}

	return 0;
}

/**
 * Stop and release the MCTP command task.
 *
 * @param task The MCTP command task to release.
 */
void mctp_cmd_task_deinit (struct mctp_cmd_task *task)
{
	if (task != NULL) {
		vTaskDelete (task->cmd_loop_task);
	}
}
