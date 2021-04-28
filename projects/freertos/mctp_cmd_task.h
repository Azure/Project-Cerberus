// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_CMD_TASK_H_
#define MCTP_CMD_TASK_H_

#include "FreeRTOS.h"
#include "task.h"
#include "mctp/mctp_interface.h"
#include "cmd_interface/cmd_channel.h"


/**
 * Task context for processing MCTP messages.
 */
struct mctp_cmd_task {
	struct cmd_channel *channel;			/**< Command channel for receiving messages. */
	struct mctp_interface *mctp;  	  		/**< MCTP protocol layer. */
	TaskHandle_t cmd_loop_task;       		/**< Task handle for command processing loop. */
};


int mctp_cmd_task_init (struct mctp_cmd_task *task, struct cmd_channel *channel,
	struct mctp_interface *mctp, int priority, uint16_t stack_words);
void mctp_cmd_task_deinit (struct mctp_cmd_task *task);


#endif /* MCTP_CMD_TASK_H_ */
