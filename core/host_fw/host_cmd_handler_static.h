// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_CMD_HANDLER_STATIC_H_
#define HOST_CMD_HANDLER_STATIC_H_

#include "host_cmd_handler.h"


/* Internal functions declared to allow for static initialization. */
int host_cmd_handler_get_next_host_verification (const struct host_cmd_interface *cmd,
	enum host_processor_reset_actions *action);
int host_cmd_handler_get_flash_configuration (const struct host_cmd_interface *cmd,
	spi_filter_flash_mode *mode, spi_filter_cs *current_ro, spi_filter_cs *next_ro,
	enum host_read_only_activation *apply_next_ro);
int host_cmd_handler_set_flash_configuration (const struct host_cmd_interface *cmd,
	int8_t current_ro, int8_t next_ro, int8_t apply_next_ro);
int host_cmd_handler_get_status (const struct host_cmd_interface *cmd);
void host_cmd_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset);


/**
 * Constant initializer for the host command API.
 */
#define	HOST_CMD_HANDLER_COMMAND_API_INIT  { \
		.get_next_host_verification = host_cmd_handler_get_next_host_verification, \
		.get_flash_configuration = host_cmd_handler_get_flash_configuration, \
		.set_flash_configuration = host_cmd_handler_set_flash_configuration, \
		.get_status = host_cmd_handler_get_status, \
	}

/**
 * Constant initializer for the host task API.
 */
#define	HOST_CMD_HANDLER_EVENT_API_INIT  { \
		.prepare = NULL, \
		.execute = host_cmd_handler_execute, \
	}


/**
 * Initialize a static instance of a host command handler.  This does not initialize the handler
 * state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the host command handler.
 * @param host_ptr The host processor to use during command processing.
 * @param task_ptr The task that will be used to execute host operations.
 */
#define	host_cmd_handler_static_init(state_ptr, host_ptr, task_ptr)	{ \
		.base_cmd = HOST_CMD_HANDLER_COMMAND_API_INIT, \
		.base_event = HOST_CMD_HANDLER_EVENT_API_INIT, \
		.state = state_ptr, \
		.host = host_ptr, \
		.task = task_ptr, \
	}


#endif	/* HOST_CMD_HANDLER_STATIC_H_ */
