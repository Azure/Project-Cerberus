// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_CMD_HANDLER_H_
#define HOST_CMD_HANDLER_H_

#include "host_cmd_interface.h"
#include "system/event_task.h"


/**
 * Action identifiers for the host command handler.
 */
enum {
	HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG = 1,	/**< Change the host flash configuration. */
};

/**
 * Variable context for the host command handler.
 */
struct host_cmd_handler_state {
	int status;	/**< The host operation status. */
};

/**
 * A handler for requests for a single protected host.
 */
struct host_cmd_handler {
	struct host_cmd_interface base_cmd;		/**< The base interface for command handling. */
	struct event_task_handler base_event;	/**< The base interface for task integration. */
	struct host_cmd_handler_state *state;	/**< Variable context for the handler. */
	const struct host_processor *host;		/**< The target host processor. */
	const struct event_task *task;			/**< The task context executing the handler. */
};


int host_cmd_handler_init (struct host_cmd_handler *handler, struct host_cmd_handler_state *state,
	const struct host_processor *host, const struct event_task *task);
int host_cmd_handler_init_state (const struct host_cmd_handler *handler);
void host_cmd_handler_release (const struct host_cmd_handler *handler);


/* This module will be treated as an extension of the host processor and use HOST_PROCESSOR_*
 * error codes. */


#endif	/* HOST_CMD_HANDLER_H_ */
