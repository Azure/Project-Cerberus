// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LOG_FLUSH_HANDLER_H_
#define LOG_FLUSH_HANDLER_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "platform_api.h"
#include "logging.h"
#include "system/periodic_task.h"


/**
 * Variable context for the handler for flushing log data.
 */
struct log_flush_handler_state {
	platform_clock next;					/**< Time at which the next execution should run. */
	bool next_valid;						/**< Indicate if the next timeout has been initialized. */
};

/**
 * Handler to flush log data.
 */
struct log_flush_handler {
	struct periodic_task_handler base;		/**< Base interface for task integration. */
	struct log_flush_handler_state *state;	/**< Variable context for the handler. */
	const struct logging **logs;			/**< List of logs to flush. */
	size_t log_count;						/**< Number of logs in the list. */
	uint32_t period;						/**< Required time between log flush requests. */
};


int log_flush_handler_init (struct log_flush_handler *handler,
	struct log_flush_handler_state *state, const struct logging **logs, size_t log_count,
	uint32_t period_ms);
int log_flush_handler_init_state (const struct log_flush_handler *handler);
void log_flush_handler_release (const struct log_flush_handler *handler);


/* This module will be treated as an extension of the logging module and use LOGGING_* error
 * codes. */


#endif /* LOG_FLUSH_HANDLER_H_ */
