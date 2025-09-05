// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "log_flush_handler.h"
#include "common/unused.h"


void log_flush_handler_prepare (const struct periodic_task_handler *handler)
{
	const struct log_flush_handler *flush = (const struct log_flush_handler*) handler;

	if (platform_init_timeout (flush->period, &flush->state->next) == 0) {
		flush->state->next_valid = true;
	}
	else {
		flush->state->next_valid = false;
	}
}

const platform_clock* log_flush_handler_get_next_execution (
	const struct periodic_task_handler *handler)
{
	const struct log_flush_handler *flush = (const struct log_flush_handler*) handler;

	if (flush->state->next_valid) {
		return &flush->state->next;
	}
	else {
		/* If the next timeout is not valid, just indicate immediate execution. */
		return NULL;
	}
}

void log_flush_handler_execute (const struct periodic_task_handler *handler)
{
	const struct log_flush_handler *flush = (const struct log_flush_handler*) handler;

	log_flush_handler_immediate_flush (flush);
	log_flush_handler_prepare (handler);
}

/**
 * Initialize a handler to flush log data.
 *
 * @note This function assumes that the `logs` `flush()` implementation is reentrant and can be
 * called from either the `periodic_task` or another task calling
 * `log_flush_handler_immediate_flush()`.
 *
 * @param handler The log handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param logs The list of logs that should be flushed.
 * @param log_count The number of logs in the list.
 * @param period_ms The amount of time between log flush requests, in milliseconds.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int log_flush_handler_init (struct log_flush_handler *handler,
	struct log_flush_handler_state *state, const struct logging *const *logs, size_t log_count,
	uint32_t period_ms)
{
	if ((handler == NULL) || (state == NULL) || (logs == NULL) || (log_count == 0)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct log_flush_handler));

	handler->base.prepare = log_flush_handler_prepare;
	handler->base.get_next_execution = log_flush_handler_get_next_execution;
	handler->base.execute = log_flush_handler_execute;

	handler->state = state;
	handler->logs = logs;
	handler->log_count = log_count;
	handler->period = period_ms;

	return log_flush_handler_init_state (handler);
}

/**
 * Initialize only the variable state for a log flush handler.  The rest of the handler is assumed
 * to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The flush handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int log_flush_handler_init_state (const struct log_flush_handler *handler)
{
	if ((handler == NULL) || (handler->state == NULL) || (handler->logs == NULL) ||
		(handler->log_count == 0)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	memset (handler->state, 0, sizeof (struct log_flush_handler_state));

	return 0;
}

/**
 * Release the resources used by a log flush handler.
 *
 * @param handler The flush handler to release.
 */
void log_flush_handler_release (const struct log_flush_handler *handler)
{
	UNUSED (handler);
}

/**
 * Flush all logs immediately.
 *
 * @param handler The flush handler to execute.
 *
 * @return 0 if the logs were successfully flushed or an error code.
 */
int log_flush_handler_immediate_flush (const struct log_flush_handler *handler)
{
	size_t i;

	if (handler == NULL) {
		return LOGGING_INVALID_ARGUMENT;
	}

	for (i = 0; i < handler->log_count; i++) {
		handler->logs[i]->flush (handler->logs[i]);
	}

	return 0;
}
