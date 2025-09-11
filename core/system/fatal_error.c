// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "fatal_error.h"
#include "system_logging.h"


/* By default, the global singleton for fatal error handling is defined here.  However, if the
 * target project wants to define this to be a constant instance, it needs to be defined and
 * initialized in that scope. */
#ifndef FATAL_ERROR_CONST_INSTANCE
const struct fatal_error_handler *fatal_error = NULL;
#endif


/**
 * Create debug log entries for the fatal error and flush the log to persistent storage.
 *
 * @param error_code Code identifying the fatal error condition that was encountered.
 * @param error_log Optional log entry containing additional details about the error condition.
 * This can be null if there are no additional details to log.
 */
static void fatal_error_log_error (int error_code, const struct debug_log_entry_info *error_log)
{
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
		SYSTEM_LOGGING_FATAL_ERROR, error_code, 0);

	if (error_log != NULL) {
		debug_log_create_entry (error_log->severity, error_log->component, error_log->msg_index,
			error_log->arg1, error_log->arg2);
	}

	debug_log_flush ();
}

/**
 * Handle an error that cannot by mitigated by software but does not leave the system in a
 * generally unusable state.  System services, specifically debug logging, are expected to be
 * functional.
 *
 * @param error_code Code identifying the fatal error condition that was encountered.
 */
void fatal_error_unrecoverable_error (int error_code)
{
	fatal_error_log_error (error_code, NULL);

	if (fatal_error != NULL) {
		fatal_error->unrecoverable_error (fatal_error);
	}
}

/**
 * Handle an error that cannot be mitigated by software and that has left the system in an unknown
 * state.  System services are assumed to not be functional.
 *
 * @param error_code Code identifying the fatal error condition that was encountered.
 * @param error_log Optional log entry containing additional details about the error condition.
 * This can be null if there are no additional details to log.
 */
void fatal_error_panic (int error_code, const struct debug_log_entry_info *error_log)
{
	if (fatal_error != NULL) {
		fatal_error->panic (fatal_error, error_code, error_log);
	}
	else {
		/* No error handler has been provided by the system.  Create log messages for the error,
		 * which may not work depending on the functional state of the system, but at least an
		 * attempt is made to leave a record of the error condition. */
		fatal_error_log_error (error_code, error_log);
	}
}

/**
 * Handle an error that cannot be mitigated by software and that has left the system in an unknown
 * state.  System services are assumed to not be functional.
 *
 * An additional debug log entry will be created to provide more details about the error condition.
 *
 * @param error_code Code identifying the fatal error condition that was encountered.
 * @param severity Severity to assign to the additional log message.
 * @param component Component identifier for the log message.
 * @param msg_index Message identifier for the log entry.
 * @param arg1 First message specific argument for the log entry.
 * @param arg2 Second message specific argument for the log entry.
 */
void fatal_error_panic_create_entry (int error_code, uint8_t severity, uint8_t component,
	uint8_t msg_index, uint32_t arg1, uint32_t arg2)
{
	struct debug_log_entry_info error_log = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = severity,
		.component = component,
		.msg_index = msg_index,
		.arg1 = arg1,
		.arg2 = arg2
	};

	fatal_error_panic (error_code, &error_log);
}
