// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include "debug_log.h"
#include "platform.h"
#include "common/unused.h"


/* By default, the global singleton for the debug log is defined here.  However, if the target
 * project wants to define this to be a constant instance, it needs to be defined and initialized
 * in that scope. */
#ifndef LOGGING_DEBUG_LOG_CONST_INSTANCE
const struct logging *debug_log = NULL;
#endif


/**
 * Create a new entry in the debug log.
 *
 * @param severity Severity level of the new entry.
 * @param component Component that is generating the entry.
 * @param msg_index Identifier code for the log entry message.
 * @param arg1 Log entry optional message specific argument.
 * @param arg2 Log entry optional message specific argument.
 *
 * @return Completion status, 0 if success or an error code.
 */
int debug_log_create_entry (uint8_t severity, uint8_t component, uint8_t msg_index, uint32_t arg1,
	uint32_t arg2)
{
#ifdef LOGGING_SUPPORT_DEBUG_LOG
	struct debug_log_entry_info entry;

	if (debug_log == NULL) {
		return LOGGING_NO_LOG_AVAILABLE;
	}

	if (severity >= DEBUG_LOG_NUM_SEVERITY) {
		return LOGGING_UNSUPPORTED_SEVERITY;
	}

	entry.format = DEBUG_LOG_ENTRY_FORMAT;
	entry.severity = severity;
	entry.component = component;
	entry.msg_index = msg_index;
	entry.arg1 = arg1;
	entry.arg2 = arg2;
	entry.time = platform_get_time ();

	return debug_log->create_entry (debug_log, (uint8_t*) &entry, sizeof (entry));
#else
	UNUSED (severity);
	UNUSED (component);
	UNUSED (msg_index);
	UNUSED (arg1);
	UNUSED (arg2);

	return LOGGING_NO_LOG_AVAILABLE;
#endif
}

#ifndef LOGGING_DISABLE_FLUSH
/**
 * Flush any buffered contents of the debug log.
 *
 * @return Completion status, 0 if success or an error code.
 */
int debug_log_flush ()
{
#ifdef LOGGING_SUPPORT_DEBUG_LOG
	if (debug_log == NULL) {
		return LOGGING_NO_LOG_AVAILABLE;
	}

	return debug_log->flush (debug_log);
#else
	return LOGGING_NO_LOG_AVAILABLE;
#endif
}
#endif

/**
 * Remove all entries from the debug log.
 *
 * @return Completion status, 0 if success or an error code.
 */
int debug_log_clear ()
{
#ifdef LOGGING_SUPPORT_DEBUG_LOG
	if (debug_log == NULL) {
		return LOGGING_NO_LOG_AVAILABLE;
	}

	return debug_log->clear (debug_log);
#else
	return LOGGING_NO_LOG_AVAILABLE;
#endif
}

/**
 * Get the total size of all entries in the debug log.
 *
 * @return The size of the debug log or an error code.  Use ROT_IS_ERROR to check the return value.
 */
int debug_log_get_size ()
{
#ifdef LOGGING_SUPPORT_DEBUG_LOG
	if (debug_log == NULL) {
		return LOGGING_NO_LOG_AVAILABLE;
	}

	return debug_log->get_size (debug_log);
#else
	return LOGGING_NO_LOG_AVAILABLE;
#endif
}

/**
 * Read entry data from the debug log.
 *
 * @param offset Offset within the log to start reading data.
 * @param contents Output buffer for the log contents.
 * @param length Maximum number of bytes to read from the log.
 *
 * @return The number of bytes read from the log or an error code.  Use ROT_IS_ERROR to check the
 * return value.
 */
int debug_log_read_contents (uint32_t offset, uint8_t *contents, size_t length)
{
#ifdef LOGGING_SUPPORT_DEBUG_LOG
	if (debug_log == NULL) {
		return LOGGING_NO_LOG_AVAILABLE;
	}

	return debug_log->read_contents (debug_log, offset, contents, length);
#else
	UNUSED (offset);
	UNUSED (contents);
	UNUSED (length);

	return LOGGING_NO_LOG_AVAILABLE;
#endif
}
