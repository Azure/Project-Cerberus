// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "crash_dump_logging.h"
#include "debug_log.h"
#include "logging_flash.h"


/**
 * Save opaque data as debug log entries.
 *
 * @param[in] buffer The buffer where crashdump data is stored.
 * @param[in] length The number bytes of crashdump data.
 *
 */
void crash_dump_logging_save_opaque_data (uint32_t *buffer, size_t length)
{
	uint32_t two_word_size = 2 * sizeof (uint32_t);
	uint32_t num_of_dwords = length / two_word_size;
	uint32_t remaining = length % two_word_size;
	uint32_t parameter0;
	uint32_t parameter1;

	for (uint32_t idx = 0; idx < num_of_dwords; idx++) {
		parameter0 = *buffer;
		buffer++;
		parameter1 = *buffer;
		buffer++;
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
			CRASH_DUMP_LOGGING_OPAQUE_DATA, parameter0, parameter1);
	}

	switch (remaining) {
		case 1:
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
				CRASH_DUMP_LOGGING_OPAQUE_DATA, *buffer & 0xFF, 0);
			break;

		case 2:
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
				CRASH_DUMP_LOGGING_OPAQUE_DATA, *buffer & 0xFFFF, 0);
			break;

		case 3:
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
				CRASH_DUMP_LOGGING_OPAQUE_DATA, *buffer & 0xFFFFFF, 0);
			break;

		case 4:
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
				CRASH_DUMP_LOGGING_OPAQUE_DATA, *buffer, 0);
			break;

		case 5:
			parameter0 = *buffer;
			buffer++;
			parameter1 = *buffer & 0xFF;
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
				CRASH_DUMP_LOGGING_OPAQUE_DATA, parameter0, parameter1);
			break;

		case 6:
			parameter0 = *buffer;
			buffer++;
			parameter1 = *buffer & 0xFFFF;
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
				CRASH_DUMP_LOGGING_OPAQUE_DATA, parameter0, parameter1);
			break;

		case 7:
			parameter0 = *buffer;
			buffer++;
			parameter1 = *buffer & 0xFFFFFF;
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
				CRASH_DUMP_LOGGING_OPAQUE_DATA, parameter0, parameter1);
			break;

		default:
			break;
	}
}

/**
 * Generate a log message indicating that a stack overflow was detected for a system task.
 *
 * @param stack The task stack pointer.  This must be a valid pointer within the task stack, not the
 * overflowed pointer.  The stack base pointer is a typical value to use here.
 */
void crash_dump_logging_save_stack_overflow (void *stack)
{
#if (UINTPTR_WIDTH <= 32)
	uint32_t stack_msb = 0;
#else
	uint32_t stack_msb = (uintptr_t) stack >> 32;
#endif

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_STACK_OVERFLOW, stack_msb, (uintptr_t) stack);
}
