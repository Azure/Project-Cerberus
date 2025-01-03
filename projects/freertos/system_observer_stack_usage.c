// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "platform_io_api.h"
#include "system_observer_stack_usage.h"
#include "common/unused.h"


static void system_observer_stack_usage_on_shutdown (struct system_observer *observer)
{
	UNUSED (observer);

	system_observer_stack_usage_print_all_tasks_usage ();
}

/**
 * Initialize a system observer to create stack usage information on system resets.
 *
 * @param stack The observer to initialize.
 *
 * return 0 if the initialization was successful or an error code.
 */
int system_observer_stack_usage_init (struct system_observer_stack_usage *observer)
{
	if (observer == NULL) {
		return SYSTEM_OBSERVER_INVALID_ARGUMENT;
	}

	memset (observer, 0, sizeof (struct system_observer_stack_usage));

	observer->base.on_shutdown = system_observer_stack_usage_on_shutdown;

	return 0;
}

/**
 * Release a system observer for generating stack usage details.
 *
 * @param observer The observer to release.
 */
void system_observer_stack_usage_release (struct system_observer_stack_usage *observer)
{
	UNUSED (observer);
}

/**
 * Print the maximum stack usage for all system tasks.
 */
void system_observer_stack_usage_print_all_tasks_usage ()
{
	TaskStatus_t *status;
	UBaseType_t tasks = uxTaskGetNumberOfTasks ();
	UBaseType_t i;

	status = platform_calloc (sizeof (TaskStatus_t), tasks);
	if (status == NULL) {
		platform_printf ("Task status alloc failed" NEWLINE);
	}
	else {
		tasks = uxTaskGetSystemState (status, tasks, NULL);
		platform_printf ("Tasks: %d" NEWLINE, tasks);
		for (i = 0; i < tasks; i++) {
			platform_printf ("\t%s:  %d" NEWLINE, status[i].pcTaskName,
				status[i].usStackHighWaterMark);
		}

		platform_free (status);
	}
}
