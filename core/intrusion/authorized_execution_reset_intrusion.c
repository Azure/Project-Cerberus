// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "authorized_execution_reset_intrusion.h"
#include "cmd_interface/cmd_logging.h"
#include "cmd_interface/config_reset.h"
#include "common/unused.h"


int authorized_execution_reset_intrusion_execute (const struct authorized_execution *execution)
{
	const struct authorized_execution_reset_intrusion *reset =
		(const struct authorized_execution_reset_intrusion*) execution;
	int status;

	if (reset == NULL) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	status = reset->intrusion->reset_intrusion (reset->intrusion);
	if (status == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_RESET_INTRUSION, 0, 0);
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_RESET_INTRUSION_FAIL, status, 0);
	}

	return status;
}

void authorized_execution_reset_intrusion_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error)
{
	UNUSED (execution);

	if (start) {
		*start = CONFIG_RESET_STATUS_RESET_INTRUSION;
	}

	if (error) {
		*error = CONFIG_RESET_STATUS_INTRUSION_FAILED;
	}
}

/**
 * Initialize an authorized execution context that will reset the current intrusion state.
 *
 * @param execution The execution context to initialize.
 * @param intrusion Intrusion manager that will be used to reset the intrusion state.
 *
 * @return 0 if the initialization was successful or an error code.
 */
int authorized_execution_reset_intrusion_init (
	struct authorized_execution_reset_intrusion *execution, struct intrusion_manager *intrusion)
{
	if ((execution == NULL) || (intrusion == NULL)) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	memset (execution, 0, sizeof (*execution));

	execution->base.execute = authorized_execution_reset_intrusion_execute;
	execution->base.get_status_identifiers =
		authorized_execution_reset_intrusion_get_status_identifiers;

	execution->intrusion = intrusion;

	return 0;
}

/**
 * Release the resources used for an intrusion reset execution context.
 *
 * @param execution The execution context to release.
 */
void authorized_execution_reset_intrusion_release (
	const struct authorized_execution_reset_intrusion *execution)
{
	UNUSED (execution);
}
