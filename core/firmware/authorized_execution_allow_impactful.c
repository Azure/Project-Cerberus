// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "authorized_execution_allow_impactful.h"
#include "firmware_logging.h"
#include "cmd_interface/config_reset.h"
#include "common/unused.h"


int authorized_execution_allow_impactful_execute (const struct authorized_execution *execution,
	bool *reset_req)
{
	const struct authorized_execution_allow_impactful *reset =
		(const struct authorized_execution_allow_impactful*) execution;
	int status;

	UNUSED (reset_req);

	if (reset == NULL) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	status = reset->impactful->authorize_update (reset->impactful, reset->auth_time_ms);
	if (status == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_ALLOW_IMPACTFUL_UPDATE, reset->auth_time_ms, 0);
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_ALLOW_IMPACTFUL_FAIL, reset->auth_time_ms, status);
	}

	return status;
}

void authorized_execution_allow_impactful_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error)
{
	UNUSED (execution);

	if (start) {
		*start = CONFIG_RESET_STATUS_AUTHORIZED_OPERATION;
	}

	if (error) {
		*error = CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED;
	}
}

/**
 * Initialize an authorized execution context to allow impactful firmware updates.
 *
 * @param execution The execution context to initialize.
 * @param impactful Manager for impactful updates that will be updated with the authorization.
 * @param auth_time_ms The amount of time each impactful authorization will be valid for, in
 * milliseconds.  If this is 0, there is no expiration for the impactful authorization.
 *
 * @return 0 if the initialization was successful or an error code.
 */
int authorized_execution_allow_impactful_init (
	struct authorized_execution_allow_impactful *execution,
	const struct impactful_update_interface *impactful, uint32_t auth_time_ms)
{
	if ((execution == NULL) || (impactful == NULL)) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	memset (execution, 0, sizeof (*execution));

	execution->base.execute = authorized_execution_allow_impactful_execute;
	execution->base.get_status_identifiers =
		authorized_execution_allow_impactful_get_status_identifiers;

	execution->impactful = impactful;
	execution->auth_time_ms = auth_time_ms;

	return 0;
}

/**
 * Release the resources used for an allow impactful update execution context.
 *
 * @param execution The execution context to release.
 */
void authorized_execution_allow_impactful_release (
	const struct authorized_execution_allow_impactful *execution)
{
	UNUSED (execution);
}
