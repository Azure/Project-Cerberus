// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "authorized_execution_allow_impactful.h"
#include "firmware_logging.h"
#include "cmd_interface/config_reset.h"
#include "common/unused.h"


int authorized_execution_allow_impactful_execute (const struct authorized_execution *execution,
	const uint8_t *data, size_t length, bool *reset_req)
{
	const struct authorized_execution_allow_impactful *reset =
		(const struct authorized_execution_allow_impactful*) execution;
	int status;

	/* No data is needed for execution. */
	UNUSED (data);
	UNUSED (length);
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

int authorized_execution_allow_impactful_validate_data (
	const struct authorized_execution *execution, const uint8_t *data, size_t length)
{
	if (execution == NULL) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	/* The command consumes no data, so anything is considered valid. */
	UNUSED (data);
	UNUSED (length);

	return 0;
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
	execution->base.validate_data = authorized_execution_allow_impactful_validate_data;
	execution->base.get_status_identifiers = authorized_execution_get_status_identifiers;

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
