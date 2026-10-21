// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "authorized_execution_rma.h"
#include "rma_logging.h"
#include "common/unused.h"


int authorized_execution_rma_execute (const struct authorized_execution *execution,
	const uint8_t *data, size_t length, bool *reset_req)
{
	const struct authorized_execution_rma *rma_exe =
		(const struct authorized_execution_rma*) execution;
	int status;

	UNUSED (reset_req);

	if (execution == NULL) {
		status = AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
		goto error;
	}

	status = rma_exe->token->authenticate (rma_exe->token, data, length);
	if (status != 0) {
		goto error;
	}

	status = rma_exe->rma->config_rma (rma_exe->rma);
	if (status != 0) {
		goto error;
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_RMA,
		RMA_LOGGING_RMA_TRANSITION_DONE, 0, 0);

	return 0;

error:
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RMA,
		RMA_LOGGING_RMA_TRANSITION_FAILED, status, 0);

	return status;
}

int authorized_execution_rma_validate_data (const struct authorized_execution *execution,
	const uint8_t *data, size_t length)
{
	const struct authorized_execution_rma *rma_exe =
		(const struct authorized_execution_rma*) execution;

	if (execution == NULL) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	return rma_exe->token->authenticate (rma_exe->token, data, length);
}

/**
 * Initialize an authorized execution context for transitioning a device to the RMA state.
 *
 * @param execution RMA execution context to initialize.
 * @param token Token handler for validating the RMA operation.
 * @param rma Device handler to transition the device for RMA.
 *
 * @return 0 if the execution context was initialized successfully or an error code.
 */
int authorized_execution_rma_init (struct authorized_execution_rma *execution,
	const struct rma_unlock_token *token, const struct device_rma_transition *rma)
{
	if ((execution == NULL) || (token == NULL) || (rma == NULL)) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	memset (execution, 0, sizeof (*execution));

	execution->base.execute = authorized_execution_rma_execute;
	execution->base.validate_data = authorized_execution_rma_validate_data;
	execution->base.get_status_identifiers = authorized_execution_get_status_identifiers;

	execution->token = token;
	execution->rma = rma;

	return 0;
}

/**
 * Release the resources used for RMA execution.
 *
 * @param execution RMA execution context to release.
 */
void authorized_execution_rma_release (const struct authorized_execution_rma *execution)
{
	UNUSED (execution);
}
