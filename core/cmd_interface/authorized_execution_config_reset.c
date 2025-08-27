// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "authorized_execution_config_reset.h"
#include "cmd_logging.h"
#include "common/unused.h"


int authorized_execution_config_reset_execute (const struct authorized_execution *execution,
	const uint8_t *data, size_t length, bool *reset_req)
{
	const struct authorized_execution_config_reset *config =
		(const struct authorized_execution_config_reset*) execution;
	int status;

	/* No data is needed for execution. */
	UNUSED (data);
	UNUSED (length);

	if (config == NULL) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	status = config->reset_handler (config->reset);
	if (status == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			config->log_success, 0, 0);

		/* Request a device reset for operations that require it. */
		if ((reset_req != NULL) && config->reset_req) {
			*reset_req = true;
		}
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			config->log_fail, status, 0);
	}

	return status;
}

void authorized_execution_config_reset_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error)
{
	const struct authorized_execution_config_reset *config =
		(const struct authorized_execution_config_reset*) execution;
	uint8_t op_start = CONFIG_RESET_STATUS_AUTHORIZED_OPERATION;
	uint8_t op_fail = CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED;

	if (config) {
		op_start = config->op_start;
		op_fail = config->op_fail;
	}

	if (start) {
		*start = op_start;
	}

	if (error) {
		*error = op_fail;
	}
}

/**
 * Initialize an authorized execution context for any configuration reset execution.
 *
 * @param execution The execution context to initialize.
 * @param reset The configuration reset manager that will be used to execute the reset operation.
 * @param log_success Log message ID for a successful execution.
 * @param log_fail Log message ID for a failed execution.
 * @param op_start Status ID to report when the execution is starting.
 * @param op_fail Status ID to report when the execution has failed.
 * @param reset_req Flag indicating if a reset will be requested by the operation or not.
 * @param reset_handler Function to call on the configuration reset manager to execute the
 * execution.
 *
 * @return 0 if initialization was successful or an error code.
 */
static int authorized_execution_config_reset_init (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset,
	uint8_t log_success, uint8_t log_fail, uint8_t op_start, uint8_t op_fail, bool reset_req,
	int (*reset_handler) (const struct config_reset*))
{
	if ((execution == NULL) || (reset == NULL)) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	memset (execution, 0, sizeof (*execution));

	execution->base.execute = authorized_execution_config_reset_execute;
	execution->base.validate_data = authorized_execution_validate_data;
	execution->base.get_status_identifiers =
		authorized_execution_config_reset_get_status_identifiers;

	execution->reset = reset;
	execution->log_success = log_success;
	execution->log_fail = log_fail;
	execution->op_start = op_start;
	execution->op_fail = op_fail;
	execution->reset_req = reset_req;
	execution->reset_handler = reset_handler;

	return 0;
}

/**
 * Initialize an authorized execution context to revert to bypass mode using a configuration reset
 * manager.
 *
 * @param execution The execution context to initialize.
 * @param reset The configuration reset manager that will be used to execute the reset operation.
 *
 * @return 0 if initialization was successful or an error code.
 */
int authorized_execution_config_reset_init_restore_bypass (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset)
{
	return authorized_execution_config_reset_init (execution, reset, CMD_LOGGING_BYPASS_RESTORED,
		CMD_LOGGING_RESTORE_BYPASS_FAIL, CONFIG_RESET_STATUS_RESTORE_BYPASS,
		CONFIG_RESET_STATUS_BYPASS_FAILED, false, config_reset_restore_bypass);
}

/**
 * Initialize an authorized execution context to restore all default configuration using a
 * configuration reset manager.
 *
 * @param execution The execution context to initialize.
 * @param reset The configuration reset manager that will be used to execute the reset operation.
 *
 * @return 0 if initialization was successful or an error code.
 */
int authorized_execution_config_reset_init_restore_defaults (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset)
{
	return authorized_execution_config_reset_init (execution, reset, CMD_LOGGING_DEFAULTS_RESTORED,
		CMD_LOGGING_RESTORE_DEFAULTS_FAIL, CONFIG_RESET_STATUS_RESTORE_DEFAULTS,
		CONFIG_RESET_STATUS_DEFAULTS_FAILED, false, config_reset_restore_defaults);
}

/**
 * Initialize an authorized execution context to remove any platform configuration manifests using a
 * configuration reset manager.
 *
 * @param execution The execution context to initialize.
 * @param reset The configuration reset manager that will be used to execute the reset operation.
 *
 * @return 0 if initialization was successful or an error code.
 */
int authorized_execution_config_reset_init_restore_platform_config (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset)
{
	return authorized_execution_config_reset_init (execution, reset,
		CMD_LOGGING_CLEAR_PLATFORM_CONFIG, CMD_LOGGING_CLEAR_PLATFORM_FAIL,
		CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG, CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED, true,
		config_reset_restore_platform_config);
}

/**
 * Initialize an authorized execution context to remove any component manifests using a
 * configuration reset manager.
 *
 * @param execution The execution context to initialize.
 * @param reset The configuration reset manager that will be used to execute the reset operation.
 *
 * @return 0 if initialization was successful or an error code.
 */
int authorized_execution_config_reset_init_clear_component_manifests (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset)
{
	return authorized_execution_config_reset_init (execution, reset, CMD_LOGGING_CLEAR_CFM,
		CMD_LOGGING_CLEAR_CFM_FAIL, CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS,
		CONFIG_RESET_STATUS_COMPONENT_MANIFESTS_FAILED, false,
		config_reset_clear_component_manifests);
}

/**
 * Initialize an authorized execution context to remove any provisioned certificates using a
 * configuration reset manager.
 *
 * @param execution The execution context to initialize.
 * @param reset The configuration reset manager that will be used to execute the reset operation.
 *
 * @return 0 if initialization was successful or an error code.
 */
int authorized_execution_config_reset_init_clear_provisioned_certificates (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset)
{
	return authorized_execution_config_reset_init (execution, reset, CMD_LOGGING_CLEAR_CERTIFICATES,
		CMD_LOGGING_CLEAR_CERTIFICATES_FAIL, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION,
		CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, false,
		config_reset_clear_provisioned_certificates);
}

/**
 * Release the resources used by a configuration reset execution context.
 *
 * @param execution The execution context to release.
 */
void authorized_execution_config_reset_release (
	const struct authorized_execution_config_reset *execution)
{
	UNUSED (execution);
}
