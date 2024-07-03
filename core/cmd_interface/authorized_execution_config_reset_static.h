// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_CONFIG_RESET_STATIC_H_
#define AUTHORIZED_EXECUTION_CONFIG_RESET_STATIC_H_

#include "authorized_execution_config_reset.h"


/* Internal functions declared to allow for static initialization. */
int authorized_execution_config_reset_execute (const struct authorized_execution *execution);
void authorized_execution_config_reset_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error);


/**
 * Constant initializer for the execution API.
 */
#define	AUTHORIZED_EXECUTION_CONFIG_RESET_API_INIT	{ \
		.execute = authorized_execution_config_reset_execute, \
		.get_status_identifiers = authorized_execution_config_reset_get_status_identifiers, \
	}

/**
 * Static initializer for an authorized execution context using a configuration reset manager.
 *
 * This is not intended to be called directly and initializers for the specific executions that are
 * supported should be called instead.
 *
 * @param reset_ptr The configuration reset manager that will be used to execute the execution.
 * @param log_success_arg Log message ID for a successful execution.
 * @param log_fail_arg Log message ID for a failed execution.
 * @param op_start_arg Status ID to report when the execution is starting.
 * @param op_fail_arg Status ID to report when the execution has failed.
 * @param reset_handler_ptr Function to call on the configuration reset manager to execute the
 * execution.
 */
#define	authorized_execution_config_reset_static_init(reset_ptr, log_success_arg, log_fail_arg, \
	op_start_arg, op_fail_arg, reset_handler_ptr) { \
		.base = AUTHORIZED_EXECUTION_CONFIG_RESET_API_INIT, \
		.reset = reset_ptr, \
		.log_success = log_success_arg, \
		.log_fail = log_fail_arg, \
		.op_start = op_start_arg, \
		.op_fail = op_fail_arg, \
		.reset_handler = reset_handler_ptr, \
	}



/**
 * Initialize a static authorized execution context to revert to bypass mode using a configuration
 * reset manager.
 *
 * There is no validation done on the arguments.
 *
 * @param reset_ptr The configuration reset manager that will be used to execute the execution.
 */
#define	authorized_execution_config_reset_static_init_restore_bypass(reset_ptr) \
	authorized_execution_config_reset_static_init (reset_ptr, CMD_LOGGING_BYPASS_RESTORED, \
		CMD_LOGGING_RESTORE_BYPASS_FAIL, CONFIG_RESET_STATUS_RESTORE_BYPASS, \
		CONFIG_RESET_STATUS_BYPASS_FAILED, config_reset_restore_bypass)

/**
 * Initialize a static authorized execution context to restore all default configuration using a
 * configuration reset manager.
 *
 * There is no validation done on the arguments.
 *
 * @param reset_ptr The configuration reset manager that will be used to execute the execution.
 */
#define	authorized_execution_config_reset_static_init_restore_defaults(reset_ptr) \
	authorized_execution_config_reset_static_init (reset_ptr, CMD_LOGGING_DEFAULTS_RESTORED, \
		CMD_LOGGING_RESTORE_DEFAULTS_FAIL, CONFIG_RESET_STATUS_RESTORE_DEFAULTS, \
		CONFIG_RESET_STATUS_DEFAULTS_FAILED, config_reset_restore_defaults)

/**
 * Initialize a static authorized execution context to remove any platform configuration manifests
 * using a configuration reset manager.
 *
 * There is no validation done on the arguments.
 *
 * @param reset_ptr The configuration reset manager that will be used to execute the execution.
 */
#define	authorized_execution_config_reset_static_init_restore_platform_config(reset_ptr) \
	authorized_execution_config_reset_static_init (reset_ptr, CMD_LOGGING_CLEAR_PLATFORM_CONFIG, \
		CMD_LOGGING_CLEAR_PLATFORM_FAIL, CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG, \
		CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED, config_reset_restore_platform_config)

/**
 * Initialize a static authorized execution context to remove any component manifests using a
 * configuration reset manager.
 *
 * There is no validation done on the arguments.
 *
 * @param reset_ptr The configuration reset manager that will be used to execute the execution.
 */
#define	authorized_execution_config_reset_static_init_clear_component_manifests(reset_ptr) \
	authorized_execution_config_reset_static_init (reset_ptr, CMD_LOGGING_CLEAR_CFM, \
		CMD_LOGGING_CLEAR_CFM_FAIL, CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS, \
		CONFIG_RESET_STATUS_COMPONENT_MANIFESTS_FAILED, config_reset_clear_component_manifests)


#endif	/* AUTHORIZED_EXECUTION_CONFIG_RESET_STATIC_H_ */
