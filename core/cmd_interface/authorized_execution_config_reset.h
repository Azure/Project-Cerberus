// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_CONFIG_RESET_H_
#define AUTHORIZED_EXECUTION_CONFIG_RESET_H_

#include <stdint.h>
#include "cmd_interface/config_reset.h"
#include "common/authorized_execution.h"


/**
 * Provides an authorized execution context for running any execution against the configuration
 * reset manager.
 */
struct authorized_execution_config_reset {
	struct authorized_execution base;	/**< Base execution API. */
	const struct config_reset *reset;	/**< Configuration reset manager to execute against. */
	uint8_t log_success;				/**< Log message ID for a successful execution. */
	uint8_t log_fail;					/**< Log message ID for a failed execution. */
	uint8_t op_start;					/**< Status ID when the execution is starting. */
	uint8_t op_fail;					/**< Status ID when the execution has failed. */
	bool reset_req;						/**< Indication if the operation will request a reset. */

	/**
	 * Handler to call on the configuration reset manager for execute the execution.
	 *
	 * This is an internal pointer for managing different executions.  It's not part of the public
	 * API for this module.
	 *
	 * @param reset The configuration reset manager.
	 *
	 * @return 0 if the reset execution was successful or an error code.
	 */
	int (*reset_handler) (const struct config_reset *reset);
};


int authorized_execution_config_reset_init_restore_bypass (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset);
int authorized_execution_config_reset_init_restore_defaults (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset);
int authorized_execution_config_reset_init_restore_platform_config (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset);
int authorized_execution_config_reset_init_clear_component_manifests (
	struct authorized_execution_config_reset *execution, const struct config_reset *reset);

void authorized_execution_config_reset_release (
	const struct authorized_execution_config_reset *execution);


#endif	/* AUTHORIZED_EXECUTION_CONFIG_RESET_H_ */
