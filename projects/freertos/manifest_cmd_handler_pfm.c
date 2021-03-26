// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_cmd_handler_pfm.h"
#include "manifest/manifest_logging.h"


static int manifest_cmd_handler_pfm_activation (struct manifest_cmd_handler *task, bool *reset)
{
	struct manifest_cmd_handler_pfm *pfm = (struct manifest_cmd_handler_pfm*) task;
	int status;
	int config_status;
	int op_status;

	spi_filter_log_configuration (pfm->filter);

	do {
		status = pfm->host->run_time_verification (pfm->host, pfm->hash, pfm->rsa);
		if (status != 0) {
			if (status != HOST_PROCESSOR_NOTHING_TO_VERIFY) {
				config_status = pfm->host->needs_config_recovery (pfm->host);
			}
			else {
				config_status = 0;
			}

			if (config_status) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
					MANIFEST_LOGGING_ACTIVATION_FLASH_ERROR, host_processor_get_port (pfm->host),
					status);

				manifest_cmd_handler_set_status (task,
					MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR, status));
			}
			else {
				if (status != HOST_PROCESSOR_NOTHING_TO_VERIFY) {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
						MANIFEST_LOGGING_ACTIVATION_FAIL, host_processor_get_port (pfm->host),
						status);
				}

				op_status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_ACTIVATION_FAIL, status);
				status = 0;
			}
		}
		else {
			if (host_state_manager_get_run_time_validation (pfm->state) !=
				HOST_STATE_PREVALIDATED_NONE) {
				op_status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_ACTIVATION_PENDING, 0);
			}
			else {
				op_status = 0;
			}

			config_status = 0;
		}
	} while (config_status != 0);

	spi_filter_log_configuration (pfm->filter);

	return op_status;
}

/**
 * Initialize the task interface for executing PFM commands.
 *
 * @param task The task interface to initialize.
 * @param manifest The manifest manager to execute commands against.
 * @param host The host instance for the PFM.
 * @param state Manager of host state information.
 * @param hash Hash engine to use with run-time PFM activation.
 * @param rsa RSA engine to use with run-time PFM activation.
 * @param filter SPI filter for the host.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int manifest_cmd_handler_pfm_init (struct manifest_cmd_handler_pfm *task,
	struct manifest_manager *manifest, struct host_processor *host,
	struct host_state_manager *state, struct hash_engine *hash, struct rsa_engine *rsa,
	struct spi_filter_interface *filter)
{
	int status;

	if ((task == NULL) || (host == NULL) || (state == NULL) || (hash == NULL) || (rsa == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct manifest_cmd_handler_pfm));

	status = manifest_cmd_handler_init (&task->base, manifest);
	if (status != 0) {
		return status;
	}

	task->host = host;
	task->state = state;
	task->hash = hash;
	task->rsa = rsa;
	task->filter = filter;

	task->base.activation = manifest_cmd_handler_pfm_activation;

	return 0;
}
