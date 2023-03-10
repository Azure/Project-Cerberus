// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_cmd_handler_pfm.h"
#include "common/unused.h"
#include "manifest/manifest_logging.h"


int manifest_cmd_handler_pfm_activation (const struct manifest_cmd_handler *handler, bool *reset)
{
	const struct manifest_cmd_handler_pfm *pfm = (const struct manifest_cmd_handler_pfm*) handler;
	int status;
	int config_status;
	int op_status;

	UNUSED (reset);

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

				manifest_cmd_handler_set_status (handler,
					MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR, status));
			}
			else {
				if (status != HOST_PROCESSOR_NOTHING_TO_VERIFY) {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
						MANIFEST_LOGGING_ACTIVATION_FAIL, host_processor_get_port (pfm->host),
						status);
				}

				op_status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_ACTIVATION_FAIL, status);
			}
		}
		else {
			if (host_state_manager_get_run_time_validation (pfm->host_state) !=
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
 * Initialize a handler for executing PFM commands.
 *
 * @param handler The PFM handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param manifest The manifest manager to use during command processing.
 * @param task The task that will be used to execute PFM operations.
 * @param host The host instance for the PFM.
 * @param host_state Manager of host state information.
 * @param hash Hash engine to use with run-time PFM activation.
 * @param rsa RSA engine to use with run-time PFM activation.
 * @param filter SPI filter for the host.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int manifest_cmd_handler_pfm_init (struct manifest_cmd_handler_pfm *handler,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task, struct host_processor *host,
	struct host_state_manager *host_state, struct hash_engine *hash, struct rsa_engine *rsa,
	const struct spi_filter_interface *filter)
{
	int status;

	if ((handler == NULL) || (host == NULL) || (host_state == NULL) || (hash == NULL) ||
		(rsa == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct manifest_cmd_handler_pfm));

	status = manifest_cmd_handler_init (&handler->base, state, manifest, task);
	if (status != 0) {
		return status;
	}

	handler->host = host;
	handler->host_state = host_state;
	handler->hash = hash;
	handler->rsa = rsa;
	handler->filter = filter;

	handler->base.activation = manifest_cmd_handler_pfm_activation;

	return 0;
}

/**
 * Initialize only the variable state for a PFM handler.  The rest of the handler is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The manifest handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int manifest_cmd_handler_pfm_init_state (const struct manifest_cmd_handler_pfm *handler)
{
	if ((handler == NULL) || (handler->host == NULL) || (handler->host_state == NULL) ||
		(handler->hash == NULL) || (handler->rsa == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_cmd_handler_init_state (&handler->base);
}

/**
 * Release the resources used by a PFM handler.
 *
 * @param handler The manifest handler to release.
 */
void manifest_cmd_handler_pfm_release (const struct manifest_cmd_handler_pfm *handler)
{
	if (handler) {
		manifest_cmd_handler_release (&handler->base);
	}
}
