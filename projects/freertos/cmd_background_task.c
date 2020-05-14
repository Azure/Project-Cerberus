// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "cmd_interface/attestation_cmd_interface.h"
#include "cmd_interface/cmd_logging.h"
#include "cmd_interface/cerberus_protocol_optional_commands.h"
#include "flash/flash_common.h"
#include "logging/logging_flash.h"
#include "cmd_background_task.h"
#include "riot/riot_logging.h"


#define	CMD_BACKGROUND_RUN_UNSEAL		(1U << 0)
#define	CMD_BACKGROUND_RUN_BYPASS		(1U << 1)
#define	CMD_BACKGROUND_RUN_DEFAULTS		(1U << 2)
#define	CMD_BACKGROUND_DEBUG_LOG_CLEAR	(1U << 3)
#define	CMD_BACKGROUND_DEBUG_LOG_FILL	(1U << 4)
#define	CMD_BACKGROUND_AUTH_RIOT		(1U << 5)


/**
 * Set the current operation status.
 *
 * @param task The task instance to update.
 * @param op_status Storage location for the status value.
 * @param status The status value to set.
 */
void cmd_background_task_set_status (struct cmd_background_task *task, int *op_status, int status)
{
	xSemaphoreTake (task->lock, portMAX_DELAY);
	*op_status = status;
	xSemaphoreGive (task->lock);
}

/**
 * The task function that will run the background commands.
 *
 * @param task The background command task instance.
 */
static void cmd_background_task_handler (struct cmd_background_task *task)
{
	uint32_t notification;
	int *op_status;
	int status;

	do {
		/* Wait for a signal to perform update action. */
		status = CMD_BACKGROUND_UNSUPPORTED_OP;
		op_status =  &task->config.config_status;
		xTaskNotifyWait (pdFALSE, ULONG_MAX, &notification, portMAX_DELAY);

		if (notification & CMD_BACKGROUND_RUN_UNSEAL) {
			struct cerberus_protocol_message_unseal *unseal =
				(struct cerberus_protocol_message_unseal*) task->attestation.unseal_request;
			enum aux_attestation_seed_param seed_param;

			op_status = &task->attestation.attestation_status;

			if (unseal->seed_type == CERBERUS_PROTOCOL_UNSEAL_SEED_ECDH) {
				seed_param = (enum aux_attestation_seed_param) unseal->seed_params.ecdh.processing;
			}
			else {
				seed_param = (enum aux_attestation_seed_param) unseal->seed_params.rsa.padding;
			}

			status = task->attestation.attestation->aux_attestation_unseal (
				task->attestation.attestation, task->attestation.hash, AUX_ATTESTATION_KEY_256BIT,
				&unseal->seed, unseal->seed_length,
				(enum aux_attestation_seed_type) unseal->seed_type, seed_param,
				cerberus_protocol_unseal_hmac (unseal), HMAC_SHA256,
				cerberus_protocol_unseal_ciphertext (unseal),
				cerberus_protocol_unseal_ciphertext_length (unseal),
				cerberus_protocol_get_unseal_pmr_sealing (unseal)->pmr, CERBERUS_PROTOCOL_MAX_PMR,
				task->attestation.key, sizeof (task->attestation.key));
			if (ROT_IS_ERROR (status)) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR,
					DEBUG_LOG_COMPONENT_CMD_INTERFACE, CMD_LOGGING_UNSEAL_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_FAILURE, status);
			}
			else {
				status = ATTESTATION_CMD_STATUS_SUCCESS;
			}

			platform_free (task->attestation.unseal_request);
			task->attestation.unseal_request = NULL;
		}
		else if (notification & CMD_BACKGROUND_RUN_BYPASS) {
			cmd_background_task_set_status (task, &task->config.config_status,
				CONFIG_RESET_STATUS_RESTORE_BYPASS);

			status = config_reset_restore_bypass (task->config.reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_BYPASS_RESTORED, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESTORE_BYPASS_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_BYPASS_FAILED, status);
			}
		}
		else if (notification & CMD_BACKGROUND_RUN_DEFAULTS) {
			cmd_background_task_set_status (task, &task->config.config_status,
				CONFIG_RESET_STATUS_RESTORE_DEFAULTS);

			status = config_reset_restore_defaults (task->config.reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_DEFAULTS_RESTORED, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESTORE_DEFAULTS_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_DEFAULTS_FAILED, status);
			}
		}
		else if (notification & CMD_BACKGROUND_DEBUG_LOG_CLEAR) {
			status = debug_log_clear ();
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_DEBUG_LOG_CLEARED, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_DEBUG_LOG_CLEAR_FAIL, status, 0);
			}
		}
#ifdef ENABLE_DEBUG_COMMANDS
		else if (notification & CMD_BACKGROUND_DEBUG_LOG_FILL) {
			int max_count =
				(FLASH_SECTOR_SIZE / sizeof (struct debug_log_entry)) * LOGGING_FLASH_SECTORS;
			int i_entry;

			debug_log_clear ();
			for (i_entry = 0; i_entry < max_count; ++i_entry) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO,
					DEBUG_LOG_COMPONENT_DEVICE_SPECIFIC, 0, 0, 0);
			}
		}
#endif
		else if (notification & CMD_BACKGROUND_AUTH_RIOT) {
			op_status = &task->riot.cert_state;

			status = riot_key_manager_verify_stored_certs (task->riot.keys);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_RIOT,
					RIOT_LOGGING_DEVID_AUTH_STATUS, status, 0);

				status = CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
			}
		}
		else {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
				CMD_LOGGING_NOTIFICATION_ERROR, notification, 0);

			if (task->attestation.attestation_status == ATTESTATION_CMD_STATUS_RUNNING) {
				op_status = &task->attestation.attestation_status;
				status = CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_INTERNAL_ERROR, status);
			}
			else if (task->config.config_status == CONFIG_RESET_STATUS_STARTING) {
				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_INTERNAL_ERROR, status);
			}
			else if (task->riot.cert_state == RIOT_CERT_STATE_VALIDATING) {
				op_status = &task->riot.cert_state;
				status = CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
			}
		}

		xSemaphoreTake (task->lock, portMAX_DELAY);
		*op_status = status;
		task->running = 0;
		xSemaphoreGive (task->lock);
	} while (1);
}

static int cmd_background_task_unseal_start (struct cmd_background *cmd,
	const uint8_t *unseal_request, size_t length)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;
	int status = 0;

	if ((task == NULL) || (unseal_request == NULL) || (length == 0)) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if ((task->attestation.attestation == NULL) || (task->attestation.hash == NULL)) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	if (task->task) {
		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (!task->running) {
			if (task->attestation.unseal_request != NULL) {
				platform_free (task->attestation.unseal_request);
			}

			task->attestation.unseal_request = platform_malloc (length);
			if (task->attestation.unseal_request != NULL) {
				task->attestation.attestation_status = ATTESTATION_CMD_STATUS_RUNNING;
				task->running = 1;

				memcpy (task->attestation.unseal_request, unseal_request, length);

				xSemaphoreGive (task->lock);
				xTaskNotify (task->task, CMD_BACKGROUND_RUN_UNSEAL, eSetBits);
			}
			else {
				status = CMD_BACKGROUND_NO_MEMORY;
				task->attestation.attestation_status =
					CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_FAILURE, status);
				xSemaphoreGive (task->lock);
			}
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			task->attestation.attestation_status =
				CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_REQUEST_BLOCKED, status);
			xSemaphoreGive (task->lock);
		}
	}
	else {
		status = CMD_BACKGROUND_NO_TASK;
		task->attestation.attestation_status =
			CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_TASK_NOT_RUNNING, status);
	}

	return status;
}

static int cmd_background_task_unseal_result (struct cmd_background *cmd, uint8_t *key,
	size_t *key_length, uint32_t *unseal_status)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;

	if ((task == NULL) || (key == NULL) || (key_length == NULL) || (unseal_status == NULL)) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if ((task->attestation.attestation == NULL) || (task->attestation.hash == NULL)) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);

	*unseal_status = task->attestation.attestation_status;

	if (task->attestation.attestation_status == ATTESTATION_CMD_STATUS_SUCCESS) {
		if (*key_length < sizeof (task->attestation.key)) {
			xSemaphoreGive (task->lock);
			return CMD_BACKGROUND_BUF_TOO_SMALL;
		}
		else {
			memcpy (key, task->attestation.key, sizeof (task->attestation.key));
			*key_length = sizeof (task->attestation.key);
			task->attestation.attestation_status = ATTESTATION_CMD_STATUS_NONE_STARTED;
		}
	}
	else {
		*key_length = 0;
	}

	xSemaphoreGive (task->lock);

	return 0;
}

static int cmd_background_task_reset_bypass (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;
	int status = 0;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if (task->config.reset == NULL) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	if (task->task) {
		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (!task->running) {
			task->config.config_status = CONFIG_RESET_STATUS_STARTING;
			task->running = 1;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_RUN_BYPASS, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			task->config.config_status =
				CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_REQUEST_BLOCKED, status);
			xSemaphoreGive (task->lock);
		}
	}
	else {
		status = CMD_BACKGROUND_NO_TASK;
		task->config.config_status =
			CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_TASK_NOT_RUNNING, status);
	}

	return status;
}

static int cmd_background_task_restore_defaults (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;
	int status = 0;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if (task->config.reset == NULL) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	if (task->task) {
		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (!task->running) {
			task->config.config_status = CONFIG_RESET_STATUS_STARTING;
			task->running = 1;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_RUN_DEFAULTS, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			task->config.config_status =
				CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_REQUEST_BLOCKED, status);
			xSemaphoreGive (task->lock);
		}
	}
	else {
		status = CMD_BACKGROUND_NO_TASK;
		task->config.config_status =
			CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_TASK_NOT_RUNNING, status);
	}

	return status;
}

static int cmd_background_task_get_config_reset_status (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;
	int status;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if (task->config.reset == NULL) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	status = task->config.config_status;
	xSemaphoreGive (task->lock);

	return status;
}

static int cmd_background_task_debug_log_clear (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	if (!task->running) {
		task->running = 1;
		xSemaphoreGive (task->lock);
		xTaskNotify (task->task, CMD_BACKGROUND_DEBUG_LOG_CLEAR, eSetBits);
	}
	else {
		xSemaphoreGive (task->lock);
		return CMD_BACKGROUND_TASK_BUSY;
	}

	return 0;
}

#ifdef ENABLE_DEBUG_COMMANDS
static int cmd_background_task_debug_log_fill (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	if (!task->running) {
		task->running = 1;
		xSemaphoreGive (task->lock);
		xTaskNotify (task->task, CMD_BACKGROUND_DEBUG_LOG_FILL, eSetBits);
	}
	else {
		xSemaphoreGive (task->lock);
		return CMD_BACKGROUND_TASK_BUSY;
	}

	return 0;
}
#endif

int cmd_background_task_authenticate_riot_certs (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;
	int status = 0;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if (task->task) {
		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (!task->running) {
			task->riot.cert_state = RIOT_CERT_STATE_VALIDATING;
			task->running = 1;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_AUTH_RIOT, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			task->config.config_status =
				CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
			xSemaphoreGive (task->lock);
		}
	}
	else {
		status = CMD_BACKGROUND_NO_TASK;
		task->config.config_status = CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
	}

	return status;
}

int cmd_background_task_get_riot_cert_chain_state (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;
	int status;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	status = task->riot.cert_state;
	xSemaphoreGive (task->lock);

	return status;
}

/**
 * Initialize the task for executing received requests outside of the main command handler.
 *
 * @param task The background task to initialize.
 * @param attestation The slave attestation manager for the command interface.
 * @param hash The hashing engine to utilize.
 * @param reset Manager for configuration reset operations.
 * @param riot Manager for RIoT keys and certificates.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int cmd_background_task_init (struct cmd_background_task *task,
	struct attestation_slave *attestation, struct hash_engine *hash, struct config_reset *reset,
	struct riot_key_manager *riot)
{
	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct cmd_background_task));

	task->lock = xSemaphoreCreateMutex ();
	if (task->lock == NULL) {
		return CMD_BACKGROUND_NO_MEMORY;
	}

	/* Attestation operations. */
	task->base.unseal_start = cmd_background_task_unseal_start;
	task->base.unseal_result = cmd_background_task_unseal_result;

	task->attestation.attestation = attestation;
	task->attestation.hash = hash;
	task->attestation.attestation_status = ATTESTATION_CMD_STATUS_NONE_STARTED;

	/* Configuration reset operations. */
	task->base.reset_bypass = cmd_background_task_reset_bypass;
	task->base.restore_defaults = cmd_background_task_restore_defaults;
	task->base.get_config_reset_status = cmd_background_task_get_config_reset_status;

	task->config.reset = reset;
	task->config.config_status = CONFIG_RESET_STATUS_NONE_STARTED;

	/* Debug log operations. */
	task->base.debug_log_clear = cmd_background_task_debug_log_clear;
#ifdef ENABLE_DEBUG_COMMANDS
	task->base.debug_log_fill = cmd_background_task_debug_log_fill;
#endif

	/* RIoT operations. */
	task->base.authenticate_riot_certs = cmd_background_task_authenticate_riot_certs;
	task->base.get_riot_cert_chain_state = cmd_background_task_get_riot_cert_chain_state;

	task->riot.keys = riot;
	task->riot.cert_state = (riot_key_manager_get_root_ca (riot) == NULL) ?
		RIOT_CERT_STATE_CHAIN_INVALID : RIOT_CERT_STATE_CHAIN_VALID;

	return 0;
}

/**
 * Start running the background command task.  No commands can be run until the command task has
 * been started.
 *
 * @param task The background command task to start.
 *
 * @return 0 if the task was started or an error code.
 */
int cmd_background_task_start (struct cmd_background_task *task)
{
	int status;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	status = xTaskCreate ((TaskFunction_t) cmd_background_task_handler, "CmdBgnd", 6 * 256, task,
		CERBERUS_PRIORITY_NORMAL, &task->task);
	if (status != pdPASS) {
		task->task = NULL;
		return CMD_BACKGROUND_NO_MEMORY;
	}

	return 0;
}
