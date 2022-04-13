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
#define	CMD_BACKGROUND_AUX_KEY_GEN		(1U << 6)
#define	CMD_BACKGROUND_PLATFORM_CFG		(1U << 7)
#define CMD_BACKGROUND_RESET_INTRUSION	(1U << 8)

/**
 * Sub command types to identify which command is consuming the background task.
 */
enum {
	CMD_BACKGROUND_TASK_NONE,
	CMD_BACKGROUND_TASK_ATTESTATION,
	CMD_BACKGROUND_TASK_CONFIG,
	CMD_BACKGROUND_TASK_DEBUG_LOG,
	CMD_BACKGROUND_TASK_DEBUG_LOG_FILL,
	CMD_BACKGROUND_TASK_AUX_KEY_GEN,
	CMD_BACKGROUND_TASK_RIOT_AUTH
};

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
	bool reset = false;
	int status;

	do {
		/* Wait for a signal to perform update action. */
		status = CMD_BACKGROUND_UNSUPPORTED_OP;
		op_status =  &status;
		xTaskNotifyWait (pdFALSE, ULONG_MAX, &notification, portMAX_DELAY);

		if (notification & CMD_BACKGROUND_EXTERNAL_HANDLER) {
			if (task->ext_handler) {
				task->ext_handler (task, notification, &reset);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING,
					DEBUG_LOG_COMPONENT_CMD_INTERFACE, CMD_LOGGING_NO_BACKGROUND_HANDELR,
					notification, 0);
			}
		}
#ifdef CMD_ENABLE_UNSEAL
		else if (notification & CMD_BACKGROUND_RUN_UNSEAL) {
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
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
		else if (notification & CMD_BACKGROUND_RUN_BYPASS) {
			op_status = &task->config.config_status;
			cmd_background_task_set_status (task, &task->config.config_status,
				CONFIG_RESET_STATUS_RESTORE_BYPASS);

			status = config_reset_restore_bypass (task->config.reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_BYPASS_RESTORED, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESTORE_BYPASS_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_BYPASS_FAILED, status);
			}
		}
		else if (notification & CMD_BACKGROUND_RUN_DEFAULTS) {
			op_status = &task->config.config_status;
			cmd_background_task_set_status (task, &task->config.config_status,
				CONFIG_RESET_STATUS_RESTORE_DEFAULTS);

			status = config_reset_restore_defaults (task->config.reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_DEFAULTS_RESTORED, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESTORE_DEFAULTS_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_DEFAULTS_FAILED, status);
			}
		}
		else if (notification & CMD_BACKGROUND_PLATFORM_CFG) {
			op_status = &task->config.config_status;
			cmd_background_task_set_status (task, &task->config.config_status,
				CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG);

			status = config_reset_restore_platform_config (task->config.reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_CLEAR_PLATFORM_CONFIG, 0, 0);

				/* Reset the device to apply the default configuration. */
				reset = true;
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_CLEAR_PLATFORM_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED, status);
			}
		}
#endif
#ifdef CMD_ENABLE_INTRUSION
		else if (notification & CMD_BACKGROUND_RESET_INTRUSION) {
			op_status = &task->config.config_status;
			cmd_background_task_set_status (task, &task->config.config_status,
				CONFIG_RESET_STATUS_RESET_INTRUSION);

			status = config_reset_reset_intrusion (task->config.reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESET_INTRUSION, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESET_INTRUSION_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_INTRUSION_FAILED, status);
			}
		}
#endif
#ifdef CMD_ENABLE_DEBUG_LOG
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
#ifdef CMD_SUPPORT_DEBUG_COMMANDS
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
#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
		else if (notification & CMD_BACKGROUND_AUX_KEY_GEN) {
			status = aux_attestation_generate_key ((struct aux_attestation*) task->arg);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_AUX_KEY, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_AUX_KEY, status, 0);
			}
		}
#endif
		else {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
				CMD_LOGGING_NOTIFICATION_ERROR, notification, 0);

#ifdef CMD_ENABLE_UNSEAL
			if (task->attestation.attestation_status == ATTESTATION_CMD_STATUS_RUNNING) {
				op_status = &task->attestation.attestation_status;
				status = CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_INTERNAL_ERROR, status);
			}
			else
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
			if (task->config.config_status == CONFIG_RESET_STATUS_STARTING) {
				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_INTERNAL_ERROR, status);
			}
			else
#endif
			if (task->riot.cert_state == RIOT_CERT_STATE_VALIDATING) {
				op_status = &task->riot.cert_state;
				status = CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
			}
			else {
				op_status = &status;
			}
		}

		xSemaphoreTake (task->lock, portMAX_DELAY);
		*op_status = status;
		if (!reset) {
			task->running = CMD_BACKGROUND_TASK_NONE;
		}
		xSemaphoreGive (task->lock);

		if (reset) {
			/* If the action requires it, reset the system.  We need to wait a bit before
			 * triggering the reset to allow time for the execution status to be reported. */
			platform_msleep (5000);
			system_reset (task->system);
			reset = false;	/* We should never get here, but clear the flag if the reset fails. */
		}
	} while (1);
}

#ifdef CMD_ENABLE_UNSEAL
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
		if (task->running == CMD_BACKGROUND_TASK_NONE) {
			if (task->attestation.unseal_request != NULL) {
				platform_free (task->attestation.unseal_request);
			}

			task->attestation.unseal_request = platform_malloc (length);
			if (task->attestation.unseal_request != NULL) {
				task->attestation.attestation_status = ATTESTATION_CMD_STATUS_RUNNING;
				task->running = CMD_BACKGROUND_TASK_ATTESTATION;

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
			if (task->running != CMD_BACKGROUND_TASK_ATTESTATION) {
				task->attestation.attestation_status =
					CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_REQUEST_BLOCKED, status);
			}	
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
#endif

#ifdef CMD_ENABLE_RESET_CONFIG
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
		if (task->running == CMD_BACKGROUND_TASK_NONE) {
			task->config.config_status = CONFIG_RESET_STATUS_STARTING;
			task->running = CMD_BACKGROUND_TASK_CONFIG;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_RUN_BYPASS, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			if (task->running != CMD_BACKGROUND_TASK_CONFIG) {
				task->config.config_status =
					CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_REQUEST_BLOCKED, status);
			}
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
		if (task->running == CMD_BACKGROUND_TASK_NONE) {
			task->config.config_status = CONFIG_RESET_STATUS_STARTING;
			task->running = CMD_BACKGROUND_TASK_CONFIG;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_RUN_DEFAULTS, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			if (task->running != CMD_BACKGROUND_TASK_CONFIG) {
				task->config.config_status =
					CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_REQUEST_BLOCKED, status);
			}
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

static int cmd_background_task_clear_platform_config (struct cmd_background *cmd)
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
		if (task->running == CMD_BACKGROUND_TASK_NONE) {
			task->config.config_status = CONFIG_RESET_STATUS_STARTING;
			task->running = CMD_BACKGROUND_TASK_CONFIG;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_PLATFORM_CFG, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			if (task->running != CMD_BACKGROUND_TASK_CONFIG) {
				task->config.config_status =
					CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_REQUEST_BLOCKED, status);
			}
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
#endif

#ifdef CMD_ENABLE_INTRUSION
static int cmd_background_task_reset_intrusion (struct cmd_background *cmd)
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
		if (task->running == CMD_BACKGROUND_TASK_NONE) {
			task->config.config_status = CONFIG_RESET_STATUS_STARTING;
			task->running = CMD_BACKGROUND_TASK_CONFIG;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_RESET_INTRUSION, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			if (task->running != CMD_BACKGROUND_TASK_CONFIG) {
				task->config.config_status =
					CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_REQUEST_BLOCKED, status);
			}
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
#endif

#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
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
#endif

#ifdef CMD_ENABLE_DEBUG_LOG
static int cmd_background_task_debug_log_clear (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	if (task->running == CMD_BACKGROUND_TASK_NONE) {
		task->running = CMD_BACKGROUND_TASK_DEBUG_LOG;
		xSemaphoreGive (task->lock);
		xTaskNotify (task->task, CMD_BACKGROUND_DEBUG_LOG_CLEAR, eSetBits);
	}
	else {
		xSemaphoreGive (task->lock);
		return CMD_BACKGROUND_TASK_BUSY;
	}

	return 0;
}

#ifdef CMD_SUPPORT_DEBUG_COMMANDS
static int cmd_background_task_debug_log_fill (struct cmd_background *cmd)
{
	struct cmd_background_task *task = (struct cmd_background_task*) cmd;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	if (task->running == CMD_BACKGROUND_TASK_NONE) {
		task->running = CMD_BACKGROUND_TASK_DEBUG_LOG_FILL;
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
		if (task->running == CMD_BACKGROUND_TASK_NONE) {
			task->riot.cert_state = RIOT_CERT_STATE_VALIDATING;
			task->running = CMD_BACKGROUND_TASK_RIOT_AUTH;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_AUTH_RIOT, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			if (task->running != CMD_BACKGROUND_TASK_RIOT_AUTH) {
				task->riot.cert_state =
					CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
			}
			xSemaphoreGive (task->lock);
		}
	}
	else {
		status = CMD_BACKGROUND_NO_TASK;
		task->riot.cert_state = CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
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
 * @param system The manager for system operations.
 * @param attestation The slave attestation manager for the command interface.
 * @param hash The hashing engine to utilize.
 * @param reset Manager for configuration reset operations.
 * @param riot Manager for RIoT keys and certificates.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int cmd_background_task_init (struct cmd_background_task *task, struct system *system,
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

	task->system = system;

	/* Attestation operations. */
#ifdef CMD_ENABLE_UNSEAL
	task->base.unseal_start = cmd_background_task_unseal_start;
	task->base.unseal_result = cmd_background_task_unseal_result;

	task->attestation.attestation = attestation;
	task->attestation.hash = hash;
	task->attestation.attestation_status = ATTESTATION_CMD_STATUS_NONE_STARTED;
#endif

	/* Configuration reset operations. */
#ifdef CMD_ENABLE_RESET_CONFIG
	task->base.reset_bypass = cmd_background_task_reset_bypass;
	task->base.restore_defaults = cmd_background_task_restore_defaults;
	task->base.clear_platform_config = cmd_background_task_clear_platform_config;
#endif
#ifdef CMD_ENABLE_INTRUSION
	task->base.reset_intrusion = cmd_background_task_reset_intrusion;
#endif
#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
	task->base.get_config_reset_status = cmd_background_task_get_config_reset_status;

	task->config.reset = reset;
	task->config.config_status = CONFIG_RESET_STATUS_NONE_STARTED;
#endif

	/* Debug log operations. */
#ifdef CMD_ENABLE_DEBUG_LOG
	task->base.debug_log_clear = cmd_background_task_debug_log_clear;
#ifdef CMD_SUPPORT_DEBUG_COMMANDS
	task->base.debug_log_fill = cmd_background_task_debug_log_fill;
#endif
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
 * @param stack_words The size of the command task stack.  The stack size is measured in words.
 *
 * @return 0 if the task was started or an error code.
 */
int cmd_background_task_start (struct cmd_background_task *task, uint16_t stack_words)
{
	int status;

	if (task == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	status = xTaskCreate ((TaskFunction_t) cmd_background_task_handler, "CmdBgnd", stack_words,
		task, CERBERUS_PRIORITY_NORMAL, &task->task);
	if (status != pdPASS) {
		task->task = NULL;
		return CMD_BACKGROUND_NO_MEMORY;
	}

	return 0;
}

/**
 * Start generation of the auxiliary attestation key.
 *
 * @param task The background task to run the key generation.
 * @param aux The auxiliary attestation handler that will generate the key.
 *
 * @return 0 if key generation was scheduled on the task or an error code.
 */
int cmd_background_task_generate_aux_key (struct cmd_background_task *task,
	struct aux_attestation *aux)
{
#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
	int status = 0;

	if ((task == NULL) || (aux == NULL)) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		CMD_LOGGING_GENERATE_AUX_KEY, 0, 0);

	if (task->task) {
		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (task->running == CMD_BACKGROUND_TASK_NONE) {
			task->arg = aux;
			task->running = CMD_BACKGROUND_TASK_AUX_KEY_GEN;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, CMD_BACKGROUND_AUX_KEY_GEN, eSetBits);
		}
		else {
			status = CMD_BACKGROUND_TASK_BUSY;
			xSemaphoreGive (task->lock);
		}
	}
	else {
		status = CMD_BACKGROUND_NO_TASK;
	}

	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_AUX_KEY, status, 0);
	}
	return status;
#else
	return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
#endif
}
