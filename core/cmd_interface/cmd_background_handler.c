// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "attestation_cmd_interface.h"
#include "cerberus_protocol_optional_commands.h"
#include "cmd_background_handler.h"
#include "cmd_logging.h"
#include "common/buffer_util.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "flash/flash_common.h"
#include "logging/logging_flash.h"
#include "riot/riot_logging.h"


/**
 * Set the current operation status.
 *
 * @param handler The handler instance to update.
 * @param op_status Storage location for the status value.
 * @param status The status value to set.
 */
void cmd_background_handler_set_status (const struct cmd_background_handler *handler,
	int *op_status, int status)
{
	if (op_status) {
		handler->task->lock (handler->task);
		*op_status = status;
		handler->task->unlock (handler->task);
	}
}

/**
 * Notify the task that a background event needs to be processed.
 *
 * @param handler The handler that received the event.
 * @param action The background action that needs to be performed.
 * @param data Data associated with the event.  Null if there is no data.
 * @param length Length of the event data.
 * @param starting_status Event status to report when the task is ready to receive a notification.
 * @param no_task_status Event status to report when the task is not running.
 * @param error_status Event status for general errors.
 * @param status_out Optional output for asynchronous status reporting.
 *
 * @return 0 if the task was notified successfully or an error code.
 */
static int cmd_background_handler_submit_event (const struct cmd_background_handler *handler,
	uint32_t action, const uint8_t *data, size_t length, int starting_status, int no_task_status,
	int error_status, int *status_out)
{
	int status;

	status = event_task_submit_event (handler->task, &handler->base_event, action, data, length,
		starting_status, status_out);
	if (status != 0) {
		if (status == EVENT_TASK_BUSY) {
			/* Do not change the command status when the task is busy.  Something is running, which
			 * could be using the status. */
			status = CMD_BACKGROUND_TASK_BUSY;
		}
		else if (status == EVENT_TASK_TOO_MUCH_DATA) {
			/* Do not change the command status, since we don't know that state of the task. */
			return CMD_BACKGROUND_INPUT_TOO_BIG;
		}
		else if (status == EVENT_TASK_NO_TASK) {
			status = CMD_BACKGROUND_NO_TASK;
			if (status_out) {
				*status_out = CMD_BACKGROUND_STATUS (no_task_status, status);
			}
		}
		else {
			cmd_background_handler_set_status (handler, status_out,
				CMD_BACKGROUND_STATUS (error_status, status));
		}
	}

	return status;
}

#ifdef CMD_ENABLE_UNSEAL
int cmd_background_handler_unseal_start (const struct cmd_background *cmd,
	const uint8_t *unseal_request, size_t length)
{
	const struct cmd_background_handler *handler = (const struct cmd_background_handler*) cmd;

	if ((handler == NULL) || (unseal_request == NULL) || (length == 0)) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if ((handler->attestation == NULL) || (handler->hash == NULL)) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	return cmd_background_handler_submit_event (handler, CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL,
		unseal_request, length, ATTESTATION_CMD_STATUS_RUNNING,
		ATTESTATION_CMD_STATUS_TASK_NOT_RUNNING, ATTESTATION_CMD_STATUS_INTERNAL_ERROR,
		&handler->state->attestation_status);
}

int cmd_background_handler_unseal_result (const struct cmd_background *cmd, uint8_t *key,
	size_t *key_length, uint32_t *unseal_status)
{
	const struct cmd_background_handler *handler = (const struct cmd_background_handler*) cmd;
	int status = 0;

	if ((handler == NULL) || (key == NULL) || (key_length == NULL) || (unseal_status == NULL)) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if ((handler->attestation == NULL) || (handler->hash == NULL)) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	handler->task->lock (handler->task);

	buffer_unaligned_write32 (unseal_status, handler->state->attestation_status);

	if (handler->state->attestation_status == ATTESTATION_CMD_STATUS_SUCCESS) {
		if (*key_length < sizeof (handler->state->key)) {
			status = CMD_BACKGROUND_BUF_TOO_SMALL;
		}
		else {
			memcpy (key, handler->state->key, sizeof (handler->state->key));
			*key_length = sizeof (handler->state->key);
			handler->state->attestation_status = ATTESTATION_CMD_STATUS_NONE_STARTED;
		}
	}
	else {
		*key_length = 0;
	}

	handler->task->unlock (handler->task);

	return status;
}
#endif

#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
/**
 * Notify the task of a config reset operation.
 *
 * @param cmd The handler being notified.
 * @param action The config reset action to perform.
 *
 * @return 0 if the task was successfully notified or an error code.
 */
static int cmd_background_handler_start_config_reset (const struct cmd_background *cmd,
	uint32_t action)
{
	const struct cmd_background_handler *handler = (const struct cmd_background_handler*) cmd;

	if (handler == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if (handler->reset == NULL) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	return cmd_background_handler_submit_event (handler, action, NULL, 0,
		CONFIG_RESET_STATUS_STARTING, CONFIG_RESET_STATUS_TASK_NOT_RUNNING,
		CONFIG_RESET_STATUS_INTERNAL_ERROR, &handler->state->config_status);
}
#endif

#ifdef CMD_ENABLE_RESET_CONFIG
int cmd_background_handler_reset_bypass (const struct cmd_background *cmd)
{
	return cmd_background_handler_start_config_reset (cmd,
		CMD_BACKGROUND_HANDLER_ACTION_RUN_BYPASS);
}

int cmd_background_handler_restore_defaults (const struct cmd_background *cmd)
{
	return cmd_background_handler_start_config_reset (cmd,
		CMD_BACKGROUND_HANDLER_ACTION_RUN_DEFAULTS);
}

int cmd_background_handler_clear_platform_config (const struct cmd_background *cmd)
{
	return cmd_background_handler_start_config_reset (cmd,
		CMD_BACKGROUND_HANDLER_ACTION_PLATFORM_CFG);
}

int cmd_background_handler_clear_component_manifests (const struct cmd_background *cmd)
{
	return cmd_background_handler_start_config_reset (cmd,
		CMD_BACKGROUND_HANDLER_ACTION_CLEAR_CFM);
}
#endif

#ifdef CMD_ENABLE_INTRUSION
int cmd_background_handler_reset_intrusion (const struct cmd_background *cmd)
{
	return cmd_background_handler_start_config_reset (cmd,
		CMD_BACKGROUND_HANDLER_ACTION_RESET_INTRUSION);
}
#endif

#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
int cmd_background_handler_get_config_reset_status (const struct cmd_background *cmd)
{
	const struct cmd_background_handler *handler = (const struct cmd_background_handler*) cmd;
	int status;

	if (handler == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	if (handler->reset == NULL) {
		return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
	}

	handler->task->lock (handler->task);
	status = handler->state->config_status;
	handler->task->unlock (handler->task);

	return status;
}
#endif

#ifdef CMD_ENABLE_DEBUG_LOG
int cmd_background_handler_debug_log_clear (const struct cmd_background *cmd)
{
	const struct cmd_background_handler *handler = (const struct cmd_background_handler*) cmd;

	if (handler == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	return cmd_background_handler_submit_event (handler,
		CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_CLEAR, NULL, 0, 0, 0, 0, NULL);
}

#ifdef CMD_SUPPORT_DEBUG_COMMANDS
int cmd_background_handler_debug_log_fill (const struct cmd_background *cmd)
{
	const struct cmd_background_handler *handler = (const struct cmd_background_handler*) cmd;

	if (handler == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	return cmd_background_handler_submit_event (handler,
		CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_FILL, NULL, 0, 0, 0, 0, NULL);
}
#endif
#endif

int cmd_background_handler_authenticate_riot_certs (const struct cmd_background *cmd)
{
	const struct cmd_background_handler *handler = (const struct cmd_background_handler*) cmd;

	if (handler == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	return cmd_background_handler_submit_event (handler, CMD_BACKGROUND_HANDLER_ACTION_AUTH_RIOT,
		NULL, 0, RIOT_CERT_STATE_VALIDATING, RIOT_CERT_STATE_CHAIN_INVALID,
		RIOT_CERT_STATE_CHAIN_INVALID, &handler->state->cert_state);
}

int cmd_background_handler_get_riot_cert_chain_state (const struct cmd_background *cmd)
{
	const struct cmd_background_handler *handler = (const struct cmd_background_handler*) cmd;
	int status;

	if (handler == NULL) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	handler->task->lock (handler->task);
	status = handler->state->cert_state;
	handler->task->unlock (handler->task);

	return status;
}

void cmd_background_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset)
{
	const struct cmd_background_handler *cmd = TO_DERIVED_TYPE (handler,
		const struct cmd_background_handler, base_event);
	int *op_status = NULL;
	int status = CMD_BACKGROUND_UNSUPPORTED_OP;

	UNUSED (reset);

	switch (context->action) {
#ifdef CMD_ENABLE_UNSEAL
		case CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL: {
			struct cerberus_protocol_message_unseal *unseal =
				(struct cerberus_protocol_message_unseal*) context->event_buffer;
			enum aux_attestation_seed_param seed_param;

			op_status = &cmd->state->attestation_status;

			if (unseal->seed_type == CERBERUS_PROTOCOL_UNSEAL_SEED_ECDH) {
				seed_param = (enum aux_attestation_seed_param) unseal->seed_params.ecdh.processing;
			}
			else {
				seed_param = (enum aux_attestation_seed_param) unseal->seed_params.rsa.padding;
			}

			status = cmd->attestation->aux_attestation_unseal (cmd->attestation, cmd->hash,
				AUX_ATTESTATION_KEY_256BIT, &unseal->seed,
				buffer_unaligned_read16 (&unseal->seed_length),
				(enum aux_attestation_seed_type) unseal->seed_type, seed_param,
				cerberus_protocol_unseal_hmac (unseal), HMAC_SHA256,
				cerberus_protocol_unseal_ciphertext (unseal),
				buffer_unaligned_read16 (
					(uint16_t*) cerberus_protocol_unseal_ciphertext_length_ptr (unseal)),
				cerberus_protocol_get_unseal_pmr_sealing (unseal)->pmr, CERBERUS_PROTOCOL_MAX_PMR,
				cmd->state->key, sizeof (cmd->state->key));
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_UNSEAL_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_FAILURE, status);
			}
			break;
		}
#endif

#ifdef CMD_ENABLE_RESET_CONFIG
		case CMD_BACKGROUND_HANDLER_ACTION_RUN_BYPASS:
			op_status = &cmd->state->config_status;
			cmd_background_handler_set_status (cmd, &cmd->state->config_status,
				CONFIG_RESET_STATUS_RESTORE_BYPASS);

			status = config_reset_restore_bypass (cmd->reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_BYPASS_RESTORED, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESTORE_BYPASS_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_BYPASS_FAILED, status);
			}
			break;

		case CMD_BACKGROUND_HANDLER_ACTION_RUN_DEFAULTS:
			op_status = &cmd->state->config_status;
			cmd_background_handler_set_status (cmd, &cmd->state->config_status,
				CONFIG_RESET_STATUS_RESTORE_DEFAULTS);

			status = config_reset_restore_defaults (cmd->reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_DEFAULTS_RESTORED, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESTORE_DEFAULTS_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_DEFAULTS_FAILED, status);
			}
			break;

		case CMD_BACKGROUND_HANDLER_ACTION_PLATFORM_CFG:
			op_status = &cmd->state->config_status;
			cmd_background_handler_set_status (cmd, &cmd->state->config_status,
				CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG);

			status = config_reset_restore_platform_config (cmd->reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_CLEAR_PLATFORM_CONFIG, 0, 0);

				/* Reset the device to apply the default configuration. */
				*reset = true;
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_CLEAR_PLATFORM_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED, status);
			}
			break;

		case CMD_BACKGROUND_HANDLER_ACTION_CLEAR_CFM:
			op_status = &cmd->state->config_status;
			cmd_background_handler_set_status (cmd, &cmd->state->config_status,
				CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS);

			status = config_reset_clear_component_manifests (cmd->reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_CLEAR_CFM, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_CLEAR_CFM_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_COMPONENT_MANIFESTS_FAILED,
					status);
			}
			break;
#endif

#ifdef CMD_ENABLE_INTRUSION
		case CMD_BACKGROUND_HANDLER_ACTION_RESET_INTRUSION:
			op_status = &cmd->state->config_status;
			cmd_background_handler_set_status (cmd, &cmd->state->config_status,
				CONFIG_RESET_STATUS_RESET_INTRUSION);

			status = config_reset_reset_intrusion (cmd->reset);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESET_INTRUSION, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_RESET_INTRUSION_FAIL, status, 0);

				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_INTRUSION_FAILED, status);
			}
			break;
#endif

#ifdef CMD_ENABLE_DEBUG_LOG
		case CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_CLEAR:
			status = debug_log_clear ();
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_DEBUG_LOG_CLEARED, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
					CMD_LOGGING_DEBUG_LOG_CLEAR_FAIL, status, 0);
			}
			break;

#ifdef CMD_SUPPORT_DEBUG_COMMANDS
		case CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_FILL: {
			/* This command assumes logging to flash.  To implement a more portable command would
			 * require an API from the logging interface to indicate the maximum number of entries
			 * or a direct API to fill the log with data.  It's not worth that flexibility for a
			 * seldom used debug command. */
			int max_count =
				(FLASH_SECTOR_SIZE / sizeof (struct debug_log_entry)) * LOGGING_FLASH_SECTORS;
			int i_entry;

			debug_log_clear ();
			for (i_entry = 0; i_entry < max_count; ++i_entry) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO,
					DEBUG_LOG_COMPONENT_DEVICE_SPECIFIC, 0, 0, 0);
			}
			break;
		}
#endif
#endif

		case CMD_BACKGROUND_HANDLER_ACTION_AUTH_RIOT:
			op_status = &cmd->state->cert_state;

			status = riot_key_manager_verify_stored_certs (cmd->keys);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_RIOT,
					RIOT_LOGGING_DEVID_AUTH_STATUS, status, 0);

				status = CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
			}
			break;

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
		case CMD_BACKGROUND_HANDLER_ACTION_AUX_KEY_GEN:
			status = aux_attestation_generate_key (
				*((struct aux_attestation**) context->event_buffer));

			debug_log_create_entry (
				(status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_ERROR,
				DEBUG_LOG_COMPONENT_CMD_INTERFACE, CMD_LOGGING_AUX_KEY, status, 0);
			break;
#endif

		default:
			debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
				CMD_LOGGING_NOTIFICATION_ERROR, context->action, 0);

#ifdef CMD_ENABLE_UNSEAL
			if (cmd->state->attestation_status == ATTESTATION_CMD_STATUS_RUNNING) {
				op_status = &cmd->state->attestation_status;
				status = CMD_BACKGROUND_STATUS (ATTESTATION_CMD_STATUS_INTERNAL_ERROR, status);
			}
#endif
#ifdef CMD_ENABLE_RESET_CONFIG
			if (cmd->state->config_status == CONFIG_RESET_STATUS_STARTING) {
				op_status = &cmd->state->config_status;
				status = CMD_BACKGROUND_STATUS (CONFIG_RESET_STATUS_INTERNAL_ERROR, status);
			}
#endif
			if (cmd->state->cert_state == RIOT_CERT_STATE_VALIDATING) {
				op_status = &cmd->state->cert_state;
				status = CMD_BACKGROUND_STATUS (RIOT_CERT_STATE_CHAIN_INVALID, status);
			}
			break;
	}

	cmd_background_handler_set_status (cmd, op_status, status);
}

/**
 * Initialize the handler for executing certain requests without consuming the main command handler.
 *
 * @param handler The background handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param attestation The responder instance to use for attestation requests.  This is not required
 * if unseal is not supported.
 * @param hash The hashing engine to use for unsealing.  This is not required
 * if unseal is not supported.
 * @param reset Manager for configuration reset operations.  This is not required if configuration
 * and intrusion reset are not supported.
 * @param riot Manager for RIoT keys and certificates.
 * @param task The task that will be used to execute background operations.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int cmd_background_handler_init (struct cmd_background_handler *handler,
	struct cmd_background_handler_state *state, struct attestation_responder *attestation,
	struct hash_engine *hash, struct config_reset *reset, struct riot_key_manager *riot,
	const struct event_task *task)
{
	if ((handler == NULL) || (state == NULL) || (riot == NULL) || (task == NULL)) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct cmd_background_handler));

	handler->state = state;
	handler->task = task;
	handler->keys = riot;

	/* Attestation operations. */
#ifdef CMD_ENABLE_UNSEAL
	handler->base_cmd.unseal_start = cmd_background_handler_unseal_start;
	handler->base_cmd.unseal_result = cmd_background_handler_unseal_result;

	handler->attestation = attestation;
	handler->hash = hash;
#endif

	/* Configuration reset operations. */
#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
#ifdef CMD_ENABLE_RESET_CONFIG
	handler->base_cmd.reset_bypass = cmd_background_handler_reset_bypass;
	handler->base_cmd.restore_defaults = cmd_background_handler_restore_defaults;
	handler->base_cmd.clear_platform_config = cmd_background_handler_clear_platform_config;
	handler->base_cmd.clear_component_manifests = cmd_background_handler_clear_component_manifests;
#endif
#ifdef CMD_ENABLE_INTRUSION
	handler->base_cmd.reset_intrusion = cmd_background_handler_reset_intrusion;
#endif
	handler->base_cmd.get_config_reset_status = cmd_background_handler_get_config_reset_status;

	handler->reset = reset;
#endif

	/* Debug log operations. */
#ifdef CMD_ENABLE_DEBUG_LOG
	handler->base_cmd.debug_log_clear = cmd_background_handler_debug_log_clear;
#ifdef CMD_SUPPORT_DEBUG_COMMANDS
	handler->base_cmd.debug_log_fill = cmd_background_handler_debug_log_fill;
#endif
#endif

	/* RIoT operations. */
	handler->base_cmd.authenticate_riot_certs = cmd_background_handler_authenticate_riot_certs;
	handler->base_cmd.get_riot_cert_chain_state = cmd_background_handler_get_riot_cert_chain_state;

	handler->base_event.prepare = NULL;
	handler->base_event.execute = cmd_background_handler_execute;

	return cmd_background_handler_init_state (handler);
}

/**
 * Initialize only the variable state for a background handler.  The rest of the handler is assumed
 * to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The background handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int cmd_background_handler_init_state (const struct cmd_background_handler *handler)
{
	if ((handler == NULL) || (handler->state == NULL) || (handler->keys == NULL) ||
		(handler->task == NULL)) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	memset (handler->state, 0, sizeof (struct cmd_background_handler_state));

	handler->state->cert_state = (riot_key_manager_get_root_ca (handler->keys) == NULL) ?
		RIOT_CERT_STATE_CHAIN_INVALID : RIOT_CERT_STATE_CHAIN_VALID;

#ifdef CMD_ENABLE_UNSEAL
	handler->state->attestation_status = ATTESTATION_CMD_STATUS_NONE_STARTED;
#endif

#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
	handler->state->config_status = CONFIG_RESET_STATUS_NONE_STARTED;
#endif

	return 0;
}

/**
 * Release the resources used by a background handler.
 *
 * @param handler The background handler to release.
 */
void cmd_background_handler_release (const struct cmd_background_handler *handler)
{
	UNUSED (handler);
}

/**
 * Start generation of the auxiliary attestation key.
 *
 * @param task The background handler that will run the key generation.
 * @param aux The auxiliary attestation handler that will generate the key.
 *
 * @return 0 if key generation was scheduled on the task or an error code.
 */
int cmd_background_handler_generate_aux_key (const struct cmd_background_handler *handler,
	struct aux_attestation *aux)
{
#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
	int status;

	if ((handler == NULL) || (aux == NULL)) {
		return CMD_BACKGROUND_INVALID_ARGUMENT;
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		CMD_LOGGING_GENERATE_AUX_KEY, 0, 0);

	status = cmd_background_handler_submit_event (handler,
		CMD_BACKGROUND_HANDLER_ACTION_AUX_KEY_GEN, (uint8_t*) &aux, sizeof (aux), 0, 0, 0, NULL);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CMD_INTERFACE,
			CMD_LOGGING_AUX_KEY, status, 0);
	}

	return status;
#else
	UNUSED (handler);
	UNUSED (aux);

	return CMD_BACKGROUND_UNSUPPORTED_REQUEST;
#endif
}
