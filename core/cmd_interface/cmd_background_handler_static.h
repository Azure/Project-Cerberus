// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_BACKGROUND_HANDLER_STATIC_H_
#define CMD_BACKGROUND_HANDLER_STATIC_H_

#include "cmd_background_handler.h"


/* Internal functions declared to allow for static initialization. */
int cmd_background_handler_unseal_start (const struct cmd_background *cmd,
	const uint8_t *unseal_request, size_t length);
int cmd_background_handler_unseal_result (const struct cmd_background *cmd, uint8_t *key,
	size_t *key_length, uint32_t *unseal_status);
int cmd_background_handler_execute_authorized_operation (const struct cmd_background *cmd,
	const struct authorized_execution *execution);
int cmd_background_handler_get_authorized_operation_status (const struct cmd_background *cmd);
int cmd_background_handler_debug_log_clear (const struct cmd_background *cmd);
int cmd_background_handler_debug_log_fill (const struct cmd_background *cmd);
int cmd_background_handler_authenticate_riot_certs (const struct cmd_background *cmd);
int cmd_background_handler_get_riot_cert_chain_state (const struct cmd_background *cmd);
int cmd_background_handler_reboot_device (const struct cmd_background *cmd);


/**
 * Constant initializer for the unseal operation.
 */
#ifdef CMD_ENABLE_UNSEAL
#define	CMD_BACKGROUND_HANDLER_UNSEAL_API   \
	.unseal_start = cmd_background_handler_unseal_start, \
	.unseal_result = cmd_background_handler_unseal_result,

#define	CMD_BACKGROUND_HANDLER_UNSEAL_DEPENDENCIES(a, h)    \
	.attestation = a, \
	.hash = h,
#else
#define	CMD_BACKGROUND_HANDLER_UNSEAL_API
#define	CMD_BACKGROUND_HANDLER_UNSEAL_DEPENDENCIES(a, h)
#endif

/**
 * Constant initializer for the configuration reset operations.
 */
#ifdef CMD_ENABLE_RESET_CONFIG
#define	CMD_BACKGROUND_HANDLER_CONFIG_RESET_API \
	.execute_authorized_operation = cmd_background_handler_execute_authorized_operation, \
	.get_authorized_operation_status = cmd_background_handler_get_authorized_operation_status,
#else
#define	CMD_BACKGROUND_HANDLER_CONFIG_RESET_API
#endif


/**
 * Constant initializer for the debug log operations.
 */
#ifdef CMD_ENABLE_DEBUG_LOG
#ifndef CMD_SUPPORT_DEBUG_COMMANDS
#define CMD_BACKGROUND_HANDLER_DEBUG_LOG_API \
	.debug_log_clear = cmd_background_handler_debug_log_clear,
#else
#define CMD_BACKGROUND_HANDLER_DEBUG_LOG_API \
	.debug_log_clear = cmd_background_handler_debug_log_clear, \
	.debug_log_fill = cmd_background_handler_debug_log_fill,
#endif
#else
#define	CMD_BACKGROUND_HANDLER_DEBUG_LOG_API
#endif


/**
 * Constant initializer for the background command API.
 */
#define	CMD_BACKGROUND_HANDLER_COMMAND_API_INIT  { \
		CMD_BACKGROUND_HANDLER_UNSEAL_API \
		CMD_BACKGROUND_HANDLER_CONFIG_RESET_API \
		CMD_BACKGROUND_HANDLER_DEBUG_LOG_API \
		.authenticate_riot_certs = cmd_background_handler_authenticate_riot_certs, \
		.get_riot_cert_chain_state = cmd_background_handler_get_riot_cert_chain_state, \
		.reboot_device = cmd_background_handler_reboot_device, \
	}

/**
 * Constant initializer for the background task API.
 */
#define	CMD_BACKGROUND_HANDLER_EVENT_API_INIT  { \
		.execute = cmd_background_handler_execute \
	}


/**
 * Initialize a static instance of a background command handler.  This does not initialize the
 * handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the background handler.
 * @param attestation_ptr The responder instance to use for attestation requests.  This is not
 * required if unseal is not supported.
 * @param hash_ptr The hashing engine to use for unsealing.  This is not required if unseal is not
 * supported.
 * @param riot_ptr Manager for RIoT keys and certificates.
 * @param task_ptr The task that will be used to execute manifest operations.
 */
#define	cmd_background_handler_static_init(state_ptr, attestation_ptr, hash_ptr, riot_ptr, \
	task_ptr)	{ \
		.base_cmd = CMD_BACKGROUND_HANDLER_COMMAND_API_INIT, \
		.base_event = CMD_BACKGROUND_HANDLER_EVENT_API_INIT, \
		.state = state_ptr, \
		.keys = riot_ptr, \
		.task = task_ptr, \
		CMD_BACKGROUND_HANDLER_UNSEAL_DEPENDENCIES (attestation_ptr, hash_ptr) \
	}


#endif	/* CMD_BACKGROUND_HANDLER_STATIC_H_ */
