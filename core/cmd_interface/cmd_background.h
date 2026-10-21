// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_BACKGROUND_H_
#define CMD_BACKGROUND_H_

#include <stddef.h>
#include <stdint.h>
#include "cmd_interface/cmd_authorization.h"
#include "status/rot_status.h"


/**
 * Make a status value formatted for status reporting.
 *
 * @param status The overall operation status.
 * @param error The error code for the operation.
 */
#define	CMD_BACKGROUND_STATUS(status, error)	(((error & 0xffffff) << 8) | status)

/**
 * States that will be reported for the stored RIoT certificates.
 */
enum riot_cert_state {
	RIOT_CERT_STATE_CHAIN_VALID = 0,	/**< A valid certificate chain has been authenticated. */
	RIOT_CERT_STATE_CHAIN_INVALID,		/**< An incomplete or invalid certificate chain is stored. */
	RIOT_CERT_STATE_VALIDATING,			/**< The stored certificates are being authenticated. */
};


/**
 * Interface for executing background operations from the command handler.
 */
struct cmd_background {
#ifdef CMD_ENABLE_UNSEAL
	/**
	 * Process an attestation payload to unseal the device encryption key.
	 *
	 * @param cmd The background context for executing the operation.
	 * @param unseal_request Buffer containing the complete unseal request to execute.  The request
	 * should be validated for correctness before passing it here.
	 * @param length Length of the unseal request.
	 *
	 * @return 0 if the action was successfully scheduled or an error code.
	 */
	int (*unseal_start) (const struct cmd_background *cmd, const uint8_t *unseal_request,
		size_t length);

	/**
	 * Get the result of the last unseal operation requested.
	 *
	 * @param cmd The background context for executing the operation.
	 * @param key Output for the unsealed encryption key that will decrypt the attestation data.
	 * @param key_length Length of the key buffer as input, then key length as output.  This will be
	 * 0 if the unseal operation has not successfully completed.
	 * @param unseal_status Output buffer with the unsealing status.  The lower 8 bits will be the
	 * status as per {@link enum attestation_cmd_status}.  The rest of the bits will be the return
	 * code from the operation.
	 *
	 * @return 0 if completed successfully or an error code.
	 */
	int (*unseal_result) (const struct cmd_background *cmd, uint8_t *key, size_t *key_length,
		uint32_t *unseal_status);
#endif

#ifdef CMD_ENABLE_RESET_CONFIG
	/**
	 * Execute a protected operation that has been authorized for execution.
	 *
	 * @param cmd The background context for executing the operation.
	 * @param op_context The execution context for the authorized operation to execute.
	 *
	 * @return 0 if the operation was successfully scheduled or an error code.
	 */
	int (*execute_authorized_operation) (const struct cmd_background *cmd,
		const struct cmd_authorization_operation_context *op_context);

	/**
	 * Get the status of the last authorized operation being executed.
	 *
	 * @param cmd The background command context to query.
	 *
	 * @return The operation status.  The lower 8 bits will be the status as per
	 * {@link enum config_reset_status}.  The rest of the bits will be the return code from the
	 * operation.
	 */
	int (*get_authorized_operation_status) (const struct cmd_background *cmd);
#endif

#ifdef CMD_ENABLE_DEBUG_LOG
	/**
	 * Remove all entries from debug log.
	 *
	 * @param cmd The background command context used to start operation.
	 *
	 * @return 0 if the operation was successfully scheduled or an error code.
	 */
	int (*debug_log_clear) (const struct cmd_background *cmd);

#ifdef CMD_SUPPORT_DEBUG_COMMANDS
	/**
	 * Fill debug log for testing purposes.
	 *
	 * @param cmd The background command context used to start operation.
	 *
	 * @return 0 if the operation was successfully scheduled or an error code.
	 */
	int (*debug_log_fill) (const struct cmd_background *cmd);
#endif
#endif

	/**
	 * Run certificate authentication against the stored RIoT certificate chain.
	 *
	 * @param cmd The background context for executing the operation.
	 *
	 * @return 0 if the operation was successfully scheduled or an error code.
	 */
	int (*authenticate_riot_certs) (const struct cmd_background *cmd);

	/**
	 * Get the current state of the stored certificate chain for RIoT keys.
	 *
	 * @param cmd The background context to query.
	 *
	 * @return The stored certificate state.  The lower 8 bits will be the state as per
	 * {@link enum riot_cert_state}.  The rest of the bits will be the return code from the previous
	 * authentication request.
	 */
	int (*get_riot_cert_chain_state) (const struct cmd_background *cmd);

	/**
	 * Execute a warm reset of the device.  The reset will be delayed in order for any necessary
	 * command response data to be sent.
	 *
	 * @param cmd The background context that will execute the device reset.
	 *
	 * @return 0 if the operation was successfully scheduled or an error code.
	 */
	int (*reboot_device) (const struct cmd_background *cmd);
};


#define	CMD_BACKGROUND_ERROR(code)		ROT_ERROR (ROT_MODULE_CMD_BACKGROUND, code)

/**
 * Error codes that can be generated by the command background context.
 */
enum {
	CMD_BACKGROUND_INVALID_ARGUMENT = CMD_BACKGROUND_ERROR (0x00),		/**< Input parameter is null or not valid. */
	CMD_BACKGROUND_NO_MEMORY = CMD_BACKGROUND_ERROR (0x01),				/**< Memory allocation failed. */
	CMD_BACKGROUND_UNSEAL_FAILED = CMD_BACKGROUND_ERROR (0x02),			/**< Failed to start unsealing. */
	CMD_BACKGROUND_UNSEAL_RESULT_FAILED = CMD_BACKGROUND_ERROR (0x03),	/**< Failed to get unsealing result. */
	CMD_BACKGROUND_BYPASS_FAILED = CMD_BACKGROUND_ERROR (0x04),			/**< Failed to reset to bypass mode. */
	CMD_BACKGROUND_DEFAULT_FAILED = CMD_BACKGROUND_ERROR (0x05),		/**< Failed to restore defaults. */
	CMD_BACKGROUND_BUF_TOO_SMALL = CMD_BACKGROUND_ERROR (0x06),			/**< Provided buffer too small for output. */
	CMD_BACKGROUND_INPUT_TOO_BIG = CMD_BACKGROUND_ERROR (0x07),			/**< Provided input too large. */
	CMD_BACKGROUND_UNSUPPORTED_REQUEST = CMD_BACKGROUND_ERROR (0x08),	/**< The command is not supported. */
	CMD_BACKGROUND_NO_TASK = CMD_BACKGROUND_ERROR (0x09),				/**< No manager command task is running. */
	CMD_BACKGROUND_TASK_BUSY = CMD_BACKGROUND_ERROR (0x0a),				/**< The command task is busy performing an operation. */
	CMD_BACKGROUND_UNSUPPORTED_OP = CMD_BACKGROUND_ERROR (0x0b),		/**< The scheduled operation is not understood by the task. */
	CMD_BACKGROUND_PLATFORM_CFG_FAILED = CMD_BACKGROUND_ERROR (0x0c),	/**< Failed to clear platform configuration. */
	CMD_BACKGROUND_INTRUSION_FAILED = CMD_BACKGROUND_ERROR (0x0d),		/**< Failed to reset the intrusion state. */
	CMD_BACKGROUND_CFM_FAILED = CMD_BACKGROUND_ERROR (0x0e),			/**< Failed to clear component manifests. */
	CMD_BACKGROUND_REBOOT_FAILED = CMD_BACKGROUND_ERROR (0x0f),			/**< Failed to warm reset the device. */
	CMD_BACKGROUND_AUTH_OP_FAILED = CMD_BACKGROUND_ERROR (0x10),		/**< Failed to execute an authorized operation. */
	CMD_BACKGROUND_AUTH_OP_INVALID_DATA = CMD_BACKGROUND_ERROR (0x11),	/**< Invalid data provided for an authorized operation. */
};


#endif	/* CMD_BACKGROUND_H_ */
