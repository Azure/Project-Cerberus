// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_AUTHORIZATION_H_
#define CMD_AUTHORIZATION_H_

#include <stddef.h>
#include <stdint.h>
#include "common/authorization.h"
#include "common/authorized_execution.h"
#include "status/rot_status.h"


/**
 * Descriptor for a single operation in the system that requires authorization.
 */
struct cmd_authorization_operation {
	/**
	 * Identifier for the operation needing authorization.
	 */
	uint32_t id;

	/**
	 * Authorization context for the operation.  If this is null, the operation will always be
	 * disallowed.
	 */
	const struct authorization *authorization;

	/**
	 * Execution context for the operation.  If this is null, no operation will be executed, even if
	 * authorization succeeds.
	 */
	const struct authorized_execution *execution;
};

/**
 * Handler for verifying access when attempting to execute commands that require authorization.
 * Each command is an independent authorization context.
 */
struct cmd_authorization {
	/**
	 * Check for authorization to execute a specified operation.
	 *
	 * @param auth Authorization handler to query.
	 * @param operation_id Identifier for the operation to authorize.
	 * @param token Input or output authorization token, depending on the initial value.  See
	 * {@link struct authorization.authorize}.
	 * @param length Input or output length of the authorization token, depending on the initial
	 * value of the authorization token.  See {@link struct authorization.authorize}.
	 * @param execution Output for the execution context of the operation.  This will only be valid
	 * if authorization was successful and there is a operation associated with it.  Otherwise, this
	 * will be null.
	 *
	 * @return 0 if the operation is authorized or an error code.  If a token was generated,
	 * CMD_AUTHORIZATION_CHALLENGE will be returned.
	 */
	int (*authorize_operation) (const struct cmd_authorization *auth, uint32_t operation_id,
		const uint8_t **token, size_t *length, const struct authorized_execution **execution);

	/**
	 * Check for authorization to revert the device to bypass mode.
	 *
	 * @param auth Authorization handler to query.
	 * @param token Input or output authorization token, depending on the initial value.  See
	 * {@link struct authorization.authorize}.
	 * @param length Input or output length of the authorization token, depending on the initial
	 * value of the authorization token.  See {@link struct authorization.authorize}.
	 *
	 * @return 0 if the operation is authorized or an error code.  If a token was generated,
	 * CMD_AUTHORIZATION_CHALLENGE will be returned.
	 */
	int (*authorize_revert_bypass) (const struct cmd_authorization *auth, const uint8_t **token,
		size_t *length);

	/**
	 * Check for authorization to reset the device to factory default configuration.
	 *
	 * @param auth Authorization handler to query.
	 * @param token Input or output authorization token, depending on the initial value.  See
	 * {@link struct authorization.authorize}.
	 * @param length Input or output length of the authorization token, depending on the initial
	 * value of the authorization token.  See {@link struct authorization.authorize}.
	 *
	 * @return 0 if the operation is authorized or an error code.  If a token was generated,
	 * CMD_AUTHORIZATION_CHALLENGE will be returned.
	 */
	int (*authorize_reset_defaults) (const struct cmd_authorization *auth, const uint8_t **token,
		size_t *length);

	/**
	 * Check for authorization to clear the platform-specific configuration for the device.
	 *
	 * @param auth Authorization handler to query.
	 * @param token Input or output authorization token, depending on the initial value.  See
	 * {@link struct authorization.authorize}.
	 * @param length Input or output length of the authorization token, depending on the initial
	 * value of the authorization token.  See {@link struct authorization.authorize}.
	 *
	 * @return 0 if the operation is authorized or an error code.  If a token was generated,
	 * CMD_AUTHORIZATION_CHALLENGE will be returned.
	 */
	int (*authorize_clear_platform_config) (const struct cmd_authorization *auth,
		const uint8_t **token, size_t *length);

	/**
	 * Check for authorization to clear component manifests on the device.
	 *
	 * @param auth Authorization handler to query.
	 * @param token Input or output authorization token, depending on the initial value.  See
	 * {@link struct authorization.authorize}.
	 * @param length Input or output length of the authorization token, depending on the initial
	 * value of the authorization token.  See {@link struct authorization.authorize}.
	 *
	 * @return 0 if the operation is authorized or an error code.  If a token was generated,
	 * CMD_AUTHORIZATION_CHALLENGE will be returned.
	 */
	int (*authorize_clear_component_manifests) (const struct cmd_authorization *auth,
		const uint8_t **token, size_t *length);

	/**
	 * Check for authorization to reset the intrusion state for the device.
	 *
	 * @param auth Authorization handler to query.
	 * @param token Input or output authorization token, depending on the initial value.  See
	 * {@link struct authorization.authorize}.
	 * @param length Input or output length of the authorization token, depending on the initial
	 * value of the authorization token.  See {@link struct authorization.authorize}.
	 *
	 * @return 0 if the operation is authorized or an error code.  If a token was generated,
	 * CMD_AUTHORIZATION_CHALLENGE will be returned.
	 */
	int (*authorize_reset_intrusion) (const struct cmd_authorization *auth, const uint8_t **token,
		size_t *length);

	/**
	 * The list of supported operations requiring authorization.  A supported operation does not
	 * mean it's authorized, just that the identifier is known.  Supported operations can have
	 * authorization contexts that always disallow the operation.
	 */
	const struct cmd_authorization_operation *op_list;

	/**
	 * The number of authorized operations supported by the handler.
	 */
	size_t op_count;
};


int cmd_authorization_init (struct cmd_authorization *auth,
	const struct cmd_authorization_operation *const op_list, size_t op_count);
void cmd_authorization_release (const struct cmd_authorization *auth);


#define	CMD_AUTHORIZATION_ERROR(code)		ROT_ERROR (ROT_MODULE_CMD_AUTHORIZATION, code)

/**
 * Error codes that can be generated by an observer manager.
 */
enum {
	CMD_AUTHORIZATION_INVALID_ARGUMENT = CMD_AUTHORIZATION_ERROR (0x00),	/**< Input parameter is null or not valid. */
	CMD_AUTHORIZATION_NO_MEMORY = CMD_AUTHORIZATION_ERROR (0x01),			/**< Memory allocation failed. */
	CMD_AUTHORIZATION_BYPASS_FAILED = CMD_AUTHORIZATION_ERROR (0x02),		/**< Failed authorization to revert to bypass mode. */
	CMD_AUTHORIZATION_DEFAULTS_FAILED = CMD_AUTHORIZATION_ERROR (0x03),		/**< Failed authorization to restore defaults. */
	CMD_AUTHORIZATION_CONFIG_FAILED = CMD_AUTHORIZATION_ERROR (0x04),		/**< Failed authorization to clear platform config. */
	CMD_AUTHORIZATION_COMPONENTS_FAILED = CMD_AUTHORIZATION_ERROR (0x05),	/**< Failed authorization to clear component manifests. */
	CMD_AUTHORIZATION_INTRUSION_FAILED = CMD_AUTHORIZATION_ERROR (0x06),	/**< Failed authorization to reset intrusion state. */
	CMD_AUTHORIZATION_AUTH_OP_FAILED = CMD_AUTHORIZATION_ERROR (0x07),		/**< Failed authorization for an authenticated operation. */
	CMD_AUTHORIZATION_UNSUPPORTED_OP = CMD_AUTHORIZATION_ERROR (0x08),		/**< The specified operation is not supported. */
};


#endif	/* CMD_AUTHORIZATION_H_ */
