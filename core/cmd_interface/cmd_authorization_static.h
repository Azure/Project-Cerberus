// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_AUTHORIZATION_STATIC_H_
#define CMD_AUTHORIZATION_STATIC_H_

#include "cmd_authorization.h"


/* Internal functions declared to allow for static initialization. */
int cmd_authorization_authorize_operation (const struct cmd_authorization *auth,
	uint32_t operation_id, const uint8_t **token, size_t *length,
	const struct authorized_execution **execution);
int cmd_authorization_authorize_revert_bypass (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length);
int cmd_authorization_authorize_reset_defaults (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length);
int cmd_authorization_authorize_clear_platform_config (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length);
int cmd_authorization_authorize_clear_component_manifests (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length);
int cmd_authorization_authorize_reset_intrusion (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length);


/**
 * Constant initializer for the authorization handler API.
 */
#define	CMD_AUTHORIZATION_API_INIT  \
	.authorize_operation = cmd_authorization_authorize_operation, \
	.authorize_revert_bypass = cmd_authorization_authorize_revert_bypass, \
	.authorize_reset_defaults = cmd_authorization_authorize_reset_defaults, \
	.authorize_clear_platform_config = cmd_authorization_authorize_clear_platform_config, \
	.authorize_clear_component_manifests = cmd_authorization_authorize_clear_component_manifests, \
	.authorize_reset_intrusion = cmd_authorization_authorize_reset_intrusion \

/**
 * Statically initialize the descriptor for an operation requiring authorization.
 *
 * @param id_arg Identifier for the operation.
 * @param authorization_ptr Authorization context for the operation.  This can be null to always
 * disallow the operation.
 * @param execution_ptr Execution context for the operation.  This can be null if no operation will
 * ever be executed.
 */
#define	cmd_authorization_operation_static_init(id_arg, authorization_ptr, execution_ptr)	{ \
		.id = id_arg, \
		.authorization = authorization_ptr, \
		.execution = execution_ptr, \
	}

/**
 * Initialize a static handler for authorizing requested operations.
 *
 * There is no validation done on the arguments.
 *
 * @param op_list_ptr The list of operations supported by the handler for authorization.  A
 * supported operation is one that is known to the handler, not necessarily one that is allowed.
 * It's possible for a supported operation to have an authorization context that always disallows
 * the operation.
 * @param op_count_arg The number of operations in the list.
 */
#define	cmd_authorization_static_init(op_list_ptr, op_count_arg) { \
		CMD_AUTHORIZATION_API_INIT, \
		.op_list = op_list_ptr, \
		.op_count = op_count_arg, \
	}


#endif	/* CMD_AUTHORIZATION_STATIC_H_ */
