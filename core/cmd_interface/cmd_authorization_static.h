// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_AUTHORIZATION_STATIC_H_
#define CMD_AUTHORIZATION_STATIC_H_

#include "cmd_authorization.h"


/* Internal functions declared to allow for static initialization. */
int cmd_authorization_authorize_operation (const struct cmd_authorization *auth,
	uint32_t operation_id, const uint8_t **token, size_t *length,
	struct cmd_authorization_operation_context *op_context);


/**
 * Constant initializer for the authorization handler API.
 */
#define	CMD_AUTHORIZATION_API_INIT  \
	.authorize_operation = cmd_authorization_authorize_operation \


/**
 * Statically initialize the descriptor for an operation requiring authorization.
 *
 * @param id_arg Identifier for the operation.
 * @param authorization_ptr Authorization context for the operation.  This can be null to always
 * disallow the operation.
 * @param data_ptr Parser context for the operation.  This can be null if data is never needed
 * during execution.
 * @param execution_ptr Execution context for the operation.  This can be null if no operation will
 * ever be executed.
 */
#define	cmd_authorization_operation_static_init(id_arg, authorization_ptr, data_ptr, \
	execution_ptr)	{ \
		.id = id_arg, \
		.authorization = authorization_ptr, \
		.data = data_ptr, \
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
