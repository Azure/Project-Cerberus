// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cerberus_protocol_optional_commands.h"
#include "cmd_authorization.h"
#include "common/unused.h"


int cmd_authorization_authorize_operation (const struct cmd_authorization *auth,
	uint32_t operation_id, const uint8_t **token, size_t *length,
	struct cmd_authorization_operation_context *op_context)
{
	const struct cmd_authorization_operation *operation = NULL;
	size_t i = 0;
	int status;

	if (op_context == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (op_context, 0, sizeof (*op_context));

	if ((auth == NULL) || (token == NULL) || (length == NULL)) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	/* Find the requested operation in the list of supported descriptors. */
	while ((operation == NULL) && (i < auth->op_count)) {
		if (auth->op_list[i].id == operation_id) {
			operation = &auth->op_list[i];
		}

		i++;
	}

	/* Authorize the operation. */
	if (operation) {
		if (operation->authorization) {
			status = operation->authorization->authorize (operation->authorization, token, length);
			if (status == 0) {
				/* The operation was authorized, so provide the execution context. */
				struct cmd_authorization_operation_context tmp_context = {0};

				if ((*token != NULL) && (operation->data != NULL)) {
					status = operation->data->get_authenticated_data (operation->data, *token,
						*length, &tmp_context.data, &tmp_context.data_length);
					if (status != 0) {
						return status;
					}
				}

				if (operation->execution != NULL) {
					status = operation->execution->validate_data (operation->execution,
						tmp_context.data, tmp_context.data_length);
					if (status != 0) {
						return status;
					}

					tmp_context.execution = operation->execution;
				}

				*op_context = tmp_context;
			}
		}
		else {
			status = AUTHORIZATION_NOT_AUTHORIZED;
		}
	}
	else {
		status = CMD_AUTHORIZATION_UNSUPPORTED_OP;
	}

	return status;
}

/**
 * Initialize the handler for authorizing requested operations.
 *
 * @param auth The authorization handler to initialize.
 * @param op_list The list of operations supported by the handler for authorization.  A supported
 * operation is one that is known to the handler, not necessarily one that is allowed.  It's
 * possible for a supported operation to have an authorization context that always disallows the
 * operation.
 * @param op_count The number of operations in the list.  This list can be empty to support no
 * operations.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int cmd_authorization_init (struct cmd_authorization *auth,
	const struct cmd_authorization_operation *const op_list, size_t op_count)
{
	if ((auth == NULL) || ((op_count != 0) && (op_list == NULL))) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (struct cmd_authorization));

	auth->authorize_operation = cmd_authorization_authorize_operation;

	auth->op_list = op_list;
	auth->op_count = op_count;

	return 0;
}

/**
 * Release the resources used by an authorization handler.
 *
 * @param auth The authorization handler to release.
 */
void cmd_authorization_release (const struct cmd_authorization *auth)
{
	UNUSED (auth);
}
