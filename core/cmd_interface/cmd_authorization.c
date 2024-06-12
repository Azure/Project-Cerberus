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
	const struct authorized_execution **execution)
{
	const struct cmd_authorization_operation *operation = NULL;
	size_t i = 0;
	int status;

	if (execution == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	*execution = NULL;

	if (auth == NULL) {
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
				*execution = operation->execution;
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

int cmd_authorization_authorize_revert_bypass (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length)
{
	const struct authorized_execution *execution;

	return cmd_authorization_authorize_operation (auth, CERBERUS_PROTOCOL_REVERT_BYPASS, token,
		length, &execution);
}

int cmd_authorization_authorize_reset_defaults (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length)
{
	const struct authorized_execution *execution;

	return cmd_authorization_authorize_operation (auth, CERBERUS_PROTOCOL_FACTORY_RESET, token,
		length, &execution);
}

int cmd_authorization_authorize_clear_platform_config (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length)
{
	const struct authorized_execution *execution;

	return cmd_authorization_authorize_operation (auth, CERBERUS_PROTOCOL_CLEAR_PCD, token,	length,
		&execution);
}

int cmd_authorization_authorize_clear_component_manifests (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length)
{
	const struct authorized_execution *execution;

	return cmd_authorization_authorize_operation (auth, CERBERUS_PROTOCOL_CLEAR_CFM, token,	length,
		&execution);
}

int cmd_authorization_authorize_reset_intrusion (const struct cmd_authorization *auth,
	const uint8_t **token, size_t *length)
{
	const struct authorized_execution *execution;

	return cmd_authorization_authorize_operation (auth, CERBERUS_PROTOCOL_RESET_INTRUSION, token,
		length, &execution);
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
	auth->authorize_revert_bypass = cmd_authorization_authorize_revert_bypass;
	auth->authorize_reset_defaults = cmd_authorization_authorize_reset_defaults;
	auth->authorize_clear_platform_config = cmd_authorization_authorize_clear_platform_config;
	auth->authorize_clear_component_manifests =
		cmd_authorization_authorize_clear_component_manifests;
	auth->authorize_reset_intrusion = cmd_authorization_authorize_reset_intrusion;

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
