// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cmd_authorization.h"


static int cmd_authorization_authorize_revert_bypass (struct cmd_authorization *auth,
	uint8_t **nonce, size_t *length)
{
	if (auth == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	if (auth->bypass) {
		return auth->bypass->authorize (auth->bypass, nonce, length);
	}
	else {
		return AUTHORIZATION_NOT_AUTHORIZED;
	}
}

static int cmd_authorization_authorize_reset_defaults (struct cmd_authorization *auth,
	uint8_t **nonce, size_t *length)
{
	if (auth == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	if (auth->defaults) {
		return auth->defaults->authorize (auth->defaults, nonce, length);
	}
	else {
		return AUTHORIZATION_NOT_AUTHORIZED;
	}
}

/**
 * Initialize the handler for authorizing requested operations.
 *
 * @param auth The authorization handler to initialize.
 * @param bypass The authorization context to revert to bypass mode.  Set to null to disallow this
 * operation.
 * @param defaults The authorization context to restore default configuration.  Set to null to
 * disallow this operation.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int cmd_authorization_init (struct cmd_authorization *auth, struct authorization *bypass,
	struct authorization *defaults)
{
	if (auth == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (struct cmd_authorization));

	auth->authorize_revert_bypass = cmd_authorization_authorize_revert_bypass;
	auth->authorize_reset_defaults = cmd_authorization_authorize_reset_defaults;

	auth->bypass = bypass;
	auth->defaults = defaults;

	return 0;
}

/**
 * Release the resources used by an authorization handler.
 *
 * @param auth The authorization handler to release.
 */
void cmd_authorization_release (struct cmd_authorization *auth)
{

}
