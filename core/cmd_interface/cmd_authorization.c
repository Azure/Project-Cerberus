// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cmd_authorization.h"


static int cmd_authorization_authorize_revert_bypass (struct cmd_authorization *auth,
	uint8_t **token, size_t *length)
{
	if (auth == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	if (auth->bypass) {
		return auth->bypass->authorize (auth->bypass, token, length);
	}
	else {
		return AUTHORIZATION_NOT_AUTHORIZED;
	}
}

static int cmd_authorization_authorize_reset_defaults (struct cmd_authorization *auth,
	uint8_t **token, size_t *length)
{
	if (auth == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	if (auth->defaults) {
		return auth->defaults->authorize (auth->defaults, token, length);
	}
	else {
		return AUTHORIZATION_NOT_AUTHORIZED;
	}
}

static int cmd_authorization_authorize_clear_platform_config (struct cmd_authorization *auth,
	uint8_t **token, size_t *length)
{
	if (auth == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	if (auth->platform) {
		return auth->platform->authorize (auth->platform, token, length);
	}
	else {
		return AUTHORIZATION_NOT_AUTHORIZED;
	}
}

static int cmd_authorization_authorize_reset_intrusion (struct cmd_authorization *auth,
	uint8_t **token, size_t *length)
{
	if (auth == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	if (auth->intrusion) {
		return auth->intrusion->authorize (auth->intrusion, token, length);
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
 * @param platform The authorization context to clear platform-specific configuration.  Set to null
 * to disallow this operation.
 * @param intrusion The authorization context to reset intrusion state.  Set to null to disallow 
 * this operation.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int cmd_authorization_init (struct cmd_authorization *auth, struct authorization *bypass,
	struct authorization *defaults, struct authorization *platform, 
	struct authorization *intrusion)
{
	if (auth == NULL) {
		return CMD_AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (struct cmd_authorization));

	auth->authorize_revert_bypass = cmd_authorization_authorize_revert_bypass;
	auth->authorize_reset_defaults = cmd_authorization_authorize_reset_defaults;
	auth->authorize_clear_platform_config = cmd_authorization_authorize_clear_platform_config;
	auth->authorize_reset_intrusion = cmd_authorization_authorize_reset_intrusion;

	auth->bypass = bypass;
	auth->defaults = defaults;
	auth->platform = platform;
	auth->intrusion = intrusion;

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
