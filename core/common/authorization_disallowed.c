// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "authorization_disallowed.h"
#include "common/unused.h"


int authorization_disallowed_authorize (const struct authorization *auth, const uint8_t **token,
	size_t *length)
{
	UNUSED (auth);
	UNUSED (token);
	UNUSED (length);

	return AUTHORIZATION_NOT_AUTHORIZED;
}

/**
 * Initialize an authorization manager that does not allow any operation.
 *
 * @param auth The authorization manager to initialize.
 *
 * @return 0 if the authorization manager was initialized successfully or an error code.
 */
int authorization_disallowed_init (struct authorization_disallowed *auth)
{
	if (auth == NULL) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (struct authorization_disallowed));

	auth->base.authorize = authorization_disallowed_authorize;

	return 0;
}

/**
 * Release the resources used by an authorization manager.
 *
 * @param auth The authorization manager to release.
 */
void authorization_disallowed_release (struct authorization_disallowed *auth)
{
	UNUSED (auth);
}
