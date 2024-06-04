// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "authorization_allowed.h"
#include "common/unused.h"


int authorization_allowed_authorize (const struct authorization *auth, const uint8_t **token,
	size_t *length)
{
	UNUSED (auth);
	UNUSED (token);
	UNUSED (length);

	return 0;
}

/**
 * Initialize an authorization manager that allows all operations.
 *
 * @param auth The authorization manager to initialize.
 *
 * @return 0 if the authorization manager was initialized successfully or an error code.
 */
int authorization_allowed_init (struct authorization_allowed *auth)
{
	if (auth == NULL) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (struct authorization_allowed));

	auth->base.authorize = authorization_allowed_authorize;

	return 0;
}

/**
 * Release the resources used by an authorization manager.
 *
 * @param auth The authorization manager to release.
 */
void authorization_allowed_release (struct authorization_allowed *auth)
{
	UNUSED (auth);
}
