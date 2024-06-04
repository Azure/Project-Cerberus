// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_ALLOWED_STATIC_H_
#define AUTHORIZATION_ALLOWED_STATIC_H_

#include "authorization_allowed.h"


/* Internal functions declared to allow for static initialization. */
int authorization_allowed_authorize (const struct authorization *auth, const uint8_t **token,
	size_t *length);


/**
 * Constant initializer for the authorization API.
 */
#define	AUTHORIZATION_ALLOWED_API_INIT  { \
		.authorize = authorization_allowed_authorize, \
	}

/**
 * Initialize a static authorization manager that allows all operations.
 */
#define	authorization_allowed_static_init { \
		.base = AUTHORIZATION_ALLOWED_API_INIT, \
	}


#endif /* AUTHORIZATION_ALLOWED_STATIC_H_ */
