// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_DISALLOWED_STATIC_H_
#define AUTHORIZATION_DISALLOWED_STATIC_H_

#include "authorization_allowed.h"


/* Internal functions declared to allow for static initialization. */
int authorization_disallowed_authorize (const struct authorization *auth, const uint8_t **token,
	size_t *length);


/**
 * Constant initializer for the authorization API.
 */
#define	AUTHORIZATION_DISALLOWED_API_INIT  { \
		.authorize = authorization_disallowed_authorize, \
	}

/**
 * Initialize a static authorization manager that does not allow any operation.
 */
#define	authorization_disallowed_static_init { \
		.base = AUTHORIZATION_DISALLOWED_API_INIT, \
	}


#endif	/* AUTHORIZATION_DISALLOWED_STATIC_H_ */
