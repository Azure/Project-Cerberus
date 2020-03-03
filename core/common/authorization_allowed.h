// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_ALLOWED_H_
#define AUTHORIZATION_ALLOWED_H_

#include "authorization.h"


/**
 * Authorization manager that allows all operations.
 */
struct authorization_allowed {
	struct authorization base;			/**< Base authorization manager. */
};


int authorization_allowed_init (struct authorization_allowed *auth);
void authorization_allowed_release (struct authorization_allowed *auth);


#endif /* AUTHORIZATION_ALLOWED_H_ */
