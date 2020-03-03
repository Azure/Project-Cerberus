// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_DISALLOWED_H_
#define AUTHORIZATION_DISALLOWED_H_

#include "authorization.h"


/**
 * Authorization manager that does not allow any operation.
 */
struct authorization_disallowed {
	struct authorization base;			/**< Base authorization manager. */
};


int authorization_disallowed_init (struct authorization_disallowed *auth);
void authorization_disallowed_release (struct authorization_disallowed *auth);


#endif /* AUTHORIZATION_DISALLOWED_H_ */
