// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURITY_MANAGER_NO_UNLOCK_H_
#define SECURITY_MANAGER_NO_UNLOCK_H_

#include "security_manager.h"


/**
 * A security manager that does not support device unlock flows.
 */
struct security_manager_no_unlock {
	struct security_manager base;	/**< The base manager API. */
};


int security_manager_no_unlock_init (struct security_manager_no_unlock *manager);
void security_manager_no_unlock_release (const struct security_manager_no_unlock *manager);


#endif	/* SECURITY_MANAGER_NO_UNLOCK_H_ */
