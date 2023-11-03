// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_MANAGER_NULL_H_
#define MANIFEST_MANAGER_NULL_H_

#include "manifest_manager.h"


/**
 * NULL object for manifest manager.
 */
struct manifest_manager_null {
	struct manifest_manager base;		/* Base interface */
};


int manifest_manager_null_init (struct manifest_manager_null *manager);
void manifest_manager_null_release (const struct manifest_manager_null *manager);


#endif /* MANIFEST_MANAGER_NULL_H_ */
