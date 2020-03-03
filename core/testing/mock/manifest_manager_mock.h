// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_MANAGER_MOCK_H_
#define MANIFEST_MANAGER_MOCK_H_

#include "manifest/manifest_manager.h"
#include "mock.h"


/**
 * A mock for generic manifest management.
 */
struct manifest_manager_mock {
	struct manifest_manager base;	/**< The base manager instance. */
	struct mock mock;				/**< The base mock interface. */
};


int manifest_manager_mock_init (struct manifest_manager_mock *mock);
void manifest_manager_mock_release (struct manifest_manager_mock *mock);

int manifest_manager_mock_validate_and_release (struct manifest_manager_mock *mock);


#endif /* MANIFEST_MANAGER_MOCK_H_ */
