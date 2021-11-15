// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_MANAGER_MOCK_H_
#define RECOVERY_IMAGE_MANAGER_MOCK_H_

#include "recovery/recovery_image_manager.h"
#include "mock.h"


/**
 * A mock for the recovery image management API.
 */
struct recovery_image_manager_mock {
	struct recovery_image_manager base;		/**< The base manager instance. */
	struct mock mock;						/**< The base mock interface. */
};


int recovery_image_manager_mock_init (struct recovery_image_manager_mock *mock);
void recovery_image_manager_mock_release (struct recovery_image_manager_mock *mock);

int recovery_image_manager_mock_validate_and_release (struct recovery_image_manager_mock *mock);


#endif /* RECOVERY_IMAGE_MANAGER_MOCK_H_ */
