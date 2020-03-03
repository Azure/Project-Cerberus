// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_MOCK_H_
#define RECOVERY_IMAGE_MOCK_H_

#include "recovery/recovery_image.h"
#include "mock.h"


/**
 * A mock for a recovery image.
 */
struct recovery_image_mock {
	struct recovery_image base;			/**< The base recovery image instance. */
	struct mock mock;					/**< The base mock interface. */
};


int recovery_image_mock_init (struct recovery_image_mock *mock);
void recovery_image_mock_release (struct recovery_image_mock *mock);

int recovery_image_mock_validate_and_release (struct recovery_image_mock *mock);


#endif /* RECOVERY_IMAGE_MOCK_H_ */
