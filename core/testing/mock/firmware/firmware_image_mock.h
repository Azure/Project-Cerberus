// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_IMAGE_MOCK_H_
#define FIRMWARE_IMAGE_MOCK_H_

#include "firmware/firmware_image.h"
#include "mock.h"


/**
 * A mock for a system firmware image.
 */
struct firmware_image_mock {
	struct firmware_image base;		/**< The base firmware image instance. */
	struct mock mock;				/**< The base mock instance. */
};


int firmware_image_mock_init (struct firmware_image_mock *mock);
void firmware_image_mock_release (struct firmware_image_mock *mock);

int firmware_image_mock_validate_and_release (struct firmware_image_mock *mock);


#endif /* FIRMWARE_IMAGE_MOCK_H_ */
