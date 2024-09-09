// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MPU_MOCK_H_
#define MPU_MOCK_H_

#include "mock.h"
#include "mpu/mpu.h"


/**
 * MPU interface mock
 */
struct mpu_mock {
	struct mpu_interface base;	/**< MPU interface */
	struct mock mock;			/**< Mock interface */
};


int mpu_mock_init (struct mpu_mock *mock);
int mpu_mock_validate_and_release (struct mpu_mock *mock);


#endif	// MPU_MOCK_H_
