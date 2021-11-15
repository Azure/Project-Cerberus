// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_CONTROL_MOCK_H_
#define FIRMWARE_UPDATE_CONTROL_MOCK_H_

#include "firmware/firmware_update_control.h"
#include "mock.h"


/**
 * A mock for a firmware update control interface.
 */
struct firmware_update_control_mock {
	struct firmware_update_control base;	/**< The base control instance. */
	struct mock mock;						/**< The base mock instance. */
};


int firmware_update_control_mock_init (struct firmware_update_control_mock *mock);
void firmware_update_control_mock_release (struct firmware_update_control_mock *mock);

int firmware_update_control_mock_validate_and_release (struct firmware_update_control_mock *mock);


#endif /* FIRMWARE_UPDATE_CONTROL_MOCK_H_ */
