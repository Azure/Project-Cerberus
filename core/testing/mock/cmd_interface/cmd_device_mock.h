// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_DEVICE_MOCK_H_
#define CMD_DEVICE_MOCK_H_

#include "cmd_interface/cmd_device.h"
#include "mock.h"


/**
 * A mock for the device command handler API.
 */
struct cmd_device_mock {
	struct cmd_device base;		/**< The base device command handler instance. */
	struct mock mock;			/**< The base mock interface. */
};


int cmd_device_mock_init (struct cmd_device_mock *mock);
void cmd_mock_release (struct cmd_device_mock *mock);

int cmd_device_mock_validate_and_release (struct cmd_device_mock *mock);


#endif /* CMD_DEVICE_MOCK_H_ */
