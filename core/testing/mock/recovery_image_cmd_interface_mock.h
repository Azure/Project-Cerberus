// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_CMD_INTERFACE_MOCK_H_
#define RECOVERY_IMAGE_CMD_INTERFACE_MOCK_H_

#include "recovery/recovery_image_cmd_interface.h"
#include "mock.h"


/**
 * A mock for the recovery image command handler API.
 */
struct recovery_image_cmd_interface_mock {
	struct recovery_image_cmd_interface base;		/**< The base command handler instance. */
	struct mock mock;								/**< The base mock interface. */
};


int recovery_image_cmd_interface_mock_init (struct recovery_image_cmd_interface_mock *mock);
void recovery_image_cmd_interface_mock_release (struct recovery_image_cmd_interface_mock *mock);

int recovery_image_cmd_interface_mock_validate_and_release (
	struct recovery_image_cmd_interface_mock *mock);


#endif /* RECOVERY_IMAGE_CMD_INTERFACE_MOCK_H_ */
