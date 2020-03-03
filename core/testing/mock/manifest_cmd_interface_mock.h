// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_INTERFACE_MOCK_H_
#define MANIFEST_CMD_INTERFACE_MOCK_H_

#include "manifest/manifest_cmd_interface.h"
#include "mock.h"


/**
 * A mock for the manifest command handler API.
 */
struct manifest_cmd_interface_mock {
	struct manifest_cmd_interface base;		/**< The base command handler instance. */
	struct mock mock;						/**< The base mock interface. */
};


int manifest_cmd_interface_mock_init (struct manifest_cmd_interface_mock *mock);
void manifest_cmd_interface_mock_release (struct manifest_cmd_interface_mock *mock);

int manifest_cmd_interface_mock_validate_and_release (struct manifest_cmd_interface_mock *mock);


#endif /* MANIFEST_CMD_INTERFACE_MOCK_H_ */
