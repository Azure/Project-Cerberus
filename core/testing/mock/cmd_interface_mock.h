// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_MOCK_H_
#define CMD_INTERFACE_MOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "cmd_interface/cmd_interface.h"
#include "mock.h"


/**
 * Command Interface API mock
 */
struct cmd_interface_mock {
	struct cmd_interface base;		/**< Command interface instance*/
	struct mock mock;				/**< Mock instance*/
};

int cmd_interface_mock_init (struct cmd_interface_mock *mock);
void cmd_interface_mock_release (struct cmd_interface_mock *mock);

int cmd_interface_mock_validate_and_release (struct cmd_interface_mock *mock);

int cmd_interface_mock_validate_request (const char *arg_info, void *expected, void *actual);


#endif /* CMD_INTERFACE_MOCK_H_ */
