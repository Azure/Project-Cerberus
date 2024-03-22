// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_MULTI_HANDLER_MOCK_H_
#define CMD_INTERFACE_MULTI_HANDLER_MOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "cmd_interface/cmd_interface_multi_handler.h"
#include "mock.h"


/**
 * A mock for a command handler supporting multiple unique message types.
 */
struct cmd_interface_multi_handler_mock {
	struct cmd_interface_multi_handler base;	/**< Base command handler API. */
	struct mock mock;							/**< Mock interface. */
};


int cmd_interface_multi_handler_mock_init (struct cmd_interface_multi_handler_mock *mock);
void cmd_interface_multi_handler_mock_release (struct cmd_interface_multi_handler_mock *mock);

int cmd_interface_multi_handler_mock_validate_and_release (
	struct cmd_interface_multi_handler_mock *mock);


#endif /* CMD_INTERFACE_MULTI_HANDLER_MOCK_H_ */
