// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_MOCK_H_
#define CMD_INTERFACE_PROTOCOL_MOCK_H_

#include <stddef.h>
#include <stdint.h>
#include "mock.h"
#include "cmd_interface/cmd_interface.h"


/**
 * Mock for a command protocol handler.
 */
struct cmd_interface_protocol_mock {
	struct cmd_interface_protocol base;	/**< Base protocol handler API. */
	struct mock mock;					/**< Mock interface. */
};


int cmd_interface_protocol_mock_init (struct cmd_interface_protocol_mock *mock);
void cmd_interface_protocol_mock_release (struct cmd_interface_protocol_mock *mock);

int cmd_interface_protocol_mock_validate_and_release (struct cmd_interface_protocol_mock *mock);


#endif	/* CMD_INTERFACE_PROTOCOL_MOCK_H_ */
