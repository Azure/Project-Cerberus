// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_CMD_INTERFACE_MOCK_H_
#define HOST_CMD_INTERFACE_MOCK_H_

#include "mock.h"
#include "host_fw/host_cmd_interface.h"


/**
 * A mock for the host command handler API.
 */
struct host_cmd_interface_mock {
	struct host_cmd_interface base;	/**< The base command handler instance. */
	struct mock mock;				/**< The base mock interface. */
};


int host_cmd_interface_mock_init (struct host_cmd_interface_mock *mock);
void host_cmd_interface_mock_release (struct host_cmd_interface_mock *mock);

int host_cmd_interface_mock_validate_and_release (struct host_cmd_interface_mock *mock);


#endif	/* HOST_CMD_INTERFACE_MOCK_H_ */
