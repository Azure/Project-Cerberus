// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DOE_CHANNEL_MOCK_H_
#define DOE_CHANNEL_MOCK_H_

#include "mock.h"
#include "cmd_interface/cmd_interface.h"
#include "pcisig/doe/doe_cmd_channel.h"
#include "pcisig/doe/doe_interface.h"


/**
 * DOE Command Channel API mock
 */
struct doe_cmd_channel_mock {
	struct doe_cmd_channel base;	/**< The cmd channel instance. */
	struct mock mock;				/**< The cmd channel mock interface. */
};


int doe_cmd_channel_mock_init (struct doe_cmd_channel_mock *mock);

int doe_cmd_channel_mock_validate_and_release (struct doe_cmd_channel_mock *mock);


#endif	/* DOE_CHANNEL_MOCK_H_ */
