// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_MOCK_H_
#define CMD_CHANNEL_MOCK_H_

#include "cmd_interface/cmd_channel.h"
#include "mock.h"


/**
 * A mock for a command communication channel.
 */
struct cmd_channel_mock {
	struct cmd_channel base;		/**< The base channel instance. */
	struct mock mock;				/**< The base mock interface. */
};


int cmd_channel_mock_init (struct cmd_channel_mock *mock, int id);
void cmd_channel_mock_release (struct cmd_channel_mock *mock);

int cmd_channel_mock_validate_and_release (struct cmd_channel_mock *mock);

int cmd_channel_mock_validate_packet (const char *arg_info, void *expected, void *actual);


#endif /* CMD_CHANNEL_MOCK_H_ */
