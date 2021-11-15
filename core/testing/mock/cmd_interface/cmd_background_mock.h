// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_BACKGROUND_MOCK_H_
#define CMD_BACKGROUND_MOCK_H_

#include "cmd_interface/cmd_background.h"
#include "mock.h"


/**
 * A mock for a background command context.
 */
struct cmd_background_mock {
	struct cmd_background base;		/**< The base control instance. */
	struct mock mock;				/**< The base mock instance. */
};


int cmd_background_mock_init (struct cmd_background_mock *mock);
void cmd_background_mock_release (struct cmd_background_mock *mock);

int cmd_background_mock_validate_and_release (struct cmd_background_mock *mock);


#endif /* CMD_BACKGROUND_MOCK_H_ */
