// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_AUTHORIZATION_MOCK_H_
#define CMD_AUTHORIZATION_MOCK_H_

#include "cmd_interface/cmd_authorization.h"
#include "mock.h"


/**
 * A mock for handling command authorization.
 */
struct cmd_authorization_mock {
	struct cmd_authorization base;	/**< The base authorization handler. */
	struct mock mock;				/**< The base mock interface. */
};


int cmd_authorization_mock_init (struct cmd_authorization_mock *mock);
void cmd_authorization_mock_release (struct cmd_authorization_mock *mock);

int cmd_authorization_mock_validate_and_release (struct cmd_authorization_mock *mock);


#endif /* CMD_AUTHORIZATION_MOCK_H_ */
