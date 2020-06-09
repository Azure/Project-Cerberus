// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SESSION_MANAGER_MOCK_H_
#define SESSION_MANAGER_MOCK_H_

#include "cmd_interface/session_manager.h"
#include "mock.h"


/**
 * A mock for a session manager.
 */
struct session_manager_mock {
	struct session_manager base;		/**< The base session manager instance. */
	struct mock mock;					/**< The base mock interface. */
};


int session_manager_mock_init (struct session_manager_mock *mock);
void session_manager_mock_release (struct session_manager_mock *mock);

int session_manager_mock_validate_and_release (struct session_manager_mock *mock);


#endif /* SESSION_MANAGER_MOCK_H_ */
