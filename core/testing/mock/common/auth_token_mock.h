// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTH_TOKEN_MOCK_H_
#define AUTH_TOKEN_MOCK_H_

#include "common/auth_token.h"
#include "mock.h"


/**
 * A mock for handling authorization tokens.
 */
struct auth_token_mock {
	struct auth_token base;		/**< The base token handler instance. */
	struct mock mock;			/**< The base mock interface. */
};


int auth_token_mock_init (struct auth_token_mock *mock);
void auth_token_mock_release (struct auth_token_mock *mock);

int auth_token_mock_validate_and_release (struct auth_token_mock *mock);


#endif /* AUTH_TOKEN_MOCK_H_ */
