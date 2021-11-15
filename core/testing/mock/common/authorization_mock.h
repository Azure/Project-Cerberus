// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_MOCK_H_
#define AUTHORIZATION_MOCK_H_

#include "common/authorization.h"
#include "mock.h"


/**
 * A mock for authorizing operations.
 */
struct authorization_mock {
	struct authorization base;	/**< The base authorization instance. */
	struct mock mock;			/**< The base mock interface. */
};


int authorization_mock_init (struct authorization_mock *mock);
void authorization_mock_release (struct authorization_mock *mock);

int authorization_mock_validate_and_release (struct authorization_mock *mock);


#endif /* AUTHORIZATION_MOCK_H_ */
