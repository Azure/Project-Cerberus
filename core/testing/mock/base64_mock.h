// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_MOCK_H_
#define BASE64_MOCK_H_

#include "crypto/base64.h"
#include "mock.h"


/**
 * A mock for the base64 API.
 */
struct base64_engine_mock {
	struct base64_engine base;		/**< The base base64 instance. */
	struct mock mock;				/**< The base mock interface. */
};


int base64_mock_init (struct base64_engine_mock *mock);
void base64_mock_release (struct base64_engine_mock *mock);

int base64_mock_validate_and_release (struct base64_engine_mock *mock);


#endif /* BASE64_MOCK_H_ */
