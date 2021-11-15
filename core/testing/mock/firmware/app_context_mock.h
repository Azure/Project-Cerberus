// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef APP_CONTEXT_MOCK_H_
#define APP_CONTEXT_MOCK_H_

#include "firmware/app_context.h"
#include "mock.h"


/**
 * A mock for the application context API.
 */
struct app_context_mock {
	struct app_context base;	/**< The base application context instance. */
	struct mock mock;			/**< The base mock instance. */
};


int app_context_mock_init (struct app_context_mock *mock);
void app_context_mock_release (struct app_context_mock *mock);

int app_context_mock_validate_and_release (struct app_context_mock *mock);


#endif /* APP_CONTEXT_MOCK_H_ */
