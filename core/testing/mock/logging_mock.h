// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LOGGING_MOCK_H_
#define LOGGING_MOCK_H_

#include "logging/logging.h"
#include "mock.h"


/**
 * A mock for a log.
 */
struct logging_mock {
	struct logging base;		/**< The base log instance. */
	struct mock mock;			/**< The base mock instance. */
};


int logging_mock_init (struct logging_mock *mock);
void logging_mock_release (struct logging_mock *mock);

int logging_mock_validate_and_release (struct logging_mock *mock);


#endif /* LOGGING_MOCK_H_ */
