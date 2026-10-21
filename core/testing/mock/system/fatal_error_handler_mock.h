// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FATAL_ERROR_HANDLER_MOCK_H_
#define FATAL_ERROR_HANDLER_MOCK_H_

#include "mock.h"
#include "system/fatal_error_handler.h"


/**
 * A mock for fatal error handling.
 */
struct fatal_error_handler_mock {
	struct fatal_error_handler base;	/**< The base handler instance. */
	struct mock mock;					/**< The base mock interface. */
};


int fatal_error_handler_mock_init (struct fatal_error_handler_mock *mock);
void fatal_error_handler_mock_release (struct fatal_error_handler_mock *mock);

int fatal_error_handler_mock_validate_and_release (struct fatal_error_handler_mock *mock);


#endif	/* FATAL_ERROR_HANDLER_MOCK_H_ */
