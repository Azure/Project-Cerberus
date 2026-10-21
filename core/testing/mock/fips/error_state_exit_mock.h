// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ERROR_STATE_EXIT_MOCK_H_
#define ERROR_STATE_EXIT_MOCK_H_

#include "mock.h"
#include "fips/error_state_exit_interface.h"


/**
 * A mock for exiting the FIPS error state.
 */
struct error_state_exit_mock {
	struct error_state_exit_interface base;	/**< The base error state API instance. */
	struct mock mock;						/**< The base mock interface. */
};


int error_state_exit_mock_init (struct error_state_exit_mock *mock);
void error_state_exit_mock_release (struct error_state_exit_mock *mock);

int error_state_exit_mock_validate_and_release (struct error_state_exit_mock *mock);


#endif	/* ERROR_STATE_EXIT_MOCK_H_ */
