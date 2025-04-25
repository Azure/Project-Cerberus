// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SELF_TEST_MOCK_H_
#define SELF_TEST_MOCK_H_

#include "mock.h"
#include "fips/self_test_interface.h"


/**
 * A mock for a module self-test.
 */
struct self_test_mock {
	struct self_test_interface base;	/**< The base self-test API instance. */
	struct mock mock;					/**< The base mock interface. */
};


int self_test_mock_init (struct self_test_mock *mock);
void self_test_mock_release (struct self_test_mock *mock);

int self_test_mock_validate_and_release (struct self_test_mock *mock);


#endif	/* SELF_TEST_MOCK_H_ */
