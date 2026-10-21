// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_CHECK_MOCK_H_
#define IMPACTFUL_CHECK_MOCK_H_

#include "mock.h"
#include "firmware/impactful_check.h"


/**
 * A mock for checking for impactful updates.
 */
struct impactful_check_mock {
	struct impactful_check base;	/**< The base interface for checking for impactful updates. */
	struct mock mock;				/**< The base mock instance. */
};


int impactful_check_mock_init (struct impactful_check_mock *mock);
void impactful_check_mock_release (struct impactful_check_mock *mock);

int impactful_check_mock_validate_and_release (struct impactful_check_mock *mock);


#endif	/* IMPACTFUL_CHECK_MOCK_H_ */
