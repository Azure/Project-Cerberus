// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef REAL_TIME_CLOCK_MOCK_H_
#define REAL_TIME_CLOCK_MOCK_H_

#include "mock.h"
#include "system/real_time_clock.h"


/**
 * A mock for the interface used for real time clock access.
 */
struct real_time_clock_mock {
	struct real_time_clock base;	/**< The base real time clock interface. */
	struct mock mock;				/**< The base mock interface. */
};


int real_time_clock_mock_init (struct real_time_clock_mock *mock);
void real_time_clock_mock_release (struct real_time_clock_mock *mock);

int real_time_clock_mock_validate_and_release (struct real_time_clock_mock *mock);


#endif	/* REAL_TIME_CLOCK_MOCK_H_ */
