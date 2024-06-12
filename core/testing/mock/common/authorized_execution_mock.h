// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_MOCK_H_
#define AUTHORIZED_EXECUTION_MOCK_H_

#include "mock.h"
#include "common/authorized_execution.h"


/**
 * A mock for executing authorized executions.
 */
struct authorized_execution_mock {
	struct authorized_execution base;	/**< The base execution instance. */
	struct mock mock;					/**< The base mock interface. */
};


int authorized_execution_mock_init (struct authorized_execution_mock *mock);
void authorized_execution_mock_release (struct authorized_execution_mock *mock);

int authorized_execution_mock_validate_and_release (struct authorized_execution_mock *mock);


#endif	/* AUTHORIZED_EXECUTION_MOCK_H_ */
