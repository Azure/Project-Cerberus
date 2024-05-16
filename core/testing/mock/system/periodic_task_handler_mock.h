// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PERIODIC_TASK_HANDLER_MOCK_H_
#define PERIODIC_TASK_HANDLER_MOCK_H_

#include "mock.h"
#include "system/periodic_task.h"


/**
 * A mock for a handler from a periodic task.
 */
struct periodic_task_handler_mock {
	struct periodic_task_handler base;	/**< The base handler instance. */
	struct mock mock;					/**< The base mock interface. */
};


int periodic_task_handler_mock_init (struct periodic_task_handler_mock *mock);
void periodic_task_handler_mock_release (struct periodic_task_handler_mock *mock);

int periodic_task_handler_mock_validate_and_release (struct periodic_task_handler_mock *mock);


#endif	/* PERIODIC_TASK_HANDLER_MOCK_H_ */
