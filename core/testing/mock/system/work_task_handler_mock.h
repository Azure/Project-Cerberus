// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef WORK_TASK_HANDLER_MOCK_H_
#define WORK_TASK_HANDLER_MOCK_H_

#include "mock.h"
#include "system/work_task.h"


/**
 * A mock for a handler that can be queued through a work task interface.
 */
struct work_task_handler_mock {
	struct work_task_handler base;	/**< The base handler instance. */
	struct mock mock;				/**< The base mock interface. */
};


int work_task_handler_mock_init (struct work_task_handler_mock *mock);
void work_task_handler_mock_release (struct work_task_handler_mock *mock);

int work_task_handler_mock_validate_and_release (struct work_task_handler_mock *mock);


#endif	/* WORK_TASK_HANDLER_MOCK_H_ */
