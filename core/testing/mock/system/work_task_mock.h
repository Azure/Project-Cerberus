// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef WORK_TASK_MOCK_H_
#define WORK_TASK_MOCK_H_

#include "mock.h"
#include "system/work_task_interface.h"


/**
 * A mock for a work task.
 */
struct work_task_mock {
	struct work_task_interface base;	/**< The base work task interface. */
	struct mock mock;		/**< The base mock interface. */
};


int work_task_mock_init (struct work_task_mock *mock);
void work_task_mock_release (struct work_task_mock *mock);

int work_task_mock_validate_and_release (struct work_task_mock *mock);


#endif	/* WORK_TASK_MOCK_H_ */
