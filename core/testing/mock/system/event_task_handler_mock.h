// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EVENT_TASK_HANDLER_MOCK_H_
#define EVENT_TASK_HANDLER_MOCK_H_

#include "mock.h"
#include "system/event_task.h"


/**
 * A mock for a handler from an event task.
 */
struct event_task_handler_mock {
	struct event_task_handler base;	/**< The base handler instance. */
	struct mock mock;				/**< The base mock interface. */
};


int event_task_handler_mock_init (struct event_task_handler_mock *mock);
void event_task_handler_mock_release (struct event_task_handler_mock *mock);

int event_task_handler_mock_validate_and_release (struct event_task_handler_mock *mock);


#endif	/* EVENT_TASK_HANDLER_MOCK_H_ */
