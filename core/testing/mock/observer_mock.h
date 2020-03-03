// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef OBSERVER_MOCK_H_
#define OBSERVER_MOCK_H_

#include "mock.h"


/**
 * A mock observer.
 */
struct observer_mock {
	/**
	 * Notification that takes no arguments.
	 *
	 * @param observer The observer instance being notified.
	 */
	void (*event) (struct observer_mock *observer);

	/**
	 * Notification that takes a single pointer as an argument.
	 *
	 * @param observer The observer instance being notified.
	 * @param arg The pointer argument passed with the notification.
	 */
	void (*event_ptr_arg) (struct observer_mock *observer, void *arg);

	struct mock mock;					/**< The base mock interface. */
};


int observer_mock_init (struct observer_mock *mock);
void observer_mock_release (struct observer_mock *mock);

int observer_mock_validate_and_release (struct observer_mock *mock);


#endif /* OBSERVER_MOCK_H_ */
