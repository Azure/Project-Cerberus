// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_OBSERVER_MOCK_H_
#define RECOVERY_IMAGE_OBSERVER_MOCK_H_

#include "recovery/recovery_image_observer.h"
#include "mock.h"


/**
 * A mock for notifying observers of recovery image events.
 */
struct recovery_image_observer_mock {
	struct recovery_image_observer base;		/**< The base observer instance. */
	struct mock mock;							/**< The base mock interface. */
};


int recovery_image_observer_mock_init (struct recovery_image_observer_mock *mock);
void recovery_image_observer_mock_release (struct recovery_image_observer_mock *mock);

int recovery_image_observer_mock_validate_and_release (struct recovery_image_observer_mock *mock);


#endif /* RECOVERY_IMAGE_OBSERVER_MOCK_H_ */
