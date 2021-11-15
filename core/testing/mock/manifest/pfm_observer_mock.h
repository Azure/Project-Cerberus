// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_OBSERVER_MOCK_H_
#define PFM_OBSERVER_MOCK_H_

#include "manifest/pfm/pfm_observer.h"
#include "mock.h"


/**
 * A mock for PFM management notifications.
 */
struct pfm_observer_mock {
	struct pfm_observer base;		/**< The base observer instance. */
	struct mock mock;				/**< The base mock interface. */
};


int pfm_observer_mock_init (struct pfm_observer_mock *mock);
void pfm_observer_mock_release (struct pfm_observer_mock *mock);

int pfm_observer_mock_validate_and_release (struct pfm_observer_mock *mock);


#endif /* PFM_OBSERVER_MOCK_H_ */
