// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_OBSERVER_MOCK_H_
#define CFM_OBSERVER_MOCK_H_

#include "manifest/cfm/cfm_observer.h"
#include "mock.h"


/**
 * A mock for CFM management notifications.
 */
struct cfm_observer_mock {
	struct cfm_observer base;		/**< The base observer instance. */
	struct mock mock;				/**< The base mock interface. */
};


int cfm_observer_mock_init (struct cfm_observer_mock *mock);
void cfm_observer_mock_release (struct cfm_observer_mock *mock);

int cfm_observer_mock_validate_and_release (struct cfm_observer_mock *mock);


#endif /* CFM_OBSERVER_MOCK_H_ */
