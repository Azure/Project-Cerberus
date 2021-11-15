// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_OBSERVER_MOCK_H_
#define PCD_OBSERVER_MOCK_H_

#include "manifest/pcd/pcd_observer.h"
#include "mock.h"


/**
 * A mock for PCD management notifications.
 */
struct pcd_observer_mock {
	struct pcd_observer base;		/**< The base observer instance. */
	struct mock mock;				/**< The base mock interface. */
};


int pcd_observer_mock_init (struct pcd_observer_mock *mock);
void pcd_observer_mock_release (struct pcd_observer_mock *mock);

int pcd_observer_mock_validate_and_release (struct pcd_observer_mock *mock);


#endif /* PCD_OBSERVER_MOCK_H_ */
