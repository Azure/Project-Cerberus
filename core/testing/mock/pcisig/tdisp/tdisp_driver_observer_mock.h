// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TDISP_DRIVER_OBSERVER_MOCK_H_
#define TDISP_DRIVER_OBSERVER_MOCK_H_

#include "mock.h"
#include "pcisig/tdisp/tdisp_driver_observer.h"


/**
 * A mock for TDISP driver notifications.
 */
struct tdisp_driver_observer_mock {
	struct tdisp_driver_observer base;	/**< The base observer instance. */
	struct mock mock;					/**< The base mock interface. */
};


int tdisp_driver_observer_mock_init (struct tdisp_driver_observer_mock *mock);
void tdisp_driver_observer_mock_release (struct tdisp_driver_observer_mock *mock);

int tdisp_driver_observer_mock_validate_and_release (
	struct tdisp_driver_observer_mock *mock);


#endif	/* TDISP_DRIVER_OBSERVER_MOCK_H_ */
