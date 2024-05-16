// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEVICE_RMA_TRANSITION_MOCK_H_
#define DEVICE_RMA_TRANSITION_MOCK_H_

#include "mock.h"
#include "rma/device_rma_transition.h"


/**
 * A mock for applying device RMA configuration.
 */
struct device_rma_transition_mock {
	struct device_rma_transition base;	/**< The base RMA configuration instance. */
	struct mock mock;					/**< The base mock interface. */
};


int device_rma_transition_mock_init (struct device_rma_transition_mock *mock);
void device_rma_transition_mock_release (struct device_rma_transition_mock *mock);

int device_rma_transition_mock_validate_and_release (struct device_rma_transition_mock *mock);


#endif	/* DEVICE_RMA_TRANSITION_MOCK_H_ */
