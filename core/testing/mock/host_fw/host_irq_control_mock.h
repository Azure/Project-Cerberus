// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_CONTROL_MOCK_H_
#define HOST_IRQ_CONTROL_MOCK_H_

#include "host_fw/host_irq_control.h"
#include "mock.h"


/**
 * Mock for the API to control host IRQs.
 */
struct host_irq_control_mock {
	struct host_irq_control base;		/**< The base IRQ control API. */
	struct mock mock;					/**< The base mock interface. */
};


int host_irq_control_mock_init (struct host_irq_control_mock *mock);
void host_irq_control_mock_release (struct host_irq_control_mock *mock);

int host_irq_control_mock_validate_and_release (struct host_irq_control_mock *mock);


#endif /* HOST_IRQ_CONTROL_MOCK_H_ */
