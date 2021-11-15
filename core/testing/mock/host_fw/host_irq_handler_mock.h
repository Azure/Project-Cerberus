// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_HANDLER_MOCK_H_
#define HOST_IRQ_HANDLER_MOCK_H_

#include "host_fw/host_irq_handler.h"
#include "mock.h"


/**
 * Mock for the handler for host IRQs.
 */
struct host_irq_handler_mock {
	struct host_irq_handler base;		/**< The base IRQ handler API. */
	struct mock mock;					/**< The base mock interface. */
};


int host_irq_handler_mock_init (struct host_irq_handler_mock *mock);
void host_irq_handler_mock_release (struct host_irq_handler_mock *mock);

int host_irq_handler_mock_validate_and_release (struct host_irq_handler_mock *mock);


#endif /* HOST_IRQ_HANDLER_MOCK_H_ */
