// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_MOCK_H_
#define HOST_PROCESSOR_MOCK_H_

#include "mock.h"
#include "host_fw/host_processor.h"


/**
 * Mock for host processor actions.
 */
struct host_processor_mock {
	struct host_processor base;			/**< The base processor instance. */
	struct mock mock;					/**< The base mock interface. */
	struct host_processor_state state;	/**< Variable context for the base processor instance. */
};


int host_processor_mock_init (struct host_processor_mock *mock);
void host_processor_mock_release (struct host_processor_mock *mock);

int host_processor_mock_validate_and_release (struct host_processor_mock *mock);


#endif	/* HOST_PROCESSOR_MOCK_H_ */
