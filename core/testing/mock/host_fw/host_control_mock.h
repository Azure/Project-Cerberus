// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_CONTROL_MOCK_H_
#define HOST_CONTROL_MOCK_H_

#include "host_fw/host_control.h"
#include "mock.h"


/**
 * A mock for the host processor control API.
 */
struct host_control_mock {
	struct host_control base;		/**< The base control instance. */
	struct mock mock;				/**< The base mock interface. */
};


int host_control_mock_init (struct host_control_mock *mock);
void host_control_mock_release (struct host_control_mock *mock);

int host_control_mock_validate_and_release (struct host_control_mock *mock);


#endif /* HOST_CONTROL_MOCK_H_ */
