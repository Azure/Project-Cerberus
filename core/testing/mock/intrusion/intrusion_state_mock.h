// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef INTRUSION_STATE_MOCK_H_
#define INTRUSION_STATE_MOCK_H_

#include "mock.h"
#include "intrusion/intrusion_state.h"


/**
 * A mock for intrusion state.
 */
struct intrusion_state_mock {
	struct intrusion_state base;	/**< The base intrusion state instance. */
	struct mock mock;				/**< The base mock interface. */
};


int intrusion_state_mock_init (struct intrusion_state_mock *mock);
void intrusion_state_mock_release (struct intrusion_state_mock *mock);

int intrusion_state_mock_validate_and_release (struct intrusion_state_mock *mock);


#endif	/* INTRUSION_STATE_MOCK_H_ */
