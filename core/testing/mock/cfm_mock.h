// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_MOCK_H_
#define CFM_MOCK_H_

#include "manifest/cfm/cfm.h"
#include "mock.h"


/**
 * A mock for a cfm.
 */
struct cfm_mock {
	struct cfm base;			/**< The base cfm instance. */
	struct mock mock;			/**< The base mock interface. */
};


int cfm_mock_init (struct cfm_mock *mock);
void cfm_mock_release (struct cfm_mock *mock);

int cfm_mock_validate_and_release (struct cfm_mock *mock);


#endif /* CFM_MOCK_H_ */
