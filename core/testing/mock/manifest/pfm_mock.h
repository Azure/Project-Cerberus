// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_MOCK_H_
#define PFM_MOCK_H_

#include "manifest/pfm/pfm.h"
#include "mock.h"


/**
 * A mock for a PFM.
 */
struct pfm_mock {
	struct pfm base;			/**< The base PFM instance. */
	struct mock mock;			/**< The base mock interface. */
};


int pfm_mock_init (struct pfm_mock *mock);
void pfm_mock_release (struct pfm_mock *mock);

int pfm_mock_validate_and_release (struct pfm_mock *mock);


#endif /* PFM_MOCK_H_ */
