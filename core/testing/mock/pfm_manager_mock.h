// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_MANAGER_MOCK_H_
#define PFM_MANAGER_MOCK_H_

#include "manifest/pfm/pfm_manager.h"
#include "mock.h"


/**
 * A mock for the PFM management API.
 */
struct pfm_manager_mock {
	struct pfm_manager base;		/**< The base manager instance. */
	struct mock mock;				/**< The base mock interface. */
};


int pfm_manager_mock_init (struct pfm_manager_mock *mock);
void pfm_manager_mock_release (struct pfm_manager_mock *mock);

int pfm_manager_mock_validate_and_release (struct pfm_manager_mock *mock);


#endif /* PFM_MANAGER_MOCK_H_ */
