// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_MANAGER_MOCK_H_
#define PCD_MANAGER_MOCK_H_

#include "manifest/pcd/pcd_manager.h"
#include "mock.h"


/**
 * A mock for the PCD management API.
 */
struct pcd_manager_mock {
	struct pcd_manager base;		/**< The base manager instance. */
	struct mock mock;				/**< The base mock interface. */
};


int pcd_manager_mock_init (struct pcd_manager_mock *mock);
void pcd_manager_mock_release (struct pcd_manager_mock *mock);

int pcd_manager_mock_validate_and_release (struct pcd_manager_mock *mock);


#endif /* PCD_MANAGER_MOCK_H_ */
