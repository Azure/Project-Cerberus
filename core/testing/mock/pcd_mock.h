// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_MOCK_H_
#define PCD_MOCK_H_

#include "manifest/pcd/pcd.h"
#include "mock.h"


/**
 * A mock for a pcd.
 */
struct pcd_mock {
	struct pcd base;			/**< The base pcd instance. */
	struct mock mock;			/**< The base mock interface. */
};


int pcd_mock_init (struct pcd_mock *mock);
void pcd_mock_release (struct pcd_mock *mock);

int pcd_mock_validate_and_release (struct pcd_mock *mock);


#endif /* PCD_MOCK_H_ */
