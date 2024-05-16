// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_HW_MOCK_H_
#define ECC_HW_MOCK_H_

#include "mock.h"
#include "crypto/ecc_hw.h"


/**
 * A mock for an ECC HW accelerator.
 */
struct ecc_hw_mock {
	struct ecc_hw base;	/**< The base ECC HW instance. */
	struct mock mock;	/**< The base mock interface. */
};


int ecc_hw_mock_init (struct ecc_hw_mock *mock);
void ecc_hw_mock_release (struct ecc_hw_mock *mock);

int ecc_hw_mock_validate_and_release (struct ecc_hw_mock *mock);


#endif	/* ECC_HW_MOCK_H_ */
