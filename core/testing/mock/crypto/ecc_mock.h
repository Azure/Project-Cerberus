// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_MOCK_H_
#define ECC_MOCK_H_

#include "crypto/ecc.h"
#include "mock.h"


/**
 * A mock for the ECC API.
 */
struct ecc_engine_mock {
	struct ecc_engine base;			/**< The base ECC API instance. */
	struct mock mock;				/**< The base mock interface. */
};


int ecc_mock_init (struct ecc_engine_mock *mock);
void ecc_mock_release (struct ecc_engine_mock *mock);

int ecc_mock_validate_and_release (struct ecc_engine_mock *mock);

int ecc_mock_validate_point_public_key (const char *arg_info, void *expected, void *actual);
int ecc_mock_validate_ecdsa_signature (const char *arg_info, void *expected, void *actual);


#endif /* ECC_MOCK_H_ */
