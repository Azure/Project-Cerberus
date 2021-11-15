// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_MOCK_H_
#define RSA_MOCK_H_

#include "crypto/rsa.h"
#include "mock.h"


/**
 * A mock for the RSA API.
 */
struct rsa_engine_mock {
	struct rsa_engine base;			/**< The base RSA API instance. */
	struct mock mock;				/**< The base mock interface. */
};


int rsa_mock_init (struct rsa_engine_mock *mock);
void rsa_mock_release (struct rsa_engine_mock *mock);

int rsa_mock_validate_and_release (struct rsa_engine_mock *mock);


#endif /* RSA_MOCK_H_ */
