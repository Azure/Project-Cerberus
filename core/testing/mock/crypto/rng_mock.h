// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_MOCK_H_
#define RNG_MOCK_H_

#include "crypto/rng.h"
#include "mock.h"


/**
 * A mock for the RNG API.
 */
struct rng_engine_mock {
	struct rng_engine base;			/**< The base RNG API instance. */
	struct mock mock;				/**< The base mock interface. */
};


int rng_mock_init (struct rng_engine_mock *mock);
void rng_mock_release (struct rng_engine_mock *mock);

int rng_mock_validate_and_release (struct rng_engine_mock *mock);


#endif /* RNG_MOCK_H_ */
