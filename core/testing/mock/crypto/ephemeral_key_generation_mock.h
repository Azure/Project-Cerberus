// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EPHEMERAL_KEY_GENERATION_MOCK_H_
#define EPHEMERAL_KEY_GENERATION_MOCK_H_

#include "mock.h"
#include "crypto/ephemeral_key_generation.h"


/**
 * A mock for the ephemeral_key_generation API.
 */
struct ephemeral_key_generation_mock {
	struct ephemeral_key_generation base;	/**< The base ephemeral_key_generation API instance. */
	struct mock mock;						/**< The base mock interface. */
};


int ephemeral_key_generation_mock_init (struct ephemeral_key_generation_mock *mock);
void ephemeral_key_generation_mock_release (struct ephemeral_key_generation_mock *mock);

int ephemeral_key_generation_mock_validate_and_release (struct ephemeral_key_generation_mock *mock);


#endif	/* EPHEMERAL_KEY_GENERATION_MOCK_H_ */
