// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_MOCK_H_
#define HASH_MOCK_H_

#include "crypto/hash.h"
#include "mock.h"


/**
 * A mock for the hash API.
 */
struct hash_engine_mock {
	struct hash_engine base;		/**< The base hash API instance. */
	struct mock mock;				/**< The base mock interface. */
};


int hash_mock_init (struct hash_engine_mock *mock);
void hash_mock_release (struct hash_engine_mock *mock);

int hash_mock_validate_and_release (struct hash_engine_mock *mock);

int hash_mock_expect_hmac_init (struct hash_engine_mock *mock, const uint8_t *key,
	size_t key_length);
int hash_mock_expect_hmac_finish (struct hash_engine_mock *mock, const uint8_t *key,
	size_t key_length, uint8_t *hmac, size_t hmac_length, const uint8_t *expected,
	size_t exp_length);
int hash_mock_expect_hmac (struct hash_engine_mock *mock, const uint8_t *key, size_t key_length,
	const uint8_t *data, size_t length, uint8_t *hmac, size_t hmac_length, const uint8_t *expected,
	size_t exp_length);


#endif /* HASH_MOCK_H_ */
