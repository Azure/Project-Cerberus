// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEY_CACHE_MOCK_H_
#define KEY_CACHE_MOCK_H_

#include "mock.h"
#include "keystore/key_cache.h"


/**
 * Mock for a cache of pre-generated keys.
 */
struct key_cache_mock {
	struct key_cache base;	/**< The key cache instance. */
	struct mock mock;		/**< The base mock interface. */
};


int key_cache_mock_init (struct key_cache_mock *mock);
void key_cache_mock_release (struct key_cache_mock *mock);

int key_cache_mock_validate_and_release (struct key_cache_mock *mock);


#endif	/* KEY_CACHE_MOCK_H_ */
