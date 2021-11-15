// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEY_MANIFEST_MOCK_H_
#define KEY_MANIFEST_MOCK_H_

#include "firmware/key_manifest.h"
#include "mock.h"


/**
 * A mock for a key manifest.
 */
struct key_manifest_mock {
	struct key_manifest base;		/**< Base key manifest instance. */
	struct mock mock;				/**< The base mock interface. */
};


int key_manifest_mock_init (struct key_manifest_mock *mock);
void key_manifest_mock_release (struct key_manifest_mock *mock);

int key_manifest_mock_validate_and_release (struct key_manifest_mock *mock);


#endif /* KEY_MANIFEST_MOCK_H_ */
