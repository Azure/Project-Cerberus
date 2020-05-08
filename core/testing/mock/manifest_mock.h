// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_MOCK_H_
#define MANIFEST_MOCK_H_

#include "manifest/manifest.h"
#include "mock.h"


/**
 * A mock for a Manifest.
 */
struct manifest_mock {
	struct manifest base;		/**< The base manifest instance. */
	struct mock mock;			/**< The base mock interface. */
};


int manifest_mock_init (struct manifest_mock *mock);
void manifest_mock_release (struct manifest_mock *mock);

int manifest_mock_validate_and_release (struct manifest_mock *mock);


#endif /* MANIFEST_MOCK_H_ */
