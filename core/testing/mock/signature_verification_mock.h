// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_MOCK_H_
#define SIGNATURE_VERIFICATION_MOCK_H_

#include "common/signature_verification.h"
#include "mock.h"


/**
 * A mock for signature verification.
 */
struct signature_verification_mock {
	struct signature_verification base;		/**< The base verification instance. */
	struct mock mock;						/**< The base mock interface. */
};


int signature_verification_mock_init (struct signature_verification_mock *mock);
void signature_verification_mock_release (struct signature_verification_mock *mock);

int signature_verification_mock_validate_and_release (struct signature_verification_mock *mock);


#endif /* SIGNATURE_VERIFICATION_MOCK_H_ */
