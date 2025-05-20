// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZING_SIGNATURE_MOCK_H_
#define AUTHORIZING_SIGNATURE_MOCK_H_

#include "mock.h"
#include "common/authorizing_signature.h"


/**
 * A mock for handling authorizing signatures.
 */
struct authorizing_signature_mock {
	struct authorizing_signature base;	/**< The base authorizing signature instance. */
	struct mock mock;					/**< The base mock interface. */
};


int authorizing_signature_mock_init (struct authorizing_signature_mock *mock);
void authorizing_signature_mock_release (struct authorizing_signature_mock *mock);

int authorizing_signature_mock_validate_and_release (struct authorizing_signature_mock *mock);


#endif	/* AUTHORIZING_SIGNATURE_MOCK_H_ */
