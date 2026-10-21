// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HKDF_MOCK_H_
#define HKDF_MOCK_H_

#include "mock.h"
#include "crypto/hkdf_interface.h"


/**
 * A mock for the HKDF API.
 */
struct hkdf_mock {
	struct hkdf_interface base;	/**< The base HKDF API instance. */
	struct mock mock;			/**< The base mock interface. */
};


int hkdf_mock_init (struct hkdf_mock *mock);
void hkdf_mock_release (struct hkdf_mock *mock);

int hkdf_mock_validate_and_release (struct hkdf_mock *mock);


#endif	/* HKDF_MOCK_H_ */
