// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERT_DEVICE_HW_MOCK_H_
#define CERT_DEVICE_HW_MOCK_H_

#include "firmware/cert_device_hw.h"
#include "mock.h"


/**
 * A mock for the certificate hardware API.
 */
struct cert_device_hw_mock {
	struct cert_device_hw base;			/**< The base device instance. */
	struct mock mock;					/**< The base mock interface. */
	uint8_t id;							/**< The revocation ID for the mock instance. */
	uint8_t fail_op;					/**< Flag to indicate if operations should fail. */
	uint8_t valid_key;					/**< Flag indicating if the root key should be valid. */
	struct cert_public_key *checked;	/**< The last root key to be checked by the mock. */
	struct hash_engine *hash_used;		/**< The hash engine used to validate the key. */
};


int cert_device_hw_mock_init (struct cert_device_hw_mock *mock);
void cert_device_hw_mock_release (struct cert_device_hw_mock *mock);

int cert_device_hw_mock_validate_and_release (struct cert_device_hw_mock *mock);


#endif /* CERT_DEVICE_HW_MOCK_H_ */
