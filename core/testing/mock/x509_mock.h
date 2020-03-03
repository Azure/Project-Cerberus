// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_MOCK_H_
#define X509_MOCK_H_

#include "crypto/x509.h"
#include "mock.h"


/**
 * A mock for the X.509 API.
 */
struct x509_engine_mock {
	struct x509_engine base;		/**< The base X.509 API instance. */
	struct mock mock;				/**< The base mock interface. */
};


int x509_mock_init (struct x509_engine_mock *mock);
void x509_mock_release (struct x509_engine_mock *mock);

int x509_mock_validate_and_release (struct x509_engine_mock *mock);


#endif /* X509_MOCK_H_ */
