// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_MOCK_H_
#define X509_EXTENSION_BUILDER_MOCK_H_

#include "asn1/x509_extension_builder.h"
#include "mock.h"


/**
 * A mock for building X.509 extensions.
 */
struct x509_extension_builder_mock {
	struct x509_extension_builder base;		/**< The base extension builder instance. */
	struct mock mock;						/**< The base mock interface. */
};


int x509_extension_builder_mock_init (struct x509_extension_builder_mock *mock);
void x509_extension_builder_mock_release (struct x509_extension_builder_mock *mock);

int x509_extension_builder_mock_validate_and_release (struct x509_extension_builder_mock *mock);


#endif /* X509_EXTENSION_BUILDER_MOCK_H_ */
