// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CERTIFICATE_H_
#define CERTIFICATE_H_

#include <stdint.h>


/**
 * Certificate Container
 */
struct der_cert {
	const uint8_t *cert;			/**< The DER formatted certificate. */
	size_t length;					/**< The length of the certificate DER. */
};


#endif // CERTIFICATE_H_
