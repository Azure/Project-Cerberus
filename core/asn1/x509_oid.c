// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "x509_oid.h"


/**
 * The encoded OID for the X.509 Extended Key Usage extension:  2.5.29.37
 */
const uint8_t X509_OID_EKU_EXTENSION[] = {
	0x55, 0x1d, 0x25
};

/**
 * The encoded OID for X.509 TLS WWW client authentication extended key usage:  1.3.6.1.5.5.7.3.2
 */
const uint8_t X509_OID_CLIENT_AUTH[] = {
	0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02
};
