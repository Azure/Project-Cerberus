// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "asn1_oid.h"


/**
 * AlgorithmIdentifier OID for an ECDSA signature using SHA2-256.
 *
 * 1.2.840.10045.4.3.2
 */
const uint8_t ASN1_OID_ECDSA_WITH_SHA256[] = {
	0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02
};

/**
 * Length of the ecdsa-with-SHA256 OID.
 */
const size_t ASN1_OID_ECDSA_WITH_SHA256_LENGTH = sizeof (ASN1_OID_ECDSA_WITH_SHA256);

/**
 * AlgorithmIdentifier OID for an ECDSA signature using SHA2-384.
 *
 * 1.2.840.10045.4.3.3
 */
const uint8_t ASN1_OID_ECDSA_WITH_SHA384[] = {
	0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03
};

/**
 * Length of the ecdsa-with-SHA384 OID.
 */
const size_t ASN1_OID_ECDSA_WITH_SHA384_LENGTH = sizeof (ASN1_OID_ECDSA_WITH_SHA384);

/**
 * AlgorithmIdentifier OID for an ECDSA signature using SHA2-512.
 *
 * 1.2.840.10045.4.3.4
 */
const uint8_t ASN1_OID_ECDSA_WITH_SHA512[] = {
	0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04
};

/**
 * Length of the ecdsa-with-SHA512 OID.
 */
const size_t ASN1_OID_ECDSA_WITH_SHA512_LENGTH = sizeof (ASN1_OID_ECDSA_WITH_SHA512);
