// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dme/x509_extension_builder_dme.h"
#include "asn1/dme/x509_extension_builder_dme_static.h"
#include "testing/asn1/dme/dme_structure_testing.h"
#include "testing/asn1/dme/x509_extension_builder_dme_testing.h"


TEST_SUITE_LABEL ("x509_extension_builder_dme");


/**
 * Encoded OID for the DME extension.
 */
const uint8_t X509_EXTENSION_BUILDER_DME_TESTING_OID[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x03, 0x01
};

/**
 * Extension data for the DME extension with ECC384_PUBKEY and SHA384 signature.
 */
const uint8_t X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384[] = {
	0x30, 0x82, 0x01, 0x31, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
	0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xcf, 0x6b, 0x8d, 0x9a,
	0x48, 0x75, 0xa9, 0x5a, 0x19, 0x89, 0x72, 0x18, 0xa4, 0x94, 0x4d, 0xef, 0x0a, 0x93, 0xce, 0x5b,
	0x8b, 0x8d, 0xf1, 0x37, 0x54, 0x09, 0x17, 0x89, 0xbc, 0xef, 0x69, 0xdb, 0x6c, 0xa7, 0x9e, 0xf6,
	0xb6, 0x4b, 0x5c, 0x13, 0xed, 0x3c, 0xbf, 0xed, 0x0b, 0x3d, 0xf1, 0x7e, 0x53, 0xbf, 0xf4, 0x76,
	0x31, 0x31, 0x33, 0xa3, 0x58, 0x3c, 0x11, 0x3d, 0xeb, 0x8d, 0xb6, 0xb7, 0x47, 0x4a, 0xe3, 0x51,
	0xd0, 0x38, 0x26, 0xac, 0xec, 0x11, 0x34, 0x33, 0x04, 0x0d, 0xc6, 0xc3, 0x75, 0x37, 0xa1, 0x89,
	0xdd, 0x4f, 0x66, 0x57, 0x72, 0xac, 0xc5, 0x3b, 0xb6, 0xc6, 0xb8, 0x0c, 0x06, 0x0b, 0x2b, 0x06,
	0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x03, 0x02, 0x00, 0x04, 0x20, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x0a, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xcb,
	0x6c, 0x99, 0x54, 0xbe, 0x7a, 0xaf, 0xd9, 0x33, 0xea, 0x13, 0xef, 0xdb, 0x1e, 0x02, 0xd3, 0x66,
	0x3e, 0x11, 0xa7, 0x36, 0xeb, 0x3f, 0x58, 0xd4, 0xf8, 0xe1, 0xfd, 0x61, 0xea, 0xca, 0xa9, 0xb0,
	0xf7, 0x39, 0xa1, 0x9b, 0x00, 0x6e, 0xfc, 0xf0, 0xb9, 0xcc, 0xbc, 0x7d, 0xa4, 0x5a, 0xb7, 0x02,
	0x30, 0x63, 0x1b, 0x1d, 0x00, 0x1d, 0xf6, 0x8c, 0x7d, 0x1a, 0x65, 0x2b, 0xee, 0xda, 0xbd, 0x45,
	0xeb, 0x12, 0xf4, 0xa9, 0xba, 0xed, 0xc6, 0xc4, 0x58, 0x06, 0xf4, 0xa2, 0x00, 0x7c, 0x2a, 0x42,
	0x30, 0x81, 0x99, 0xee, 0x4c, 0xd3, 0x56, 0xb6, 0x26, 0xbf, 0x2f, 0xd0, 0x1d, 0xb5, 0x9a, 0x81,
	0xb8, 0x80, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x01, 0x0a, 0x01, 0x81, 0x05,
	0x00, 0x01, 0x23, 0x45, 0x67
};

const size_t X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN =
	sizeof (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384);

/**
 * Extension data for the DME extension with ECC384_PUBKEY and SHA384 signature.  There is no device
 * type OID.
 */
const uint8_t X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID[] = {
	0x30, 0x82, 0x01, 0x24, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
	0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xcf, 0x6b, 0x8d, 0x9a,
	0x48, 0x75, 0xa9, 0x5a, 0x19, 0x89, 0x72, 0x18, 0xa4, 0x94, 0x4d, 0xef, 0x0a, 0x93, 0xce, 0x5b,
	0x8b, 0x8d, 0xf1, 0x37, 0x54, 0x09, 0x17, 0x89, 0xbc, 0xef, 0x69, 0xdb, 0x6c, 0xa7, 0x9e, 0xf6,
	0xb6, 0x4b, 0x5c, 0x13, 0xed, 0x3c, 0xbf, 0xed, 0x0b, 0x3d, 0xf1, 0x7e, 0x53, 0xbf, 0xf4, 0x76,
	0x31, 0x31, 0x33, 0xa3, 0x58, 0x3c, 0x11, 0x3d, 0xeb, 0x8d, 0xb6, 0xb7, 0x47, 0x4a, 0xe3, 0x51,
	0xd0, 0x38, 0x26, 0xac, 0xec, 0x11, 0x34, 0x33, 0x04, 0x0d, 0xc6, 0xc3, 0x75, 0x37, 0xa1, 0x89,
	0xdd, 0x4f, 0x66, 0x57, 0x72, 0xac, 0xc5, 0x3b, 0xb6, 0xc6, 0xb8, 0x0c, 0x06, 0x0b, 0x2b, 0x06,
	0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x03, 0x02, 0x00, 0x04, 0x20, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x0a, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xcb,
	0x6c, 0x99, 0x54, 0xbe, 0x7a, 0xaf, 0xd9, 0x33, 0xea, 0x13, 0xef, 0xdb, 0x1e, 0x02, 0xd3, 0x66,
	0x3e, 0x11, 0xa7, 0x36, 0xeb, 0x3f, 0x58, 0xd4, 0xf8, 0xe1, 0xfd, 0x61, 0xea, 0xca, 0xa9, 0xb0,
	0xf7, 0x39, 0xa1, 0x9b, 0x00, 0x6e, 0xfc, 0xf0, 0xb9, 0xcc, 0xbc, 0x7d, 0xa4, 0x5a, 0xb7, 0x02,
	0x30, 0x63, 0x1b, 0x1d, 0x00, 0x1d, 0xf6, 0x8c, 0x7d, 0x1a, 0x65, 0x2b, 0xee, 0xda, 0xbd, 0x45,
	0xeb, 0x12, 0xf4, 0xa9, 0xba, 0xed, 0xc6, 0xc4, 0x58, 0x06, 0xf4, 0xa2, 0x00, 0x7c, 0x2a, 0x42,
	0x30, 0x81, 0x99, 0xee, 0x4c, 0xd3, 0x56, 0xb6, 0x26, 0xbf, 0x2f, 0xd0, 0x1d, 0xb5, 0x9a, 0x81,
	0xb8, 0x81, 0x05, 0x00, 0x01, 0x23, 0x45, 0x67
};

const size_t X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID_LEN =
	sizeof (X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID);

/**
 * Extension data for the DME extension with ECC384_PUBKEY and SHA384 signature.  There is no DME
 * renewal counter.
 */
const uint8_t X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL[] = {
	0x30, 0x82, 0x01, 0x2a, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
	0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xcf, 0x6b, 0x8d, 0x9a,
	0x48, 0x75, 0xa9, 0x5a, 0x19, 0x89, 0x72, 0x18, 0xa4, 0x94, 0x4d, 0xef, 0x0a, 0x93, 0xce, 0x5b,
	0x8b, 0x8d, 0xf1, 0x37, 0x54, 0x09, 0x17, 0x89, 0xbc, 0xef, 0x69, 0xdb, 0x6c, 0xa7, 0x9e, 0xf6,
	0xb6, 0x4b, 0x5c, 0x13, 0xed, 0x3c, 0xbf, 0xed, 0x0b, 0x3d, 0xf1, 0x7e, 0x53, 0xbf, 0xf4, 0x76,
	0x31, 0x31, 0x33, 0xa3, 0x58, 0x3c, 0x11, 0x3d, 0xeb, 0x8d, 0xb6, 0xb7, 0x47, 0x4a, 0xe3, 0x51,
	0xd0, 0x38, 0x26, 0xac, 0xec, 0x11, 0x34, 0x33, 0x04, 0x0d, 0xc6, 0xc3, 0x75, 0x37, 0xa1, 0x89,
	0xdd, 0x4f, 0x66, 0x57, 0x72, 0xac, 0xc5, 0x3b, 0xb6, 0xc6, 0xb8, 0x0c, 0x06, 0x0b, 0x2b, 0x06,
	0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x03, 0x02, 0x00, 0x04, 0x20, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x0a, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xcb,
	0x6c, 0x99, 0x54, 0xbe, 0x7a, 0xaf, 0xd9, 0x33, 0xea, 0x13, 0xef, 0xdb, 0x1e, 0x02, 0xd3, 0x66,
	0x3e, 0x11, 0xa7, 0x36, 0xeb, 0x3f, 0x58, 0xd4, 0xf8, 0xe1, 0xfd, 0x61, 0xea, 0xca, 0xa9, 0xb0,
	0xf7, 0x39, 0xa1, 0x9b, 0x00, 0x6e, 0xfc, 0xf0, 0xb9, 0xcc, 0xbc, 0x7d, 0xa4, 0x5a, 0xb7, 0x02,
	0x30, 0x63, 0x1b, 0x1d, 0x00, 0x1d, 0xf6, 0x8c, 0x7d, 0x1a, 0x65, 0x2b, 0xee, 0xda, 0xbd, 0x45,
	0xeb, 0x12, 0xf4, 0xa9, 0xba, 0xed, 0xc6, 0xc4, 0x58, 0x06, 0xf4, 0xa2, 0x00, 0x7c, 0x2a, 0x42,
	0x30, 0x81, 0x99, 0xee, 0x4c, 0xd3, 0x56, 0xb6, 0x26, 0xbf, 0x2f, 0xd0, 0x1d, 0xb5, 0x9a, 0x81,
	0xb8, 0x80, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x01, 0x0a, 0x01
};

const size_t X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL_LEN =
	sizeof (X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL);

/**
 * Extension data for the DME extension with ECC_PUBKEY and SHA256 signature.
 */
const uint8_t X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256[] = {
	0x30, 0x81, 0xf4, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xe3, 0x51,
	0xfa, 0x63, 0x3c, 0x37, 0xbe, 0xe6, 0xde, 0x7f, 0x65, 0x8e, 0xdd, 0xbd, 0xd6, 0xd5, 0x31, 0xef,
	0x9c, 0xd6, 0xb5, 0x14, 0xc2, 0x28, 0xb1, 0x08, 0x8b, 0x0b, 0xe4, 0x29, 0xc3, 0x03, 0x67, 0x0e,
	0x28, 0xc2, 0xb2, 0x8b, 0xd0, 0x9b, 0xc0, 0xe4, 0x33, 0xa6, 0x23, 0x5a, 0xa9, 0x7a, 0xeb, 0x3a,
	0x65, 0x15, 0x95, 0x08, 0xac, 0x7a, 0xde, 0x27, 0x36, 0x71, 0xe4, 0x4c, 0xde, 0x4e, 0x06, 0x0b,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x03, 0x02, 0x00, 0x04, 0x20, 0x10, 0x11, 0x12,
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
	0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x0a, 0x06,
	0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20,
	0x1e, 0x09, 0xe8, 0x51, 0xb9, 0x7d, 0xf6, 0xb0, 0x44, 0x63, 0x4f, 0x80, 0x03, 0x4f, 0x7c, 0xfe,
	0x79, 0x15, 0xfe, 0x1b, 0xcb, 0xa3, 0xb0, 0x12, 0x5e, 0x92, 0x98, 0x99, 0xa0, 0xda, 0x3f, 0x50,
	0x02, 0x21, 0x00, 0x84, 0x90, 0x4a, 0x5c, 0x5e, 0x48, 0x60, 0x4d, 0xa6, 0x4b, 0xc7, 0x46, 0xdc,
	0x7d, 0x56, 0x81, 0x01, 0x5d, 0x5c, 0xb4, 0x0a, 0x83, 0x09, 0xc7, 0xcf, 0x4d, 0x04, 0x52, 0x96,
	0x41, 0x2c, 0x2e, 0x80, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x01, 0x0a, 0x01,
	0x81, 0x05, 0x00, 0x01, 0x23, 0x45, 0x67
};

const size_t X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256_LEN =
	sizeof (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256);


/**
 * Extension output structure for the DME extension using
 * X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DME_TESTING_EXTENSION_ECC384_SHA384 = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DME_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384,
	.data_length = X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN
};

/**
 * Extension output structure for the DME extension using
 * X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DME_TESTING_EXTENSION_NO_DEVICE_OID = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DME_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID,
	.data_length = X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID_LEN
};

/**
 * Extension output structure for the DME extension using
 * X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DME_TESTING_EXTENSION_NO_RENEWAL = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DME_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL,
	.data_length = X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL_LEN
};

/**
 * Extension output structure for the DME extension using
 * X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DME_TESTING_EXTENSION_ECC256_SHA256 = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DME_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256,
	.data_length = X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256_LEN
};


/**
 * Length of the static buffer to use for testing.
 */
#define	X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH(type)      \
	(X509_EXTENSION_BUILDER_DME_TESTING_DATA_ ## type ## _LEN + 32)


/*******************
 * Test cases
 *******************/

static void x509_extension_builder_dme_test_init (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;

	TEST_START;

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_init_null (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;

	TEST_START;

	status = x509_extension_builder_dme_init (NULL, &dme);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_dme_init (&builder, NULL);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_dme_test_init_with_buffer (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384)];
	int status;

	TEST_START;

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_init_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384)];
	int status;

	TEST_START;

	status = x509_extension_builder_dme_init_with_buffer (NULL, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_dme_init_with_buffer (&builder, NULL, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, NULL,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_dme_test_static_init (CuTest *test)
{
	struct dme_structure dme;
	struct x509_extension_builder_dme builder = x509_extension_builder_dme_static_init (&dme);

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_static_init_with_buffer (CuTest *test)
{
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384)];
	struct x509_extension_builder_dme builder =
		x509_extension_builder_dme_static_init_with_buffer (&dme, ext_buffer, sizeof (ext_buffer));

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_ecc256_sha256 (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc256_sha256 (&dme);

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_no_device_oid (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_no_device_oid (&dme);

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_no_renewal_counter (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_no_renewal (&dme);

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_static_init (CuTest *test)
{
	struct dme_structure dme;
	struct x509_extension_builder_dme builder = x509_extension_builder_dme_static_init (&dme);
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_null (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_static_init_null_dme_structure (CuTest *test)
{
	struct x509_extension_builder_dme builder = x509_extension_builder_dme_static_init (NULL);
	int status;
	struct x509_extension extension;

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_no_structure_type_oid (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.data_oid = NULL;

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_TYPE_OID, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_no_structure_data (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.data = NULL;

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_DATA, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_no_signature_type_oid (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.sig_oid = NULL;

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_SIG_TYPE_OID, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_no_signature (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.signature = NULL;

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_SIGNATURE, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_no_dme_key (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.dme_pub_key = NULL;

	status = x509_extension_builder_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_DME_KEY, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384)];
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_ecc256_sha256 (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC256_SHA256)];
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc256_sha256 (&dme);

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_no_device_oid (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (NO_DEVICE_OID)];
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_no_device_oid (&dme);

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_no_renewal_counter (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (NO_RENEWAL)];
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_no_renewal (&dme);

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_extra_space (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384) + 32];
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_static_init (CuTest *test)
{
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384)];
	struct x509_extension_builder_dme builder =
		x509_extension_builder_dme_static_init_with_buffer (&dme, ext_buffer, sizeof (ext_buffer));
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_dme builder;
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384)];
	int status;
	struct x509_extension extension;

	TEST_START;

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_static_init_null_buffer (
	CuTest *test)
{
	struct dme_structure dme;
	struct x509_extension_builder_dme builder =
		x509_extension_builder_dme_static_init_with_buffer (&dme, NULL,
		X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384));
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_static_init_null_dme_structure (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_BUFFER_LENGTH (ECC384_SHA384)];
	struct x509_extension_builder_dme builder =
		x509_extension_builder_dme_static_init_with_buffer (NULL, ext_buffer, sizeof (ext_buffer));
	int status;
	struct x509_extension extension;

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_build_with_buffer_small_buffer (CuTest *test)
{
	struct dme_structure dme;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN - 1];
	struct x509_extension_builder_dme builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = x509_extension_builder_dme_init_with_buffer (&builder, &dme, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_dme_release (&builder);
}

static void x509_extension_builder_dme_test_get_ext_buffer_length (CuTest *test)
{
	struct dme_structure dme;
	size_t length;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	length = x509_extension_builder_dme_get_ext_buffer_length (&dme);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC384_SHA384_LEN));
}

static void x509_extension_builder_dme_test_get_ext_buffer_length_ecc256_sha256 (CuTest *test)
{
	struct dme_structure dme;
	size_t length;

	TEST_START;

	dme_structure_testing_structure_ecc256_sha256 (&dme);

	length = x509_extension_builder_dme_get_ext_buffer_length (&dme);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DME_TESTING_DATA_ECC256_SHA256_LEN));
}

static void x509_extension_builder_dme_test_get_ext_buffer_length_no_device_oid (CuTest *test)
{
	struct dme_structure dme;
	size_t length;

	TEST_START;

	dme_structure_testing_structure_no_device_oid (&dme);

	length = x509_extension_builder_dme_get_ext_buffer_length (&dme);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_DEVICE_OID_LEN));
}

static void x509_extension_builder_dme_test_get_ext_buffer_length_no_renewal_counter (CuTest *test)
{
	struct dme_structure dme;
	size_t length;

	TEST_START;

	dme_structure_testing_structure_no_renewal (&dme);

	length = x509_extension_builder_dme_get_ext_buffer_length (&dme);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DME_TESTING_DATA_NO_RENEWAL_LEN));
}

static void x509_extension_builder_dme_test_get_ext_buffer_length_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = x509_extension_builder_dme_get_ext_buffer_length (NULL);
	CuAssertIntEquals (test, 4, length);
}


// *INDENT-OFF*
TEST_SUITE_START (x509_extension_builder_dme);

TEST (x509_extension_builder_dme_test_init);
TEST (x509_extension_builder_dme_test_init_null);
TEST (x509_extension_builder_dme_test_init_with_buffer);
TEST (x509_extension_builder_dme_test_init_with_buffer_null);
TEST (x509_extension_builder_dme_test_static_init);
TEST (x509_extension_builder_dme_test_static_init_with_buffer);
TEST (x509_extension_builder_dme_test_build);
TEST (x509_extension_builder_dme_test_build_ecc256_sha256);
TEST (x509_extension_builder_dme_test_build_no_device_oid);
TEST (x509_extension_builder_dme_test_build_no_renewal_counter);
TEST (x509_extension_builder_dme_test_build_static_init);
TEST (x509_extension_builder_dme_test_build_null);
TEST (x509_extension_builder_dme_test_build_static_init_null_dme_structure);
TEST (x509_extension_builder_dme_test_build_no_structure_type_oid);
TEST (x509_extension_builder_dme_test_build_no_structure_data);
TEST (x509_extension_builder_dme_test_build_no_signature_type_oid);
TEST (x509_extension_builder_dme_test_build_no_signature);
TEST (x509_extension_builder_dme_test_build_no_dme_key);
TEST (x509_extension_builder_dme_test_build_with_buffer);
TEST (x509_extension_builder_dme_test_build_with_buffer_ecc256_sha256);
TEST (x509_extension_builder_dme_test_build_with_buffer_no_device_oid);
TEST (x509_extension_builder_dme_test_build_with_buffer_no_renewal_counter);
TEST (x509_extension_builder_dme_test_build_with_buffer_extra_space);
TEST (x509_extension_builder_dme_test_build_with_buffer_static_init);
TEST (x509_extension_builder_dme_test_build_with_buffer_null);
TEST (x509_extension_builder_dme_test_build_with_buffer_static_init_null_buffer);
TEST (x509_extension_builder_dme_test_build_with_buffer_static_init_null_dme_structure);
TEST (x509_extension_builder_dme_test_build_with_buffer_small_buffer);
TEST (x509_extension_builder_dme_test_get_ext_buffer_length);
TEST (x509_extension_builder_dme_test_get_ext_buffer_length_ecc256_sha256);
TEST (x509_extension_builder_dme_test_get_ext_buffer_length_no_device_oid);
TEST (x509_extension_builder_dme_test_get_ext_buffer_length_no_renewal_counter);
TEST (x509_extension_builder_dme_test_get_ext_buffer_length_null);

TEST_SUITE_END;
// *INDENT-ON*
