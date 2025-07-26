// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dice/x509_extension_builder_dice_tcbinfo.h"
#include "asn1/dice/x509_extension_builder_dice_tcbinfo_static.h"
#include "common/array_size.h"
#include "testing/asn1/dice/x509_extension_builder_dice_tcbinfo_testing.h"
#include "testing/asn1/x509_testing.h"


TEST_SUITE_LABEL ("x509_extension_builder_dice_tcbinfo");


/**
 * Encoded OID for the TCG DICE TcbInfo extension.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x01
};

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA1_FWID, X509_RIOT_VERSION,
 * and X509_RIOT_SVN for layer 0.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1[] = {
	0x30, 0x33, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34, 0x56,
	0x78, 0x84, 0x01, 0x00, 0xa6, 0x1f, 0x30, 0x1d, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04,
	0x14, 0xfc, 0x3d, 0x91, 0xe6, 0xc1, 0x13, 0xd6, 0x82, 0x18, 0x33, 0xf6, 0x5b, 0x12, 0xc7, 0xe7,
	0x6e, 0x7f, 0x38, 0x9c, 0x4f
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA256_FWID, X509_RIOT_VERSION,
 * and X509_RIOT_SVN for layer 0.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256[] = {
	0x30, 0x43, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34, 0x56,
	0x78, 0x84, 0x01, 0x00, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x01, 0x04, 0x20, 0x88, 0x69, 0xde, 0x57, 0x9d, 0xd0, 0xe9, 0x05, 0xe0, 0xa7, 0x11,
	0x24, 0x57, 0x55, 0x94, 0xf5, 0x0a, 0x03, 0xd3, 0xd9, 0xcd, 0xf1, 0x6e, 0x9a, 0x3f, 0x9d, 0x6c,
	0x60, 0xc0, 0x32, 0x4b, 0x54
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA384_FWID, X509_RIOT_VERSION,
 * and X509_RIOT_SVN for layer 0.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384[] = {
	0x30, 0x53, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34, 0x56,
	0x78, 0x84, 0x01, 0x00, 0xa6, 0x3f, 0x30, 0x3d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x02, 0x04, 0x30, 0xd3, 0x31, 0xf1, 0x53, 0x07, 0x7e, 0xfb, 0xad, 0x73, 0x8e, 0xea,
	0x4f, 0x3e, 0x0c, 0x5d, 0x3f, 0x6b, 0x60, 0x4d, 0x7b, 0x32, 0xb6, 0xa2, 0xe8, 0xb0, 0xeb, 0x4e,
	0x4e, 0x7f, 0xc9, 0x52, 0x7b, 0xc6, 0x04, 0x44, 0xf2, 0x04, 0x7e, 0xac, 0xc1, 0xec, 0x88, 0x0b,
	0xff, 0xd0, 0xb1, 0xc1, 0xf2
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA512_FWID, X509_RIOT_VERSION,
 * and X509_RIOT_SVN for layer 0.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512[] = {
	0x30, 0x63, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34, 0x56,
	0x78, 0x84, 0x01, 0x00, 0xa6, 0x4f, 0x30, 0x4d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x03, 0x04, 0x40, 0x39, 0xb8, 0x29, 0x9b, 0x43, 0x30, 0xcb, 0x1e, 0x8b, 0x51, 0xfa,
	0xcb, 0x76, 0x79, 0xaf, 0x47, 0xea, 0x35, 0xbf, 0xea, 0xb9, 0x1b, 0x34, 0xd0, 0x9e, 0x0a, 0xac,
	0xc9, 0xde, 0x64, 0x80, 0x60, 0x29, 0x8d, 0x86, 0xd5, 0x47, 0x9d, 0x4e, 0xb5, 0x68, 0xdf, 0xe0,
	0xea, 0xb6, 0x2c, 0x0e, 0x4a, 0x47, 0x90, 0x7e, 0x28, 0x09, 0xb8, 0x4b, 0x21, 0xdd, 0x6b, 0xc7,
	0x41, 0xca, 0x09, 0x00, 0x3a
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_VERSION and X509_RIOT_SVN for
 * layer 0.  The FWID list contains each of the FWIDs:  X509_RIOT_SHA256_FWID, X509_RIOT_SHA1_FWID,
 * X509_RIOT_SHA512_FWID, and X509_RIOT_SHA384_FWID.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS[] = {
	0x30, 0x81, 0xf1, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34,
	0x56, 0x78, 0x84, 0x01, 0x00, 0xa6, 0x81, 0xdc, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20, 0x88, 0x69, 0xde, 0x57, 0x9d, 0xd0, 0xe9, 0x05, 0xe0,
	0xa7, 0x11, 0x24, 0x57, 0x55, 0x94, 0xf5, 0x0a, 0x03, 0xd3, 0xd9, 0xcd, 0xf1, 0x6e, 0x9a, 0x3f,
	0x9d, 0x6c, 0x60, 0xc0, 0x32, 0x4b, 0x54, 0x30, 0x1d, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
	0x04, 0x14, 0xfc, 0x3d, 0x91, 0xe6, 0xc1, 0x13, 0xd6, 0x82, 0x18, 0x33, 0xf6, 0x5b, 0x12, 0xc7,
	0xe7, 0x6e, 0x7f, 0x38, 0x9c, 0x4f, 0x30, 0x4d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x03, 0x04, 0x40, 0x39, 0xb8, 0x29, 0x9b, 0x43, 0x30, 0xcb, 0x1e, 0x8b, 0x51, 0xfa,
	0xcb, 0x76, 0x79, 0xaf, 0x47, 0xea, 0x35, 0xbf, 0xea, 0xb9, 0x1b, 0x34, 0xd0, 0x9e, 0x0a, 0xac,
	0xc9, 0xde, 0x64, 0x80, 0x60, 0x29, 0x8d, 0x86, 0xd5, 0x47, 0x9d, 0x4e, 0xb5, 0x68, 0xdf, 0xe0,
	0xea, 0xb6, 0x2c, 0x0e, 0x4a, 0x47, 0x90, 0x7e, 0x28, 0x09, 0xb8, 0x4b, 0x21, 0xdd, 0x6b, 0xc7,
	0x41, 0xca, 0x09, 0x00, 0x3a, 0x30, 0x3d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	0x02, 0x02, 0x04, 0x30, 0xd3, 0x31, 0xf1, 0x53, 0x07, 0x7e, 0xfb, 0xad, 0x73, 0x8e, 0xea, 0x4f,
	0x3e, 0x0c, 0x5d, 0x3f, 0x6b, 0x60, 0x4d, 0x7b, 0x32, 0xb6, 0xa2, 0xe8, 0xb0, 0xeb, 0x4e, 0x4e,
	0x7f, 0xc9, 0x52, 0x7b, 0xc6, 0x04, 0x44, 0xf2, 0x04, 0x7e, 0xac, 0xc1, 0xec, 0x88, 0x0b, 0xff,
	0xd0, 0xb1, 0xc1, 0xf2
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA256_FWID, X509_RIOT_VERSION,
 * and SVN of 0 for layer 0.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO[] = {
	0x30, 0x40, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x01, 0x00, 0x84, 0x01,
	0x00, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x04, 0x20, 0x88, 0x69, 0xde, 0x57, 0x9d, 0xd0, 0xe9, 0x05, 0xe0, 0xa7, 0x11, 0x24, 0x57, 0x55,
	0x94, 0xf5, 0x0a, 0x03, 0xd3, 0xd9, 0xcd, 0xf1, 0x6e, 0x9a, 0x3f, 0x9d, 0x6c, 0x60, 0xc0, 0x32,
	0x4b, 0x54
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA256_FWID, X509_RIOT_VERSION,
 * and X509_RIOT_SVN for layer 1.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1[] = {
	0x30, 0x43, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34, 0x56,
	0x78, 0x84, 0x01, 0x01, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x01, 0x04, 0x20, 0x88, 0x69, 0xde, 0x57, 0x9d, 0xd0, 0xe9, 0x05, 0xe0, 0xa7, 0x11,
	0x24, 0x57, 0x55, 0x94, 0xf5, 0x0a, 0x03, 0xd3, 0xd9, 0xcd, 0xf1, 0x6e, 0x9a, 0x3f, 0x9d, 0x6c,
	0x60, 0xc0, 0x32, 0x4b, 0x54
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA256_FWID, X509_RIOT_VERSION,
 * and X509_RIOT_SVN for layer 1000.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000[] = {
	0x30, 0x44, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34, 0x56,
	0x78, 0x84, 0x02, 0x03, 0xe8, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x01, 0x04, 0x20, 0x88, 0x69, 0xde, 0x57, 0x9d, 0xd0, 0xe9, 0x05, 0xe0, 0xa7,
	0x11, 0x24, 0x57, 0x55, 0x94, 0xf5, 0x0a, 0x03, 0xd3, 0xd9, 0xcd, 0xf1, 0x6e, 0x9a, 0x3f, 0x9d,
	0x6c, 0x60, 0xc0, 0x32, 0x4b, 0x54
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA256_FWID, X509_RIOT_VERSION,
 * and X509_RIOT_SVN for layer 0.  The optional vendor field uses
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR[] = {
	0x30, 0x4b, 0x80, 0x06, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e,
	0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34, 0x56, 0x78, 0x84, 0x01, 0x00, 0xa6, 0x2f, 0x30, 0x2d,
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20, 0x88, 0x69, 0xde,
	0x57, 0x9d, 0xd0, 0xe9, 0x05, 0xe0, 0xa7, 0x11, 0x24, 0x57, 0x55, 0x94, 0xf5, 0x0a, 0x03, 0xd3,
	0xd9, 0xcd, 0xf1, 0x6e, 0x9a, 0x3f, 0x9d, 0x6c, 0x60, 0xc0, 0x32, 0x4b, 0x54
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR);

/**
 * Extension data for the TCG DICE TcbInfo extension using X509_RIOT_SHA256_FWID, X509_RIOT_VERSION,
 * and X509_RIOT_SVN for layer 0.  The optional model field uses
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR.
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL[] = {
	0x30, 0x4a, 0x81, 0x05, 0x4d, 0x6f, 0x64, 0x65, 0x6c, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33,
	0x2e, 0x34, 0x83, 0x04, 0x12, 0x34, 0x56, 0x78, 0x84, 0x01, 0x00, 0xa6, 0x2f, 0x30, 0x2d, 0x06,
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20, 0x88, 0x69, 0xde, 0x57,
	0x9d, 0xd0, 0xe9, 0x05, 0xe0, 0xa7, 0x11, 0x24, 0x57, 0x55, 0x94, 0xf5, 0x0a, 0x03, 0xd3, 0xd9,
	0xcd, 0xf1, 0x6e, 0x9a, 0x3f, 0x9d, 0x6c, 0x60, 0xc0, 0x32, 0x4b, 0x54
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL);

/**
 * Extension data for the TCG DICE TcbInfo extension with all possible data populated.  This uses
 * - X509_RIOT_VERSION
 * - X509_RIOT_SVN
 * - Layer 3
 * - The FWID list contains each of the FWIDs:  X509_RIOT_SHA256_FWID, X509_RIOT_SHA1_FWID,
 * X509_RIOT_SHA512_FWID, and X509_RIOT_SHA384_FWID.
 * - X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR
 * - X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL[] = {
	0x30, 0x82, 0x01, 0x00, 0x80, 0x06, 0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x81, 0x05, 0x4d, 0x6f,
	0x64, 0x65, 0x6c, 0x82, 0x07, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x83, 0x04, 0x12, 0x34,
	0x56, 0x78, 0x84, 0x01, 0x03, 0xa6, 0x81, 0xdc, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20, 0x88, 0x69, 0xde, 0x57, 0x9d, 0xd0, 0xe9, 0x05, 0xe0,
	0xa7, 0x11, 0x24, 0x57, 0x55, 0x94, 0xf5, 0x0a, 0x03, 0xd3, 0xd9, 0xcd, 0xf1, 0x6e, 0x9a, 0x3f,
	0x9d, 0x6c, 0x60, 0xc0, 0x32, 0x4b, 0x54, 0x30, 0x1d, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
	0x04, 0x14, 0xfc, 0x3d, 0x91, 0xe6, 0xc1, 0x13, 0xd6, 0x82, 0x18, 0x33, 0xf6, 0x5b, 0x12, 0xc7,
	0xe7, 0x6e, 0x7f, 0x38, 0x9c, 0x4f, 0x30, 0x4d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x03, 0x04, 0x40, 0x39, 0xb8, 0x29, 0x9b, 0x43, 0x30, 0xcb, 0x1e, 0x8b, 0x51, 0xfa,
	0xcb, 0x76, 0x79, 0xaf, 0x47, 0xea, 0x35, 0xbf, 0xea, 0xb9, 0x1b, 0x34, 0xd0, 0x9e, 0x0a, 0xac,
	0xc9, 0xde, 0x64, 0x80, 0x60, 0x29, 0x8d, 0x86, 0xd5, 0x47, 0x9d, 0x4e, 0xb5, 0x68, 0xdf, 0xe0,
	0xea, 0xb6, 0x2c, 0x0e, 0x4a, 0x47, 0x90, 0x7e, 0x28, 0x09, 0xb8, 0x4b, 0x21, 0xdd, 0x6b, 0xc7,
	0x41, 0xca, 0x09, 0x00, 0x3a, 0x30, 0x3d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	0x02, 0x02, 0x04, 0x30, 0xd3, 0x31, 0xf1, 0x53, 0x07, 0x7e, 0xfb, 0xad, 0x73, 0x8e, 0xea, 0x4f,
	0x3e, 0x0c, 0x5d, 0x3f, 0x6b, 0x60, 0x4d, 0x7b, 0x32, 0xb6, 0xa2, 0xe8, 0xb0, 0xeb, 0x4e, 0x4e,
	0x7f, 0xc9, 0x52, 0x7b, 0xc6, 0x04, 0x44, 0xf2, 0x04, 0x7e, 0xac, 0xc1, 0xec, 0x88, 0x0b, 0xff,
	0xd0, 0xb1, 0xc1, 0xf2
};

const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL_LEN =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL);


/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA1 = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256 = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384 = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512 = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_MULTIPLE_FWIDS = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SVN_ZERO = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_LAYER_1 = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_LAYER_1000 = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_VERDOR = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_MODEL = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL_LEN
};

/**
 * Extension output structure for the TCG DICE TcbInfo extension using
 * X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL.
 */
const struct x509_extension X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_FULL = {
	.critical = false,
	.oid = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID,
	.oid_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
	.data = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL,
	.data_length = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL_LEN
};


/**
 * Length of the static buffer to use for testing.
 */
#define	X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH(type) \
	((X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_ ## type ## _LEN) + 32)


/*******************
 * Test cases
 *******************/

static void x509_extension_builder_dice_tcbinfo_test_init (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_init_null (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (NULL, &tcb);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, NULL);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_dice_tcbinfo_test_init_with_buffer (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_init_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (NULL, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, NULL, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, NULL,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_dice_tcbinfo_test_static_init (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct x509_extension_builder_dice_tcbinfo builder =
		x509_extension_builder_dice_tcbinfo_static_init (&tcb);

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_static_init_with_buffer (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	struct x509_extension_builder_dice_tcbinfo builder =
		x509_extension_builder_dice_tcbinfo_static_init_with_buffer (&tcb, ext_buffer,
		sizeof (ext_buffer));

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_release_null (CuTest *test)
{
	TEST_START;

	x509_extension_builder_dice_tcbinfo_release (NULL);
}

static void x509_extension_builder_dice_tcbinfo_test_build (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_sha1 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_sha384 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_sha512 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_multiple_fwids (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		},
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		},
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status =
		testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_svn_zero (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t zero = 0;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = &zero;
	tcb.svn_length = 1;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_layer_1 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 1;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_layer_1000 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 1000;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_vendor (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_model (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_full (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		},
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		},
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR;
	tcb.model = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 3;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_static_init (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct x509_extension_builder_dice_tcbinfo builder =
		x509_extension_builder_dice_tcbinfo_static_init (&tcb);
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_null (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_static_init_null_tcb (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder =
		x509_extension_builder_dice_tcbinfo_static_init (NULL);
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_unknown_fwid (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = (enum hash_type) 10
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_UNKNOWN_FWID, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_no_fwid_digest (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = NULL,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_FWID, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_no_fwid_list (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = NULL;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_FWID_LIST, status);

	tcb.fwid_list = fwid_list;
	tcb.fwid_count = 0;

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_FWID_LIST, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_no_version (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = NULL;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_VERSION, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_no_svn (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	/* SVN null */
	tcb.svn = NULL;
	tcb.svn_length = X509_RIOT_SVN_LEN;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_SVN, status);

	/* SVN zero length */
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = 0;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_SVN, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_free_null (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (NULL, &extension);
	builder.base.free (&builder.base, NULL);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_sha1 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA1)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_sha384 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA384)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_sha512 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA512)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_multiple_fwids (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		},
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		},
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (MULTIPLE_FWIDS)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status =
		testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_svn_zero (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t zero = 0;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SVN_ZERO)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = &zero;
	tcb.svn_length = 1;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_layer_1 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (LAYER_1)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 1;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_layer_1000 (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (LAYER_1000)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 1000;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_vendor (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (VENDOR)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_model (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (MODEL)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_full (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		},
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		},
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (FULL)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR;
	tcb.model = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 3;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_extra_space (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256) + 32];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_static_init (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	struct x509_extension_builder_dice_tcbinfo builder =
		x509_extension_builder_dice_tcbinfo_static_init_with_buffer (&tcb, ext_buffer,
		sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_static_init_null_buffer (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct x509_extension_builder_dice_tcbinfo builder =
		x509_extension_builder_dice_tcbinfo_static_init_with_buffer (&tcb, NULL,
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_static_init_null_tcb (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	struct x509_extension_builder_dice_tcbinfo builder =
		x509_extension_builder_dice_tcbinfo_static_init_with_buffer (NULL, ext_buffer,
		sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_build_with_buffer_small_buffer (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN - 1];
	struct x509_extension_builder_dice_tcbinfo builder;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_free_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	status = x509_extension_builder_dice_tcbinfo_init_with_buffer (&builder, &tcb, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	builder.base.free (NULL, &extension);
	builder.base.free (&builder.base, NULL);

	x509_extension_builder_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_sha1 (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA1_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_sha384 (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA384_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_sha512 (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA512_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_multiple_fwids (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		},
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		},
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test,
		(length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_FWIDS_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_svn_zero (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t zero = 0;
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = &zero;
	tcb.svn_length = 1;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SVN_ZERO_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_layer_1 (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 1;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_layer_1000 (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 1000;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test,
		(length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_LAYER_1000_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_vendor (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_VENDOR_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_model (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MODEL_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_full (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		},
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		},
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	size_t length;

	TEST_START;

	tcb.vendor = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR;
	tcb.model = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 3;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_FULL_LEN));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_version_null (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	size_t length;
	size_t min_length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = NULL;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);

	min_length = (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN -
		sizeof (X509_RIOT_VERSION) + 2);

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= min_length));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_fwid_list_null (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	size_t length;
	size_t min_length;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = NULL;
	tcb.fwid_count = 0;

	min_length = (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN -
		(SHA256_HASH_LENGTH + 2 + 9 + 2 + 2 + 2));

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (&tcb);
	CuAssertTrue (test, (length >= min_length));
}

static void x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (NULL);
	CuAssertIntEquals (test, 4, length);
}


// *INDENT-OFF*
TEST_SUITE_START (x509_extension_builder_dice_tcbinfo);

TEST (x509_extension_builder_dice_tcbinfo_test_init);
TEST (x509_extension_builder_dice_tcbinfo_test_init_null);
TEST (x509_extension_builder_dice_tcbinfo_test_init_with_buffer);
TEST (x509_extension_builder_dice_tcbinfo_test_init_with_buffer_null);
TEST (x509_extension_builder_dice_tcbinfo_test_static_init);
TEST (x509_extension_builder_dice_tcbinfo_test_static_init_with_buffer);
TEST (x509_extension_builder_dice_tcbinfo_test_release_null);
TEST (x509_extension_builder_dice_tcbinfo_test_build);
TEST (x509_extension_builder_dice_tcbinfo_test_build_sha1);
TEST (x509_extension_builder_dice_tcbinfo_test_build_sha384);
TEST (x509_extension_builder_dice_tcbinfo_test_build_sha512);
TEST (x509_extension_builder_dice_tcbinfo_test_build_multiple_fwids);
TEST (x509_extension_builder_dice_tcbinfo_test_build_svn_zero);
TEST (x509_extension_builder_dice_tcbinfo_test_build_layer_1);
TEST (x509_extension_builder_dice_tcbinfo_test_build_layer_1000);
TEST (x509_extension_builder_dice_tcbinfo_test_build_vendor);
TEST (x509_extension_builder_dice_tcbinfo_test_build_model);
TEST (x509_extension_builder_dice_tcbinfo_test_build_full);
TEST (x509_extension_builder_dice_tcbinfo_test_build_static_init);
TEST (x509_extension_builder_dice_tcbinfo_test_build_null);
TEST (x509_extension_builder_dice_tcbinfo_test_build_static_init_null_tcb);
TEST (x509_extension_builder_dice_tcbinfo_test_build_unknown_fwid);
TEST (x509_extension_builder_dice_tcbinfo_test_build_no_fwid_digest);
TEST (x509_extension_builder_dice_tcbinfo_test_build_no_fwid_list);
TEST (x509_extension_builder_dice_tcbinfo_test_build_no_version);
TEST (x509_extension_builder_dice_tcbinfo_test_build_no_svn);
TEST (x509_extension_builder_dice_tcbinfo_test_free_null);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_sha1);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_sha384);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_sha512);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_multiple_fwids);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_svn_zero);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_layer_1);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_layer_1000);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_vendor);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_model);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_full);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_extra_space);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_static_init);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_null);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_static_init_null_buffer);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_static_init_null_tcb);
TEST (x509_extension_builder_dice_tcbinfo_test_build_with_buffer_small_buffer);
TEST (x509_extension_builder_dice_tcbinfo_test_free_with_buffer_null);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_sha1);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_sha384);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_sha512);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_multiple_fwids);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_svn_zero);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_layer_1);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_layer_1000);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_vendor);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_model);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_full);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_version_null);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_fwid_list_null);
TEST (x509_extension_builder_dice_tcbinfo_test_get_ext_buffer_length_null);

TEST_SUITE_END;
// *INDENT-ON*
