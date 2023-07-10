// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dice/x509_extension_builder_dice_tcbinfo.h"
#include "asn1/dice/x509_extension_builder_mbedtls_dice_tcbinfo.h"
#include "asn1/dice/x509_extension_builder_mbedtls_dice_tcbinfo_static.h"
#include "testing/asn1/dice/x509_extension_builder_dice_tcbinfo_testing.h"
#include "testing/crypto/x509_testing.h"


TEST_SUITE_LABEL ("x509_extension_builder_mbedtls_dice_tcbinfo");


/**
 * Length of the static buffer to use for testing.
 */
#define	X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH(type) \
	(X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_ ## type ## _LEN)


/*******************
 * Test cases
 *******************/

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_init (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_init_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (NULL, &tcb);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, NULL);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_init_with_buffer (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_init_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (NULL, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, NULL,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		NULL, sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_static_init (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder =
		x509_extension_builder_mbedtls_dice_tcbinfo_static_init (&tcb);

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_static_init_with_buffer (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder =
		x509_extension_builder_mbedtls_dice_tcbinfo_static_init_with_buffer (&tcb, ext_buffer,
			sizeof (ext_buffer));

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_sha1 (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA1_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA1;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_sha384 (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA384_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA384;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_sha512 (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA512_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA512;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_svn_zero (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = 0;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_static_init (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder =
		x509_extension_builder_mbedtls_dice_tcbinfo_static_init (&tcb);
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_static_init_null_tcb (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder =
		x509_extension_builder_mbedtls_dice_tcbinfo_static_init (NULL);
	int status;
	struct x509_extension extension;

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_unknown_fwid (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = (enum hash_type) 10;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_UNKNOWN_FWID, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_no_fwid (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = NULL;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_FWID, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_no_version (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = NULL;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_VERSION, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_sha1 (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA1)];
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA1_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA1;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_sha384 (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA384)];
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA384_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA384;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_sha512 (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA512)];
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA512_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA512;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_svn_zero (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[
		X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SVN_ZERO)];
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = 0;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_extra_space (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[
		X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256) + 32];
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_static_init (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder =
		x509_extension_builder_mbedtls_dice_tcbinfo_static_init_with_buffer (&tcb, ext_buffer,
			sizeof (ext_buffer));
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

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

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	int status;
	struct x509_extension extension;

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_static_init_null_buffer (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder =
		x509_extension_builder_mbedtls_dice_tcbinfo_static_init_with_buffer (&tcb, NULL,
			X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256));
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_static_init_null_tcb (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_TESTING_BUFFER_LENGTH (SHA256)];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder =
		x509_extension_builder_mbedtls_dice_tcbinfo_static_init_with_buffer (NULL, ext_buffer,
			sizeof (ext_buffer));
	int status;
	struct x509_extension extension;

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH - 1];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_len (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_tag (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH + 1];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_oid (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH + 2 +
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_FWID_OID_LEN - 1];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_sequence_len (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH + 2 +
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_FWID_OID_LEN + 2 - 2];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_sequence_tag (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH + 2 +
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_FWID_OID_LEN + 2 - 1];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_list_len (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH + 2 +
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_FWID_OID_LEN + 2 + 2 - 2];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_list_tag (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH + 2 +
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_FWID_OID_LEN + 2 + 2 - 1];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_svn (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH + 2 +
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_FWID_OID_LEN + 2 + 2 + 6 - 1];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_version (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[SHA256_HASH_LENGTH + 2 +
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_FWID_OID_LEN + 2 + 2 + 6 + 7 + 2 - 1];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_ext_sequence_len (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN - 2];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_ext_sequence_tag (
	CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_SHA256_LEN - 1];
	struct x509_extension_builder_mbedtls_dice_tcbinfo builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fwid = X509_RIOT_SHA256_FWID;
	tcb.fwid_hash = HASH_TYPE_SHA256;

	status = x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (&builder, &tcb,
		ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_tcbinfo_release (&builder);
}


TEST_SUITE_START (x509_extension_builder_mbedtls_dice_tcbinfo);

TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_init);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_init_null);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_init_with_buffer);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_init_with_buffer_null);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_static_init);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_static_init_with_buffer);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_sha1);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_sha384);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_sha512);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_svn_zero);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_static_init);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_null);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_static_init_null_tcb);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_unknown_fwid);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_no_fwid);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_no_version);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_sha1);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_sha384);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_sha512);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_svn_zero);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_extra_space);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_static_init);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_null);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_static_init_null_buffer);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_static_init_null_tcb);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_len);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_tag);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_oid);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_sequence_len);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_sequence_tag);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_list_len);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_fwid_list_tag);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_svn);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_version);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_ext_sequence_len);
TEST (x509_extension_builder_mbedtls_dice_tcbinfo_test_build_with_buffer_small_buffer_ext_sequence_tag);

TEST_SUITE_END;
