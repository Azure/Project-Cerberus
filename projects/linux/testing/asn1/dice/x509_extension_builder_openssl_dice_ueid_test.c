// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dice/x509_extension_builder_dice_ueid.h"
#include "asn1/dice/x509_extension_builder_openssl_dice_ueid.h"
#include "asn1/dice/x509_extension_builder_openssl_dice_ueid_static.h"
#include "testing/asn1/x509_testing.h"
#include "testing/asn1/dice/x509_extension_builder_dice_ueid_testing.h"


TEST_SUITE_LABEL ("x509_extension_builder_openssl_dice_ueid");


/**
 * Min length of the static buffer for testing extension building.
 */
#define	X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH	\
	X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA_LEN


/*******************
 * Test cases
 *******************/

static void x509_extension_builder_openssl_dice_ueid_test_init (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_ueid builder;
	int status;

	TEST_START;

	status = x509_extension_builder_openssl_dice_ueid_init (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_openssl_dice_ueid_release (&builder);
}

static void x509_extension_builder_openssl_dice_ueid_test_init_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_ueid builder;
	int status;

	TEST_START;

	status = x509_extension_builder_openssl_dice_ueid_init (NULL, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_openssl_dice_ueid_init (&builder, NULL,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_openssl_dice_ueid_init (&builder, X509_RIOT_UEID,
		0);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_openssl_dice_ueid_test_static_init (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_ueid builder =
		x509_extension_builder_openssl_dice_ueid_static_init (X509_RIOT_UEID, X509_RIOT_UEID_LEN);

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_openssl_dice_ueid_release (&builder);
}

static void x509_extension_builder_openssl_dice_ueid_test_release_null (CuTest *test)
{
	TEST_START;

	x509_extension_builder_openssl_dice_ueid_release (NULL);
}

static void x509_extension_builder_openssl_dice_ueid_test_build (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_ueid builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	status = x509_extension_builder_openssl_dice_ueid_init (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_UEID_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA, extension.data,
		extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_openssl_dice_ueid_release (&builder);
}

static void x509_extension_builder_openssl_dice_ueid_test_build_static_init (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_ueid builder =
		x509_extension_builder_openssl_dice_ueid_static_init (X509_RIOT_UEID, X509_RIOT_UEID_LEN);
	int status;
	struct x509_extension extension;

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_UEID_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA, extension.data,
		extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_openssl_dice_ueid_release (&builder);
}

static void x509_extension_builder_openssl_dice_ueid_test_build_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_ueid builder;
	int status;
	struct x509_extension extension;

	TEST_START;

	status = x509_extension_builder_openssl_dice_ueid_init (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_openssl_dice_ueid_release (&builder);
}

static void x509_extension_builder_openssl_dice_ueid_test_build_static_init_null_ueid (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_ueid null_ueid =
		x509_extension_builder_openssl_dice_ueid_static_init (NULL, X509_RIOT_UEID_LEN);
	struct x509_extension_builder_openssl_dice_ueid zero_ueid =
		x509_extension_builder_openssl_dice_ueid_static_init (X509_RIOT_UEID, 0);
	int status;
	struct x509_extension extension;

	TEST_START;

	status = null_ueid.base.build (&null_ueid.base, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = zero_ueid.base.build (&zero_ueid.base, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_openssl_dice_ueid_release (&null_ueid);
	x509_extension_builder_openssl_dice_ueid_release (&zero_ueid);
}

static void x509_extension_builder_openssl_dice_ueid_test_free_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_ueid builder;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_openssl_dice_ueid_init (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (NULL, &extension);
	builder.base.free (&builder.base, NULL);

	x509_extension_builder_openssl_dice_ueid_release (&builder);
}


TEST_SUITE_START (x509_extension_builder_openssl_dice_ueid);

TEST (x509_extension_builder_openssl_dice_ueid_test_init);
TEST (x509_extension_builder_openssl_dice_ueid_test_init_null);
TEST (x509_extension_builder_openssl_dice_ueid_test_static_init);
TEST (x509_extension_builder_openssl_dice_ueid_test_release_null);
TEST (x509_extension_builder_openssl_dice_ueid_test_build);
TEST (x509_extension_builder_openssl_dice_ueid_test_build_static_init);
TEST (x509_extension_builder_openssl_dice_ueid_test_build_null);
TEST (x509_extension_builder_openssl_dice_ueid_test_build_static_init_null_ueid);
TEST (x509_extension_builder_openssl_dice_ueid_test_free_null);

TEST_SUITE_END;
