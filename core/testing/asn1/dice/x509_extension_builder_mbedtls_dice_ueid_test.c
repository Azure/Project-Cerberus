// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dice/x509_extension_builder_dice_ueid.h"
#include "asn1/dice/x509_extension_builder_mbedtls_dice_ueid.h"
#include "asn1/dice/x509_extension_builder_mbedtls_dice_ueid_static.h"
#include "testing/asn1/x509_testing.h"
#include "testing/asn1/dice/x509_extension_builder_dice_ueid_testing.h"


TEST_SUITE_LABEL ("x509_extension_builder_mbedtls_dice_ueid");


/**
 * Min length of the static buffer for testing extension building.
 */
#define	X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH	\
	X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA_LEN


/*******************
 * Test cases
 *******************/

static void x509_extension_builder_mbedtls_dice_ueid_test_init (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_init_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init (NULL, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_dice_ueid_init (&builder, NULL,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_dice_ueid_init (&builder, X509_RIOT_UEID,
		0);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_init_with_buffer (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH];
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_init_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH];
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (NULL, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (&builder, NULL,
		X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (&builder, X509_RIOT_UEID,
		0, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN, NULL, sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_init_with_buffer_small_buffer (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH - 1];
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_SMALL_EXT_BUFFER, status);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_static_init (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder =
		x509_extension_builder_mbedtls_dice_ueid_static_init (X509_RIOT_UEID, X509_RIOT_UEID_LEN);

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_static_init_with_buffer (CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH];
	struct x509_extension_builder_mbedtls_dice_ueid builder =
		x509_extension_builder_mbedtls_dice_ueid_static_init_with_buffer (X509_RIOT_UEID,
			X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init (&builder, X509_RIOT_UEID,
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

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_static_init (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder =
		x509_extension_builder_mbedtls_dice_ueid_static_init (X509_RIOT_UEID, X509_RIOT_UEID_LEN);
	int status;
	struct x509_extension extension = {0};

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

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
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

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_extra_space (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH + 32];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
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

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH];
	struct x509_extension_builder_mbedtls_dice_ueid builder =
		x509_extension_builder_mbedtls_dice_ueid_static_init_with_buffer (X509_RIOT_UEID,
			X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
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

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (&builder, X509_RIOT_UEID,
		X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init_null_buffer (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_dice_ueid builder =
		x509_extension_builder_mbedtls_dice_ueid_static_init_with_buffer (X509_RIOT_UEID,
			X509_RIOT_UEID_LEN, NULL,
			X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_TESTING_BUFFER_LENGTH);
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init_small_buffer_ueid (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA_LEN - 3];
	struct x509_extension_builder_mbedtls_dice_ueid builder =
		x509_extension_builder_mbedtls_dice_ueid_static_init_with_buffer (X509_RIOT_UEID,
			X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init_small_buffer_ext_sequence_len (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA_LEN - 2];
	struct x509_extension_builder_mbedtls_dice_ueid builder =
		x509_extension_builder_mbedtls_dice_ueid_static_init_with_buffer (X509_RIOT_UEID,
			X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}

static void x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init_small_buffer_ext_sequence_tag (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_DICE_UEID_TESTING_DATA_LEN - 1];
	struct x509_extension_builder_mbedtls_dice_ueid builder =
		x509_extension_builder_mbedtls_dice_ueid_static_init_with_buffer (X509_RIOT_UEID,
			X509_RIOT_UEID_LEN, ext_buffer, sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_UEID_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_dice_ueid_release (&builder);
}


TEST_SUITE_START (x509_extension_builder_mbedtls_dice_ueid);

TEST (x509_extension_builder_mbedtls_dice_ueid_test_init);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_init_null);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_init_with_buffer);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_init_with_buffer_null);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_init_with_buffer_small_buffer);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_static_init);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_static_init_with_buffer);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_static_init);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_null);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_extra_space);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_null);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init_null_buffer);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init_small_buffer_ueid);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init_small_buffer_ext_sequence_len);
TEST (x509_extension_builder_mbedtls_dice_ueid_test_build_with_buffer_static_init_small_buffer_ext_sequence_tag);

TEST_SUITE_END;
