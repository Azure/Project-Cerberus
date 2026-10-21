// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dice/tcg_dice_oid.h"
#include "asn1/spdm/spdm_oid.h"
#include "asn1/x509_extension_builder_mbedtls_eku.h"
#include "asn1/x509_extension_builder_mbedtls_eku_static.h"
#include "asn1/x509_oid.h"
#include "testing/asn1/x509_extension_builder_eku_testing.h"


TEST_SUITE_LABEL ("x509_extension_builder_mbedtls_eku");


/**
 * Min length of the static buffer for testing extension building with a single OID.
 */
#define	X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE  \
	(X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE_LEN)

/**
 * Min length of the static buffer for testing extension building with multiple OIDs.
 */
#define	X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_MULTIPLE  \
	(X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE_LEN)


/*******************
 * Test cases
 *******************/

static void x509_extension_builder_mbedtls_eku_test_init (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_init_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init (NULL,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_eku_init (&builder, NULL,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_eku_init (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID, 0, true);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_mbedtls_eku_test_init_with_buffer (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_init_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	int status;

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (NULL,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder, NULL,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID, 0, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, NULL, sizeof (ext_buffer));
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_mbedtls_eku_test_static_init (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder =
		x509_extension_builder_mbedtls_eku_static_init (
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_static_init_with_buffer (CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	struct x509_extension_builder_mbedtls_eku builder =
		x509_extension_builder_mbedtls_eku_static_init_with_buffer (
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_release_null (CuTest *test)
{
	TEST_START;

	x509_extension_builder_mbedtls_eku_release (NULL);
}

static void x509_extension_builder_mbedtls_eku_test_build_single_oid (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE, extension.data,
		extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_multiple_oid (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS,
		X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS_COUNT, false);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_static_init_single_oid (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder =
		x509_extension_builder_mbedtls_eku_static_init (
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE, extension.data,
		extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_static_init_multiple_oids (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder =
		x509_extension_builder_mbedtls_eku_static_init (
		X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS,
		X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS_COUNT, false);
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_static_init_null_oids (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku null_oids =
		x509_extension_builder_mbedtls_eku_static_init (NULL,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);
	struct x509_extension_builder_mbedtls_eku zero_oids =
		x509_extension_builder_mbedtls_eku_static_init (
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID, 0, true);
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = null_oids.base.build (&null_oids.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = zero_oids.base.build (&zero_oids.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_eku_release (&null_oids);
	x509_extension_builder_mbedtls_eku_release (&zero_oids);
}

static void x509_extension_builder_mbedtls_eku_test_free_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (NULL, &extension);
	builder.base.free (&builder.base, NULL);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_single_oid (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE, extension.data,
		extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_multiple_oids (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_MULTIPLE];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS,
		X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS_COUNT, false, ext_buffer,
		sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_extra_space (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE + 32];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE, extension.data,
		extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_static_init_single_oid (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	struct x509_extension_builder_mbedtls_eku builder =
		x509_extension_builder_mbedtls_eku_static_init_with_buffer (
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_SINGLE, extension.data,
		extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_static_init_multiple_oids (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_MULTIPLE];
	struct x509_extension_builder_mbedtls_eku builder =
		x509_extension_builder_mbedtls_eku_static_init_with_buffer (
		X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS,
		X509_EXTENSION_BUILDER_EKU_TESTING_MULTIPLE_OIDS_COUNT, false, ext_buffer,
		sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrEquals (test, ext_buffer, (void*) extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_OID_LEN, extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_EKU_TESTING_DATA_MULTIPLE,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_static_init_null_buffer (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	struct x509_extension_builder_mbedtls_eku builder =
		x509_extension_builder_mbedtls_eku_static_init_with_buffer (
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, NULL, sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_static_init_null_oids (
	CuTest *test)
{
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	struct x509_extension_builder_mbedtls_eku null_oids =
		x509_extension_builder_mbedtls_eku_static_init_with_buffer (NULL,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	struct x509_extension_builder_mbedtls_eku zero_oids =
		x509_extension_builder_mbedtls_eku_static_init_with_buffer (
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID, 0, true, ext_buffer, sizeof (ext_buffer));
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = null_oids.base.build (&null_oids.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	status = zero_oids.base.build (&zero_oids.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_mbedtls_eku_release (&null_oids);
	x509_extension_builder_mbedtls_eku_release (&zero_oids);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_oid (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_OID_CLIENT_AUTH_LENGTH - 1];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_oid_len (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_OID_CLIENT_AUTH_LENGTH];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_oid_tag (
	CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_OID_CLIENT_AUTH_LENGTH + 1];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_ext_sequence_len
	(CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE - 2];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_ext_sequence_tag
	(CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE - 1];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, EKU_EXTENSION_SMALL_EXT_BUFFER, status);

	x509_extension_builder_mbedtls_eku_release (&builder);
}

static void x509_extension_builder_mbedtls_eku_test_free_with_buffer_null (CuTest *test)
{
	struct x509_extension_builder_mbedtls_eku builder;
	uint8_t ext_buffer[X509_EXTENSION_BUILDER_EKU_TESTING_BUFFER_LENGTH_SINGLE];
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	status = x509_extension_builder_mbedtls_eku_init_with_buffer (&builder,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID,
		X509_EXTENSION_BUILDER_EKU_TESTING_SINGLE_OID_COUNT, true, ext_buffer, sizeof (ext_buffer));
	CuAssertIntEquals (test, 0, status);

	builder.base.free (NULL, &extension);
	builder.base.free (&builder.base, NULL);

	x509_extension_builder_mbedtls_eku_release (&builder);
}


// *INDENT-OFF*
TEST_SUITE_START (x509_extension_builder_mbedtls_eku);

TEST (x509_extension_builder_mbedtls_eku_test_init);
TEST (x509_extension_builder_mbedtls_eku_test_init_null);
TEST (x509_extension_builder_mbedtls_eku_test_init_with_buffer);
TEST (x509_extension_builder_mbedtls_eku_test_init_with_buffer_null);
TEST (x509_extension_builder_mbedtls_eku_test_static_init);
TEST (x509_extension_builder_mbedtls_eku_test_static_init_with_buffer);
TEST (x509_extension_builder_mbedtls_eku_test_release_null);
TEST (x509_extension_builder_mbedtls_eku_test_build_single_oid);
TEST (x509_extension_builder_mbedtls_eku_test_build_multiple_oid);
TEST (x509_extension_builder_mbedtls_eku_test_build_static_init_single_oid);
TEST (x509_extension_builder_mbedtls_eku_test_build_static_init_multiple_oids);
TEST (x509_extension_builder_mbedtls_eku_test_build_null);
TEST (x509_extension_builder_mbedtls_eku_test_build_static_init_null_oids);
TEST (x509_extension_builder_mbedtls_eku_test_free_null);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_single_oid);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_multiple_oids);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_extra_space);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_static_init_single_oid);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_static_init_multiple_oids);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_null);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_static_init_null_buffer);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_static_init_null_oids);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_oid);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_oid_len);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_oid_tag);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_ext_sequence_len);
TEST (x509_extension_builder_mbedtls_eku_test_build_with_buffer_small_buffer_ext_sequence_tag);
TEST (x509_extension_builder_mbedtls_eku_test_free_with_buffer_null);

TEST_SUITE_END;
// *INDENT-ON*
