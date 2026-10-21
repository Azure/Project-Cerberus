// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dme/x509_extension_builder_dme.h"
#include "asn1/dme/x509_extension_builder_openssl_dme.h"
#include "asn1/dme/x509_extension_builder_openssl_dme_static.h"
#include "testing/asn1/dme/dme_structure_testing.h"
#include "testing/asn1/dme/x509_extension_builder_dme_testing.h"


TEST_SUITE_LABEL ("x509_extension_builder_openssl_dme");


/*******************
 * Test cases
 *******************/

static void x509_extension_builder_openssl_dme_test_init (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;

	TEST_START;

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_init_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;

	TEST_START;

	status = x509_extension_builder_openssl_dme_init (NULL, &dme);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_openssl_dme_init (&builder, NULL);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_openssl_dme_test_static_init (CuTest *test)
{
	struct dme_structure dme;
	struct x509_extension_builder_openssl_dme builder =
		x509_extension_builder_openssl_dme_static_init (&dme);

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_release_null (CuTest *test)
{
	TEST_START;

	x509_extension_builder_openssl_dme_release (NULL);
}

static void x509_extension_builder_openssl_dme_test_build (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
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
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_ecc256_sha256 (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc256_sha256 (&dme);

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
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

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_no_device_oid (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_no_device_oid (&dme);

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
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

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_no_renewal_counter (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_no_renewal (&dme);

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
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

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_static_init (CuTest *test)
{
	struct dme_structure dme;
	struct x509_extension_builder_openssl_dme builder =
		x509_extension_builder_openssl_dme_static_init (&dme);
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

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_static_init_null_dme_structure (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder =
		x509_extension_builder_openssl_dme_static_init (NULL);
	int status;
	struct x509_extension extension;

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_no_structure_type_oid (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.data_oid = NULL;

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_TYPE_OID, status);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_no_structure_data (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.data = NULL;

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_DATA, status);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_no_signature_type_oid (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.sig_oid = NULL;

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_SIG_TYPE_OID, status);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_no_signature (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.signature = NULL;

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_SIGNATURE, status);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_build_no_dme_key (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension;

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);
	dme.dme_pub_key = NULL;

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DME_EXTENSION_NO_DME_KEY, status);

	x509_extension_builder_openssl_dme_release (&builder);
}

static void x509_extension_builder_openssl_dme_test_free_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dme builder;
	struct dme_structure dme;
	int status;
	struct x509_extension extension = {0};

	TEST_START;

	dme_structure_testing_structure_ecc384_sha384 (&dme);

	status = x509_extension_builder_openssl_dme_init (&builder, &dme);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (NULL, &extension);
	builder.base.free (&builder.base, NULL);

	x509_extension_builder_openssl_dme_release (&builder);
}


TEST_SUITE_START (x509_extension_builder_openssl_dme);

TEST (x509_extension_builder_openssl_dme_test_init);
TEST (x509_extension_builder_openssl_dme_test_init_null);
TEST (x509_extension_builder_openssl_dme_test_static_init);
TEST (x509_extension_builder_openssl_dme_test_release_null);
TEST (x509_extension_builder_openssl_dme_test_build);
TEST (x509_extension_builder_openssl_dme_test_build_ecc256_sha256);
TEST (x509_extension_builder_openssl_dme_test_build_no_device_oid);
TEST (x509_extension_builder_openssl_dme_test_build_no_renewal_counter);
TEST (x509_extension_builder_openssl_dme_test_build_static_init);
TEST (x509_extension_builder_openssl_dme_test_build_null);
TEST (x509_extension_builder_openssl_dme_test_build_static_init_null_dme_structure);
TEST (x509_extension_builder_openssl_dme_test_build_no_structure_type_oid);
TEST (x509_extension_builder_openssl_dme_test_build_no_structure_data);
TEST (x509_extension_builder_openssl_dme_test_build_no_signature_type_oid);
TEST (x509_extension_builder_openssl_dme_test_build_no_signature);
TEST (x509_extension_builder_openssl_dme_test_build_no_dme_key);
TEST (x509_extension_builder_openssl_dme_test_free_null);

TEST_SUITE_END;
