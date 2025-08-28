// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dice/x509_extension_builder_dice_tcbinfo.h"
#include "asn1/dice/x509_extension_builder_openssl_dice_tcbinfo.h"
#include "asn1/dice/x509_extension_builder_openssl_dice_tcbinfo_static.h"
#include "common/array_size.h"
#include "testing/asn1/dice/x509_extension_builder_dice_tcbinfo_testing.h"
#include "testing/asn1/x509_testing.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("x509_extension_builder_openssl_dice_tcbinfo");


/*******************
 * Test cases
 *******************/

static void x509_extension_builder_openssl_dice_tcbinfo_test_init (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
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
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_init_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
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
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (NULL, &tcb);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, NULL);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_static_init (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct x509_extension_builder_openssl_dice_tcbinfo builder =
		x509_extension_builder_openssl_dice_tcbinfo_static_init (&tcb);

	TEST_START;

	CuAssertPtrNotNull (test, builder.base.build);
	CuAssertPtrNotNull (test, builder.base.free);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_release_null (CuTest *test)
{
	TEST_START;

	x509_extension_builder_openssl_dice_tcbinfo_release (NULL);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_sha1 (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA1_FWID,
			.hash_alg = HASH_TYPE_SHA1
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_sha384 (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA384_FWID,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_sha512 (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA512_FWID,
			.hash_alg = HASH_TYPE_SHA512
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_multiple_fwids (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
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
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_svn_zero (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	uint8_t zero = 0;
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = &zero;
	tcb.svn_length = 1;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_layer_1 (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 1;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_layer_1000 (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 1000;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_vendor (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_model (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_string (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list[] = {
		{
			.digest = SHA256_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR,
			.number = -1,
			.digests = digest_list,
			.digest_count = ARRAY_SIZE (digest_list)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_IR_STRING_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_IR_STRING,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_int (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list[] = {
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = NULL,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER,
			.digests = digest_list,
			.digest_count = ARRAY_SIZE (digest_list)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_IR_INT_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_IR_INT,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void
x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_multiple_digests (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list[] = {
		{
			.digest = SHA256_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = SHA1_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA1
		},
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		},
		{
			.digest = SHA512_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA512
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR2,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER2,
			.digests = digest_list,
			.digest_count = ARRAY_SIZE (digest_list)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test,
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_IR_MULTIPLE_DIGESTS_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status =
		testing_validate_array (
		X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_IR_MULTIPLE_DIGESTS, extension.data,
		extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_multiple_integrity_registers (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list1[] = {
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	struct tcg_dice_fwid digest_list2[] = {
		{
			.digest = SHA256_TEST2_HASH,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list3[] = {
		{
			.digest = SHA512_TEST_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA512
		},
		{
			.digest = SHA384_TEST_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		},
		{
			.digest = SHA256_TEST_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR,
			.number = -1,
			.digests = digest_list1,
			.digest_count = ARRAY_SIZE (digest_list1)
		},
		{
			.name = NULL,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER,
			.digests = digest_list2,
			.digest_count = ARRAY_SIZE (digest_list2)
		},
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR2,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER2,
			.digests = digest_list3,
			.digest_count = ARRAY_SIZE (digest_list3)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, extension.critical);
	CuAssertPtrNotNull (test, extension.oid);
	CuAssertPtrNotNull (test, extension.data);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID_LEN,
		extension.oid_length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_IRS_LEN,
		extension.data_length);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_OID, extension.oid,
		extension.oid_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_DATA_MULTIPLE_IRS,
		extension.data, extension.data_length);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (&builder.base, &extension);
	CuAssertPtrEquals (test, NULL, extension.data);
	CuAssertIntEquals (test, 0, extension.data_length);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_empty_list (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list[] = {
		{
			.digest = SHA256_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR,
			.number = -1,
			.digests = digest_list,
			.digest_count = ARRAY_SIZE (digest_list)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_full (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
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
	struct tcg_dice_fwid digest_list1[] = {
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	struct tcg_dice_fwid digest_list2[] = {
		{
			.digest = SHA256_TEST2_HASH,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list3[] = {
		{
			.digest = SHA512_TEST_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA512
		},
		{
			.digest = SHA384_TEST_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		},
		{
			.digest = SHA256_TEST_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR2,
			.number = -1,
			.digests = digest_list1,
			.digest_count = ARRAY_SIZE (digest_list1)
		},
		{
			.name = NULL,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER2,
			.digests = digest_list2,
			.digest_count = ARRAY_SIZE (digest_list2)
		},
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER,
			.digests = digest_list3,
			.digest_count = ARRAY_SIZE (digest_list3)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_VENDOR_STR;
	tcb.model = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_MODEL_STR;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 3;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_static_init (CuTest *test)
{
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct x509_extension_builder_openssl_dice_tcbinfo builder =
		x509_extension_builder_openssl_dice_tcbinfo_static_init (&tcb);
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = builder.base.build (NULL, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	status = builder.base.build (&builder.base, NULL);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_static_init_null_tcb (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder =
		x509_extension_builder_openssl_dice_tcbinfo_static_init (NULL);
	int status;
	struct x509_extension extension;

	TEST_START;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_unknown_fwid (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
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
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_UNKNOWN_FWID, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_no_fwid_digest (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
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
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_FWID, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_no_fwid_list (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = NULL;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_FWID_LIST, status);

	tcb.fwid_list = fwid_list;
	tcb.fwid_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_FWID_LIST, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_no_version (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = NULL;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_VERSION, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_no_svn (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
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

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_no_id (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list1[] = {
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	struct tcg_dice_fwid digest_list2[] = {
		{
			.digest = SHA256_TEST2_HASH,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR,
			.number = -1,
			.digests = digest_list1,
			.digest_count = ARRAY_SIZE (digest_list1)
		},
		{
			.name = NULL,
			.number = -1,
			.digests = digest_list2,
			.digest_count = ARRAY_SIZE (digest_list2)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_IR_ID, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_unknown_digest
	(CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list1[] = {
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	struct tcg_dice_fwid digest_list2[] = {
		{
			.digest = SHA256_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = (enum hash_type) 10
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR,
			.number = -1,
			.digests = digest_list1,
			.digest_count = ARRAY_SIZE (digest_list1)
		},
		{
			.name = NULL,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER,
			.digests = digest_list2,
			.digest_count = ARRAY_SIZE (digest_list2)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_UNKNOWN_IR_DIGEST, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_no_digest (
	CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list1[] = {
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	struct tcg_dice_fwid digest_list2[] = {
		{
			.digest = SHA256_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA256
		},
		{
			.digest = NULL,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR,
			.number = -1,
			.digests = digest_list1,
			.digest_count = ARRAY_SIZE (digest_list1)
		},
		{
			.name = NULL,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER,
			.digests = digest_list2,
			.digest_count = ARRAY_SIZE (digest_list2)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_IR_DIGEST, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_no_digest_list
	(CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
	struct tcg_dice_tcbinfo tcb;
	struct tcg_dice_fwid fwid_list[] = {
		{
			.digest = X509_RIOT_SHA256_FWID,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_fwid digest_list1[] = {
		{
			.digest = SHA384_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA384
		}
	};
	struct tcg_dice_fwid digest_list2[] = {
		{
			.digest = SHA256_TEST_HASH,
			.hash_alg = HASH_TYPE_SHA256
		}
	};
	struct tcg_dice_integrity_register ir_list[] = {
		{
			.name = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NAME_STR,
			.number = -1,
			.digests = digest_list1,
			.digest_count = ARRAY_SIZE (digest_list1)
		},
		{
			.name = NULL,
			.number = X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_IR_NUMBER,
			.digests = NULL,
			.digest_count = ARRAY_SIZE (digest_list2)
		}
	};
	int status;
	struct x509_extension extension;

	TEST_START;

	tcb.vendor = NULL;
	tcb.model = NULL;
	tcb.version = X509_RIOT_VERSION;
	tcb.layer = 0;
	tcb.svn = X509_RIOT_SVN;
	tcb.svn_length = X509_RIOT_SVN_LEN;
	tcb.fwid_list = fwid_list;
	tcb.fwid_count = ARRAY_SIZE (fwid_list);
	tcb.ir_list = ir_list;
	tcb.ir_count = ARRAY_SIZE (ir_list);

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_IR_DIGEST_LIST, status);

	ir_list[1].digests = digest_list2;
	ir_list[1].digest_count = 0;

	status = builder.base.build (&builder.base, &extension);
	CuAssertIntEquals (test, DICE_TCBINFO_EXTENSION_NO_IR_DIGEST_LIST, status);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}

static void x509_extension_builder_openssl_dice_tcbinfo_test_free_null (CuTest *test)
{
	struct x509_extension_builder_openssl_dice_tcbinfo builder;
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
	tcb.ir_list = NULL;
	tcb.ir_count = 0;

	status = x509_extension_builder_openssl_dice_tcbinfo_init (&builder, &tcb);
	CuAssertIntEquals (test, 0, status);

	builder.base.free (NULL, &extension);
	builder.base.free (&builder.base, NULL);

	x509_extension_builder_openssl_dice_tcbinfo_release (&builder);
}


TEST_SUITE_START (x509_extension_builder_openssl_dice_tcbinfo);

TEST (x509_extension_builder_openssl_dice_tcbinfo_test_init);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_init_null);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_static_init);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_release_null);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_sha1);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_sha384);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_sha512);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_multiple_fwids);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_svn_zero);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_layer_1);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_layer_1000);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_vendor);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_model);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_string);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_int);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_multiple_digests);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_multiple_integrity_registers);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_empty_list);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_full);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_static_init);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_null);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_static_init_null_tcb);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_unknown_fwid);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_no_fwid_digest);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_no_fwid_list);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_no_version);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_no_svn);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_no_id);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_unknown_digest);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_no_digest);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_build_integrity_register_no_digest_list);
TEST (x509_extension_builder_openssl_dice_tcbinfo_test_free_null);

TEST_SUITE_END;
