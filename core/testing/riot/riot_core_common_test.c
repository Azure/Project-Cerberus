// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "riot/riot_core_common.h"
#include "riot_core_testing.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/mock/crypto/base64_mock.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/engines/base64_testing_engine.h"
#include "testing/crypto/x509_testing.h"


TEST_SUITE_LABEL ("riot_core_common");

/**
 * RIoT Core UEID information for testing.
 */
static struct x509_dice_ueid riot_ueid;

/**
 * RIoT Core TCB information for testing.
 */
static struct x509_dice_tcbinfo riot_tcb;

/**
 * Cerberus OID for testing.
 */
#define	RIOT_CORE_CERBERUS			"\x2B\x06\x01\x04\x01\x82\x37\x66\x01\x0A\x01"


/**
 * Initialize the test suite for execution.
 *
 * @param test The test framework.
 */
static void riot_core_common_testing_setup_suite (CuTest *test)
{
	riot_ueid.ueid = X509_RIOT_UEID;
	riot_ueid.length = X509_RIOT_UEID_LEN;

	riot_tcb.version = X509_RIOT_VERSION;
	riot_tcb.svn = X509_RIOT_SVN;
	riot_tcb.fw_id = X509_RIOT_SHA256_FWID;
	riot_tcb.fw_id_hash = HASH_TYPE_SHA256;
	riot_tcb.ueid = &riot_ueid;
}


/*******************
 * Test cases
 *******************/

static void riot_core_common_test_init (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, riot.base.generate_device_id);
	CuAssertPtrNotNull (test, riot.base.get_device_id_csr);
	CuAssertPtrNotNull (test, riot.base.get_device_id_cert);
	CuAssertPtrNotNull (test, riot.base.generate_alias_key);
	CuAssertPtrNotNull (test, riot.base.get_alias_key);
	CuAssertPtrNotNull (test, riot.base.get_alias_key_cert);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_init_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (NULL, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot, NULL, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot, &hash.base, NULL, &x509.base, &base64.base);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, NULL, &base64.base);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_release_null (CuTest *test)
{
	TEST_START;

	riot_core_common_release (NULL);
}

static void riot_core_common_test_release_twice (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (NULL, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, 0, &riot_tcb);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_cdi_hash_start_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_cdi_hash_first_byte_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_cdi_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_cdi_hash_finish_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_key_pair_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc,
		ECC_ENGINE_DERIVED_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, ECC_ENGINE_DERIVED_KEY_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_der_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc,
		ECC_ENGINE_PRIVATE_KEY_DER_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, ECC_ENGINE_PRIVATE_KEY_DER_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_serial_hmac_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_subject_name_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, BASE64_ENGINE_ENCODE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, BASE64_ENGINE_ENCODE_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_device_id_cert_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509,
		X509_ENGINE_SELF_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, X509_ENGINE_SELF_SIGNED_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_device_id_csr (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (csr, RIOT_CORE_DEVID_CSR, csr_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	/* Generate the CSR. */
	status = mock_expect (&x509.mock, x509.base.create_csr, &x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)), MOCK_ARG (&out),
		MOCK_ARG (&out_length));
	status |= mock_expect_output (&x509.mock, 6, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&x509.mock, 7, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_csr (&riot.base, NULL, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);

	platform_free (csr);
}

static void riot_core_common_test_get_device_id_csr_with_oid (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (csr, RIOT_CORE_DEVID_CSR, csr_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	/* Generate the CSR. */
	status = mock_expect (&x509.mock, x509.base.create_csr, &x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CERBERUS, strlen (RIOT_CORE_CERBERUS) + 1),
		MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)), MOCK_ARG (&out),
		MOCK_ARG (&out_length));
	status |= mock_expect_output (&x509.mock, 6, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&x509.mock, 7, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_csr (&riot.base, RIOT_CORE_CERBERUS, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);

	platform_free (csr);
}

static void riot_core_common_test_get_device_id_csr_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (csr, RIOT_CORE_DEVID_CSR, csr_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_csr (NULL, NULL, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.get_device_id_csr (&riot.base, NULL, NULL, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.get_device_id_csr (&riot.base, NULL, &out, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);

	platform_free (csr);
}

static void riot_core_common_test_get_device_id_csr_no_device_id (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_csr (&riot.base, NULL, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_NO_DEVICE_ID, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_device_id_csr_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	/* Generate the CSR. */
	status = mock_expect (&x509.mock, x509.base.create_csr, &x509, X509_ENGINE_CSR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)), MOCK_ARG (&out),
		MOCK_ARG (&out_length));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_csr (&riot.base, NULL, &out, &out_length);
	CuAssertIntEquals (test, X509_ENGINE_CSR_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_device_id_cert (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *cert;
	size_t cert_length = RIOT_CORE_DEVID_CERT_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	cert = platform_malloc (cert_length);
	CuAssertPtrNotNull (test, cert);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (cert, RIOT_CORE_DEVID_CERT, cert_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	/* Encode the certificate. */
	status = mock_expect (&x509.mock, x509.base.get_certificate_der, &x509, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&out), MOCK_ARG (&out_length));
	status |= mock_expect_output (&x509.mock, 1, &cert, sizeof (cert), -1);
	status |= mock_expect_output (&x509.mock, 2, &cert_length, sizeof (cert_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_cert (&riot.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CERT_LEN, out_length);
	CuAssertPtrEquals (test, cert, out);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);

	platform_free (cert);
}

static void riot_core_common_test_get_device_id_cert_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_cert (NULL, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.get_device_id_cert (&riot.base, NULL, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.get_device_id_cert (&riot.base, &out, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_device_id_cert_no_device_id (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_cert (&riot.base, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_NO_DEVICE_ID, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_device_id_cert_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	/* Encode the certificate. */
	status = mock_expect (&x509.mock, x509.base.get_certificate_der, &x509,
		X509_ENGINE_CERT_DER_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&out),
		MOCK_ARG (&out_length));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_cert (&riot.base, &out, &out_length);
	CuAssertIntEquals (test, X509_ENGINE_CERT_DER_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&alias_tcb, sizeof (alias_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	status = riot.base.generate_alias_key (NULL, &alias_tcb);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.generate_alias_key (&riot.base, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	alias_tcb.fw_id = NULL;
	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_invalid_fwid_hash (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA1;
	alias_tcb.ueid = NULL;

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, RIOT_CORE_BAD_FWID_LENGTH, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_no_device_id (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, RIOT_CORE_NO_DEVICE_ID, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_alias_kdf_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_key_pair_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc,
		ECC_ENGINE_DERIVED_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, ECC_ENGINE_DERIVED_KEY_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_der_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc,
		ECC_ENGINE_PRIVATE_KEY_DER_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, ECC_ENGINE_PRIVATE_KEY_DER_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_serial_hmac_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_subject_name_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, BASE64_ENGINE_ENCODE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_ALIAS_NAME_LEN));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, BASE64_ENGINE_ENCODE_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_generate_alias_key_cert_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&alias_tcb, sizeof (alias_tcb)));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_alias_key (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&alias_tcb, sizeof (alias_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_alias_key (&riot.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_KEY_LEN, out_length);
	CuAssertPtrNotNull (test, out);

	status = testing_validate_array (RIOT_CORE_ALIAS_KEY, out, out_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (out);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_alias_key_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&alias_tcb, sizeof (alias_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_alias_key (NULL, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.get_alias_key (&riot.base, NULL, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.get_alias_key (&riot.base, &out, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_alias_key_no_alias_key (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_alias_key (&riot.base, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_NO_ALIAS_KEY, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_alias_key_cert (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;
	uint8_t *cert;
	size_t cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	cert = platform_malloc (cert_length);
	CuAssertPtrNotNull (test, cert);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);
	memcpy (cert, RIOT_CORE_ALIAS_CERT, cert_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&alias_tcb, sizeof (alias_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	/* Encode the certificate. */
	status = mock_expect (&x509.mock, x509.base.get_certificate_der, &x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG (&out), MOCK_ARG (&out_length));
	status |= mock_expect_output (&x509.mock, 1, &cert, sizeof (cert), -1);
	status |= mock_expect_output (&x509.mock, 2, &cert_length, sizeof (cert_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_alias_key_cert (&riot.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, out_length);
	CuAssertPtrEquals (test, cert, out);

	platform_free (cert);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_alias_key_cert_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&alias_tcb, sizeof (alias_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_alias_key_cert (NULL, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.get_alias_key_cert (&riot.base, NULL, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.base.get_alias_key_cert (&riot.base, &out, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_alias_key_cert_no_alias_key (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_alias_key_cert (&riot.base, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_NO_ALIAS_KEY, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_get_alias_key_cert_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct base64_engine_mock base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);
	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	/* Hash the CDI. */
	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1);

	/* Derive the Device ID. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN),
		MOCK_ARG (RIOT_CORE_CDI_HASH_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_self_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS_TMP (&riot_tcb, sizeof (riot_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, RIOT_CORE_FWID_KDF,
		RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&ecc.mock, ecc.base.generate_derived_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_FWID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&ecc.mock, ecc.base.get_private_key_der, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&ecc.mock, 2, &alias_der_length, sizeof (alias_der_length), -1);

	status |= hash_mock_expect_hmac (&hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_DATA, RIOT_CORE_SERIAL_KDF_DATA_LEN, NULL, SHA256_HASH_LENGTH,
		RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&base64.mock, base64.base.encode, &base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&alias_tcb, sizeof (alias_tcb)));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	/* Encode the certificate. */
	status = mock_expect (&x509.mock, x509.base.get_certificate_der, &x509,
		X509_ENGINE_CERT_DER_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG (&out),
		MOCK_ARG (&out_length));

	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_alias_key_cert (&riot.base, &out, &out_length);
	CuAssertIntEquals (test, X509_ENGINE_CERT_DER_FAILED, status);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&x509.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&base64.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG (NULL));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_validate_and_release (&base64);
	CuAssertIntEquals (test, 0, status);
}

static void riot_core_common_test_authenticate_generated_keys (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	X509_TESTING_ENGINE x509;
	X509_TESTING_ENGINE x509_verify;
	BASE64_TESTING_ENGINE base64;
	struct riot_core_common riot;
	struct x509_dice_tcbinfo alias_tcb;
	int status;
	struct riot_core_common zero;
	uint8_t *der;
	size_t der_length;
	struct x509_certificate alias;
	struct x509_ca_certs ca_certs;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509_verify);
	CuAssertIntEquals (test, 0, status);

	status = BASE64_TESTING_ENGINE_INIT (&base64);
	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot, &hash.base, &ecc.base, &x509.base, &base64.base);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.generate_device_id (&riot.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN, &riot_tcb);
	CuAssertIntEquals (test, 0, status);

	memset (&alias_tcb, 0, sizeof (alias_tcb));
	alias_tcb.version = RIOT_CORE_ALIAS_VERSION;
	alias_tcb.svn = RIOT_CORE_ALIAS_SVN;
	alias_tcb.fw_id = RIOT_CORE_FWID;
	alias_tcb.fw_id_hash = HASH_TYPE_SHA256;
	alias_tcb.ueid = NULL;

	status = riot.base.generate_alias_key (&riot.base, &alias_tcb);
	CuAssertIntEquals (test, 0, status);

	status = riot.base.get_device_id_cert (&riot.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.init_ca_cert_store (&x509.base, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.add_root_ca (&x509_verify.base, &ca_certs, der, der_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	status = riot.base.get_alias_key_cert (&riot.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.load_certificate (&x509_verify.base, &alias, der, der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.authenticate (&x509_verify.base, &alias, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	x509.base.release_certificate (&x509_verify.base, &alias);
	platform_free (der);

	status = riot.base.get_alias_key (&riot.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_KEY_LEN, der_length);

	status = testing_validate_array (RIOT_CORE_ALIAS_KEY, der, der_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	riot_core_common_release (&riot);

	memset (&zero, 0, sizeof (zero));
	status = memcmp (&riot, &zero, sizeof (riot));
	CuAssertIntEquals (test, 0, status);

	x509.base.release_ca_cert_store (&x509.base, &ca_certs);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	X509_TESTING_ENGINE_RELEASE (&x509);
	X509_TESTING_ENGINE_RELEASE (&x509_verify);
	BASE64_TESTING_ENGINE_RELEASE (&base64);
}


TEST_SUITE_START (riot_core_common);

/* Run global setup for the test suite. */
TEST (riot_core_common_testing_setup_suite);

TEST (riot_core_common_test_init);
TEST (riot_core_common_test_init_null);
TEST (riot_core_common_test_release_null);
TEST (riot_core_common_test_release_twice);
TEST (riot_core_common_test_generate_device_id);
TEST (riot_core_common_test_generate_device_id_null);
TEST (riot_core_common_test_generate_device_id_cdi_hash_start_error);
TEST (riot_core_common_test_generate_device_id_cdi_hash_first_byte_error);
TEST (riot_core_common_test_generate_device_id_cdi_hash_error);
TEST (riot_core_common_test_generate_device_id_cdi_hash_finish_error);
TEST (riot_core_common_test_generate_device_id_key_pair_error);
TEST (riot_core_common_test_generate_device_id_der_error);
TEST (riot_core_common_test_generate_device_id_serial_hmac_error);
TEST (riot_core_common_test_generate_device_id_subject_name_error);
TEST (riot_core_common_test_generate_device_id_cert_error);
TEST (riot_core_common_test_get_device_id_csr);
TEST (riot_core_common_test_get_device_id_csr_with_oid);
TEST (riot_core_common_test_get_device_id_csr_null);
TEST (riot_core_common_test_get_device_id_csr_no_device_id);
TEST (riot_core_common_test_get_device_id_csr_error);
TEST (riot_core_common_test_get_device_id_cert);
TEST (riot_core_common_test_get_device_id_cert_null);
TEST (riot_core_common_test_get_device_id_cert_no_device_id);
TEST (riot_core_common_test_get_device_id_cert_error);
TEST (riot_core_common_test_generate_alias_key);
TEST (riot_core_common_test_generate_alias_key_null);
TEST (riot_core_common_test_generate_alias_key_invalid_fwid_hash);
TEST (riot_core_common_test_generate_alias_key_no_device_id);
TEST (riot_core_common_test_generate_alias_key_alias_kdf_error);
TEST (riot_core_common_test_generate_alias_key_key_pair_error);
TEST (riot_core_common_test_generate_alias_key_der_error);
TEST (riot_core_common_test_generate_alias_key_serial_hmac_error);
TEST (riot_core_common_test_generate_alias_key_subject_name_error);
TEST (riot_core_common_test_generate_alias_key_cert_error);
TEST (riot_core_common_test_get_alias_key);
TEST (riot_core_common_test_get_alias_key_null);
TEST (riot_core_common_test_get_alias_key_no_alias_key);
TEST (riot_core_common_test_get_alias_key_cert);
TEST (riot_core_common_test_get_alias_key_cert_null);
TEST (riot_core_common_test_get_alias_key_cert_no_alias_key);
TEST (riot_core_common_test_get_alias_key_cert_error);
TEST (riot_core_common_test_authenticate_generated_keys);

TEST_SUITE_END;
