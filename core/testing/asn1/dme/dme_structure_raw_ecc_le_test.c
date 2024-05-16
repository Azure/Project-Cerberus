// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/dme/dme_structure_raw_ecc_le.h"
#include "testing/asn1/dme/dme_structure_testing.h"
#include "testing/asn1/x509_testing.h"
#include "testing/crypto/ecc_testing.h"


TEST_SUITE_LABEL ("dme_structure_raw_ecc_le");


/*******************
 * Test cases
 *******************/

static void dme_structure_raw_ecc_le_test_init_sha384_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
}

static void dme_structure_raw_ecc_le_test_init_sha384_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC384_PUBKEY2_LE,
		&ECC384_PUBKEY2_LE[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384_RAW_S_LE, HASH_TYPE_SHA384);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC384_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha384_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC521_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha384_null (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384 (NULL, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, NULL, DME_STRUCTURE_TESTING_TYPE1_DATA_LEN,
		ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, NULL, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_LE, NULL,	ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, NULL, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,	NULL,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_raw_ecc_le_test_init_sha384_bad_structure_length (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN - 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN + 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha384_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_raw_ecc_le_test_init_sha384_unsupported_key_length (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		(224 / 8), DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], (536 / 8),
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha384_with_challenge_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
}

static void dme_structure_raw_ecc_le_test_init_sha384_with_challenge_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC384_PUBKEY2_LE,
		&ECC384_PUBKEY2_LE[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384_RAW_S_LE, HASH_TYPE_SHA384);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC384_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha384_with_challenge_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC521_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha384_with_challenge_null (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (NULL,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,	NULL,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256,	DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, NULL,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE,
		NULL, ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, NULL,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,	NULL, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_raw_ecc_le_test_init_sha384_with_challenge_bad_structure_length (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN - 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN + 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha384_with_challenge_unsupported_signature_hash (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_raw_ecc_le_test_init_sha384_with_challenge_unsupported_key_length (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], (224 / 8),
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha384_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE2_DATA, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], (536 / 8),
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha256_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
}

static void dme_structure_raw_ecc_le_test_init_sha256_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC384_PUBKEY2_LE,
		&ECC384_PUBKEY2_LE[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384_RAW_S_LE, HASH_TYPE_SHA384);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC384_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha256_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC521_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha256_null (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256 (NULL, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, NULL, DME_STRUCTURE_TESTING_TYPE3_DATA_LEN,
		ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, NULL, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_LE, NULL,	ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, NULL, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,	NULL,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_raw_ecc_le_test_init_sha256_bad_structure_length (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN - 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN + 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha256_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_raw_ecc_le_test_init_sha256_unsupported_key_length (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		(224 / 8), DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], (536 / 8),
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha256_with_challenge_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
}

static void dme_structure_raw_ecc_le_test_init_sha256_with_challenge_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC384_PUBKEY2_LE,
		&ECC384_PUBKEY2_LE[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384_RAW_S_LE, HASH_TYPE_SHA384);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC384_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha256_with_challenge_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC521_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha256_with_challenge_null (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (NULL,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,	NULL,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256,	DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, NULL,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE,
		NULL, ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, NULL,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,	NULL, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_raw_ecc_le_test_init_sha256_with_challenge_bad_structure_length (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN - 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN + 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha256_with_challenge_unsupported_signature_hash (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_raw_ecc_le_test_init_sha256_with_challenge_unsupported_key_length (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], (224 / 8),
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha256_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE4_DATA, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], (536 / 8),
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha512_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
}

static void dme_structure_raw_ecc_le_test_init_sha512_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC384_PUBKEY2_LE,
		&ECC384_PUBKEY2_LE[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384_RAW_S_LE, HASH_TYPE_SHA384);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC384_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha512_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC521_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha512_null (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512 (NULL, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, NULL, DME_STRUCTURE_TESTING_TYPE5_DATA_LEN,
		ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, NULL, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_LE, NULL,	ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, NULL, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,	NULL,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_raw_ecc_le_test_init_sha512_bad_structure_length (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN - 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN + 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha512_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_raw_ecc_le_test_init_sha512_unsupported_key_length (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		(224 / 8), DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], (536 / 8),
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha512_with_challenge_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
}

static void dme_structure_raw_ecc_le_test_init_sha512_with_challenge_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC384_PUBKEY2_LE,
		&ECC384_PUBKEY2_LE[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384_RAW_S_LE, HASH_TYPE_SHA384);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC384_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha512_with_challenge_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC521_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_sha512_with_challenge_null (CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (NULL,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,	NULL,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256,	DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, NULL,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE,
		NULL, ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, NULL,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,	NULL, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_raw_ecc_le_test_init_sha512_with_challenge_bad_structure_length (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN - 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN + 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_raw_ecc_le_test_init_sha512_with_challenge_unsupported_signature_hash (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_raw_ecc_le_test_init_sha512_with_challenge_unsupported_key_length (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], (224 / 8),
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_sha512_with_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE6_DATA, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], (536 / 8),
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
}

static void
dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_dme_key_ecc256 (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE7_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE7_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
}

static void
dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_dme_key_ecc384 (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC384_PUBKEY2_LE,
		&ECC384_PUBKEY2_LE[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC384_SHA384_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC384_SHA384_RAW_S_LE, HASH_TYPE_SHA384);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE7_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE7_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_SIG_ECC384_SHA384_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE7_SIG_ECC384_SHA384,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC384_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void
dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_dme_key_ecc521 (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_OID_LEN, dme.base.base.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE7_OID, dme.base.base.data_oid,
		dme.base.base.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, dme.base.base.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE7_DATA, (void*) dme.base.base.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN,
		dme.base.base.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512,
		dme.base.base.sig_oid, dme.base.base.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE7_SIG_ECC521_SHA512_LEN,
		dme.base.base.signature_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE7_SIG_ECC521_SHA512,
		dme.base.base.signature, dme.base.base.signature_length);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.base.base.key_length);
	status = testing_validate_array (ECC521_PUBKEY2_DER, dme.base.base.dme_pub_key,
		dme.base.base.key_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.device_oid);
	CuAssertIntEquals (test, 0, dme.base.base.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.base.base.renewal_counter);
	CuAssertIntEquals (test, 0, dme.base.base.counter_length);
#else
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_null (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (NULL,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,	NULL,
		DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE, &ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256,	DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, NULL,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE,
		NULL, ECC_KEY_LENGTH_256, DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, NULL,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,	NULL, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void
dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_bad_structure_length (
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN - 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN + 1, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void
dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_unsupported_signature_hash
(
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void
dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_unsupported_key_length
(
	CuTest *test)
{
	struct dme_structure_raw_ecc_le dme;
	int status;

	TEST_START;

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC_PUBKEY2_LE,
		&ECC_PUBKEY2_LE[ECC_KEY_LENGTH_256], (224 / 8),
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC256_SHA256_RAW_S_LE, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);

	status = dme_structure_raw_ecc_le_init_le_ecc384_with_sha512_nonce_and_challenge (&dme,
		DME_STRUCTURE_TESTING_TYPE7_DATA, DME_STRUCTURE_TESTING_TYPE7_DATA_LEN, ECC521_PUBKEY2_LE,
		&ECC521_PUBKEY2_LE[ECC_KEY_LENGTH_521], (536 / 8),
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC521_SHA512_RAW_R_LE,
		DME_STRUCTURE_TESTING_TYPE7_SIG_ECC521_SHA512_RAW_S_LE, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH, status);
}


// *INDENT-OFF*
TEST_SUITE_START (dme_structure_raw_ecc_le);

TEST (dme_structure_raw_ecc_le_test_init_sha384_dme_key_ecc256);
TEST (dme_structure_raw_ecc_le_test_init_sha384_dme_key_ecc384);
TEST (dme_structure_raw_ecc_le_test_init_sha384_dme_key_ecc521);
TEST (dme_structure_raw_ecc_le_test_init_sha384_null);
TEST (dme_structure_raw_ecc_le_test_init_sha384_bad_structure_length);
TEST (dme_structure_raw_ecc_le_test_init_sha384_unsupported_signature_hash);
TEST (dme_structure_raw_ecc_le_test_init_sha384_unsupported_key_length);
TEST (dme_structure_raw_ecc_le_test_init_sha384_with_challenge_dme_key_ecc256);
TEST (dme_structure_raw_ecc_le_test_init_sha384_with_challenge_dme_key_ecc384);
TEST (dme_structure_raw_ecc_le_test_init_sha384_with_challenge_dme_key_ecc521);
TEST (dme_structure_raw_ecc_le_test_init_sha384_with_challenge_null);
TEST (dme_structure_raw_ecc_le_test_init_sha384_with_challenge_bad_structure_length);
TEST (dme_structure_raw_ecc_le_test_init_sha384_with_challenge_unsupported_signature_hash);
TEST (dme_structure_raw_ecc_le_test_init_sha384_with_challenge_unsupported_key_length);
TEST (dme_structure_raw_ecc_le_test_init_sha256_dme_key_ecc256);
TEST (dme_structure_raw_ecc_le_test_init_sha256_dme_key_ecc384);
TEST (dme_structure_raw_ecc_le_test_init_sha256_dme_key_ecc521);
TEST (dme_structure_raw_ecc_le_test_init_sha256_null);
TEST (dme_structure_raw_ecc_le_test_init_sha256_bad_structure_length);
TEST (dme_structure_raw_ecc_le_test_init_sha256_unsupported_signature_hash);
TEST (dme_structure_raw_ecc_le_test_init_sha256_unsupported_key_length);
TEST (dme_structure_raw_ecc_le_test_init_sha256_with_challenge_dme_key_ecc256);
TEST (dme_structure_raw_ecc_le_test_init_sha256_with_challenge_dme_key_ecc384);
TEST (dme_structure_raw_ecc_le_test_init_sha256_with_challenge_dme_key_ecc521);
TEST (dme_structure_raw_ecc_le_test_init_sha256_with_challenge_null);
TEST (dme_structure_raw_ecc_le_test_init_sha256_with_challenge_bad_structure_length);
TEST (dme_structure_raw_ecc_le_test_init_sha256_with_challenge_unsupported_signature_hash);
TEST (dme_structure_raw_ecc_le_test_init_sha256_with_challenge_unsupported_key_length);
TEST (dme_structure_raw_ecc_le_test_init_sha512_dme_key_ecc256);
TEST (dme_structure_raw_ecc_le_test_init_sha512_dme_key_ecc384);
TEST (dme_structure_raw_ecc_le_test_init_sha512_dme_key_ecc521);
TEST (dme_structure_raw_ecc_le_test_init_sha512_null);
TEST (dme_structure_raw_ecc_le_test_init_sha512_bad_structure_length);
TEST (dme_structure_raw_ecc_le_test_init_sha512_unsupported_signature_hash);
TEST (dme_structure_raw_ecc_le_test_init_sha512_unsupported_key_length);
TEST (dme_structure_raw_ecc_le_test_init_sha512_with_challenge_dme_key_ecc256);
TEST (dme_structure_raw_ecc_le_test_init_sha512_with_challenge_dme_key_ecc384);
TEST (dme_structure_raw_ecc_le_test_init_sha512_with_challenge_dme_key_ecc521);
TEST (dme_structure_raw_ecc_le_test_init_sha512_with_challenge_null);
TEST (dme_structure_raw_ecc_le_test_init_sha512_with_challenge_bad_structure_length);
TEST (dme_structure_raw_ecc_le_test_init_sha512_with_challenge_unsupported_signature_hash);
TEST (dme_structure_raw_ecc_le_test_init_sha512_with_challenge_unsupported_key_length);
TEST (dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_dme_key_ecc256);
TEST (dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_dme_key_ecc384);
TEST (dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_dme_key_ecc521);
TEST (dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_null);
TEST (dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_bad_structure_length);
TEST (dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_unsupported_signature_hash);
TEST (dme_structure_raw_ecc_le_test_init_le_ecc384_with_sha512_nonce_and_challenge_unsupported_key_length);

TEST_SUITE_END;
// *INDENT-ON*
