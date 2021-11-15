// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "riot/x509_riot.h"
#include "riot/reference/include/RiotX509Bldr.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/crypto/x509_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("x509_riot");


/*******************
 * Test cases
 *******************/

static void x509_riot_test_init (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.create_csr);
	CuAssertPtrNotNull (test, engine.base.create_self_signed_certificate);
	CuAssertPtrNotNull (test, engine.base.create_ca_signed_certificate);
	CuAssertPtrNotNull (test, engine.base.load_certificate);
	CuAssertPtrNotNull (test, engine.base.release_certificate);
	CuAssertPtrNotNull (test, engine.base.get_certificate_der);
	CuAssertPtrEquals (test, NULL, engine.base.get_certificate_version);
	CuAssertPtrEquals (test, NULL, engine.base.get_serial_number);
	CuAssertPtrEquals (test, NULL, engine.base.get_public_key_type);
	CuAssertPtrEquals (test, NULL, engine.base.get_public_key_length);
	CuAssertPtrEquals (test, NULL, engine.base.get_public_key);
	CuAssertPtrEquals (test, NULL, engine.base.add_root_ca);
	CuAssertPtrEquals (test, NULL, engine.base.init_ca_cert_store);
	CuAssertPtrEquals (test, NULL, engine.base.release_ca_cert_store);
	CuAssertPtrEquals (test, NULL, engine.base.add_intermediate_ca);
	CuAssertPtrEquals (test, NULL, engine.base.authenticate);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_init_null (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (NULL, &ecc.base, &hash.base);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = x509_riot_init (&engine, NULL, &hash.base);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = x509_riot_init (&engine, &ecc.base, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_release_null (CuTest *test)
{
	TEST_START;

	x509_riot_release (NULL);
}

static void x509_riot_test_create_csr_ecc_ca (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, NULL, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ecc_end_entity (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, NULL, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_EE, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_non_zero_path_length_constraint (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_PATHLEN (2), NULL, NULL, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_PL2, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_no_path_length_constraint (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, NULL, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_NOPL, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_with_eku_oid (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, X509_EKU_OID, NULL, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_EKU, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_end_entity_with_eku_oid (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	csr = (uint8_t*) &length;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_END_ENTITY, X509_EKU_OID, NULL, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_NOT_CA_CERT, status);
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_tcbinfo_and_ueid_extension (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_end_entity_tcbinfo_and_ueid_extension (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_tcbinfo_and_ueid_extension_sha1 (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA1_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA1;
	tcb.ueid = &ueid;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA1, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_tcbinfo_and_ueid_extension_svn_zero (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = 0;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SVN, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_tcbinfo_extension_ueid_null (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = NULL;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_end_entity_tcbinfo_extension_ueid_null (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = NULL;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_null (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	uint8_t *csr = (uint8_t*) &status;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (NULL, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, NULL, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	csr = (uint8_t*) &status;
	status = engine.base.create_csr (&engine.base, NULL, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, NULL, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	csr = (uint8_t*) &status;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, 0,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, NULL, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	csr = (uint8_t*) &status;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		NULL, X509_CERT_CA, NULL, NULL, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, NULL, NULL, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	csr = (uint8_t*) &status;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, NULL, &csr, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_with_public_key (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	uint8_t *csr = (uint8_t*) &status;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, NULL, &csr, &length);
	CuAssertTrue (test, (status < 0));
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_tcbinfo_unknown_hash (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = (enum hash_type) 10;
	tcb.ueid = &ueid;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_RIOT_UNSUPPORTED_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_tcbinfo_fwid_null (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = NULL;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_RIOT_NO_FWID, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ca_tcbinfo_version_null (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = NULL;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_VERSION, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ueid_null (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = NULL;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_UEID, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_csr_ueid_zero_length (CuTest *test)
{
	struct x509_engine_riot engine;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = 0;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, &tcb, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_UEID, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ecc_ca (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ecc_end_entity (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ca_non_zero_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME,
		X509_CERT_CA_PATHLEN (1), NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_PL1, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ca_no_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME,
		X509_CERT_CA_NO_PATHLEN, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_NOPL, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, &tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha1 (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA1_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA1;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA1, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_svn_zero (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = 0;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SVN, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ecc_ca_tcbinfo_extension_ueid_null (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = NULL;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_extension_ueid_null (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = NULL;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, &tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (NULL, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, NULL, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, NULL,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		0, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, 0, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, NULL, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_with_public_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertTrue (test, (status < 0));

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_with_long_serial_num (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, X509_SERIAL_NUM, RIOT_X509_SNUM_LEN + 1, X509_SUBJECT_NAME,
		X509_CERT_CA, NULL);
	CuAssertIntEquals (test, X509_ENGINE_LONG_SERIAL_NUM, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_tcbinfo_unknown_hash (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = (enum hash_type) 10;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, X509_ENGINE_RIOT_UNSUPPORTED_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_tcbinfo_fwid_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = NULL;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, X509_ENGINE_RIOT_NO_FWID, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_tcbinfo_version_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = NULL;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_VERSION, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ueid_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = NULL;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_UEID, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_ueid_zero_length (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = 0;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		&tcb);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_UEID, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_self_signed_certificate_serial_zero (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t zero[] = {0};
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, zero, sizeof (zero), X509_SUBJECT_NAME, X509_CERT_CA, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_SERIAL_NUM, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_load_certificate (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, X509_CERTSS_ECC_CA_DER_LEN, length);

	status = testing_validate_array (X509_CERTSS_ECC_CA_DER, der, X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_load_certificate_riot (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_ECC_EE_UEID_DER,
		X509_CERTCA_ECC_EE_UEID_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, X509_CERTCA_ECC_EE_UEID_DER_LEN, length);

	status = testing_validate_array (X509_CERTCA_ECC_EE_UEID_DER, der,
		X509_CERTCA_ECC_EE_UEID_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_load_certificate_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (NULL, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.load_certificate (&engine.base, NULL, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.load_certificate (&engine.base, &cert, NULL,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,	0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_load_certificate_bad (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t bad_cert[X509_CERTSS_ECC_CA_DER_LEN];
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	memcpy (bad_cert, X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);
	bad_cert[0] ^= 0x55;	/* Corrupt the certificate. */

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, X509_ENGINE_LOAD_FAILED, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_load_certificate_big_cert_size (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_MAX_SIZE+1);
	CuAssertIntEquals (test, X509_ENGINE_BIG_CERT_SIZE, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ecc_ca_private_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_intermediate_ca_ecc_ca_private_key (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA3_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2_ICA, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ecc_end_entity_private_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_rsa_ca_private_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ecc_ca_public_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ecc_end_entity_public_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_rsa_ca_public_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, RSA_CA, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_rsa_end_entity_public_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, RSA_EE, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ecc_ca2_public_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_end_entity_ecc_ca2_public_key (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ca_non_zero_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA_PATHLEN (15), ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2_PL15, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ca_no_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA_NO_PATHLEN, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2_NOPL, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_end_entity_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&ca_cert, &tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha1 (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA1_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA1;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA1, CERTCA, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_svn_zero (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = 0;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SVN, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ca_tcbinfo_extension_ueid_null (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = NULL;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_end_entity_tcbinfo_extension_ueid_null (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = NULL;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&ca_cert, &tcb);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (NULL, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, NULL, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, NULL,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		0, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, NULL, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, 0, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, NULL,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, NULL, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, 0, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ca_public_key (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &ca_cert, NULL);
	CuAssertTrue (test, (status != 0));

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_tcbinfo_extension_unknown_hash (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = (enum hash_type) 10;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, X509_ENGINE_RIOT_UNSUPPORTED_HASH, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_tcbinfo_extension_fwid_null (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = NULL;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, X509_ENGINE_RIOT_NO_FWID, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_tcbinfo_extension_version_null (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = NULL;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_VERSION, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ueid_extension_ueid_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = NULL;
	ueid.length = X509_RIOT_UEID_LEN;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_UEID, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_ueid_extension_ueid_zero_length (
	CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_dice_tcbinfo tcb;
	struct x509_dice_ueid ueid;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ueid.ueid = X509_RIOT_UEID;
	ueid.length = 0;

	tcb.version = X509_RIOT_VERSION;
	tcb.svn = X509_RIOT_SVN;
	tcb.fw_id = X509_RIOT_SHA256_FWID;
	tcb.fw_id_hash = HASH_TYPE_SHA256;
	tcb.ueid = &ueid;

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, &tcb);
	CuAssertIntEquals (test, X509_ENGINE_DICE_NO_UEID, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_serial_zero (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t zero[] = {0};
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, zero, sizeof (zero), X509_CA2_SUBJECT_NAME, X509_CERT_CA,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_SERIAL_NUM, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_create_ca_signed_certificate_with_long_serial_num (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN+1, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_LONG_SERIAL_NUM, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_release_certificate_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (NULL, &cert);
	engine.base.release_certificate (&engine.base, NULL);

	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}

static void x509_riot_test_get_certificate_der_null (CuTest *test)
{
	struct x509_engine_riot engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_riot_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	der = (uint8_t*) &status;
	status = engine.base.get_certificate_der (NULL, &cert, &der, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	der = (uint8_t*) &status;
	status = engine.base.get_certificate_der (&engine.base, NULL, &der, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	status = engine.base.get_certificate_der (&engine.base, &cert, NULL, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	der = (uint8_t*) &status;
	status = engine.base.get_certificate_der (&engine.base, &cert, &der, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_riot_release (&engine);
}


TEST_SUITE_START (x509_riot);

TEST (x509_riot_test_init);
TEST (x509_riot_test_init_null);
TEST (x509_riot_test_release_null);
TEST (x509_riot_test_create_csr_ecc_ca);
TEST (x509_riot_test_create_csr_ecc_end_entity);
TEST (x509_riot_test_create_csr_ca_non_zero_path_length_constraint);
TEST (x509_riot_test_create_csr_ca_no_path_length_constraint);
TEST (x509_riot_test_create_csr_ca_with_eku_oid);
TEST (x509_riot_test_create_csr_end_entity_with_eku_oid);
TEST (x509_riot_test_create_csr_ca_tcbinfo_and_ueid_extension);
TEST (x509_riot_test_create_csr_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_riot_test_create_csr_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_riot_test_create_csr_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_riot_test_create_csr_ca_tcbinfo_extension_ueid_null);
TEST (x509_riot_test_create_csr_end_entity_tcbinfo_extension_ueid_null);
TEST (x509_riot_test_create_csr_null);
TEST (x509_riot_test_create_csr_with_public_key);
TEST (x509_riot_test_create_csr_ca_tcbinfo_unknown_hash);
TEST (x509_riot_test_create_csr_ca_tcbinfo_fwid_null);
TEST (x509_riot_test_create_csr_ca_tcbinfo_version_null);
TEST (x509_riot_test_create_csr_ueid_null);
TEST (x509_riot_test_create_csr_ueid_zero_length);
TEST (x509_riot_test_create_self_signed_certificate_ecc_ca);
TEST (x509_riot_test_create_self_signed_certificate_ecc_end_entity);
TEST (x509_riot_test_create_self_signed_certificate_ca_non_zero_path_length_constraint);
TEST (x509_riot_test_create_self_signed_certificate_ca_no_path_length_constraint);
TEST (x509_riot_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension);
TEST (x509_riot_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_riot_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_riot_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_riot_test_create_self_signed_certificate_ecc_ca_tcbinfo_extension_ueid_null);
TEST (x509_riot_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_extension_ueid_null);
TEST (x509_riot_test_create_self_signed_certificate_null);
TEST (x509_riot_test_create_self_signed_certificate_with_public_key);
TEST (x509_riot_test_create_self_signed_certificate_with_long_serial_num);
TEST (x509_riot_test_create_self_signed_certificate_tcbinfo_unknown_hash);
TEST (x509_riot_test_create_self_signed_certificate_tcbinfo_fwid_null);
TEST (x509_riot_test_create_self_signed_certificate_tcbinfo_version_null);
TEST (x509_riot_test_create_self_signed_certificate_ueid_null);
TEST (x509_riot_test_create_self_signed_certificate_ueid_zero_length);
TEST (x509_riot_test_create_self_signed_certificate_serial_zero);
TEST (x509_riot_test_load_certificate);
TEST (x509_riot_test_load_certificate_riot);
TEST (x509_riot_test_load_certificate_null);
TEST (x509_riot_test_load_certificate_bad);
TEST (x509_riot_test_load_certificate_big_cert_size);
TEST (x509_riot_test_create_ca_signed_certificate_ecc_ca_private_key);
TEST (x509_riot_test_create_ca_signed_certificate_intermediate_ca_ecc_ca_private_key);
TEST (x509_riot_test_create_ca_signed_certificate_ecc_end_entity_private_key);
TEST (x509_riot_test_create_ca_signed_certificate_rsa_ca_private_key);
TEST (x509_riot_test_create_ca_signed_certificate_ecc_ca_public_key);
TEST (x509_riot_test_create_ca_signed_certificate_ecc_end_entity_public_key);
TEST (x509_riot_test_create_ca_signed_certificate_rsa_ca_public_key);
TEST (x509_riot_test_create_ca_signed_certificate_rsa_end_entity_public_key);
TEST (x509_riot_test_create_ca_signed_certificate_ecc_ca2_public_key);
TEST (x509_riot_test_create_ca_signed_certificate_end_entity_ecc_ca2_public_key);
TEST (x509_riot_test_create_ca_signed_certificate_ca_non_zero_path_length_constraint);
TEST (x509_riot_test_create_ca_signed_certificate_ca_no_path_length_constraint);
TEST (x509_riot_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension);
TEST (x509_riot_test_create_ca_signed_certificate_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_riot_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_riot_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_riot_test_create_ca_signed_certificate_ca_tcbinfo_extension_ueid_null);
TEST (x509_riot_test_create_ca_signed_certificate_end_entity_tcbinfo_extension_ueid_null);
TEST (x509_riot_test_create_ca_signed_certificate_null);
TEST (x509_riot_test_create_ca_signed_certificate_ca_public_key);
TEST (x509_riot_test_create_ca_signed_certificate_tcbinfo_extension_unknown_hash);
TEST (x509_riot_test_create_ca_signed_certificate_tcbinfo_extension_fwid_null);
TEST (x509_riot_test_create_ca_signed_certificate_tcbinfo_extension_version_null);
TEST (x509_riot_test_create_ca_signed_certificate_ueid_extension_ueid_null);
TEST (x509_riot_test_create_ca_signed_certificate_ueid_extension_ueid_zero_length);
TEST (x509_riot_test_create_ca_signed_certificate_serial_zero);
TEST (x509_riot_test_create_ca_signed_certificate_with_long_serial_num);
TEST (x509_riot_test_release_certificate_null);
TEST (x509_riot_test_get_certificate_der_null);

TEST_SUITE_END;
