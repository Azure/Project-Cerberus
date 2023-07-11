// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/x509_cert_build.h"
#include "asn1/x509_cert_build_static.h"
#include "common/array_size.h"
#include "riot/reference/include/RiotX509Bldr.h"
#include "testing/mock/asn1/x509_extension_builder_mock.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/asn1/x509_testing.h"
#include "testing/asn1/dice/x509_extension_builder_dice_tcbinfo_testing.h"
#include "testing/asn1/dice/x509_extension_builder_dice_ueid_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("x509_cert_build");


/*******************
 * Test cases
 *******************/

static void x509_cert_build_test_init (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
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
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_init_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (NULL, &ecc.base, &hash.base);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = x509_cert_build_init (&engine, NULL, &hash.base);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = x509_cert_build_init (&engine, &ecc.base, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_static_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct x509_engine_cert_build engine = x509_cert_build_static_init (&ecc.base, &hash.base);

	TEST_START;

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

	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_release_null (CuTest *test)
{
	TEST_START;

	x509_cert_build_release (NULL);
}

static void x509_cert_build_test_create_csr_ecc_ca (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ecc_end_entity (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_EE, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void x509_cert_build_test_create_csr_ecc384_ca (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC384_CA, CSR, UTF8STRING, ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ecc384_end_entity (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC384_EE, CSR, UTF8STRING, ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_cert_build_test_create_csr_ecc521_ca (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC521_CA, CSR, UTF8STRING, ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ecc521_end_entity (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC521_EE, CSR, UTF8STRING, ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

static void x509_cert_build_test_create_csr_ca_non_zero_path_length_constraint (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA_PATHLEN (2), NULL, 0, NULL, 0, &csr,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_PL2, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_no_path_length_constraint (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0, NULL, 0, &csr,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_NOPL, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_with_eku_oid (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, X509_EKU_OID, X509_EKU_OID_LEN, NULL, 0,
		&csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_EKU, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_end_entity_with_eku_oid (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	csr = (uint8_t*) &length;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, X509_EKU_OID, X509_EKU_OID_LEN,
		NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_NOT_CA_CERT, status);
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_end_entity_tcbinfo_and_ueid_extension (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension_sha1 (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA1,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA1), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA1, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension_sha384 (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA384, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension_sha512 (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA512, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension_svn_zero (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SVN_ZERO,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SVN_ZERO), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SVN, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_tcbinfo_extension_no_ueid (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_end_entity_tcbinfo_extension_no_ueid (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_critical_extension (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	struct x509_extension critical_ext;
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	memcpy (&critical_ext, &X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (critical_ext));
	critical_ext.critical = true;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0, &critical_ext, sizeof (critical_ext), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO_CRIT, CSR, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ca_null_extension (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {NULL, &tcb.base, NULL, NULL, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_static_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct x509_engine_cert_build engine = x509_cert_build_static_init (&ecc.base, &hash.base);
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA, CSR, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (NULL, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	csr = (uint8_t*) &status;
	status = engine.base.create_csr (&engine.base, NULL, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	csr = (uint8_t*) &status;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, 0,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	csr = (uint8_t*) &status;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, NULL, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, NULL, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	csr = (uint8_t*) &status;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_eku_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, X509_EKU_OID_LEN, NULL, 0, &csr,
		&length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_extensions_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 2, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_with_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertTrue (test, (status < 0));
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_sig_unsupported_hash (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA1, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);
	CuAssertPtrEquals (test, NULL, csr);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		(enum hash_type) 10, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);
	CuAssertPtrEquals (test, NULL, csr);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_tcbinfo_error (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, X509_EXTENSION_BUILD_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILD_FAILED, status);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_csr_ueid_error (CuTest *test)
{
	struct x509_engine_cert_build engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, X509_EXTENSION_BUILD_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, extensions,
		ARRAY_SIZE (extensions), &csr, &length);
	CuAssertIntEquals (test, X509_EXTENSION_BUILD_FAILED, status);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_ca (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_end_entity (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void x509_cert_build_test_create_self_signed_certificate_ecc384_ca (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY_DER,
		ECC384_PRIVKEY_DER_LEN, HASH_TYPE_SHA384, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_CA, CERTSS, UTF8STRING,
		ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc384_end_entity (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY_DER,
		ECC384_PRIVKEY_DER_LEN, HASH_TYPE_SHA384, X509_ENTITY_SERIAL_NUM,
		X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_EE, CERTSS, UTF8STRING,
		ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_cert_build_test_create_self_signed_certificate_ecc521_ca (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC521_PRIVKEY_DER,
		ECC521_PRIVKEY_DER_LEN, HASH_TYPE_SHA512, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_CA, CERTSS, UTF8STRING,
		ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc521_end_entity (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC521_PRIVKEY_DER,
		ECC521_PRIVKEY_DER_LEN, HASH_TYPE_SHA512, X509_ENTITY_SERIAL_NUM,
		X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_EE, CERTSS, UTF8STRING,
		ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

static void x509_cert_build_test_create_self_signed_certificate_ca_non_zero_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_PATHLEN (1), NULL, 0);
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
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ca_no_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
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
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha1 (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA1,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA1), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA1, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha384 (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA384, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha512 (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA512, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_svn_zero (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SVN_ZERO,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SVN_ZERO), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SVN, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_extension_no_ueid (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_extension_no_ueid (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ca_critical_extension (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	struct x509_extension critical_ext;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	memcpy (&critical_ext, &X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (critical_ext));
	critical_ext.critical = true;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0, &critical_ext, sizeof (critical_ext), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO_CRIT, CERTSS, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ca_null_extension (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {NULL, &tcb.base, NULL, NULL, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_static_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct x509_engine_cert_build engine = x509_cert_build_static_init (&ecc.base, &hash.base);
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA, CERTSS, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (NULL, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, NULL, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, NULL,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		0, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, NULL, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, 0,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		NULL, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_extensions_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 2);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_with_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertTrue (test, (status < 0));

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_sig_unsupported_hash (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA1, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, (enum hash_type) 10, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_serial_zero (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, zero, sizeof (zero), X509_SUBJECT_NAME, X509_CERT_CA,
		NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_SERIAL_NUM, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_tcbinfo_error (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, X509_EXTENSION_BUILD_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, X509_EXTENSION_BUILD_FAILED, status);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_self_signed_certificate_ueid_error (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, X509_EXTENSION_BUILD_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, X509_EXTENSION_BUILD_FAILED, status);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_load_certificate (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
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
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_load_certificate_cert_build (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
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
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_load_certificate_static_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct x509_engine_cert_build engine = x509_cert_build_static_init (&ecc.base, &hash.base);
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
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
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_load_certificate_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
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
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_load_certificate_bad (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, X509_ENGINE_LOAD_FAILED, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_load_certificate_big_cert_size (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERT_BUILD_MAX_SIZE + 1);
	CuAssertIntEquals (test, X509_ENGINE_BIG_CERT_SIZE, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc_ca_private_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_intermediate_ca_ecc_ca_private_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA3_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2_ICA, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc_end_entity_private_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void x509_cert_build_test_create_ca_signed_certificate_ecc384_ca_private_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY2_DER,
		ECC384_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		X509_CA2_SUBJECT_NAME, X509_CERT_CA, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_CA2, CERTCA, UTF8STRING,
		ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_intermediate_ca_ecc384_ca_private_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTCA_ECC384_CA_DER,
		X509_CERTCA_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY2_DER,
		ECC384_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		X509_CA3_SUBJECT_NAME, X509_CERT_CA, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_CA2_ICA, CERTCA, UTF8STRING,
		ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc384_end_entity_private_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY2_DER,
		ECC384_PRIVKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_EE2, CERTCA, UTF8STRING,
		ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_cert_build_test_create_ca_signed_certificate_ecc521_ca_private_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC521_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PRIVKEY2_DER,
		ECC521_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		X509_CA2_SUBJECT_NAME, X509_CERT_CA, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_CA2, CERTCA, UTF8STRING,
		ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_intermediate_ca_ecc521_ca_private_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTCA_ECC521_CA_DER,
		X509_CERTCA_ECC521_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PRIVKEY2_DER,
		ECC521_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		X509_CA3_SUBJECT_NAME, X509_CERT_CA, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_CA2_ICA, CERTCA, UTF8STRING,
		ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc521_end_entity_private_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC521_CA_DER,
		X509_CERTSS_ECC521_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PRIVKEY2_DER,
		ECC521_PRIVKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_EE2, CERTCA, UTF8STRING,
		ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

static void x509_cert_build_test_create_ca_signed_certificate_rsa_ca_private_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc_ca_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc_end_entity_public_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void x509_cert_build_test_create_ca_signed_certificate_ecc384_ca_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc384_end_entity_public_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PUBKEY2_DER,
		ECC384_PUBKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_EE2, CERTCA, UTF8STRING,
		ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_cert_build_test_create_ca_signed_certificate_ecc521_ca_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PUBKEY_DER,
		ECC521_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc521_end_entity_public_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC521_CA_DER,
		X509_CERTSS_ECC521_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PUBKEY2_DER,
		ECC521_PUBKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_EE2, CERTCA, UTF8STRING,
		ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

static void x509_cert_build_test_create_ca_signed_certificate_rsa_ca_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, RSA_CA, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_rsa_end_entity_public_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, RSA_EE, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ecc_ca2_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_end_entity_ecc_ca2_public_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void x509_cert_build_test_create_ca_signed_certificate_ecc384_ca2_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PUBKEY2_DER,
		ECC384_PUBKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN, HASH_TYPE_SHA384, &ca_cert, NULL,
		0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_CA2, CERTCA, UTF8STRING,
		ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_end_entity_ecc384_ca2_public_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PUBKEY2_DER,
		ECC384_PUBKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_EE2, CERTCA, UTF8STRING,
		ECDSA_SHA384_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_cert_build_test_create_ca_signed_certificate_ecc521_ca2_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC521_CA_DER,
		X509_CERTSS_ECC521_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PUBKEY2_DER,
		ECC521_PUBKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN, HASH_TYPE_SHA512, &ca_cert, NULL,
		0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_CA2, CERTCA, UTF8STRING,
		ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_end_entity_ecc521_ca2_public_key (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC521_CA_DER,
		X509_CERTSS_ECC521_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PUBKEY2_DER,
		ECC521_PUBKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_EE2, CERTCA, UTF8STRING,
		ECDSA_SHA512_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}
#endif

static void x509_cert_build_test_create_ca_signed_certificate_ca_non_zero_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA_PATHLEN (15), ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert,
		NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2_PL15, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_no_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA_NO_PATHLEN, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert,
		NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2_NOPL, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_end_entity_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha1 (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA1,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA1), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA1, CERTCA, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha384 (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA384, CERTCA, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha512 (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA512, CERTCA, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_svn_zero (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SVN_ZERO,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SVN_ZERO), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SVN, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_extension_no_ueid (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_end_entity_tcbinfo_extension_no_ueid (
	CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_critical_extension (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	struct x509_extension critical_ext;
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	memcpy (&critical_ext, &X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (critical_ext));
	critical_ext.critical = true;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0, &critical_ext, sizeof (critical_ext), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO_CRIT, CERTCA, UTF8STRING,
		ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_null_extension (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {NULL, &tcb.base, NULL, NULL, &ueid.base};
	uint8_t *der = NULL;
	size_t length;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ueid.mock, 0, 0);
	status |= mock_expect_output (&ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&ueid.mock, ueid.base.free, &ueid, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_static_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct x509_engine_cert_build engine = x509_cert_build_static_init (&ecc.base, &hash.base);
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA2, CERTCA, UTF8STRING, ECDSA_NO_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (NULL, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, NULL, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, NULL,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		0, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, NULL, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, 0, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, NULL,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, NULL, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, 0, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, NULL, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_extensions_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 2);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ca_public_key (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertTrue (test, (status != 0));

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_sig_unsupported_hash (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA1, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, (enum hash_type) 10, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_serial_zero (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, zero, sizeof (zero), X509_CA2_SUBJECT_NAME, X509_CERT_CA,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_SERIAL_NUM, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_tcbinfo_error (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, X509_EXTENSION_BUILD_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, X509_EXTENSION_BUILD_FAILED, status);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_create_ca_signed_certificate_ueid_error (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&ueid.mock, "ueid");

	status = mock_expect (&tcb.mock, tcb.base.build, &tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&tcb.mock, 0, 0);
	status |= mock_expect_output (&tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&tcb.mock, tcb.base.free, &tcb, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ueid.mock, ueid.base.build, &ueid, X509_EXTENSION_BUILD_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY2_DER,
		ECC_PRIVKEY2_DER_LEN, X509_RIOT_SERIAL_NUM, X509_RIOT_SERIAL_NUM_LEN,
		X509_RIOT_SUBJECT_NAME, X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, extensions, ARRAY_SIZE (extensions));
	CuAssertIntEquals (test, X509_EXTENSION_BUILD_FAILED, status);

	status = x509_extension_builder_mock_validate_and_release (&tcb);
	status |= x509_extension_builder_mock_validate_and_release (&ueid);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_release_certificate_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
	struct x509_certificate cert;
	int status;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (NULL, &cert);
	engine.base.release_certificate (&engine.base, NULL);

	engine.base.release_certificate (&engine.base, &cert);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	x509_cert_build_release (&engine);
}

static void x509_cert_build_test_get_certificate_der_null (CuTest *test)
{
	struct x509_engine_cert_build engine;
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

	status = x509_cert_build_init (&engine, &ecc.base, &hash.base);
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
	x509_cert_build_release (&engine);
}


TEST_SUITE_START (x509_cert_build);

TEST (x509_cert_build_test_init);
TEST (x509_cert_build_test_init_null);
TEST (x509_cert_build_test_static_init);
TEST (x509_cert_build_test_release_null);
TEST (x509_cert_build_test_create_csr_ecc_ca);
TEST (x509_cert_build_test_create_csr_ecc_end_entity);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (x509_cert_build_test_create_csr_ecc384_ca);
TEST (x509_cert_build_test_create_csr_ecc384_end_entity);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_cert_build_test_create_csr_ecc521_ca);
TEST (x509_cert_build_test_create_csr_ecc521_end_entity);
#endif
TEST (x509_cert_build_test_create_csr_ca_non_zero_path_length_constraint);
TEST (x509_cert_build_test_create_csr_ca_no_path_length_constraint);
TEST (x509_cert_build_test_create_csr_ca_with_eku_oid);
TEST (x509_cert_build_test_create_csr_end_entity_with_eku_oid);
TEST (x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension);
TEST (x509_cert_build_test_create_csr_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension_sha384);
TEST (x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension_sha512);
TEST (x509_cert_build_test_create_csr_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_cert_build_test_create_csr_ca_tcbinfo_extension_no_ueid);
TEST (x509_cert_build_test_create_csr_end_entity_tcbinfo_extension_no_ueid);
TEST (x509_cert_build_test_create_csr_ca_critical_extension);
TEST (x509_cert_build_test_create_csr_ca_null_extension);
TEST (x509_cert_build_test_create_csr_static_init);
TEST (x509_cert_build_test_create_csr_null);
TEST (x509_cert_build_test_create_csr_eku_null);
TEST (x509_cert_build_test_create_csr_extensions_null);
TEST (x509_cert_build_test_create_csr_with_public_key);
TEST (x509_cert_build_test_create_csr_sig_unsupported_hash);
TEST (x509_cert_build_test_create_csr_tcbinfo_error);
TEST (x509_cert_build_test_create_csr_ueid_error);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_ca);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_end_entity);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (x509_cert_build_test_create_self_signed_certificate_ecc384_ca);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc384_end_entity);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_cert_build_test_create_self_signed_certificate_ecc521_ca);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc521_end_entity);
#endif
TEST (x509_cert_build_test_create_self_signed_certificate_ca_non_zero_path_length_constraint);
TEST (x509_cert_build_test_create_self_signed_certificate_ca_no_path_length_constraint);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha384);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha512);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_ca_tcbinfo_extension_no_ueid);
TEST (x509_cert_build_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_extension_no_ueid);
TEST (x509_cert_build_test_create_self_signed_certificate_ca_critical_extension);
TEST (x509_cert_build_test_create_self_signed_certificate_ca_null_extension);
TEST (x509_cert_build_test_create_self_signed_certificate_static_init);
TEST (x509_cert_build_test_create_self_signed_certificate_null);
TEST (x509_cert_build_test_create_self_signed_certificate_extensions_null);
TEST (x509_cert_build_test_create_self_signed_certificate_with_public_key);
TEST (x509_cert_build_test_create_self_signed_certificate_sig_unsupported_hash);
TEST (x509_cert_build_test_create_self_signed_certificate_serial_zero);
TEST (x509_cert_build_test_create_self_signed_certificate_tcbinfo_error);
TEST (x509_cert_build_test_create_self_signed_certificate_ueid_error);
TEST (x509_cert_build_test_load_certificate);
TEST (x509_cert_build_test_load_certificate_cert_build);
TEST (x509_cert_build_test_load_certificate_static_init);
TEST (x509_cert_build_test_load_certificate_null);
TEST (x509_cert_build_test_load_certificate_bad);
TEST (x509_cert_build_test_load_certificate_big_cert_size);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc_ca_private_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_intermediate_ca_ecc_ca_private_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc_end_entity_private_key);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc384_ca_private_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_intermediate_ca_ecc384_ca_private_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc384_end_entity_private_key);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc521_ca_private_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_intermediate_ca_ecc521_ca_private_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc521_end_entity_private_key);
#endif
TEST (x509_cert_build_test_create_ca_signed_certificate_rsa_ca_private_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc_ca_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc_end_entity_public_key);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc384_ca_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc384_end_entity_public_key);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc521_ca_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc521_end_entity_public_key);
#endif
TEST (x509_cert_build_test_create_ca_signed_certificate_rsa_ca_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_rsa_end_entity_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc_ca2_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_end_entity_ecc_ca2_public_key);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc384_ca2_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_end_entity_ecc384_ca2_public_key);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_cert_build_test_create_ca_signed_certificate_ecc521_ca2_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_end_entity_ecc521_ca2_public_key);
#endif
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_non_zero_path_length_constraint);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_no_path_length_constraint);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension);
TEST (x509_cert_build_test_create_ca_signed_certificate_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha384);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha512);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_tcbinfo_extension_no_ueid);
TEST (x509_cert_build_test_create_ca_signed_certificate_end_entity_tcbinfo_extension_no_ueid);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_critical_extension);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_null_extension);
TEST (x509_cert_build_test_create_ca_signed_certificate_static_init);
TEST (x509_cert_build_test_create_ca_signed_certificate_null);
TEST (x509_cert_build_test_create_ca_signed_certificate_extensions_null);
TEST (x509_cert_build_test_create_ca_signed_certificate_ca_public_key);
TEST (x509_cert_build_test_create_ca_signed_certificate_sig_unsupported_hash);
TEST (x509_cert_build_test_create_ca_signed_certificate_serial_zero);
TEST (x509_cert_build_test_create_ca_signed_certificate_tcbinfo_error);
TEST (x509_cert_build_test_create_ca_signed_certificate_ueid_error);
TEST (x509_cert_build_test_release_certificate_null);
TEST (x509_cert_build_test_get_certificate_der_null);

TEST_SUITE_END;
