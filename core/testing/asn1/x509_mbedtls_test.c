// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/x509_mbedtls.h"
#include "common/array_size.h"
#include "crypto/ecc.h"
#include "testing/mock/asn1/x509_extension_builder_mock.h"
#include "testing/asn1/x509_testing.h"
#include "testing/asn1/dice/x509_extension_builder_dice_tcbinfo_testing.h"
#include "testing/asn1/dice/x509_extension_builder_dice_ueid_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("x509_mbedtls");


/*******************
 * Test cases
 *******************/

static void x509_mbedtls_test_init (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.create_csr);
	CuAssertPtrNotNull (test, engine.base.create_self_signed_certificate);
	CuAssertPtrNotNull (test, engine.base.create_ca_signed_certificate);
	CuAssertPtrNotNull (test, engine.base.load_certificate);
	CuAssertPtrNotNull (test, engine.base.release_certificate);
	CuAssertPtrNotNull (test, engine.base.get_certificate_der);
	CuAssertPtrNotNull (test, engine.base.get_certificate_version);
	CuAssertPtrNotNull (test, engine.base.get_serial_number);
	CuAssertPtrNotNull (test, engine.base.get_public_key_type);
	CuAssertPtrNotNull (test, engine.base.get_public_key_length);
	CuAssertPtrNotNull (test, engine.base.get_public_key);
	CuAssertPtrNotNull (test, engine.base.add_root_ca);
	CuAssertPtrNotNull (test, engine.base.init_ca_cert_store);
	CuAssertPtrNotNull (test, engine.base.release_ca_cert_store);
	CuAssertPtrNotNull (test, engine.base.add_intermediate_ca);
	CuAssertPtrNotNull (test, engine.base.authenticate);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = x509_mbedtls_init (NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
}

static void x509_mbedtls_test_release_null (CuTest *test)
{
	TEST_START;

	x509_mbedtls_release (NULL);
}

static void x509_mbedtls_test_create_csr_ecc_ca (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ecc_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_EE, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
#ifdef HASH_ENABLE_SHA384
static void x509_mbedtls_test_create_csr_ecc384_ca (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC384_CA, CSR, UTF8STRING, ECDSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ecc384_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC384_EE, CSR, UTF8STRING, ECDSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_create_csr_ecc384_ca_sha256_digest (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC384_SHA256_CA, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC384_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ecc384_end_entity_sha256_digest (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC384_SHA256_EE, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC384_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_mbedtls_test_create_csr_ecc521_ca (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC521_CA, CSR, UTF8STRING, ECDSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ecc521_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC521_EE, CSR, UTF8STRING, ECDSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_create_csr_rsa_ca (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, RSA_CA, CSR, UTF8STRING, RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_rsa (test, csr, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_rsa_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, RSA_EE, CSR, UTF8STRING, RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_rsa (test, csr, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_non_zero_path_length_constraint (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA_PATHLEN (2), NULL, 0, NULL, 0, &csr,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_PL2, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_no_path_length_constraint (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0, NULL, 0, &csr,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_NOPL, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_with_eku_oid (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, X509_EKU_OID, X509_EKU_OID_LEN, NULL, 0,
		&csr, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, csr);

	x509_testing_start_cert_verification (test, ECC_CA_EKU, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_end_entity_with_eku_oid (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	csr = (uint8_t*) &length;
	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_END_ENTITY, X509_EKU_OID, X509_EKU_OID_LEN,
		NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_NOT_CA_CERT, status);
	CuAssertPtrEquals (test, NULL, csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_end_entity_tcbinfo_and_ueid_extension (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension_sha1 (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA1, CSR, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension_sha384 (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA384, CSR, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension_sha512 (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SHA512, CSR, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension_svn_zero (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SVN, CSR, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_tcbinfo_extension_no_ueid (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CSR, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_end_entity_tcbinfo_extension_no_ueid (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CSR, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_critical_extension (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	struct x509_extension critical_ext = {0};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	memcpy (&critical_ext, &X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (critical_ext));
	critical_ext.critical = true;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ca_null_extension (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {NULL, &tcb.base, NULL, NULL, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CSR, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, csr, length);
	x509_testing_verify_cert (test, csr);
	x509_testing_verify_sig_algorithm (test, csr);
	x509_testing_verify_signature_ecc (test, csr, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_eku_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, X509_EKU_OID_LEN, NULL, 0, &csr,
		&length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_extensions_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 2, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_with_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		HASH_TYPE_SHA256, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertTrue (test, (status < 0));
	CuAssertPtrEquals (test, NULL, csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_sig_unsupported_hash (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA1, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);
	CuAssertPtrEquals (test, NULL, csr);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		(enum hash_type) 10, X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0, NULL, 0, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);
	CuAssertPtrEquals (test, NULL, csr);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_tcbinfo_error (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_csr_ueid_error (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_ca (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA, CERTSS, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE, CERTSS, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
#ifdef HASH_ENABLE_SHA384
static void x509_mbedtls_test_create_self_signed_certificate_ecc384_ca (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc384_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_create_self_signed_certificate_ecc384_ca_sha256_digest (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY_DER,
		ECC384_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_SHA256_CA, CERTSS, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc384_end_entity_sha256_digest (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY_DER,
		ECC384_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_ENTITY_SERIAL_NUM,
		X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_SHA256_EE, CERTSS, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_mbedtls_test_create_self_signed_certificate_ecc521_ca (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc521_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_create_self_signed_certificate_rsa_ca (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, RSA_CA, CERTSS, UTF8STRING, RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_rsa_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, RSA_EE, CERTSS, UTF8STRING, RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ca_non_zero_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ca_no_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTSS, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CERTSS, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha1 (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha384 (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha512 (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_svn_zero (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_extension_no_ueid (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CERTSS, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_extension_no_ueid (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CERTSS, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ca_critical_extension (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	struct x509_extension critical_ext = {0};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	memcpy (&critical_ext, &X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (critical_ext));
	critical_ext.critical = true;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ca_null_extension (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {NULL, &tcb.base, NULL, NULL, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTSS, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_extensions_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 2);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_with_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertTrue (test, (status < 0));

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_sig_unsupported_hash (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA1, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, (enum hash_type) 10, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_UNSUPPORTED_SIG_HASH, status);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_serial_zero (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t zero[] = {0};

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, zero, sizeof (zero), X509_SUBJECT_NAME, X509_CERT_CA,
		NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_SERIAL_NUM, status);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_tcbinfo_error (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_self_signed_certificate_ueid_error (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_load_certificate (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_load_certificate_riot (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_load_certificate_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_load_certificate_bad (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t bad_cert[X509_CERTSS_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);
	bad_cert[0] ^= 0x55;	/* Corrupt the certificate. */

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, bad_cert, sizeof (bad_cert));
	CuAssertTrue (test, (status < 0));

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc_ca_private_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA, CERTCA, UTF8STRING, RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_intermediate_ca_ecc_ca_private_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA2_ICA, CERTCA, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc_end_entity_private_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE, CERTCA, UTF8STRING, RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
#ifdef HASH_ENABLE_SHA384
static void x509_mbedtls_test_create_ca_signed_certificate_ecc384_ca_private_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY_DER,
		ECC384_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_CA, CERTCA, UTF8STRING,
		RSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_intermediate_ca_ecc384_ca_private_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc384_end_entity_private_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY_DER,
		ECC384_PRIVKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_EE, CERTCA, UTF8STRING,
		RSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_create_ca_signed_certificate_intermediate_ca_ecc384_ca_private_key_sha256_digest (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTCA_ECC384_CA_DER,
		X509_CERTCA_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY2_DER,
		ECC384_PRIVKEY2_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		X509_CA3_SUBJECT_NAME, X509_CERT_CA, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_SHA256_CA2_ICA, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc384_end_entity_private_key_sha256_digest (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PRIVKEY2_DER,
		ECC384_PRIVKEY2_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_SHA256_EE2, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_mbedtls_test_create_ca_signed_certificate_ecc521_ca_private_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PRIVKEY_DER,
		ECC521_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_CA, CERTCA, UTF8STRING,
		RSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_intermediate_ca_ecc521_ca_private_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc521_end_entity_private_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PRIVKEY_DER,
		ECC521_PRIVKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_EE, CERTCA, UTF8STRING,
		RSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_create_ca_signed_certificate_rsa_ca_private_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, RSA_CA, CERTCA, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_rsa_end_entity_private_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, RSA_EE, CERTCA, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc_ca_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA, CERTCA, UTF8STRING, RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc_end_entity_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_EE, CERTCA, UTF8STRING, RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void x509_mbedtls_test_create_ca_signed_certificate_ecc384_ca_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_CA, CERTCA, UTF8STRING,
		RSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc384_end_entity_public_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA384, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC384_EE, CERTCA, UTF8STRING,
		RSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_mbedtls_test_create_ca_signed_certificate_ecc521_ca_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PUBKEY_DER,
		ECC521_PUBKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_CA, CERTCA, UTF8STRING,
		RSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc521_end_entity_public_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC521_PUBKEY_DER,
		ECC521_PUBKEY_DER_LEN, X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN,
		X509_ENTITY_SUBJECT_NAME, X509_CERT_END_ENTITY, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA512, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC521_EE, CERTCA, UTF8STRING,
		RSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_create_ca_signed_certificate_rsa_ca_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, RSA_CA, CERTCA, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_rsa_end_entity_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, RSA_EE, CERTCA, UTF8STRING, ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ecc_ca2_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA2, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_end_entity_ecc_ca2_public_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_EE2, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void x509_mbedtls_test_create_ca_signed_certificate_ecc384_ca2_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_end_entity_ecc384_ca2_public_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA384_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC384_PUBKEY, SHA384);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void x509_mbedtls_test_create_ca_signed_certificate_ecc521_ca2_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_end_entity_ecc521_ca2_public_key (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_SHA512_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC521_PUBKEY, SHA512);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_create_ca_signed_certificate_ca_non_zero_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA_PATHLEN (15), RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert,
		NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_PL15, CERTCA, UTF8STRING,
		RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_no_path_length_constraint (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA_NO_PATHLEN, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert,
		NULL, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cert.context);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);

	x509_testing_start_cert_verification (test, ECC_CA_NOPL, CERTCA, UTF8STRING,
		RSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_rsa (test, der, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_end_entity_tcbinfo_and_ueid_extension (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_EE_UEID, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha1 (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha384 (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha512 (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_svn_zero (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID_SVN, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_extension_no_ueid (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_TCBINFO, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_end_entity_tcbinfo_extension_no_ueid (
	CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_EE_TCBINFO, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_critical_extension (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	const struct x509_extension_builder *extensions[] = {&tcb.base};
	struct x509_extension critical_ext = {0};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	memcpy (&critical_ext, &X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (critical_ext));
	critical_ext.critical = true;

	status = x509_mbedtls_init (&engine);
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
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_null_extension (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {NULL, &tcb.base, NULL, NULL, &ueid.base};
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_testing_start_cert_verification (test, ECC_CA_UEID, CERTCA, UTF8STRING,
		ECDSA_WITH_NULL);
	x509_testing_verify_cert_length (test, der, length);
	x509_testing_verify_cert (test, der);
	x509_testing_verify_sig_algorithm (test, der);
	x509_testing_verify_signature_ecc (test, der, ECC_PUBKEY, SHA256);
	x509_testing_end_cert_verification;

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (NULL, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, NULL, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, NULL,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		0, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, 0, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, NULL,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, NULL, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, 0, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, NULL, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_extensions_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 2);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ca_public_key (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertTrue (test, (status != 0));

	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_sig_unsupported_hash (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_serial_zero (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	uint8_t zero[] = {0};

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca_cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, zero, sizeof (zero), X509_CA2_SUBJECT_NAME, X509_CERT_CA,
		RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca_cert, NULL, 0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_SERIAL_NUM, status);

	engine.base.release_certificate (&engine.base, &ca_cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_tcbinfo_error (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_create_ca_signed_certificate_ueid_error (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate ca_cert;
	struct x509_certificate cert;
	int status;
	struct x509_extension_builder_mock tcb;
	struct x509_extension_builder_mock ueid;
	const struct x509_extension_builder *extensions[] = {&tcb.base, &ueid.base};

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_release_certificate_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (NULL, &cert);
	engine.base.release_certificate (&engine.base, NULL);

	engine.base.release_certificate (&engine.base, &cert);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_certificate_der_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
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

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_certificate_version (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_version (&engine.base, &cert);
	CuAssertIntEquals (test, X509_VERSION_3, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_certificate_version_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_version (NULL, &cert);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_certificate_version (&engine.base, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_serial_number (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t serial[X509_MAX_SERIAL_NUMBER * 2];

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_serial_number (&engine.base, &cert, serial, sizeof (serial));
	CuAssertIntEquals (test, X509_SERIAL_NUM_LEN, status);

	status = testing_validate_array (X509_SERIAL_NUM, serial, status);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_serial_number_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t serial[X509_MAX_SERIAL_NUMBER * 2];

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_serial_number (NULL, &cert, serial, sizeof (serial));
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_serial_number (&engine.base, NULL, serial, sizeof (serial));
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_serial_number (&engine.base, &cert, NULL, sizeof (serial));
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_serial_number_small_buffer (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t serial[X509_SERIAL_NUM_LEN - 1];

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_serial_number (&engine.base, &cert, serial, sizeof (serial));
	CuAssertIntEquals (test, X509_ENGINE_SMALL_SERIAL_BUFFER, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_type_ecc (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_type (&engine.base, &cert);
	CuAssertIntEquals (test, X509_PUBLIC_KEY_ECC, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_type_rsa (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_type (&engine.base, &cert);
	CuAssertIntEquals (test, X509_PUBLIC_KEY_RSA, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_type_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_type (NULL, &cert);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_public_key_type (&engine.base, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_length_ecc (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (&engine.base, &cert);
	CuAssertIntEquals (test, 256, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void x509_mbedtls_test_get_public_key_length_ecc384 (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (&engine.base, &cert);
	CuAssertIntEquals (test, 384, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void x509_mbedtls_test_get_public_key_length_ecc521 (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC521_CA_DER,
		X509_CERTSS_ECC521_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (&engine.base, &cert);
	CuAssertIntEquals (test, 521, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}
#endif

static void x509_mbedtls_test_get_public_key_length_rsa (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (&engine.base, &cert);
	CuAssertIntEquals (test, 2048, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_length_rsa4k (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_RSA4K_CA_DER,
		X509_CERTSS_RSA4K_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (&engine.base, &cert);
	CuAssertIntEquals (test, 4096, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_length_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (NULL, &cert);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_public_key_length (&engine.base, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_ecc (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PUBKEY_DER, der, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_rsa (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, RSA_PUBKEY_DER_LEN, length);

	status = testing_validate_array (RSA_PUBKEY_DER, der, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_get_public_key_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key (NULL, &cert, &der, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key (&engine.base, NULL, &der, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	status = engine.base.get_public_key (&engine.base, &cert, NULL, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key (&engine.base, &cert, &der, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_certificate (&engine.base, &cert);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_init_ca_cert_store (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_init_ca_cert_store_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (NULL, &store);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_ca_cert_store (&engine.base, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_release_ca_cert_store_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (NULL, &store);
	engine.base.release_ca_cert_store (&engine.base, NULL);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_ecc (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_ecc_bad_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTSS_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);
	status = x509_testing_corrupt_serial_number (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, X509_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_rsa (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_rsa_bad_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTSS_RSA_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTSS_RSA_CA_DER, X509_CERTSS_RSA_CA_DER_LEN);
	status = x509_testing_corrupt_serial_number (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, X509_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (NULL, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.add_root_ca (&engine.base, &store, NULL,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.add_root_ca (&engine.base, NULL, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_ECC_CA_DER,
		0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_ecc_corrupt_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTSS_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);
	status = x509_testing_corrupt_signature (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, X509_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_rsa_corrupt_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTSS_RSA_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTSS_RSA_CA_DER, X509_CERTSS_RSA_CA_DER_LEN);
	status = x509_testing_corrupt_signature (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, X509_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_bad_cert (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTSS_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);
	bad_cert[0] ^= 0x55;	/* Corrupt the certificate. */

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertTrue (test, (status < 0));

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_not_self_signed (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_NOT_SELF_SIGNED, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_root_ca_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);


	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_ECC_EE_DER,
		X509_CERTSS_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_NOT_CA_CERT, status);

	engine.base.release_ca_cert_store (&engine.base, &store);
	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_ecc (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_ecc_bad_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTCA_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTCA_ECC_CA_DER, X509_CERTCA_ECC_CA_DER_LEN);
	status = x509_testing_corrupt_serial_number (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_ecc_corrupt_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTCA_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTCA_ECC_CA_DER, X509_CERTCA_ECC_CA_DER_LEN);
	status = x509_testing_corrupt_signature (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_rsa (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_RSA_CA_DER,
		X509_CERTCA_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_rsa_bad_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTCA_RSA_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTCA_RSA_CA_DER, X509_CERTCA_RSA_CA_DER_LEN);
	status = x509_testing_corrupt_serial_number (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_rsa_corrupt_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTCA_RSA_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTCA_RSA_CA_DER, X509_CERTCA_RSA_CA_DER_LEN);
	status = x509_testing_corrupt_signature (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (NULL, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.add_intermediate_ca (&engine.base, NULL, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, NULL,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		0);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_ecc_bad_cert (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTCA_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTCA_ECC_CA_DER, X509_CERTCA_ECC_CA_DER_LEN);
	bad_cert[0] ^= 0x55;	/* Corrupt the certificate. */

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, bad_cert, sizeof (bad_cert));
	CuAssertTrue (test, (status < 0));

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_self_signed (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_IS_SELF_SIGNED, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_add_intermediate_ca_end_entity (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_NOT_CA_CERT, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_ecc_end_entity_no_intermediate_certs (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_ecc_ca_no_intermediate_certs (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_rsa_end_entity_no_intermediate_certs (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_rsa_ca_no_intermediate_certs (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_RSA_CA_DER,
		X509_CERTCA_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_end_entity_one_intermediate_cert (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	platform_free (root_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_ca_one_intermediate_cert (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		key_der, X509_SERIAL_NUM_LEN, "CA2", X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	platform_free (root_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_end_entity_root_pathlen_constraint (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate ca;
	struct x509_certificate cert;
	int status;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	// mbedTLS does not ignore the pathLength constraint on the root CA.
	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &ca);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_ca_root_pathlen_constraint (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate ca;
	struct x509_certificate cert;
	int status;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		key_der, X509_SERIAL_NUM_LEN, "CA", X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	// mbedTLS does not ignore the pathLength constraint on the root CA.
	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &ca);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_end_entity_multiple_intermediate_certs (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key2;
	struct ecc_private_key key3;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca1;
	struct x509_certificate ca2;
	struct x509_certificate ca3;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key2_der;
	size_t key2_length;
	uint8_t *ca2_der;
	size_t ca2_der_length;
	uint8_t *key3_der;
	size_t key3_length;
	uint8_t *ca3_der;
	size_t ca3_der_length;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key3, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca1, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key2, &key2_der, &key2_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &ca2, key2_der, key2_length,
		key2_der, X509_SERIAL_NUM_LEN, "CA2", X509_CERT_CA_PATHLEN (1), ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca1, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &ca2, &ca2_der, &ca2_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, ca2_der, ca2_der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key3, &key3_der, &key3_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &ca3, key3_der, key3_length,
		key3_der, X509_SERIAL_NUM_LEN, "CA3", X509_CERT_CA, key2_der, key2_length, HASH_TYPE_SHA256,
		&ca2, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &ca3, &ca3_der, &ca3_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, ca3_der, ca3_der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, key3_der, key3_length, HASH_TYPE_SHA256, &ca3, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	platform_free (root_der);
	platform_free (key2_der);
	platform_free (ca2_der);
	platform_free (key3_der);
	platform_free (ca3_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca1);
	engine.base.release_certificate (&engine.base, &ca2);
	engine.base.release_certificate (&engine.base, &ca3);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key2, NULL);
	ecc.base.release_key_pair (&ecc.base, &key3, NULL);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_ca_multiple_intermediate_certs (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key2;
	struct ecc_private_key key3;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca1;
	struct x509_certificate ca2;
	struct x509_certificate ca3;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key2_der;
	size_t key2_length;
	uint8_t *ca2_der;
	size_t ca2_der_length;
	uint8_t *key3_der;
	size_t key3_length;
	uint8_t *ca3_der;
	size_t ca3_der_length;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key3, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca1, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key2, &key2_der, &key2_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &ca2, key2_der, key2_length,
		key2_der, X509_SERIAL_NUM_LEN, "CA2", X509_CERT_CA_PATHLEN (1), ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca1, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &ca2, &ca2_der, &ca2_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, ca2_der, ca2_der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key3, &key3_der, &key3_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &ca3, key3_der, key3_length,
		key3_der, X509_SERIAL_NUM_LEN, "CA3", X509_CERT_CA, key2_der, key2_length, HASH_TYPE_SHA256,
		&ca2, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &ca3, &ca3_der, &ca3_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, ca3_der, ca3_der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		key_der, X509_SERIAL_NUM_LEN, "CA4", X509_CERT_CA, key3_der, key3_length, HASH_TYPE_SHA256,
		&ca3, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	platform_free (root_der);
	platform_free (key2_der);
	platform_free (ca2_der);
	platform_free (key3_der);
	platform_free (ca3_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca1);
	engine.base.release_certificate (&engine.base, &ca2);
	engine.base.release_certificate (&engine.base, &ca3);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key2, NULL);
	ecc.base.release_key_pair (&ecc.base, &key3, NULL);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_ecc_riot_alias (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_ECC_EE_UEID_DER,
		X509_CERTCA_ECC_EE_UEID_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_null (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (NULL, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.authenticate (&engine.base, NULL, &store);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.authenticate (&engine.base, &cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_no_path_to_root (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	platform_free (root_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_partial_path_to_root (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key2;
	struct ecc_private_key key3;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca1;
	struct x509_certificate ca2;
	struct x509_certificate ca3;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key2_der;
	size_t key2_length;
	uint8_t *ca2_der;
	size_t ca2_der_length;
	uint8_t *key3_der;
	size_t key3_length;
	uint8_t *ca3_der;
	size_t ca3_der_length;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key3, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca1, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key2, &key2_der, &key2_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &ca2, key2_der, key2_length,
		key2_der, X509_SERIAL_NUM_LEN, "CA2", X509_CERT_CA_PATHLEN (1), ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca1, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &ca2, &ca2_der, &ca2_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, ca2_der, ca2_der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key3, &key3_der, &key3_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &ca3, key3_der, key3_length,
		key3_der, X509_SERIAL_NUM_LEN, "CA3", X509_CERT_CA, key2_der, key2_length, HASH_TYPE_SHA256,
		&ca2, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &ca3, &ca3_der, &ca3_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, ca3_der, ca3_der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, key3_der, key3_length, HASH_TYPE_SHA256, &ca3, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	platform_free (root_der);
	platform_free (key2_der);
	platform_free (ca2_der);
	platform_free (key3_der);
	platform_free (ca3_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca1);
	engine.base.release_certificate (&engine.base, &ca2);
	engine.base.release_certificate (&engine.base, &ca3);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key2, NULL);
	ecc.base.release_key_pair (&ecc.base, &key3, NULL);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_violate_path_length_constraint (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key2;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca1;
	struct x509_certificate ca2;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key2_der;
	size_t key2_length;
	uint8_t *ca2_der;
	size_t ca2_der_length;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca1, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key2, &key2_der, &key2_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &ca2, key2_der, key2_length,
		key2_der, X509_SERIAL_NUM_LEN, "CA2", X509_CERT_CA, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		HASH_TYPE_SHA256, &ca1, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &ca2, &ca2_der, &ca2_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, ca2_der, ca2_der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, key2_der, key2_length, HASH_TYPE_SHA256, &ca2, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	platform_free (root_der);
	platform_free (key2_der);
	platform_free (ca2_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca1);
	engine.base.release_certificate (&engine.base, &ca2);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key2, NULL);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_intermediate_bad_signature (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key_der;
	size_t key_length;
	uint8_t bad_ca[X509_CERTCA_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_ca, X509_CERTCA_ECC_CA_DER, X509_CERTCA_ECC_CA_DER_LEN);
	status = x509_testing_corrupt_serial_number (bad_ca);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, bad_ca, sizeof (bad_ca));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	platform_free (root_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_intermediate_corrupt_signature (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate root;
	struct x509_certificate ca;
	struct x509_certificate cert;
	int status;
	uint8_t *root_der;
	size_t root_der_length;
	uint8_t *key_der;
	size_t key_length;
	uint8_t bad_ca[X509_CERTCA_ECC_CA_DER_LEN];

	TEST_START;

	memcpy (bad_ca, X509_CERTCA_ECC_CA_DER, X509_CERTCA_ECC_CA_DER_LEN);
	status = x509_testing_corrupt_signature (bad_ca);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &root, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA_NO_PATHLEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &root, &root_der, &root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, root_der, root_der_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, bad_ca, sizeof (bad_ca));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	platform_free (root_der);
	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &root);
	engine.base.release_certificate (&engine.base, &ca);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_bad_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTCA_ECC_EE_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTCA_ECC_EE_DER, X509_CERTCA_ECC_EE_DER_LEN);
	status = x509_testing_corrupt_serial_number (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_corrupt_signature (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store;
	int status;
	uint8_t bad_cert[X509_CERTCA_ECC_EE_DER_LEN];

	TEST_START;

	memcpy (bad_cert, X509_CERTCA_ECC_EE_DER, X509_CERTCA_ECC_EE_DER_LEN);
	status = x509_testing_corrupt_signature (bad_cert);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, bad_cert, sizeof (bad_cert));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_no_root_ca (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct ecc_private_key key;
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate ca;
	struct x509_certificate cert;
	int status;
	uint8_t *key_der;
	size_t key_length;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.generate_key_pair (&ecc.base, ECC_KEY_LENGTH_256, &key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &ca, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_private_key_der (&ecc.base, &key, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, key_der, key_length,
		X509_ENTITY_SERIAL_NUM, X509_ENTITY_SERIAL_NUM_LEN, X509_ENTITY_SUBJECT_NAME,
		X509_CERT_END_ENTITY, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, HASH_TYPE_SHA256, &ca, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	platform_free (key_der);
	engine.base.release_certificate (&engine.base, &ca);
	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
	ecc.base.release_key_pair (&ecc.base, &key, NULL);
}

static void x509_mbedtls_test_authenticate_empty_ca_store (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_self_signed (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_ca_certs store;
	struct x509_certificate cert;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_EE_DER,
		X509_CERTSS_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store);

	x509_mbedtls_release (&engine);
}

static void x509_mbedtls_test_authenticate_different_ca_stores (CuTest *test)
{
	struct x509_engine_mbedtls engine;
	struct x509_certificate cert;
	struct x509_ca_certs store1;
	struct x509_ca_certs store2;
	int status;

	TEST_START;

	status = x509_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store2);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store1, X509_CERTSS_RSA_CA_DER,
		X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store2);
	CuAssertIntEquals (test, X509_ENGINE_CERT_NOT_VALID, status);

	engine.base.release_certificate (&engine.base, &cert);
	engine.base.release_ca_cert_store (&engine.base, &store1);
	engine.base.release_ca_cert_store (&engine.base, &store2);

	x509_mbedtls_release (&engine);
}


TEST_SUITE_START (x509_mbedtls);

TEST (x509_mbedtls_test_init);
TEST (x509_mbedtls_test_init_null);
TEST (x509_mbedtls_test_release_null);
TEST (x509_mbedtls_test_create_csr_ecc_ca);
TEST (x509_mbedtls_test_create_csr_ecc_end_entity);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
#ifdef HASH_ENABLE_SHA384
TEST (x509_mbedtls_test_create_csr_ecc384_ca);
TEST (x509_mbedtls_test_create_csr_ecc384_end_entity);
#endif
TEST (x509_mbedtls_test_create_csr_ecc384_ca_sha256_digest);
TEST (x509_mbedtls_test_create_csr_ecc384_end_entity_sha256_digest);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_mbedtls_test_create_csr_ecc521_ca);
TEST (x509_mbedtls_test_create_csr_ecc521_end_entity);
#endif
TEST (x509_mbedtls_test_create_csr_rsa_ca);
TEST (x509_mbedtls_test_create_csr_rsa_end_entity);
TEST (x509_mbedtls_test_create_csr_ca_non_zero_path_length_constraint);
TEST (x509_mbedtls_test_create_csr_ca_no_path_length_constraint);
TEST (x509_mbedtls_test_create_csr_ca_with_eku_oid);
TEST (x509_mbedtls_test_create_csr_end_entity_with_eku_oid);
TEST (x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension);
TEST (x509_mbedtls_test_create_csr_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension_sha384);
TEST (x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension_sha512);
TEST (x509_mbedtls_test_create_csr_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_mbedtls_test_create_csr_ca_tcbinfo_extension_no_ueid);
TEST (x509_mbedtls_test_create_csr_end_entity_tcbinfo_extension_no_ueid);
TEST (x509_mbedtls_test_create_csr_ca_critical_extension);
TEST (x509_mbedtls_test_create_csr_ca_null_extension);
TEST (x509_mbedtls_test_create_csr_null);
TEST (x509_mbedtls_test_create_csr_eku_null);
TEST (x509_mbedtls_test_create_csr_extensions_null);
TEST (x509_mbedtls_test_create_csr_with_public_key);
TEST (x509_mbedtls_test_create_csr_sig_unsupported_hash);
TEST (x509_mbedtls_test_create_csr_tcbinfo_error);
TEST (x509_mbedtls_test_create_csr_ueid_error);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_ca);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_end_entity);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
#ifdef HASH_ENABLE_SHA384
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc384_ca);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc384_end_entity);
#endif
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc384_ca_sha256_digest);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc384_end_entity_sha256_digest);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc521_ca);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc521_end_entity);
#endif
TEST (x509_mbedtls_test_create_self_signed_certificate_rsa_ca);
TEST (x509_mbedtls_test_create_self_signed_certificate_rsa_end_entity);
TEST (x509_mbedtls_test_create_self_signed_certificate_ca_non_zero_path_length_constraint);
TEST (x509_mbedtls_test_create_self_signed_certificate_ca_no_path_length_constraint);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha384);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_sha512);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_ca_tcbinfo_extension_no_ueid);
TEST (x509_mbedtls_test_create_self_signed_certificate_ecc_end_entity_tcbinfo_extension_no_ueid);
TEST (x509_mbedtls_test_create_self_signed_certificate_ca_critical_extension);
TEST (x509_mbedtls_test_create_self_signed_certificate_ca_null_extension);
TEST (x509_mbedtls_test_create_self_signed_certificate_null);
TEST (x509_mbedtls_test_create_self_signed_certificate_extensions_null);
TEST (x509_mbedtls_test_create_self_signed_certificate_with_public_key);
TEST (x509_mbedtls_test_create_self_signed_certificate_sig_unsupported_hash);
TEST (x509_mbedtls_test_create_self_signed_certificate_serial_zero);
TEST (x509_mbedtls_test_create_self_signed_certificate_tcbinfo_error);
TEST (x509_mbedtls_test_create_self_signed_certificate_ueid_error);
TEST (x509_mbedtls_test_load_certificate);
TEST (x509_mbedtls_test_load_certificate_riot);
TEST (x509_mbedtls_test_load_certificate_null);
TEST (x509_mbedtls_test_load_certificate_bad);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc_ca_private_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_intermediate_ca_ecc_ca_private_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc_end_entity_private_key);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
#ifdef HASH_ENABLE_SHA384
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc384_ca_private_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_intermediate_ca_ecc384_ca_private_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc384_end_entity_private_key);
#endif
TEST (x509_mbedtls_test_create_ca_signed_certificate_intermediate_ca_ecc384_ca_private_key_sha256_digest);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc384_end_entity_private_key_sha256_digest);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc521_ca_private_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_intermediate_ca_ecc521_ca_private_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc521_end_entity_private_key);
#endif
TEST (x509_mbedtls_test_create_ca_signed_certificate_rsa_ca_private_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_rsa_end_entity_private_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc_ca_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc_end_entity_public_key);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc384_ca_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc384_end_entity_public_key);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc521_ca_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc521_end_entity_public_key);
#endif
TEST (x509_mbedtls_test_create_ca_signed_certificate_rsa_ca_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_rsa_end_entity_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc_ca2_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_end_entity_ecc_ca2_public_key);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc384_ca2_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_end_entity_ecc384_ca2_public_key);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (x509_mbedtls_test_create_ca_signed_certificate_ecc521_ca2_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_end_entity_ecc521_ca2_public_key);
#endif
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_non_zero_path_length_constraint);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_no_path_length_constraint);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension);
TEST (x509_mbedtls_test_create_ca_signed_certificate_end_entity_tcbinfo_and_ueid_extension);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha1);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha384);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_sha512);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_and_ueid_extension_svn_zero);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_tcbinfo_extension_no_ueid);
TEST (x509_mbedtls_test_create_ca_signed_certificate_end_entity_tcbinfo_extension_no_ueid);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_critical_extension);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_null_extension);
TEST (x509_mbedtls_test_create_ca_signed_certificate_null);
TEST (x509_mbedtls_test_create_ca_signed_certificate_extensions_null);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ca_public_key);
TEST (x509_mbedtls_test_create_ca_signed_certificate_sig_unsupported_hash);
TEST (x509_mbedtls_test_create_ca_signed_certificate_serial_zero);
TEST (x509_mbedtls_test_create_ca_signed_certificate_tcbinfo_error);
TEST (x509_mbedtls_test_create_ca_signed_certificate_ueid_error);
TEST (x509_mbedtls_test_release_certificate_null);
TEST (x509_mbedtls_test_get_certificate_der_null);
TEST (x509_mbedtls_test_get_certificate_version);
TEST (x509_mbedtls_test_get_certificate_version_null);
TEST (x509_mbedtls_test_get_serial_number);
TEST (x509_mbedtls_test_get_serial_number_null);
TEST (x509_mbedtls_test_get_serial_number_small_buffer);
TEST (x509_mbedtls_test_get_public_key_type_ecc);
TEST (x509_mbedtls_test_get_public_key_type_rsa);
TEST (x509_mbedtls_test_get_public_key_type_null);
TEST (x509_mbedtls_test_get_public_key_length_ecc);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (x509_mbedtls_test_get_public_key_length_ecc384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (x509_mbedtls_test_get_public_key_length_ecc521);
#endif
TEST (x509_mbedtls_test_get_public_key_length_rsa);
TEST (x509_mbedtls_test_get_public_key_length_rsa4k);
TEST (x509_mbedtls_test_get_public_key_length_null);
TEST (x509_mbedtls_test_get_public_key_ecc);
TEST (x509_mbedtls_test_get_public_key_rsa);
TEST (x509_mbedtls_test_get_public_key_null);
TEST (x509_mbedtls_test_init_ca_cert_store);
TEST (x509_mbedtls_test_init_ca_cert_store_null);
TEST (x509_mbedtls_test_release_ca_cert_store_null);
TEST (x509_mbedtls_test_add_root_ca_ecc);
TEST (x509_mbedtls_test_add_root_ca_ecc_bad_signature);
TEST (x509_mbedtls_test_add_root_ca_rsa);
TEST (x509_mbedtls_test_add_root_ca_rsa_bad_signature);
TEST (x509_mbedtls_test_add_root_ca_null);
TEST (x509_mbedtls_test_add_root_ca_ecc_corrupt_signature);
TEST (x509_mbedtls_test_add_root_ca_rsa_corrupt_signature);
TEST (x509_mbedtls_test_add_root_ca_bad_cert);
TEST (x509_mbedtls_test_add_root_ca_not_self_signed);
TEST (x509_mbedtls_test_add_root_ca_end_entity);
TEST (x509_mbedtls_test_add_intermediate_ca_ecc);
TEST (x509_mbedtls_test_add_intermediate_ca_ecc_bad_signature);
TEST (x509_mbedtls_test_add_intermediate_ca_ecc_corrupt_signature);
TEST (x509_mbedtls_test_add_intermediate_ca_rsa);
TEST (x509_mbedtls_test_add_intermediate_ca_rsa_bad_signature);
TEST (x509_mbedtls_test_add_intermediate_ca_rsa_corrupt_signature);
TEST (x509_mbedtls_test_add_intermediate_ca_null);
TEST (x509_mbedtls_test_add_intermediate_ca_ecc_bad_cert);
TEST (x509_mbedtls_test_add_intermediate_ca_self_signed);
TEST (x509_mbedtls_test_add_intermediate_ca_end_entity);
TEST (x509_mbedtls_test_authenticate_ecc_end_entity_no_intermediate_certs);
TEST (x509_mbedtls_test_authenticate_ecc_ca_no_intermediate_certs);
TEST (x509_mbedtls_test_authenticate_rsa_end_entity_no_intermediate_certs);
TEST (x509_mbedtls_test_authenticate_rsa_ca_no_intermediate_certs);
TEST (x509_mbedtls_test_authenticate_end_entity_one_intermediate_cert);
TEST (x509_mbedtls_test_authenticate_ca_one_intermediate_cert);
TEST (x509_mbedtls_test_authenticate_end_entity_root_pathlen_constraint);
TEST (x509_mbedtls_test_authenticate_ca_root_pathlen_constraint);
TEST (x509_mbedtls_test_authenticate_end_entity_multiple_intermediate_certs);
TEST (x509_mbedtls_test_authenticate_ca_multiple_intermediate_certs);
TEST (x509_mbedtls_test_authenticate_ecc_riot_alias);
TEST (x509_mbedtls_test_authenticate_null);
TEST (x509_mbedtls_test_authenticate_no_path_to_root);
TEST (x509_mbedtls_test_authenticate_partial_path_to_root);
TEST (x509_mbedtls_test_authenticate_violate_path_length_constraint);
TEST (x509_mbedtls_test_authenticate_intermediate_bad_signature);
TEST (x509_mbedtls_test_authenticate_intermediate_corrupt_signature);
TEST (x509_mbedtls_test_authenticate_bad_signature);
TEST (x509_mbedtls_test_authenticate_corrupt_signature);
TEST (x509_mbedtls_test_authenticate_no_root_ca);
TEST (x509_mbedtls_test_authenticate_empty_ca_store);
TEST (x509_mbedtls_test_authenticate_self_signed);
TEST (x509_mbedtls_test_authenticate_different_ca_stores);

TEST_SUITE_END;
