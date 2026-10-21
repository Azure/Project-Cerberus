// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/x509.h"
#include "spdm/cert_chain_verifier_interface.h"
#include "spdm/spdm_cert_chain_verifier.h"
#include "spdm/spdm_cert_chain_verifier_static.h"
#include "status/rot_status.h"
#include "testing/asn1/x509_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/mock/asn1/x509_mock.h"


TEST_SUITE_LABEL ("spdm_cert_chain_verifier");


/**
 * Dependencies for testing the SPDM certificate chain verifier.
 *
 * The verifier treats certificates as opaque byte strings (the X.509 engine is mocked), so the
 * shared core test vectors are reused directly: X509_CERTSS_ECC384_CA_DER as the self-signed root,
 * X509_CERTCA_ECC384_CA2_DER as an intermediate CA, X509_CERTCA_ECC384_EE_DER as the alias
 * certificate, and ECC384_PUBKEY_DER as the extracted alias public key.
 */
struct spdm_cert_chain_verifier_testing {
	struct x509_engine_mock x509;					/**< Mock for X.509 chain validation and key extraction. */
	struct spdm_cert_chain_verifier_state state;	/**< Variable context for the verifier under test. */
	struct spdm_cert_chain_verifier test;			/**< Verifier under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The test framework.
 * @param verifier The testing dependencies to initialize.
 */
static void spdm_cert_chain_verifier_testing_init_dependencies (CuTest *test,
	struct spdm_cert_chain_verifier_testing *verifier)
{
	int status;

	status = x509_mock_init (&verifier->x509);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Validate and release all testing dependencies.
 *
 * @param test The test framework.
 * @param verifier The testing dependencies to release.
 */
static void spdm_cert_chain_verifier_testing_release_dependencies (CuTest *test,
	struct spdm_cert_chain_verifier_testing *verifier)
{
	int status;

	status = x509_mock_validate_and_release (&verifier->x509);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a certificate chain verifier for testing.
 *
 * @param test The test framework.
 * @param verifier The testing components to initialize.
 */
static void spdm_cert_chain_verifier_testing_init (CuTest *test,
	struct spdm_cert_chain_verifier_testing *verifier)
{
	int status;

	spdm_cert_chain_verifier_testing_init_dependencies (test, verifier);

	status = spdm_cert_chain_verifier_init (&verifier->test, &verifier->state,
		&verifier->x509.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a certificate chain verifier and validate all dependencies.
 *
 * @param test The test framework.
 * @param verifier The testing components to release.
 */
static void spdm_cert_chain_verifier_testing_release (CuTest *test,
	struct spdm_cert_chain_verifier_testing *verifier)
{
	CuAssertPtrEquals (test, NULL, verifier->state.pending_cert);
	CuAssertIntEquals (test, 0, verifier->state.pending_cert_len);
	spdm_cert_chain_verifier_release (&verifier->test);
	CuAssertPtrEquals (test, NULL, verifier->state.root_cert);
	CuAssertIntEquals (test, 0, verifier->state.root_len);
	spdm_cert_chain_verifier_testing_release_dependencies (test, verifier);
}

/**
 * Set up mock expectations for building a local trust store anchored at a CA certificate.
 *
 * @param verifier The testing dependencies.
 * @param der The anchor certificate DER.
 * @param length Length of the anchor certificate DER.
 * @param is_root Flag indicating the anchor is the self-signed root rather than an intermediate.
 * @param store_id Save ID to assign to the trust store.
 *
 * @return 0 if the expectations were configured successfully.
 */
static int spdm_cert_chain_verifier_testing_expect_anchor (
	struct spdm_cert_chain_verifier_testing *verifier, const uint8_t *der, size_t length,
	bool is_root, int store_id)
{
	int status;

	status = mock_expect (&verifier->x509.mock, verifier->x509.base.init_ca_cert_store,
		&verifier->x509, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&verifier->x509.mock, 0, store_id);
	if (is_root) {
		status |= mock_expect (&verifier->x509.mock, verifier->x509.base.add_root_ca,
			&verifier->x509, 0, MOCK_ARG_SAVED_ARG (store_id), MOCK_ARG_PTR_CONTAINS (der, length),
			MOCK_ARG (length));
	}
	else {
		status |= mock_expect (&verifier->x509.mock, verifier->x509.base.add_trusted_ca,
			&verifier->x509, 0, MOCK_ARG_SAVED_ARG (store_id), MOCK_ARG_PTR_CONTAINS (der, length),
			MOCK_ARG (length));
	}

	return status;
}

/**
 * Set up mock expectations for building a local trust store anchored at the test root.
 *
 * @param verifier The testing dependencies.
 * @param store_id Save ID to assign to the trust store.
 *
 * @return 0 if the expectations were configured successfully.
 */
static int spdm_cert_chain_verifier_testing_expect_root_anchor (
	struct spdm_cert_chain_verifier_testing *verifier, int store_id)
{
	return spdm_cert_chain_verifier_testing_expect_anchor (verifier, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN, true, store_id);
}

/**
 * Set up mock expectations for successfully processing the self-signed root certificate.  The root
 * is validated in a local trust store that is released before the call returns.
 *
 * @param verifier The testing dependencies.
 * @param store_id Save ID to assign to the trust store passed to the X.509 engine.
 *
 * @return 0 if the expectations were configured successfully.
 */
static int spdm_cert_chain_verifier_testing_expect_root (
	struct spdm_cert_chain_verifier_testing *verifier, int store_id)
{
	int status;

	status = spdm_cert_chain_verifier_testing_expect_root_anchor (verifier, store_id);
	status |= mock_expect (&verifier->x509.mock, verifier->x509.base.release_ca_cert_store,
		&verifier->x509, 0, MOCK_ARG_SAVED_ARG (store_id));

	return status;
}

/**
 * Set up mock expectations for successfully authenticating a non-root certificate.  The certificate
 * is parsed first, then the anchor store is built, the certificate is authenticated, and the parsed
 * certificate and the store are released before the call returns.
 *
 * @param verifier The testing dependencies.
 * @param der The certificate DER expected to be loaded.
 * @param length Length of the certificate DER.
 * @param anchor The anchor certificate DER the store is built on.
 * @param anchor_length Length of the anchor certificate DER.
 * @param anchor_is_root Flag indicating the anchor is the self-signed root rather than a pending CA.
 * @param cert_id Save ID to assign to the parsed certificate.
 * @param store_id Save ID of the trust store used for authentication.
 *
 * @return 0 if the expectations were configured successfully.
 */
static int spdm_cert_chain_verifier_testing_expect_cert (
	struct spdm_cert_chain_verifier_testing *verifier, const uint8_t *der, size_t length,
	const uint8_t *anchor, size_t anchor_length, bool anchor_is_root, int cert_id, int store_id)
{
	int status;

	status = mock_expect (&verifier->x509.mock, verifier->x509.base.load_certificate,
		&verifier->x509, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (der, length),
		MOCK_ARG (length));
	status |= mock_expect_save_arg (&verifier->x509.mock, 0, cert_id);
	status |= spdm_cert_chain_verifier_testing_expect_anchor (verifier, anchor, anchor_length,
		anchor_is_root, store_id);
	status |= mock_expect (&verifier->x509.mock, verifier->x509.base.authenticate, &verifier->x509,
		0, MOCK_ARG_SAVED_ARG (cert_id), MOCK_ARG_SAVED_ARG (store_id));
	status |= mock_expect (&verifier->x509.mock, verifier->x509.base.release_certificate,
		&verifier->x509, 0, MOCK_ARG_SAVED_ARG (cert_id));
	status |= mock_expect (&verifier->x509.mock, verifier->x509.base.release_ca_cert_store,
		&verifier->x509, 0, MOCK_ARG_SAVED_ARG (store_id));

	return status;
}

/**
 * Set up mock expectations for re-loading the leaf certificate during finalize and extracting its
 * public key.  The leaf certificate is released once the key has been read.
 *
 * @param verifier The testing dependencies.
 * @param der The leaf certificate DER expected to be re-loaded.
 * @param length Length of the leaf certificate DER.
 * @param cert_id Save ID to assign to the re-loaded leaf certificate.
 * @param key_type Key type to report for the leaf.
 * @param key Public key DER to return for the leaf.
 * @param key_length Length of the public key DER.
 *
 * @return 0 if the expectations were configured successfully.
 */
static int spdm_cert_chain_verifier_testing_expect_leaf_key (
	struct spdm_cert_chain_verifier_testing *verifier, const uint8_t *der, size_t length,
	int cert_id, int key_type, const uint8_t *key, size_t key_length)
{
	uint8_t *key_copy;
	int status;

	key_copy = platform_malloc (key_length);
	if (key_copy == NULL) {
		return -1;
	}
	memcpy (key_copy, key, key_length);

	status = mock_expect (&verifier->x509.mock, verifier->x509.base.load_certificate,
		&verifier->x509, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (der, length),
		MOCK_ARG (length));
	status |= mock_expect_save_arg (&verifier->x509.mock, 0, cert_id);
	status |= mock_expect (&verifier->x509.mock, verifier->x509.base.get_public_key_type,
		&verifier->x509, key_type, MOCK_ARG_SAVED_ARG (cert_id));
	status |= mock_expect (&verifier->x509.mock, verifier->x509.base.get_public_key,
		&verifier->x509, 0, MOCK_ARG_SAVED_ARG (cert_id), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&verifier->x509.mock, 1, &key_copy, sizeof (key_copy), -1);
	status |= mock_expect_output_tmp (&verifier->x509.mock, 2, &key_length, sizeof (key_length),
		-1);
	status |= mock_expect (&verifier->x509.mock, verifier->x509.base.release_certificate,
		&verifier->x509, 0, MOCK_ARG_SAVED_ARG (cert_id));

	return status;
}


static void spdm_cert_chain_verifier_testing_check_aborted (CuTest *test,
	struct spdm_cert_chain_verifier_testing *verifier)
{
	struct cert_chain_verifier_result result;
	int status;

	CuAssertIntEquals (test, false, verifier->state.started);
	CuAssertIntEquals (test, 0, verifier->state.cert_count);
	CuAssertPtrEquals (test, NULL, verifier->state.pending_cert);
	CuAssertPtrEquals (test, NULL, verifier->state.root_cert);
	CuAssertIntEquals (test, 0, verifier->state.pending_cert_len);
	CuAssertIntEquals (test, 0, verifier->state.root_len);

	status = verifier->test.base.process_cert (&verifier->test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NOT_STARTED, status);
	status = verifier->test.base.finalize_verification (&verifier->test.base, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NOT_STARTED, status);

	status = verifier->test.base.start_verification (&verifier->test.base);
	CuAssertIntEquals (test, 0, status);
	status = spdm_cert_chain_verifier_testing_expect_root (verifier, 10);
	CuAssertIntEquals (test, 0, status);
	status = verifier->test.base.process_cert (&verifier->test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	spdm_cert_chain_verifier_release (&verifier->test);
}


/*******************
 * Test cases
 *******************/

static void spdm_cert_chain_verifier_test_init (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init_dependencies (test, &verifier);

	status = spdm_cert_chain_verifier_init (&verifier.test, &verifier.state, &verifier.x509.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verifier.test.base.start_verification);
	CuAssertPtrNotNull (test, verifier.test.base.process_cert);
	CuAssertPtrNotNull (test, verifier.test.base.finalize_verification);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_static_init (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier = {
		.test = spdm_cert_chain_verifier_static_init (&verifier.state, &verifier.x509.base)
	};
	int status;

	TEST_START;

	status = spdm_cert_chain_verifier_init_state (&verifier.test);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verifier.test.base.start_verification);
	CuAssertPtrNotNull (test, verifier.test.base.process_cert);
	CuAssertPtrNotNull (test, verifier.test.base.finalize_verification);

	spdm_cert_chain_verifier_testing_init_dependencies (test, &verifier);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_init_null (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init_dependencies (test, &verifier);

	status = spdm_cert_chain_verifier_init (NULL, &verifier.state, &verifier.x509.base);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	status = spdm_cert_chain_verifier_init (&verifier.test, NULL, &verifier.x509.base);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	status = spdm_cert_chain_verifier_init (&verifier.test, &verifier.state, NULL);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	spdm_cert_chain_verifier_testing_release_dependencies (test, &verifier);
}

static void spdm_cert_chain_verifier_test_start_null (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (NULL);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_before_start (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NOT_STARTED, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_null (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (NULL, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	status = verifier.test.base.process_cert (&verifier.test.base, NULL,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER, 0);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_root_too_large (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		(size_t) UINT16_MAX + 1);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_ROOT_TOO_LARGE, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_root_init_store_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.init_ca_cert_store,
		&verifier.x509, X509_ENGINE_INIT_STORE_FAILED, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INIT_STORE_FAILED, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_root_add_root_ca_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.init_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 0);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.add_root_ca, &verifier.x509,
		X509_ENGINE_ROOT_CA_FAILED, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN),
		MOCK_ARG (X509_CERTSS_ECC384_CA_DER_LEN));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_ROOT_CA_FAILED, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_load_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* The leaf fails to load before any anchor store is built. */
	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		X509_ENGINE_LOAD_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_CHAIN_INVALID, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_authenticate_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 2);
	status |= spdm_cert_chain_verifier_testing_expect_root_anchor (&verifier, 1);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.authenticate, &verifier.x509,
		X509_ENGINE_CERT_NOT_VALID, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_certificate,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_CHAIN_INVALID, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_reanchor_add_trusted_ca_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	/* Root. */
	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Intermediate. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_CA2_DER,
		X509_CERTCA_ECC384_CA2_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_CA2_DER,
		X509_CERTCA_ECC384_CA2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Leaf: anchoring to the intermediate fails. */
	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 4);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.init_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 3);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.add_trusted_ca, &verifier.x509,
		X509_ENGINE_TRUSTED_CA_FAILED, MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_CA2_DER, X509_CERTCA_ECC384_CA2_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_CA2_DER_LEN));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (3));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_certificate,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (4));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_TRUSTED_CA_FAILED, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_anchor_init_store_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 2);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.init_ca_cert_store,
		&verifier.x509, X509_ENGINE_INIT_STORE_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_certificate,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INIT_STORE_FAILED, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_anchor_add_root_ca_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Re-anchoring the next certificate to the retained root fails. */
	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 2);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.init_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 1);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.add_root_ca, &verifier.x509,
		X509_ENGINE_ROOT_CA_FAILED, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN),
		MOCK_ARG (X509_CERTSS_ECC384_CA_DER_LEN));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_certificate,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_ROOT_CA_FAILED, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_no_anchor (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	/* Force a non-root call with neither a root nor a pending CA to anchor to. */
	verifier.state.cert_count = 1;

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 2);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.init_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 0);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_certificate,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NO_TRUST_ANCHOR, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_process_cert_load_error_after_intermediate (
	CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_CA2_DER,
		X509_CERTCA_ECC384_CA2_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_CA2_DER,
		X509_CERTCA_ECC384_CA2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* The leaf fails to load before any anchor store is built. */
	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		X509_ENGINE_LOAD_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_CHAIN_INVALID, status);

	spdm_cert_chain_verifier_testing_check_aborted (test, &verifier);
	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_finalize_before_start (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NOT_STARTED, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_finalize_null (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.finalize_verification (NULL, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, NULL);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INVALID_ARGUMENT, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_finalize_incomplete_chain (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_INCOMPLETE_CHAIN, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_finalize_get_public_key_type_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 3);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.get_public_key_type,
		&verifier.x509, X509_ENGINE_KEY_TYPE_FAILED, MOCK_ARG_SAVED_ARG (3));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_certificate,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NO_KEY, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_finalize_get_public_key_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 3);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.get_public_key_type,
		&verifier.x509, X509_PUBLIC_KEY_ECC, MOCK_ARG_SAVED_ARG (3));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.get_public_key, &verifier.x509,
		X509_ENGINE_KEY_FAILED, MOCK_ARG_SAVED_ARG (3), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_certificate,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NO_KEY, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_finalize_load_certificate_error (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.load_certificate, &verifier.x509,
		X509_ENGINE_LOAD_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC384_EE_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NO_KEY, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_finalize_rsa_leaf (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_leaf_key (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, 3, X509_PUBLIC_KEY_RSA, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, X509_PUBLIC_KEY_RSA, result.key_type);
	CuAssertPtrNotNull (test, result.alias_key);
	CuAssertIntEquals (test, RSA_PUBKEY_DER_LEN, result.alias_key_length);
	status = testing_validate_array (RSA_PUBKEY_DER, result.alias_key, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, result.root_cert.cert);
	CuAssertIntEquals (test, X509_CERTSS_ECC384_CA_DER_LEN, result.root_cert.length);

	/* The verifier keeps no residue and is idle after a successful finalize. */
	CuAssertIntEquals (test, false, verifier.state.started);
	CuAssertIntEquals (test, 0, verifier.state.cert_count);
	CuAssertPtrEquals (test, NULL, verifier.state.pending_cert);
	CuAssertPtrEquals (test, NULL, verifier.state.root_cert);

	/* A second finalize without a new start fails. */
	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NOT_STARTED, status);

	cert_chain_verifier_result_release (&result);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_verify_two_cert_chain (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	/* Root. */
	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Leaf authenticated directly against the root. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Finalize. */
	status = spdm_cert_chain_verifier_testing_expect_leaf_key (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, 3, X509_PUBLIC_KEY_ECC, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, X509_PUBLIC_KEY_ECC, result.key_type);
	CuAssertPtrNotNull (test, result.alias_key);
	CuAssertIntEquals (test, ECC384_PUBKEY_DER_LEN, result.alias_key_length);
	status = testing_validate_array (ECC384_PUBKEY_DER, result.alias_key, ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, result.root_cert.cert);
	CuAssertIntEquals (test, X509_CERTSS_ECC384_CA_DER_LEN, result.root_cert.length);
	status = testing_validate_array (X509_CERTSS_ECC384_CA_DER, result.root_cert.cert,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* The verifier retains no residue after a successful finalize. */
	CuAssertPtrEquals (test, NULL, verifier.state.root_cert);
	CuAssertPtrEquals (test, NULL, verifier.state.pending_cert);

	cert_chain_verifier_result_release (&result);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, verifier.state.root_cert);
	CuAssertIntEquals (test, 0, verifier.state.root_len);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_verify_two_cert_chain_static_init (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier = {
		.test = spdm_cert_chain_verifier_static_init (&verifier.state, &verifier.x509.base)
	};
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init_dependencies (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	/* Root. */
	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Leaf authenticated directly against the root. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Finalize. */
	status = spdm_cert_chain_verifier_testing_expect_leaf_key (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, 3, X509_PUBLIC_KEY_ECC, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, X509_PUBLIC_KEY_ECC, result.key_type);
	CuAssertPtrNotNull (test, result.alias_key);
	CuAssertIntEquals (test, ECC384_PUBKEY_DER_LEN, result.alias_key_length);
	status = testing_validate_array (ECC384_PUBKEY_DER, result.alias_key, ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, result.root_cert.cert);
	CuAssertIntEquals (test, X509_CERTSS_ECC384_CA_DER_LEN, result.root_cert.length);
	status = testing_validate_array (X509_CERTSS_ECC384_CA_DER, result.root_cert.cert,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	cert_chain_verifier_result_release (&result);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_verify_three_cert_chain (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	uint8_t cert_buffer[1024];
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	/* Root. */
	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Intermediate authenticated against the root. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_CA2_DER,
		X509_CERTCA_ECC384_CA2_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	memcpy (cert_buffer, X509_CERTCA_ECC384_CA2_DER, X509_CERTCA_ECC384_CA2_DER_LEN);
	status = verifier.test.base.process_cert (&verifier.test.base, cert_buffer,
		X509_CERTCA_ECC384_CA2_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	memset (cert_buffer, 0, sizeof (cert_buffer));
	status = testing_validate_array (X509_CERTCA_ECC384_CA2_DER, verifier.state.pending_cert,
		X509_CERTCA_ECC384_CA2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Leaf: a local store anchored at the intermediate authenticates the leaf. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTCA_ECC384_CA2_DER, X509_CERTCA_ECC384_CA2_DER_LEN,
		false, 4, 3);
	CuAssertIntEquals (test, 0, status);

	memcpy (cert_buffer, X509_CERTCA_ECC384_EE_DER, X509_CERTCA_ECC384_EE_DER_LEN);
	status = verifier.test.base.process_cert (&verifier.test.base, cert_buffer,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	memset (cert_buffer, 0, sizeof (cert_buffer));
	status = testing_validate_array (X509_CERTCA_ECC384_EE_DER, verifier.state.pending_cert,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Finalize. */
	status = spdm_cert_chain_verifier_testing_expect_leaf_key (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, 5, X509_PUBLIC_KEY_ECC, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, X509_PUBLIC_KEY_ECC, result.key_type);
	CuAssertPtrNotNull (test, result.alias_key);
	CuAssertIntEquals (test, ECC384_PUBKEY_DER_LEN, result.alias_key_length);
	status = testing_validate_array (ECC384_PUBKEY_DER, result.alias_key, ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, result.root_cert.cert);
	CuAssertIntEquals (test, X509_CERTSS_ECC384_CA_DER_LEN, result.root_cert.length);

	cert_chain_verifier_result_release (&result);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_verify_four_cert_chain (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	/* Root. */
	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, verifier.state.pending_cert);

	/* First intermediate, anchored at the root. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_CA2_DER,
		X509_CERTCA_ECC384_CA2_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_CA2_DER,
		X509_CERTCA_ECC384_CA2_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_ECC384_CA2_DER_LEN, verifier.state.pending_cert_len);
	status = testing_validate_array (X509_CERTCA_ECC384_CA2_DER, verifier.state.pending_cert,
		X509_CERTCA_ECC384_CA2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Second intermediate, anchored at the first. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier,
		X509_CERTCA_ECC384_CA2_ICA_DER, X509_CERTCA_ECC384_CA2_ICA_DER_LEN,
		X509_CERTCA_ECC384_CA2_DER,	X509_CERTCA_ECC384_CA2_DER_LEN, false, 4, 3);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_CA2_ICA_DER,
		X509_CERTCA_ECC384_CA2_ICA_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_ECC384_CA2_ICA_DER_LEN, verifier.state.pending_cert_len);
	status = testing_validate_array (X509_CERTCA_ECC384_CA2_ICA_DER, verifier.state.pending_cert,
		X509_CERTCA_ECC384_CA2_ICA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Leaf, anchored at the second intermediate. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTCA_ECC384_CA2_ICA_DER,
		X509_CERTCA_ECC384_CA2_ICA_DER_LEN, false, 6, 5);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, verifier.state.cert_count);
	status = testing_validate_array (X509_CERTCA_ECC384_EE_DER, verifier.state.pending_cert,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Finalize. */
	status = spdm_cert_chain_verifier_testing_expect_leaf_key (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, 7, X509_PUBLIC_KEY_ECC, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, X509_PUBLIC_KEY_ECC, result.key_type);
	status = testing_validate_array (ECC384_PUBKEY_DER, result.alias_key, ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, result.root_cert.cert);
	CuAssertIntEquals (test, X509_CERTSS_ECC384_CA_DER_LEN, result.root_cert.length);
	CuAssertPtrEquals (test, NULL, verifier.state.root_cert);
	CuAssertPtrEquals (test, NULL, verifier.state.pending_cert);

	cert_chain_verifier_result_release (&result);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_start_resets_previous_chain (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	/* Root of the first chain. */
	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Leaf of the first chain. */
	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, verifier.state.pending_cert);

	/* Restarting frees the retained DER from the first chain. */
	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, verifier.state.pending_cert);
	CuAssertPtrEquals (test, NULL, verifier.state.root_cert);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}


static void spdm_cert_chain_verifier_test_process_large_root (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	uint8_t cert_buffer[2048];
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);
	memset (cert_buffer, 0xa5, sizeof (cert_buffer));

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verifier.x509.mock, verifier.x509.base.init_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&verifier.x509.mock, 0, 0);
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.add_root_ca, &verifier.x509,	0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR_CONTAINS (cert_buffer, sizeof (cert_buffer)),
		MOCK_ARG (sizeof (cert_buffer)));
	status |= mock_expect (&verifier.x509.mock, verifier.x509.base.release_ca_cert_store,
		&verifier.x509, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, cert_buffer,
		sizeof (cert_buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, verifier.state.root_cert);
	CuAssertIntEquals (test, sizeof (cert_buffer), verifier.state.root_len);

	memset (cert_buffer, 0, sizeof (cert_buffer));
	CuAssertIntEquals (test, 0xa5, verifier.state.root_cert[0]);
	CuAssertIntEquals (test, 0xa5, verifier.state.root_cert[sizeof (cert_buffer) - 1]);
	memset (cert_buffer, 0xa5, sizeof (cert_buffer));
	status = testing_validate_array (cert_buffer, verifier.state.root_cert, sizeof (cert_buffer));
	CuAssertIntEquals (test, 0, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_release_null (CuTest *test)
{
	TEST_START;

	spdm_cert_chain_verifier_release (NULL);
}

static void spdm_cert_chain_verifier_test_release_root (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	struct cert_chain_verifier_result result;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_cert_chain_verifier_release (&verifier.test);
	CuAssertIntEquals (test, false, verifier.state.started);
	CuAssertIntEquals (test, 0, verifier.state.cert_count);
	CuAssertIntEquals (test, 0, verifier.state.root_len);

	status = verifier.test.base.finalize_verification (&verifier.test.base, &result);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NOT_STARTED, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}

static void spdm_cert_chain_verifier_test_release_pending_cert (CuTest *test)
{
	struct spdm_cert_chain_verifier_testing verifier;
	int status;

	TEST_START;

	spdm_cert_chain_verifier_testing_init (test, &verifier);

	status = verifier.test.base.start_verification (&verifier.test.base);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_root (&verifier, 0);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = spdm_cert_chain_verifier_testing_expect_cert (&verifier, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN, X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN,
		true, 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, verifier.state.pending_cert);

	spdm_cert_chain_verifier_release (&verifier.test);
	CuAssertIntEquals (test, false, verifier.state.started);
	CuAssertIntEquals (test, 0, verifier.state.cert_count);

	status = verifier.test.base.process_cert (&verifier.test.base, X509_CERTCA_ECC384_EE_DER,
		X509_CERTCA_ECC384_EE_DER_LEN);
	CuAssertIntEquals (test, CERT_CHAIN_VERIFIER_NOT_STARTED, status);

	spdm_cert_chain_verifier_testing_release (test, &verifier);
}


// *INDENT-OFF*
TEST_SUITE_START (spdm_cert_chain_verifier);

TEST (spdm_cert_chain_verifier_test_init);
TEST (spdm_cert_chain_verifier_test_static_init);
TEST (spdm_cert_chain_verifier_test_init_null);
TEST (spdm_cert_chain_verifier_test_start_null);
TEST (spdm_cert_chain_verifier_test_process_cert_before_start);
TEST (spdm_cert_chain_verifier_test_process_cert_null);
TEST (spdm_cert_chain_verifier_test_process_root_too_large);
TEST (spdm_cert_chain_verifier_test_process_large_root);
TEST (spdm_cert_chain_verifier_test_process_root_init_store_error);
TEST (spdm_cert_chain_verifier_test_process_root_add_root_ca_error);
TEST (spdm_cert_chain_verifier_test_process_cert_load_error);
TEST (spdm_cert_chain_verifier_test_process_cert_authenticate_error);
TEST (spdm_cert_chain_verifier_test_process_cert_reanchor_add_trusted_ca_error);
TEST (spdm_cert_chain_verifier_test_process_cert_anchor_init_store_error);
TEST (spdm_cert_chain_verifier_test_process_cert_anchor_add_root_ca_error);
TEST (spdm_cert_chain_verifier_test_process_cert_no_anchor);
TEST (spdm_cert_chain_verifier_test_process_cert_load_error_after_intermediate);
TEST (spdm_cert_chain_verifier_test_finalize_before_start);
TEST (spdm_cert_chain_verifier_test_finalize_null);
TEST (spdm_cert_chain_verifier_test_finalize_incomplete_chain);
TEST (spdm_cert_chain_verifier_test_finalize_get_public_key_type_error);
TEST (spdm_cert_chain_verifier_test_finalize_get_public_key_error);
TEST (spdm_cert_chain_verifier_test_finalize_load_certificate_error);
TEST (spdm_cert_chain_verifier_test_finalize_rsa_leaf);
TEST (spdm_cert_chain_verifier_test_verify_two_cert_chain);
TEST (spdm_cert_chain_verifier_test_verify_two_cert_chain_static_init);
TEST (spdm_cert_chain_verifier_test_verify_three_cert_chain);
TEST (spdm_cert_chain_verifier_test_verify_four_cert_chain);
TEST (spdm_cert_chain_verifier_test_start_resets_previous_chain);
TEST (spdm_cert_chain_verifier_test_release_null);
TEST (spdm_cert_chain_verifier_test_release_root);
TEST (spdm_cert_chain_verifier_test_release_pending_cert);

TEST_SUITE_END;
// *INDENT-ON*
