// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/x509_thread_safe.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/crypto/x509_testing.h"


TEST_SUITE_LABEL ("x509_thread_safe");


/*******************
 * Test cases
 *******************/

static void x509_thread_safe_test_init (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
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

	status = x509_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_init_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (NULL, &mock.base);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = x509_thread_safe_init (&engine, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = x509_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void x509_thread_safe_test_release_null (CuTest *test)
{
	TEST_START;

	x509_thread_safe_release (NULL);
}

static void x509_thread_safe_test_create_csr (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.create_csr, &mock, 0, MOCK_ARG (ECC_PRIVKEY_DER),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG (X509_SUBJECT_NAME), MOCK_ARG (X509_CERT_CA),
		MOCK_ARG (X509_EKU_OID), MOCK_ARG (NULL), MOCK_ARG (&csr), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, X509_EKU_OID, NULL, &csr, &length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_create_csr_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.create_csr, &mock, X509_ENGINE_CSR_FAILED,
		MOCK_ARG (ECC_PRIVKEY_DER), MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG (X509_SUBJECT_NAME),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG (X509_EKU_OID), MOCK_ARG (NULL), MOCK_ARG (&csr),
		MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, X509_EKU_OID, NULL, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_CSR_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_create_csr_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	uint8_t *csr = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_csr (NULL, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		X509_SUBJECT_NAME, X509_CERT_CA, X509_EKU_OID, NULL, &csr, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_create_self_signed_certificate (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.create_self_signed_certificate, &mock, 0,
		MOCK_ARG (&cert), MOCK_ARG (ECC_PRIVKEY_DER), MOCK_ARG (ECC_PRIVKEY_DER_LEN),
		MOCK_ARG (X509_SERIAL_NUM), MOCK_ARG (X509_SERIAL_NUM_LEN), MOCK_ARG (X509_SUBJECT_NAME),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_create_self_signed_certificate_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.create_self_signed_certificate, &mock,
		X509_ENGINE_SELF_SIGNED_FAILED, MOCK_ARG (&cert), MOCK_ARG (ECC_PRIVKEY_DER),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG (X509_SERIAL_NUM), MOCK_ARG (X509_SERIAL_NUM_LEN),
		MOCK_ARG (X509_SUBJECT_NAME), MOCK_ARG (X509_CERT_CA), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_SELF_SIGNED_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_create_self_signed_certificate_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_self_signed_certificate (NULL, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_SERIAL_NUM, X509_SERIAL_NUM_LEN, X509_SUBJECT_NAME, X509_CERT_CA,
		NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_create_ca_signed_certificate (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	struct x509_certificate ca_cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.create_ca_signed_certificate, &mock, 0,
		MOCK_ARG (&cert), MOCK_ARG (ECC_PRIVKEY_DER), MOCK_ARG (ECC_PRIVKEY_DER_LEN),
		MOCK_ARG (X509_CA2_SERIAL_NUM), MOCK_ARG (X509_CA2_SERIAL_NUM_LEN),
		MOCK_ARG (X509_CA2_SUBJECT_NAME), MOCK_ARG (X509_CERT_CA), MOCK_ARG (RSA_PRIVKEY_DER),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN), MOCK_ARG (&ca_cert), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_create_ca_signed_certificate_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	struct x509_certificate ca_cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.create_ca_signed_certificate, &mock,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG (&cert), MOCK_ARG (ECC_PRIVKEY_DER),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG (X509_CA2_SERIAL_NUM),
		MOCK_ARG (X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (X509_CA2_SUBJECT_NAME),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG (RSA_PRIVKEY_DER), MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (&ca_cert), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (&engine.base, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_create_ca_signed_certificate_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	struct x509_certificate ca_cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.create_ca_signed_certificate (NULL, &cert, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, X509_CA2_SUBJECT_NAME,
		X509_CERT_CA, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &ca_cert, NULL);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_load_certificate (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.load_certificate, &mock, 0, MOCK_ARG (&cert),
		MOCK_ARG (X509_CERTSS_ECC_CA_DER), MOCK_ARG (X509_CERTSS_ECC_CA_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_load_certificate_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.load_certificate, &mock, X509_ENGINE_LOAD_FAILED,
		MOCK_ARG (&cert), MOCK_ARG (X509_CERTSS_ECC_CA_DER), MOCK_ARG (X509_CERTSS_ECC_CA_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (&engine.base, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_LOAD_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_load_certificate_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.load_certificate (NULL, &cert, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_release_certificate (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.release_certificate, &mock, 0, MOCK_ARG (&cert));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (&engine.base, &cert);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_release_certificate_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_certificate (NULL, &cert);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_certificate_der (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_certificate_der, &mock, 0, MOCK_ARG (&cert),
		MOCK_ARG (&der), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_certificate_der_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_certificate_der, &mock,
		X509_ENGINE_CERT_DER_FAILED, MOCK_ARG (&cert), MOCK_ARG (&der), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, X509_ENGINE_CERT_DER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_certificate_der_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_der (NULL, &cert, &der, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_certificate_version (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_certificate_version, &mock, X509_VERSION_3,
		MOCK_ARG (&cert));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_version (&engine.base, &cert);
	CuAssertIntEquals (test, X509_VERSION_3, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_certificate_version_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_certificate_version, &mock,
		X509_ENGINE_VERSION_FAILED, MOCK_ARG (&cert));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_version (&engine.base, &cert);
	CuAssertIntEquals (test, X509_ENGINE_VERSION_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_certificate_version_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_certificate_version (NULL, &cert);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_serial_number (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t serial[X509_MAX_SERIAL_NUMBER];

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_serial_number, &mock, X509_SERIAL_NUM_LEN,
		MOCK_ARG (&cert), MOCK_ARG (serial), MOCK_ARG (sizeof (serial)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_serial_number (&engine.base, &cert, serial, sizeof (serial));
	CuAssertIntEquals (test, X509_SERIAL_NUM_LEN, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_serial_number_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t serial[X509_MAX_SERIAL_NUMBER];

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_serial_number, &mock,
		X509_ENGINE_SERIAL_NUM_FAILED, MOCK_ARG (&cert), MOCK_ARG (serial),
		MOCK_ARG (sizeof (serial)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_serial_number (&engine.base, &cert, serial, sizeof (serial));
	CuAssertIntEquals (test, X509_ENGINE_SERIAL_NUM_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_serial_number_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t serial[X509_MAX_SERIAL_NUMBER];

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_serial_number (NULL, &cert, serial, sizeof (serial));
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key_type (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_public_key_type, &mock, X509_PUBLIC_KEY_ECC,
		MOCK_ARG (&cert));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_type (&engine.base, &cert);
	CuAssertIntEquals (test, X509_PUBLIC_KEY_ECC, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key_type_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_public_key_type, &mock,
		X509_ENGINE_KEY_TYPE_FAILED, MOCK_ARG (&cert));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_type (&engine.base, &cert);
	CuAssertIntEquals (test, X509_ENGINE_KEY_TYPE_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key_type_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_type (NULL, &cert);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key_length (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_public_key_length, &mock, 256,
		MOCK_ARG (&cert));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (&engine.base, &cert);
	CuAssertIntEquals (test, 256, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key_length_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_public_key_length, &mock,
		X509_ENGINE_KEY_LENGTH_FAILED, MOCK_ARG (&cert));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (&engine.base, &cert);
	CuAssertIntEquals (test, X509_ENGINE_KEY_LENGTH_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key_length_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_length (NULL, &cert);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_public_key, &mock, 0, MOCK_ARG (&cert),
		MOCK_ARG (&der), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_public_key, &mock, X509_ENGINE_KEY_FAILED,
		MOCK_ARG (&cert), MOCK_ARG (&der), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key (&engine.base, &cert, &der, &length);
	CuAssertIntEquals (test, X509_ENGINE_KEY_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_get_public_key_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key (NULL, &cert, &der, &length);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_init_ca_cert_store (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.init_ca_cert_store, &mock, 0, MOCK_ARG (&store));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_init_ca_cert_store_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.init_ca_cert_store, &mock,
		X509_ENGINE_INIT_STORE_FAILED, MOCK_ARG (&store));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (&engine.base, &store);
	CuAssertIntEquals (test, X509_ENGINE_INIT_STORE_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_init_ca_cert_store_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_ca_cert_store (NULL, &store);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_release_ca_cert_store (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.release_ca_cert_store, &mock, 0, MOCK_ARG (&store));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (&engine.base, &store);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_release_ca_cert_store_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_ca_cert_store (NULL, &store);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_add_root_ca (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.add_root_ca, &mock, 0, MOCK_ARG (&store),
		MOCK_ARG (X509_CERTSS_ECC_CA_DER), MOCK_ARG (X509_CERTSS_ECC_CA_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_add_root_ca_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.add_root_ca, &mock, X509_ENGINE_ROOT_CA_FAILED,
		MOCK_ARG (&store), MOCK_ARG (X509_CERTSS_ECC_CA_DER),
		MOCK_ARG (X509_CERTSS_ECC_CA_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (&engine.base, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_ROOT_CA_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_add_root_ca_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_root_ca (NULL, &store, X509_CERTSS_ECC_CA_DER,
		X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_add_intermediate_ca (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.add_intermediate_ca, &mock, 0, MOCK_ARG (&store),
		MOCK_ARG (X509_CERTCA_ECC_CA_DER), MOCK_ARG (X509_CERTCA_ECC_CA_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_add_intermediate_ca_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.add_intermediate_ca, &mock,
		X509_ENGINE_INTER_CA_FAILED, MOCK_ARG (&store), MOCK_ARG (X509_CERTCA_ECC_CA_DER),
		MOCK_ARG (X509_CERTCA_ECC_CA_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (&engine.base, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INTER_CA_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_add_intermediate_ca_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.add_intermediate_ca (NULL, &store, X509_CERTCA_ECC_CA_DER,
		X509_CERTCA_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_authenticate (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.authenticate, &mock, 0, MOCK_ARG (&cert),
		MOCK_ARG (&store));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_authenticate_error (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.authenticate, &mock, X509_ENGINE_AUTH_FAILED,
		MOCK_ARG (&cert), MOCK_ARG (&store));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (&engine.base, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_AUTH_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}

static void x509_thread_safe_test_authenticate_null (CuTest *test)
{
	struct x509_engine_thread_safe engine;
	struct x509_engine_mock mock;
	int status;
	struct x509_certificate cert;
	struct x509_ca_certs store;

	TEST_START;

	status = x509_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = x509_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.authenticate (NULL, &cert, &store);
	CuAssertIntEquals (test, X509_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.release_certificate (&engine.base, NULL);

	x509_mock_release (&mock);
	x509_thread_safe_release (&engine);
}


TEST_SUITE_START (x509_thread_safe);

TEST (x509_thread_safe_test_init);
TEST (x509_thread_safe_test_init_null);
TEST (x509_thread_safe_test_release_null);
TEST (x509_thread_safe_test_create_csr);
TEST (x509_thread_safe_test_create_csr_error);
TEST (x509_thread_safe_test_create_csr_null);
TEST (x509_thread_safe_test_create_self_signed_certificate);
TEST (x509_thread_safe_test_create_self_signed_certificate_error);
TEST (x509_thread_safe_test_create_self_signed_certificate_null);
TEST (x509_thread_safe_test_create_ca_signed_certificate);
TEST (x509_thread_safe_test_create_ca_signed_certificate_error);
TEST (x509_thread_safe_test_create_ca_signed_certificate_null);
TEST (x509_thread_safe_test_load_certificate);
TEST (x509_thread_safe_test_load_certificate_error);
TEST (x509_thread_safe_test_load_certificate_null);
TEST (x509_thread_safe_test_release_certificate);
TEST (x509_thread_safe_test_release_certificate_null);
TEST (x509_thread_safe_test_get_certificate_der);
TEST (x509_thread_safe_test_get_certificate_der_error);
TEST (x509_thread_safe_test_get_certificate_der_null);
TEST (x509_thread_safe_test_get_certificate_version);
TEST (x509_thread_safe_test_get_certificate_version_error);
TEST (x509_thread_safe_test_get_certificate_version_null);
TEST (x509_thread_safe_test_get_serial_number);
TEST (x509_thread_safe_test_get_serial_number_error);
TEST (x509_thread_safe_test_get_serial_number_null);
TEST (x509_thread_safe_test_get_public_key_type);
TEST (x509_thread_safe_test_get_public_key_type_error);
TEST (x509_thread_safe_test_get_public_key_type_null);
TEST (x509_thread_safe_test_get_public_key_length);
TEST (x509_thread_safe_test_get_public_key_length_error);
TEST (x509_thread_safe_test_get_public_key_length_null);
TEST (x509_thread_safe_test_get_public_key);
TEST (x509_thread_safe_test_get_public_key_error);
TEST (x509_thread_safe_test_get_public_key_null);
TEST (x509_thread_safe_test_init_ca_cert_store);
TEST (x509_thread_safe_test_init_ca_cert_store_error);
TEST (x509_thread_safe_test_init_ca_cert_store_null);
TEST (x509_thread_safe_test_release_ca_cert_store);
TEST (x509_thread_safe_test_release_ca_cert_store_null);
TEST (x509_thread_safe_test_add_root_ca);
TEST (x509_thread_safe_test_add_root_ca_error);
TEST (x509_thread_safe_test_add_root_ca_null);
TEST (x509_thread_safe_test_add_intermediate_ca);
TEST (x509_thread_safe_test_add_intermediate_ca_error);
TEST (x509_thread_safe_test_add_intermediate_ca_null);
TEST (x509_thread_safe_test_authenticate);
TEST (x509_thread_safe_test_authenticate_error);
TEST (x509_thread_safe_test_authenticate_null);

TEST_SUITE_END;
