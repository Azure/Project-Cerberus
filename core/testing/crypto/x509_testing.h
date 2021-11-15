// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_TESTING_H_
#define X509_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"


int x509_testing_get_item_length (const uint8_t *der, uint8_t *header);
int x509_testing_get_start_offset (const uint8_t *der);
int x509_testing_set_csr_cn_type (uint8_t *der, uint8_t type);
int x509_testing_set_cert_cn_type (uint8_t *der, uint8_t type);
int x509_testing_set_cert_sig_algo_params (uint8_t *der, bool use_null, size_t *length);
int x509_testing_corrupt_serial_number (uint8_t *der);
int x509_testing_corrupt_signature (uint8_t *der);

/**
 * Helper macro to write DER data to a file for test debugging.
 */
#define	x509_testing_write_der_file(der, length, name) do { \
	FILE *out; \
	\
	out = fopen (name, "w+"); \
	CuAssertPtrNotNull (test, out); \
	fwrite (der, length, 1, out); \
	fclose (out); \
} while (0);


/* Definitions for manipulating the expected certificate data during tests. */
#define	X509_TESTING_DER_EXTRA_SPACE		20

#define	X509_TESTING_CN_UTF8STRING			0x0c
#define	X509_TESTING_CN_PRINTABLESTRING		0x13

#define	X509_TESTING_CN_SET_CSR				x509_testing_set_csr_cn_type
#define	X509_TESTING_CN_SET_CERTSS			x509_testing_set_cert_cn_type
#define	X509_TESTING_CN_SET_CERTCA			X509_TESTING_CN_SET_CERTSS
#define	X509_TESTING_CN_SET_RIOT			X509_TESTING_CN_SET_CERTSS

#define	X509_TESTING_CSR_ALGO_SET_ECDSA_NO_NULL(der, len)		0
#define	X509_TESTING_CSR_ALGO_SET_ECDSA_WITH_NULL(der, len)		0
#define	X509_TESTING_CSR_ALGO_SET_RSA_WITH_NULL(der, len)		0

#define	X509_TESTING_CERTSS_ALGO_SET_ECDSA_NO_NULL(der, len) \
	x509_testing_set_cert_sig_algo_params (der, false, len)
#define	X509_TESTING_CERTSS_ALGO_SET_ECDSA_WITH_NULL(der, len) \
	x509_testing_set_cert_sig_algo_params (der, true, len)
#define	X509_TESTING_CERTSS_ALGO_SET_RSA_WITH_NULL(der, len) \
	x509_testing_set_cert_sig_algo_params (der, true, len)

#define	X509_TESTING_CERTCA_ALGO_SET_ECDSA_NO_NULL		X509_TESTING_CERTSS_ALGO_SET_ECDSA_NO_NULL
#define	X509_TESTING_CERTCA_ALGO_SET_ECDSA_WITH_NULL	X509_TESTING_CERTSS_ALGO_SET_ECDSA_WITH_NULL
#define	X509_TESTING_CERTCA_ALGO_SET_RSA_WITH_NULL		X509_TESTING_CERTSS_ALGO_SET_RSA_WITH_NULL

#define	X509_TESTING_RIOT_ALGO_SET_ECDSA_NO_NULL		X509_TESTING_CERTSS_ALGO_SET_ECDSA_NO_NULL
#define	X509_TESTING_RIOT_ALGO_SET_ECDSA_WITH_NULL		X509_TESTING_CERTSS_ALGO_SET_ECDSA_WITH_NULL
#define	X509_TESTING_RIOT_ALGO_SET_RSA_WITH_NULL		X509_TESTING_CERTSS_ALGO_SET_RSA_WITH_NULL


/**
 * Initialize verification of a generated certificate.
 */
#define	x509_testing_start_cert_verification(test, exp, cert_type, cn_type, algo_type) do { \
	uint8_t exp_der[X509_##cert_type##_##exp##_DER_LEN + X509_TESTING_DER_EXTRA_SPACE]; \
	size_t exp_der_len; \
	int exp_header_len; \
	int exp_cert_len; \
	const uint8_t *exp_algo; \
	size_t exp_algo_len; \
	uint8_t tmp; \
	HASH_TESTING_ENGINE hash_verify; \
	uint8_t actual_hash[SHA256_HASH_LENGTH]; \
	uint8_t actual_header_len; \
	int actual_total_len; \
	int actual_cert_len; \
	int actual_algo_len; \
	int actual_sig_len; \
	int verify_status;\
	\
	verify_status = HASH_TESTING_ENGINE_INIT (&hash_verify); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	exp_der_len = X509_##cert_type##_##exp##_DER_LEN; \
	memcpy (exp_der, X509_##cert_type##_##exp##_DER, exp_der_len); \
	exp_algo = X509_##algo_type##_SIG_ALGO_DER; \
	exp_algo_len = X509_##algo_type##_SIG_ALGO_DER_LEN; \
	\
	verify_status = X509_TESTING_CN_SET_##cert_type (exp_der, X509_TESTING_CN_##cn_type); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	verify_status = X509_TESTING_##cert_type##_ALGO_SET_##algo_type (exp_der, &exp_der_len); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	exp_header_len = x509_testing_get_start_offset (exp_der); \
	CuAssertTrue (test, (exp_header_len > 0)); \
	\
	exp_cert_len = x509_testing_get_item_length (&exp_der[exp_header_len], &tmp); \
	CuAssertTrue (test, (exp_cert_len > 0));

/**
 * Verify the returned length value matches the length of the DER.
 */
#define	x509_testing_verify_cert_length(test, actual, length) \
	actual_total_len = x509_testing_get_item_length (actual, &actual_header_len); \
	CuAssertIntEquals (test, actual_total_len, length);

/**
 * Verify the generated certificate information matches the expected data.
 */
#define	x509_testing_verify_cert(test, actual) \
	actual_cert_len = x509_testing_get_item_length (&actual[actual_header_len], &tmp); \
	CuAssertIntEquals (test, exp_cert_len, actual_cert_len); \
	\
	verify_status = testing_validate_array (&exp_der[exp_header_len], &actual[actual_header_len], \
		exp_cert_len); \
	CuAssertIntEquals (test, 0, verify_status);

/**
 * Verify the signature algorithm section is constructed as expected.
 */
#define	x509_testing_verify_sig_algorithm(test, actual) \
	actual_algo_len = x509_testing_get_item_length (&actual[actual_header_len + actual_cert_len], \
		&tmp); \
	CuAssertIntEquals (test, exp_algo_len, actual_algo_len); \
	\
	verify_status = testing_validate_array (exp_algo, &actual[actual_header_len + actual_cert_len], \
		exp_algo_len); \
	CuAssertIntEquals (test, 0, verify_status);

/**
 * Verify an ECC signature on the certificate.
 */
#define	x509_testing_verify_signature_ecc(test, actual) do { \
	ECC_TESTING_ENGINE ecc_verify; \
	struct ecc_public_key key_verify; \
	\
	verify_status = ECC_TESTING_ENGINE_INIT (&ecc_verify); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	verify_status = ecc_verify.base.init_public_key (&ecc_verify.base, (uint8_t*) ECC_PUBKEY_DER, \
		ECC_PUBKEY_DER_LEN, &key_verify); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	verify_status = hash_verify.base.calculate_sha256 (&hash_verify.base, \
		&actual[actual_header_len], actual_cert_len, actual_hash, sizeof (actual_hash)); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	actual_sig_len = x509_testing_get_item_length ( \
		&actual[actual_header_len + actual_cert_len + actual_algo_len], &tmp); \
	CuAssertTrue (test, (actual_sig_len > 0)); \
	\
	verify_status = ecc_verify.base.verify (&ecc_verify.base, &key_verify, actual_hash, \
		sizeof (actual_hash), \
		&actual[actual_header_len + actual_cert_len + actual_algo_len + tmp + 1], \
		actual_sig_len - (tmp + 1)); \
	CuAssertIntEquals (test, 0, status); \
	\
	ecc_verify.base.release_key_pair (&ecc_verify.base, NULL, &key_verify); \
	ECC_TESTING_ENGINE_RELEASE (&ecc_verify); \
} while (0);

/**
 * Verify an RSA signature on the certificate.
 */
#define	x509_testing_verify_signature_rsa(test, actual) do { \
	RSA_TESTING_ENGINE rsa_verify; \
	\
	verify_status = RSA_TESTING_ENGINE_INIT (&rsa_verify); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	verify_status = hash_verify.base.calculate_sha256 (&hash_verify.base, \
		&actual[actual_header_len], actual_cert_len, actual_hash, sizeof (actual_hash)); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	actual_sig_len = x509_testing_get_item_length ( \
		&actual[actual_header_len + actual_cert_len + actual_algo_len], &tmp); \
	CuAssertTrue (test, (actual_sig_len > 0)); \
	\
	verify_status = rsa_verify.base.sig_verify (&rsa_verify.base, &RSA_PUBLIC_KEY, \
		&actual[actual_header_len + actual_cert_len + actual_algo_len + tmp + 1], \
		actual_sig_len - (tmp + 1), actual_hash, sizeof (actual_hash)); \
	CuAssertIntEquals (test, 0, verify_status); \
	\
	RSA_TESTING_ENGINE_RELEASE (&rsa_verify); \
} while (0);

/**
 * Close the certificate verification block.
 */
#define	x509_testing_end_cert_verification	} while (0);


/* Signature algorithm sequences */
extern const uint8_t X509_ECDSA_NO_NULL_SIG_ALGO_DER[];
extern const size_t X509_ECDSA_NO_NULL_SIG_ALGO_DER_LEN;

extern const uint8_t X509_ECDSA_WITH_NULL_SIG_ALGO_DER[];
extern const size_t X509_ECDSA_WITH_NULL_SIG_ALGO_DER_LEN;

extern const uint8_t X509_RSA_WITH_NULL_SIG_ALGO_DER[];
extern const size_t X509_RSA_WITH_NULL_SIG_ALGO_DER_LEN;


/* CA certificates */
extern const char *X509_SUBJECT_NAME;
extern const uint8_t X509_SERIAL_NUM[];
extern const size_t X509_SERIAL_NUM_LEN;
extern const char *X509_EKU_OID;

extern const char *X509_CA2_SUBJECT_NAME;
extern const uint8_t X509_CA2_SERIAL_NUM[];
extern const size_t X509_CA2_SERIAL_NUM_LEN;

extern const char *X509_CA3_SUBJECT_NAME;

/* Certificate Signing Request */
extern const uint8_t X509_CSR_ECC_CA_DER[];
extern const size_t X509_CSR_ECC_CA_DER_LEN;
extern const uint8_t X509_CSR_RSA_CA_DER[];
extern const size_t X509_CSR_RSA_CA_DER_LEN;

/* CSR with path length constraint of 2 */
extern const uint8_t X509_CSR_ECC_CA_PL2_DER[];
extern const size_t X509_CSR_ECC_CA_PL2_DER_LEN;

/* CSR with no path length constraint */
extern const uint8_t X509_CSR_ECC_CA_NOPL_DER[];
extern const size_t X509_CSR_ECC_CA_NOPL_DER_LEN;

/* CSR with EKU OID */
extern const uint8_t X509_CSR_ECC_CA_EKU_DER[];
extern const size_t X509_CSR_ECC_CA_EKU_DER_LEN;

/* Self-signed certificate */
extern const uint8_t X509_CERTSS_ECC_CA_DER[];
extern const size_t X509_CERTSS_ECC_CA_DER_LEN;
extern const uint8_t X509_CERTSS_ECC384_CA_DER[];
extern const size_t X509_CERTSS_ECC384_CA_DER_LEN;
extern const uint8_t X509_CERTSS_ECC521_CA_DER[];
extern const size_t X509_CERTSS_ECC521_CA_DER_LEN;
extern const uint8_t X509_CERTSS_RSA_CA_DER[];
extern const size_t X509_CERTSS_RSA_CA_DER_LEN;
extern const uint8_t X509_CERTSS_RSA4K_CA_DER[];
extern const size_t X509_CERTSS_RSA4K_CA_DER_LEN;

/* Self-signed certificate with path length constraint of 1 */
extern const uint8_t X509_CERTSS_ECC_CA_PL1_DER[];
extern const size_t X509_CERTSS_ECC_CA_PL1_DER_LEN;

/* Self-signed certificate with no path length constraint */
extern const uint8_t X509_CERTSS_ECC_CA_NOPL_DER[];
extern const size_t X509_CERTSS_ECC_CA_NOPL_DER_LEN;
extern const uint8_t X509_CERTSS_RSA_CA_NOPL_DER[];
extern const size_t X509_CERTSS_RSA_CA_NOPL_DER_LEN;

/* CA-signed certificate
 * Signed by self-signed CA of opposite algorithm (e.g. CERTCA_ECC_CA signed by CERTSS_RSA_CA). */
extern const uint8_t X509_CERTCA_ECC_CA_DER[];
extern const size_t X509_CERTCA_ECC_CA_DER_LEN;
extern const uint8_t X509_CERTCA_RSA_CA_DER[];
extern const size_t X509_CERTCA_RSA_CA_DER_LEN;

/* CA-signed certificate
 * ECC certificate signed by a self-signed ECC CA. */
extern const uint8_t X509_CERTCA_ECC_CA2_DER[];
extern const size_t X509_CERTCA_ECC_CA2_DER_LEN;

/* CA-signed certificate
 * ECC certificate signed by an intermediate ECC CA. */
extern const uint8_t X509_CERTCA_ECC_CA2_ICA_DER[];
extern const size_t X509_CERTCA_ECC_CA2_ICA_DER_LEN;

/* CA-signed certificate with path length constraint of 15 */
extern const uint8_t X509_CERTCA_ECC_CA_PL15_DER[];
extern const size_t X509_CERTCA_ECC_CA_PL15_DER_LEN;

/* CA-signed certificate
 * Generated using second ECC key pair and with path length constraint of 15. */
extern const uint8_t X509_CERTCA_ECC_CA2_PL15_DER[];
extern const size_t X509_CERTCA_ECC_CA2_PL15_DER_LEN;

/* CA-signed certificate with no path length constraint */
extern const uint8_t X509_CERTCA_ECC_CA_NOPL_DER[];
extern const size_t X509_CERTCA_ECC_CA_NOPL_DER_LEN;
extern const uint8_t X509_CERTCA_RSA_CA_NOPL_DER[];
extern const size_t X509_CERTCA_RSA_CA_NOPL_DER_LEN;
extern const uint8_t X509_CERTCA_ECC_CA2_NOPL_DER[];
extern const size_t X509_CERTCA_ECC_CA2_NOPL_DER_LEN;


/* End entity certificates */
extern const char *X509_ENTITY_SUBJECT_NAME;
extern const uint8_t X509_ENTITY_SERIAL_NUM[];
extern const size_t X509_ENTITY_SERIAL_NUM_LEN;

/* Certificate Signing Request */
extern const uint8_t X509_CSR_ECC_EE_DER[];
extern const size_t X509_CSR_ECC_EE_DER_LEN;
extern const uint8_t X509_CSR_RSA_EE_DER[];
extern const size_t X509_CSR_RSA_EE_DER_LEN;

/* Self-signed certificate */
extern const uint8_t X509_CERTSS_ECC_EE_DER[];
extern const size_t X509_CERTSS_ECC_EE_DER_LEN;
extern const uint8_t X509_CERTSS_RSA_EE_DER[];
extern const size_t X509_CERTSS_RSA_EE_DER_LEN;

/* CA-signed certificate
 * Signed by self-signed CA of opposite algorithm (e.g. CERTCA_ECC_EE signed by CERTSS_RSA_CA). */
extern const uint8_t X509_CERTCA_ECC_EE_DER[];
extern const size_t X509_CERTCA_ECC_EE_DER_LEN;
extern const uint8_t X509_CERTCA_RSA_EE_DER[];
extern const size_t X509_CERTCA_RSA_EE_DER_LEN;

/* CA-signed certificate
 * ECC certificate signed by a self-signed ECC CA. */
extern const uint8_t X509_CERTCA_ECC_EE2_DER[];
extern const size_t X509_CERTCA_ECC_EE2_DER_LEN;


/* RIoT extension certificates */
extern const char *X509_RIOT_SUBJECT_NAME;
extern const uint8_t X509_RIOT_SERIAL_NUM[];
extern const size_t X509_RIOT_SERIAL_NUM_LEN;

extern const uint8_t X509_RIOT_SHA1_FWID[];
extern const uint8_t X509_RIOT_SHA256_FWID[];

extern const uint8_t X509_RIOT_UEID[];
extern const size_t X509_RIOT_UEID_LEN;

extern const char *X509_RIOT_VERSION;
extern const uint32_t X509_RIOT_SVN;

/* TCB Info and UEID */
extern const uint8_t X509_CSR_ECC_CA_UEID_DER[];
extern const size_t X509_CSR_ECC_CA_UEID_DER_LEN;
extern const uint8_t X509_CSR_ECC_EE_UEID_DER[];
extern const size_t X509_CSR_ECC_EE_UEID_DER_LEN;

extern const uint8_t X509_CSR_ECC_CA_UEID_SHA1_DER[];
extern const size_t X509_CSR_ECC_CA_UEID_SHA1_DER_LEN;
extern const uint8_t X509_CSR_ECC_CA_UEID_SVN_DER[];
extern const size_t X509_CSR_ECC_CA_UEID_SVN_DER_LEN;

extern const uint8_t X509_CERTSS_ECC_CA_UEID_DER[];
extern const size_t X509_CERTSS_ECC_CA_UEID_DER_LEN;
extern const uint8_t X509_CERTSS_ECC_EE_UEID_DER[];
extern const size_t X509_CERTSS_ECC_EE_UEID_DER_LEN;

extern const uint8_t X509_CERTSS_ECC_CA_UEID_SHA1_DER[];
extern const size_t X509_CERTSS_ECC_CA_UEID_SHA1_DER_LEN;
extern const uint8_t X509_CERTSS_ECC_CA_UEID_SVN_DER[];
extern const size_t X509_CERTSS_ECC_CA_UEID_SVN_DER_LEN;

extern const uint8_t X509_CERTCA_ECC_CA_UEID_DER[];
extern const size_t X509_CERTCA_ECC_CA_UEID_DER_LEN;
extern const uint8_t X509_CERTCA_ECC_EE_UEID_DER[];
extern const size_t X509_CERTCA_ECC_EE_UEID_DER_LEN;

extern const uint8_t X509_CERTCA_ECC_CA_UEID_SHA1_DER[];
extern const size_t X509_CERTCA_ECC_CA_UEID_SHA1_DER_LEN;
extern const uint8_t X509_CERTCA_ECC_CA_UEID_SVN_DER[];
extern const size_t X509_CERTCA_ECC_CA_UEID_SVN_DER_LEN;

/* TCB Info */
extern const uint8_t X509_CSR_ECC_CA_TCBINFO_DER[];
extern const size_t X509_CSR_ECC_CA_TCBINFO_DER_LEN;
extern const uint8_t X509_CSR_ECC_EE_TCBINFO_DER[];
extern const size_t X509_CSR_ECC_EE_TCBINFO_DER_LEN;

extern const uint8_t X509_CERTSS_ECC_CA_TCBINFO_DER[];
extern const size_t X509_CERTSS_ECC_CA_TCBINFO_DER_LEN;
extern const uint8_t X509_CERTSS_ECC_EE_TCBINFO_DER[];
extern const size_t X509_CERTSS_ECC_EE_TCBINFO_DER_LEN;

extern const uint8_t X509_CERTCA_ECC_CA_TCBINFO_DER[];
extern const size_t X509_CERTCA_ECC_CA_TCBINFO_DER_LEN;
extern const uint8_t X509_CERTCA_ECC_EE_TCBINFO_DER[];
extern const size_t X509_CERTCA_ECC_EE_TCBINFO_DER_LEN;


#endif /* X509_TESTING_H_ */
