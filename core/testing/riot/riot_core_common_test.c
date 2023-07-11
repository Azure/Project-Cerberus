// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "common/array_size.h"
#include "riot/riot_core_common.h"
#include "riot/riot_core_common_static.h"
#include "testing/mock/asn1/base64_mock.h"
#include "testing/mock/asn1/x509_extension_builder_mock.h"
#include "testing/mock/asn1/x509_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/engines/base64_testing_engine.h"
#include "testing/asn1/x509_testing.h"
#include "testing/asn1/dice/x509_extension_builder_dice_tcbinfo_testing.h"
#include "testing/asn1/dice/x509_extension_builder_dice_ueid_testing.h"
#include "testing/crypto/kdf_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("riot_core_common");


/**
 * Dependencies for testing the generic DICE layer 0 handler.
 */
struct riot_core_common_testing {
	struct hash_engine_mock hash;						/**< Mock for the hash engine. */
	struct ecc_engine_mock ecc;							/**< Mock for the ECC engine. */
	struct base64_engine_mock base64;					/**< Mock for the base64 engine. */
	struct x509_engine_mock x509;						/**< Mock for the X.509 engine. */
	struct x509_extension_builder_mock tcb;				/**< Mock for the TcbInfo extension. */
	struct x509_extension_builder_mock ueid;			/**< Mock for the Ueid extension. */
	const struct x509_extension_builder *dev_id_ext[2];	/**< List of Device ID extensions. */
	struct x509_extension_builder_mock alias_tcb;		/**< Alias key TcbInfo extension information. */
	const struct x509_extension_builder *alias_ext[1];	/**< List of Alias extensions. */
	struct riot_core_common_state zero_state;			/**< An empty DICE state. */
	struct riot_core_common_state state;				/**< Variable context for the DICE handler. */
	struct riot_core_common test;						/**< DICE handler under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param riot Testing dependencies to initialize.
 */
static void riot_core_common_testing_init_dependencies (CuTest *test,
	struct riot_core_common_testing *riot)
{
	int status;

	status = hash_mock_init (&riot->hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&riot->ecc);
	CuAssertIntEquals (test, 0, status);

	status = base64_mock_init (&riot->base64);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&riot->x509);
	CuAssertIntEquals (test, 0, status);

	status = x509_extension_builder_mock_init (&riot->tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&riot->tcb.mock, "tcb");

	status = x509_extension_builder_mock_init (&riot->ueid);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&riot->ueid.mock, "ueid");

	status = x509_extension_builder_mock_init (&riot->alias_tcb);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&riot->alias_tcb.mock, "alias_tcb");

	riot->dev_id_ext[0] = &riot->tcb.base;
	riot->dev_id_ext[1] = &riot->ueid.base;

	riot->alias_ext[0] = &riot->alias_tcb.base;

	memset (&riot->zero_state, 0, sizeof (riot->zero_state));
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param riot Testing dependencies to release.
 */
static void riot_core_common_testing_release_dependencies (CuTest *test,
	struct riot_core_common_testing *riot)
{
	int status;

	status = hash_mock_validate_and_release (&riot->hash);
	status |= ecc_mock_validate_and_release (&riot->ecc);
	status |= base64_mock_validate_and_release (&riot->base64);
	status |= x509_mock_validate_and_release (&riot->x509);
	status |= x509_extension_builder_mock_validate_and_release (&riot->tcb);
	status |= x509_extension_builder_mock_validate_and_release (&riot->ueid);
	status |= x509_extension_builder_mock_validate_and_release (&riot->alias_tcb);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Validate all mocks without releasing them.
 *
 * @param test The test framework.
 * @param riot Testing dependencies to validate.
 *
 */
static void riot_core_common_testing_validate_mocks (CuTest *test,
	struct riot_core_common_testing *riot)
{
	int status;

	status = mock_validate (&riot->hash.mock);
	status |= mock_validate (&riot->ecc.mock);
	status |= mock_validate (&riot->base64.mock);
	status |= mock_validate (&riot->x509.mock);
	status |= mock_validate (&riot->tcb.mock);
	status |= mock_validate (&riot->ueid.mock);
	status |= mock_validate (&riot->alias_tcb.mock);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a DICE layer 0 handler for testing.
 *
 * @param test The test framework.
 * @param riot Testing dependencies.
 * @param key_length ECC key length to generate.
 */
static void riot_core_common_testing_init (CuTest *test, struct riot_core_common_testing *riot,
	size_t key_length)
{
	int status;

	riot_core_common_testing_init_dependencies (test, riot);

	status = riot_core_common_init (&riot->test, &riot->state, &riot->hash.base, &riot->ecc.base,
		&riot->x509.base, &riot->base64.base, key_length, riot->dev_id_ext,
		ARRAY_SIZE (riot->dev_id_ext), riot->alias_ext, ARRAY_SIZE (riot->alias_ext));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static DICE layer 0 handler for testing.
 *
 * @param test The test framework.
 * @param riot Testing dependencies.
 * @param test_static The static instance to initialize.
 */
static void riot_core_common_testing_init_static (CuTest *test,
	struct riot_core_common_testing *riot, struct riot_core_common *test_static)
{
	int status;

	riot_core_common_testing_init_dependencies (test, riot);

	status = riot_core_common_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release DICE layer 0 test components and validate all mocks.
 *
 * @param test The test framework.
 * @param riot Testing components to release.
 * @param handler the DICE handle to release.
 */
static void riot_core_common_testing_release (CuTest *test, struct riot_core_common_testing *riot,
	struct riot_core_common *handler)
{
	int status;

	riot_core_common_release (handler);

	status = testing_validate_array ((uint8_t*) &riot->zero_state, (uint8_t*) &riot->state,
		sizeof (riot->state));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release_dependencies (test, riot);
}

/**
 * Execute the DICE Device ID key generation workflow for a 256-bit key.
 *
 * @param test The testing framework.
 * @param riot Testing dependencies.
 * @param dice The DICE handler being tested.
 */
static void riot_core_common_testing_device_id_generation_256 (CuTest *test,
	struct riot_core_common_testing *riot, struct riot_core_common *dice)
{
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;
	int status;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	/* Hash the CDI. */
	status = mock_expect (&riot->hash.mock, riot->hash.base.start_sha256, &riot->hash, 0);
	status |= mock_expect (&riot->hash.mock, riot->hash.base.update, &riot->hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot->hash.mock, riot->hash.base.update, &riot->hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot->hash.mock, riot->hash.base.finish, &riot->hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot->hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot->hash, HASH_TYPE_SHA256,
		RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_DEVICE_ID_KDF,
		RIOT_CORE_DEVICE_ID_KDF_LEN);

	status |= mock_expect (&riot->ecc.mock, riot->ecc.base.generate_derived_key_pair, &riot->ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF, RIOT_CORE_DEVICE_ID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot->ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot->ecc.mock, riot->ecc.base.get_private_key_der, &riot->ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot->ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot->ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot->hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&riot->base64.mock, riot->base64.base.encode, &riot->base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&riot->base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&riot->x509.mock, riot->x509.base.create_self_signed_certificate,
		&riot->x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA),
		MOCK_ARG_PTR_CONTAINS (&riot->dev_id_ext, sizeof (riot->dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot->dev_id_ext)));
	status |= mock_expect_save_arg (&riot->x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = dice->base.generate_device_id (&dice->base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, riot);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
/**
 * Execute the DICE Device ID key generation workflow for a 384-bit key.
 *
 * @param test The testing framework.
 * @param riot Testing dependencies.
 * @param dice The DICE handler being tested.
 */
static void riot_core_common_testing_device_id_generation_384 (CuTest *test,
	struct riot_core_common_testing *riot, struct riot_core_common *dice)
{
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_384_LEN;
	int status;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID_384, der_length);

	/* Hash the CDI. */
	status = mock_expect (&riot->hash.mock, riot->hash.base.start_sha384, &riot->hash, 0);
	status |= mock_expect (&riot->hash.mock, riot->hash.base.update, &riot->hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot->hash.mock, riot->hash.base.update, &riot->hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot->hash.mock, riot->hash.base.finish, &riot->hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&riot->hash.mock, 0, RIOT_CORE_CDI_HASH_384,
		RIOT_CORE_CDI_HASH_384_LEN, 1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot->hash, HASH_TYPE_SHA384,
		RIOT_CORE_CDI_HASH_384, RIOT_CORE_CDI_HASH_384_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_384, RIOT_CORE_DEVICE_ID_KDF_384,
		RIOT_CORE_DEVICE_ID_KDF_384_LEN);

	status |= mock_expect (&riot->ecc.mock, riot->ecc.base.generate_derived_key_pair, &riot->ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF_384, RIOT_CORE_DEVICE_ID_KDF_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_384_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot->ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot->ecc.mock, riot->ecc.base.get_private_key_der, &riot->ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot->ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot->ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot->hash, RIOT_CORE_CDI_HASH_384,
		RIOT_CORE_CDI_HASH_384_LEN, RIOT_CORE_SERIAL_KDF_TEST_DATA,
		RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL, SHA384_HASH_LENGTH, HASH_TYPE_SHA384,
		RIOT_CORE_DEVID_SERIAL_384, RIOT_CORE_DEVID_SERIAL_384_LEN);

	status |= mock_expect (&riot->base64.mock, riot->base64.base.encode, &riot->base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_384, RIOT_CORE_DEVID_SERIAL_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_384_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_384_LEN));
	status |= mock_expect_output (&riot->base64.mock, 2, RIOT_CORE_DEVID_NAME_384,
		RIOT_CORE_DEVID_NAME_384_LEN, 3);

	status |= mock_expect (&riot->x509.mock, riot->x509.base.create_self_signed_certificate,
		&riot->x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_384, RIOT_CORE_DEVICE_ID_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_384_LEN), MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_384, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_384, RIOT_CORE_DEVID_NAME_384_LEN),
		MOCK_ARG (X509_CERT_CA),
		MOCK_ARG_PTR_CONTAINS (&riot->dev_id_ext, sizeof (riot->dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot->dev_id_ext)));
	status |= mock_expect_save_arg (&riot->x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = dice->base.generate_device_id (&dice->base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, riot);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
/**
 * Execute the DICE Device ID key generation workflow for a 521-bit key.
 *
 * @param test The testing framework.
 * @param riot Testing dependencies.
 * @param dice The DICE handler being tested.
 */
static void riot_core_common_testing_device_id_generation_521 (CuTest *test,
	struct riot_core_common_testing *riot, struct riot_core_common *dice)
{
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_521_LEN;
	int status;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID_521, der_length);

	/* Hash the CDI. */
	status = mock_expect (&riot->hash.mock, riot->hash.base.start_sha512, &riot->hash, 0);
	status |= mock_expect (&riot->hash.mock, riot->hash.base.update, &riot->hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot->hash.mock, riot->hash.base.update, &riot->hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot->hash.mock, riot->hash.base.finish, &riot->hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&riot->hash.mock, 0, RIOT_CORE_CDI_HASH_512,
		RIOT_CORE_CDI_HASH_512_LEN, 1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot->hash, HASH_TYPE_SHA512,
		RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521,
		RIOT_CORE_DEVICE_ID_KDF_521_OUT_1, RIOT_CORE_DEVICE_ID_KDF_521_OUT_1_LEN);

	status |= kdf_testing_expect_nist800_108_counter_mode (&riot->hash, HASH_TYPE_SHA512,
		RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN, 2, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521,
		RIOT_CORE_DEVICE_ID_KDF_521_OUT_2, RIOT_CORE_DEVICE_ID_KDF_521_OUT_2_LEN);

	status |= mock_expect (&riot->ecc.mock, riot->ecc.base.generate_derived_key_pair, &riot->ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF_521, RIOT_CORE_DEVICE_ID_KDF_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_521_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot->ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot->ecc.mock, riot->ecc.base.get_private_key_der, &riot->ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot->ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot->ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot->hash, RIOT_CORE_CDI_HASH_512,
		RIOT_CORE_CDI_HASH_512_LEN, RIOT_CORE_SERIAL_KDF_TEST_DATA,
		RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL, SHA512_HASH_LENGTH, HASH_TYPE_SHA512,
		RIOT_CORE_DEVID_SERIAL_521, RIOT_CORE_DEVID_SERIAL_521_LEN);

	status |= mock_expect (&riot->base64.mock, riot->base64.base.encode, &riot->base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_521, RIOT_CORE_DEVID_SERIAL_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_521_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_521_LEN));
	status |= mock_expect_output (&riot->base64.mock, 2, RIOT_CORE_DEVID_NAME_521,
		RIOT_CORE_DEVID_NAME_521_LEN, 3);

	status |= mock_expect (&riot->x509.mock, riot->x509.base.create_self_signed_certificate,
		&riot->x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_521, RIOT_CORE_DEVICE_ID_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_521_LEN), MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_521, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_521, RIOT_CORE_DEVID_NAME_521_LEN),
		MOCK_ARG (X509_CERT_CA),
		MOCK_ARG_PTR_CONTAINS (&riot->dev_id_ext, sizeof (riot->dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot->dev_id_ext)));
	status |= mock_expect_save_arg (&riot->x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = dice->base.generate_device_id (&dice->base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, riot);
}
#endif

/**
 * Execute the DICE Alias key generation workflow for a 256-bit key.
 *
 * @param test The testing framework.
 * @param riot Testing dependencies.
 * @param dice The DICE handler being tested.
 */
static void riot_core_common_testing_alias_generation_256 (CuTest *test,
	struct riot_core_common_testing *riot, struct riot_core_common *dice)
{
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;
	int status;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot->hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot->hash, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_ALIAS_KDF,
		RIOT_CORE_ALIAS_KDF_LEN);

	status |= mock_expect (&riot->ecc.mock, riot->ecc.base.generate_derived_key_pair, &riot->ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF, RIOT_CORE_ALIAS_KDF_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot->ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot->ecc.mock, riot->ecc.base.get_private_key_der, &riot->ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot->ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot->ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot->hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&riot->base64.mock, riot->base64.base.encode, &riot->base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&riot->base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&riot->x509.mock, riot->x509.base.create_ca_signed_certificate,
		&riot->x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&riot->alias_ext, sizeof (riot->alias_ext)),
		MOCK_ARG (ARRAY_SIZE (riot->alias_ext)));
	status |= mock_expect_save_arg (&riot->x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = dice->base.generate_alias_key (&dice->base, RIOT_CORE_FWID, RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, riot);
}


/*******************
 * Test cases
 *******************/

static void riot_core_common_test_init (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, riot.test.base.generate_device_id);
	CuAssertPtrNotNull (test, riot.test.base.get_device_id_csr);
	CuAssertPtrNotNull (test, riot.test.base.get_device_id_cert);
	CuAssertPtrNotNull (test, riot.test.base.generate_alias_key);
	CuAssertPtrNotNull (test, riot.test.base.get_alias_key);
	CuAssertPtrNotNull (test, riot.test.base.get_alias_key_cert);

	riot_core_common_release (&riot.test);

	status = testing_validate_array ((uint8_t*) &riot.zero_state, (uint8_t*) &riot.state,
		sizeof (riot.state));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}

static void riot_core_common_test_static_init (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, test_static.base.generate_device_id);
	CuAssertPtrNotNull (test, test_static.base.get_device_id_csr);
	CuAssertPtrNotNull (test, test_static.base.get_device_id_cert);
	CuAssertPtrNotNull (test, test_static.base.generate_alias_key);
	CuAssertPtrNotNull (test, test_static.base.get_alias_key);
	CuAssertPtrNotNull (test, test_static.base.get_alias_key_cert);

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&test_static);

	status = testing_validate_array ((uint8_t*) &riot.zero_state, (uint8_t*) &riot.state,
		sizeof (riot.state));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void riot_core_common_test_init_ecc384 (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_384, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot.test);

	status = testing_validate_array ((uint8_t*) &riot.zero_state, (uint8_t*) &riot.state,
		sizeof (riot.state));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}

static void riot_core_common_test_static_init_ecc384 (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_384,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&test_static);

	status = testing_validate_array ((uint8_t*) &riot.zero_state, (uint8_t*) &riot.state,
		sizeof (riot.state));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void riot_core_common_test_init_ecc521 (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_521, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot.test);

	status = testing_validate_array ((uint8_t*) &riot.zero_state, (uint8_t*) &riot.state,
		sizeof (riot.state));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}

static void riot_core_common_test_static_init_ecc521 (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_521,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&test_static);

	status = testing_validate_array ((uint8_t*) &riot.zero_state, (uint8_t*) &riot.state,
		sizeof (riot.state));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}
#endif

static void riot_core_common_test_init_null (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init (NULL, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot.test, NULL, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot.test, &riot.state, NULL, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, NULL,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		NULL, &riot.base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, NULL, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256, NULL,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), NULL, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}

static void riot_core_common_test_init_unknown_key_length (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, 64, riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext),
		riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, RIOT_CORE_UNSUPPORTED_KEY_LENGTH, status);


	riot_core_common_testing_release_dependencies (test, &riot);
}

static void riot_core_common_test_static_init_null (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init_state (NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	test_static.state = &riot.state;
	test_static.hash = NULL;
	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	test_static.hash = &riot.hash.base;
	test_static.ecc = NULL;
	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	test_static.ecc = &riot.ecc.base;
	test_static.base64 = NULL;
	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	test_static.base64 = &riot.base64.base;
	test_static.x509 = NULL;
	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	test_static.x509 = &riot.x509.base;
	test_static.dev_id_ext = NULL;
	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	test_static.dev_id_ext = riot.dev_id_ext;
	test_static.alias_ext = NULL;
	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}

static void riot_core_common_test_static_init_unknown_key_length (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, 96, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init_state (&test_static);
	CuAssertIntEquals (test, RIOT_CORE_UNSUPPORTED_KEY_LENGTH, status);

	riot_core_common_testing_release_dependencies (test, &riot);
}

static void riot_core_common_test_release_null (CuTest *test)
{
	TEST_START;

	riot_core_common_release (NULL);
}

static void riot_core_common_test_release_twice (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

	status = riot_core_common_init (&riot.test, &riot.state, &riot.hash.base, &riot.ecc.base,
		&riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext,
		ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot.test);

	status = testing_validate_array ((uint8_t*) &riot.zero_state, (uint8_t*) &riot.state,
		sizeof (riot.state));
	CuAssertIntEquals (test, 0, status);

	riot_core_common_release (&riot.test);

	riot_core_common_testing_release_dependencies (test, &riot);
}

static void riot_core_common_test_generate_device_id (CuTest *test)
{

	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_DEVICE_ID_KDF,
		RIOT_CORE_DEVICE_ID_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF, RIOT_CORE_DEVICE_ID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_self_signed_certificate,
		&riot.x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_static_init (CuTest *test)
{

	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_DEVICE_ID_KDF,
		RIOT_CORE_DEVICE_ID_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF, RIOT_CORE_DEVICE_ID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_self_signed_certificate,
		&riot.x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.generate_device_id (&test_static.base, RIOT_CORE_CDI,
		RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void riot_core_common_test_generate_device_id_ecc384 (CuTest *test)
{

	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_384_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID_384, der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_384);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha384, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH_384,
		RIOT_CORE_CDI_HASH_384_LEN, 1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA384,
		RIOT_CORE_CDI_HASH_384, RIOT_CORE_CDI_HASH_384_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_384, RIOT_CORE_DEVICE_ID_KDF_384,
		RIOT_CORE_DEVICE_ID_KDF_384_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF_384, RIOT_CORE_DEVICE_ID_KDF_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_384_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH_384, RIOT_CORE_CDI_HASH_384_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA384_HASH_LENGTH, HASH_TYPE_SHA384, RIOT_CORE_DEVID_SERIAL_384,
		RIOT_CORE_DEVID_SERIAL_384_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_384, RIOT_CORE_DEVID_SERIAL_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_384_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_384_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_DEVID_NAME_384,
		RIOT_CORE_DEVID_NAME_384_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_self_signed_certificate,
		&riot.x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_384, RIOT_CORE_DEVICE_ID_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_384_LEN), MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_384, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_384, RIOT_CORE_DEVID_NAME_384_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_static_init_ecc384 (CuTest *test)
{

	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_384,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_384_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID_384, der_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha384, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH_384,
		RIOT_CORE_CDI_HASH_384_LEN, 1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA384,
		RIOT_CORE_CDI_HASH_384, RIOT_CORE_CDI_HASH_384_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_384, RIOT_CORE_DEVICE_ID_KDF_384,
		RIOT_CORE_DEVICE_ID_KDF_384_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF_384, RIOT_CORE_DEVICE_ID_KDF_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_384_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH_384, RIOT_CORE_CDI_HASH_384_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA384_HASH_LENGTH, HASH_TYPE_SHA384, RIOT_CORE_DEVID_SERIAL_384,
		RIOT_CORE_DEVID_SERIAL_384_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_384, RIOT_CORE_DEVID_SERIAL_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_384_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_384_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_DEVID_NAME_384,
		RIOT_CORE_DEVID_NAME_384_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_self_signed_certificate,
		&riot.x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_384, RIOT_CORE_DEVICE_ID_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_384_LEN), MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_384, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_384, RIOT_CORE_DEVID_NAME_384_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.generate_device_id (&test_static.base, RIOT_CORE_CDI,
		RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void riot_core_common_test_generate_device_id_ecc521 (CuTest *test)
{

	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_521_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID_521, der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_521);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha512, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH_512,
		RIOT_CORE_CDI_HASH_512_LEN, 1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA512,
		RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521,
		RIOT_CORE_DEVICE_ID_KDF_521_OUT_1, RIOT_CORE_DEVICE_ID_KDF_521_OUT_1_LEN);

	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA512,
		RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN, 2, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521,
		RIOT_CORE_DEVICE_ID_KDF_521_OUT_2, RIOT_CORE_DEVICE_ID_KDF_521_OUT_2_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF_521, RIOT_CORE_DEVICE_ID_KDF_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_521_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA512_HASH_LENGTH, HASH_TYPE_SHA512, RIOT_CORE_DEVID_SERIAL_521,
		RIOT_CORE_DEVID_SERIAL_521_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_521, RIOT_CORE_DEVID_SERIAL_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_521_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_521_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_DEVID_NAME_521,
		RIOT_CORE_DEVID_NAME_521_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_self_signed_certificate,
		&riot.x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_521, RIOT_CORE_DEVICE_ID_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_521_LEN), MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_521, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_521, RIOT_CORE_DEVID_NAME_521_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_static_init_ecc521 (CuTest *test)
{

	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_521,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_521_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID_521, der_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha512, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH_512,
		RIOT_CORE_CDI_HASH_512_LEN, 1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA512,
		RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521,
		RIOT_CORE_DEVICE_ID_KDF_521_OUT_1, RIOT_CORE_DEVICE_ID_KDF_521_OUT_1_LEN);

	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA512,
		RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN, 2, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521,
		RIOT_CORE_DEVICE_ID_KDF_521_OUT_2, RIOT_CORE_DEVICE_ID_KDF_521_OUT_2_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF_521, RIOT_CORE_DEVICE_ID_KDF_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_521_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA512_HASH_LENGTH, HASH_TYPE_SHA512, RIOT_CORE_DEVID_SERIAL_521,
		RIOT_CORE_DEVID_SERIAL_521_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_521, RIOT_CORE_DEVID_SERIAL_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_521_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_521_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_DEVID_NAME_521,
		RIOT_CORE_DEVID_NAME_521_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_self_signed_certificate,
		&riot.x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_521, RIOT_CORE_DEVICE_ID_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_521_LEN), MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL_521, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_521, RIOT_CORE_DEVID_NAME_521_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.generate_device_id (&test_static.base, RIOT_CORE_CDI,
		RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);
}
#endif

static void riot_core_common_test_generate_device_id_null (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	status = riot.test.base.generate_device_id (NULL, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, 0);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_cdi_hash_start_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_cdi_hash_first_byte_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));

	status |= mock_expect (&riot.hash.mock, riot.hash.base.cancel, &riot.hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_cdi_hash_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR (RIOT_CORE_CDI + 1),
		MOCK_ARG (RIOT_CORE_CDI_LEN - 1));

	status |= mock_expect (&riot.hash.mock, riot.hash.base.cancel, &riot.hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_cdi_hash_finish_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&riot.hash.mock, riot.hash.base.cancel, &riot.hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_key_pair_hmac_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_key_pair_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_DEVICE_ID_KDF,
		RIOT_CORE_DEVICE_ID_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc,
		ECC_ENGINE_DERIVED_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF, RIOT_CORE_DEVICE_ID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_DERIVED_KEY_FAILED, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_der_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_DEVICE_ID_KDF,
		RIOT_CORE_DEVICE_ID_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF, RIOT_CORE_DEVICE_ID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc,
		ECC_ENGINE_PRIVATE_KEY_DER_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_PRIVATE_KEY_DER_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_serial_hmac_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_DEVICE_ID_KDF,
		RIOT_CORE_DEVICE_ID_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF, RIOT_CORE_DEVICE_ID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_subject_name_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_DEVICE_ID_KDF,
		RIOT_CORE_DEVICE_ID_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF, RIOT_CORE_DEVICE_ID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64,
		BASE64_ENGINE_ENCODE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_LEN));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, BASE64_ENGINE_ENCODE_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_device_id_cert_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length = RIOT_CORE_DEVICE_ID_LEN;

	TEST_START;

	der = platform_malloc (der_length);
	CuAssertPtrNotNull (test, der);

	memcpy (der, RIOT_CORE_DEVICE_ID, der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	/* Hash the CDI. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash, 0);
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_CDI, 1), MOCK_ARG (1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.update, &riot.hash, 0,
		MOCK_ARG_PTR (RIOT_CORE_CDI + 1), MOCK_ARG (RIOT_CORE_CDI_LEN - 1));
	status |= mock_expect (&riot.hash.mock, riot.hash.base.finish, &riot.hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&riot.hash.mock, 0, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		1);

	/* Derive the Device ID. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN, 1, RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL,
		RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN, RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT,
		RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_DEVICE_ID_KDF,
		RIOT_CORE_DEVICE_ID_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_KDF, RIOT_CORE_DEVICE_ID_KDF_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 0);

	/* Generate the Device ID X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &der, sizeof (der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &der_length, sizeof (der_length), -1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_DEVID_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_DEVID_NAME_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_DEVID_NAME,
		RIOT_CORE_DEVID_NAME_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_self_signed_certificate,
		&riot.x509, X509_ENGINE_SELF_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, X509_ENGINE_SELF_SIGNED_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_device_id_csr (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (csr, RIOT_CORE_DEVID_CSR, csr_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Generate the CSR. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.create_csr, &riot.x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 9, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&riot.x509.mock, 10, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_csr (&riot.test.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);

	platform_free (csr);
}

static void riot_core_common_test_get_device_id_csr_with_oid (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (csr, RIOT_CORE_DEVID_CSR, csr_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Generate the CSR. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.create_csr, &riot.x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_OID, RIOT_CORE_DEVICE_ID_OID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_OID_LEN),
		MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 9, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&riot.x509.mock, 10, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_csr (&riot.test.base, RIOT_CORE_DEVICE_ID_OID,
		RIOT_CORE_DEVICE_ID_OID_LEN, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);

	platform_free (csr);
}

static void riot_core_common_test_get_device_id_csr_static_init (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (csr, RIOT_CORE_DEVID_CSR, csr_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &test_static);

	/* Generate the CSR. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.create_csr, &riot.x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 9, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&riot.x509.mock, 10, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.get_device_id_csr (&test_static.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);

	platform_free (csr);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void riot_core_common_test_get_device_id_csr_ecc384 (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_384_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (csr, RIOT_CORE_DEVID_CSR_384, csr_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_384);
	riot_core_common_testing_device_id_generation_384 (test, &riot, &riot.test);

	/* Generate the CSR. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.create_csr, &riot.x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_384, RIOT_CORE_DEVICE_ID_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_384_LEN), MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_384, RIOT_CORE_DEVID_NAME_384_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR (NULL),  MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 9, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&riot.x509.mock, 10, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_csr (&riot.test.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_384_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);

	platform_free (csr);
}

static void riot_core_common_test_get_device_id_csr_static_init_ecc384 (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_384,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_384_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (csr, RIOT_CORE_DEVID_CSR_384, csr_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_384 (test, &riot, &test_static);

	/* Generate the CSR. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.create_csr, &riot.x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_384, RIOT_CORE_DEVICE_ID_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_384_LEN), MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_384, RIOT_CORE_DEVID_NAME_384_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 9, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&riot.x509.mock, 10, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.get_device_id_csr (&test_static.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_384_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);

	platform_free (csr);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void riot_core_common_test_get_device_id_csr_ecc521 (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_521_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (csr, RIOT_CORE_DEVID_CSR_521, csr_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_521);
	riot_core_common_testing_device_id_generation_521 (test, &riot, &riot.test);

	/* Generate the CSR. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.create_csr, &riot.x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_521, RIOT_CORE_DEVICE_ID_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_521_LEN), MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_521, RIOT_CORE_DEVID_NAME_521_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 9, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&riot.x509.mock, 10, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_csr (&riot.test.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_521_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);

	platform_free (csr);
}

static void riot_core_common_test_get_device_id_csr_static_init_ecc521 (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_521,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_521_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (csr, RIOT_CORE_DEVID_CSR_521, csr_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_521 (test, &riot, &test_static);

	/* Generate the CSR. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.create_csr, &riot.x509, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_521, RIOT_CORE_DEVICE_ID_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_521_LEN), MOCK_ARG (HASH_TYPE_SHA512),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME_521, RIOT_CORE_DEVID_NAME_521_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 9, &csr, sizeof (csr), -1);
	status |= mock_expect_output (&riot.x509.mock, 10, &csr_length, sizeof (csr_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.get_device_id_csr (&test_static.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CSR_521_LEN, out_length);
	CuAssertPtrEquals (test, csr, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);

	platform_free (csr);
}
#endif

static void riot_core_common_test_get_device_id_csr_null (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *csr;
	size_t csr_length = RIOT_CORE_DEVID_CSR_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	csr = platform_malloc (csr_length);
	CuAssertPtrNotNull (test, csr);

	memcpy (csr, RIOT_CORE_DEVID_CSR, csr_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	status = riot.test.base.get_device_id_csr (NULL, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.get_device_id_csr (&riot.test.base, NULL, 0, NULL, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.get_device_id_csr (&riot.test.base, NULL, 0, &out, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);

	platform_free (csr);
}

static void riot_core_common_test_get_device_id_csr_no_device_id (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	status = riot.test.base.get_device_id_csr (&riot.test.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_NO_DEVICE_ID, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_device_id_csr_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Generate the CSR. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.create_csr, &riot.x509,
		X509_ENGINE_CSR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_NAME, RIOT_CORE_DEVID_NAME_LEN),
		MOCK_ARG (X509_CERT_CA), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (riot.dev_id_ext, sizeof (riot.dev_id_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.dev_id_ext)), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_csr (&riot.test.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, X509_ENGINE_CSR_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_device_id_cert (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *cert;
	size_t cert_length = RIOT_CORE_DEVID_CERT_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	cert = platform_malloc (cert_length);
	CuAssertPtrNotNull (test, cert);

	memcpy (cert, RIOT_CORE_DEVID_CERT, cert_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Encode the certificate. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.get_certificate_der, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 1, &cert, sizeof (cert), -1);
	status |= mock_expect_output (&riot.x509.mock, 2, &cert_length, sizeof (cert_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_cert (&riot.test.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CERT_LEN, out_length);
	CuAssertPtrEquals (test, cert, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);

	platform_free (cert);
}

static void riot_core_common_test_get_device_id_cert_static_init (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *cert;
	size_t cert_length = RIOT_CORE_DEVID_CERT_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	cert = platform_malloc (cert_length);
	CuAssertPtrNotNull (test, cert);

	memcpy (cert, RIOT_CORE_DEVID_CERT, cert_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &test_static);

	/* Encode the certificate. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.get_certificate_der, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 1, &cert, sizeof (cert), -1);
	status |= mock_expect_output (&riot.x509.mock, 2, &cert_length, sizeof (cert_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.get_device_id_cert (&test_static.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CERT_LEN, out_length);
	CuAssertPtrEquals (test, cert, out);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);

	platform_free (cert);
}

static void riot_core_common_test_get_device_id_cert_null (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	status = riot.test.base.get_device_id_cert (NULL, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.get_device_id_cert (&riot.test.base, NULL, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.get_device_id_cert (&riot.test.base, &out, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_device_id_cert_no_device_id (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	status = riot.test.base.get_device_id_cert (&riot.test.base, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_NO_DEVICE_ID, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_device_id_cert_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Encode the certificate. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.get_certificate_der, &riot.x509,
		X509_ENGINE_CERT_DER_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&out),
		MOCK_ARG_PTR (&out_length));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_cert (&riot.test.base, &out, &out_length);
	CuAssertIntEquals (test, X509_ENGINE_CERT_DER_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_ALIAS_KDF,
		RIOT_CORE_ALIAS_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF, RIOT_CORE_ALIAS_KDF_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_ca_signed_certificate, &riot.x509,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&riot.alias_ext, sizeof (riot.alias_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.alias_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_static_init (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &test_static);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_ALIAS_KDF,
		RIOT_CORE_ALIAS_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF, RIOT_CORE_ALIAS_KDF_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_ca_signed_certificate, &riot.x509,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&riot.alias_ext, sizeof (riot.alias_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.alias_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.generate_alias_key (&test_static.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void riot_core_common_test_generate_alias_key_ecc384 (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_384_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY_384, alias_der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_384);
	riot_core_common_testing_device_id_generation_384 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH_384, RIOT_CORE_CDI_HASH_384_LEN,
		RIOT_CORE_FWID_SHA384, RIOT_CORE_FWID_SHA384_LEN, NULL, SHA384_HASH_LENGTH,
		HASH_TYPE_SHA384, RIOT_CORE_FWID_KDF_384, RIOT_CORE_FWID_KDF_384_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA384,
		RIOT_CORE_FWID_KDF_384, RIOT_CORE_FWID_KDF_384_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_384, RIOT_CORE_ALIAS_KDF_384,
		RIOT_CORE_ALIAS_KDF_384_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF_384, RIOT_CORE_ALIAS_KDF_384_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_384_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_FWID_KDF_384, RIOT_CORE_FWID_KDF_384_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA384_HASH_LENGTH, HASH_TYPE_SHA384, RIOT_CORE_ALIAS_SERIAL_384,
		RIOT_CORE_ALIAS_SERIAL_384_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL_384, RIOT_CORE_ALIAS_SERIAL_384_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_384_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_384_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_ALIAS_NAME_384,
		RIOT_CORE_ALIAS_NAME_384_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_ca_signed_certificate, &riot.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY_384, RIOT_CORE_ALIAS_KEY_384_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_384_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL_384, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME_384, RIOT_CORE_ALIAS_NAME_384_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_384, RIOT_CORE_DEVICE_ID_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_384_LEN), MOCK_ARG (HASH_TYPE_SHA384), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&riot.alias_ext, sizeof (riot.alias_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.alias_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID_SHA384,
		RIOT_CORE_FWID_SHA384_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_static_init_ecc384 (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_384,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_384_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY_384, alias_der_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_384 (test, &riot, &test_static);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH_384, RIOT_CORE_CDI_HASH_384_LEN,
		RIOT_CORE_FWID_SHA384, RIOT_CORE_FWID_SHA384_LEN, NULL, SHA384_HASH_LENGTH,
		HASH_TYPE_SHA384, RIOT_CORE_FWID_KDF_384, RIOT_CORE_FWID_KDF_384_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA384,
		RIOT_CORE_FWID_KDF_384, RIOT_CORE_FWID_KDF_384_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_384, RIOT_CORE_ALIAS_KDF_384,
		RIOT_CORE_ALIAS_KDF_384_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF_384, RIOT_CORE_ALIAS_KDF_384_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_384_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_FWID_KDF_384, RIOT_CORE_FWID_KDF_384_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA384_HASH_LENGTH, HASH_TYPE_SHA384, RIOT_CORE_ALIAS_SERIAL_384,
		RIOT_CORE_ALIAS_SERIAL_384_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL_384, RIOT_CORE_ALIAS_SERIAL_384_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_384_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_384_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_ALIAS_NAME_384,
		RIOT_CORE_ALIAS_NAME_384_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_ca_signed_certificate, &riot.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY_384, RIOT_CORE_ALIAS_KEY_384_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_384_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL_384, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME_384, RIOT_CORE_ALIAS_NAME_384_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_384, RIOT_CORE_DEVICE_ID_384_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_384_LEN), MOCK_ARG (HASH_TYPE_SHA384), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&riot.alias_ext, sizeof (riot.alias_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.alias_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.generate_alias_key (&test_static.base, RIOT_CORE_FWID_SHA384,
		RIOT_CORE_FWID_SHA384_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void riot_core_common_test_generate_alias_key_ecc521 (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_521_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY_521, alias_der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_521);
	riot_core_common_testing_device_id_generation_521 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN,
		RIOT_CORE_FWID_SHA512, RIOT_CORE_FWID_SHA512_LEN, NULL, SHA512_HASH_LENGTH,
		HASH_TYPE_SHA512, RIOT_CORE_FWID_KDF_521, RIOT_CORE_FWID_KDF_521_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA512,
		RIOT_CORE_FWID_KDF_521, RIOT_CORE_FWID_KDF_521_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521, RIOT_CORE_ALIAS_KDF_521_OUT_1,
		RIOT_CORE_ALIAS_KDF_521_OUT_1_LEN);

	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA512,
		RIOT_CORE_FWID_KDF_521, RIOT_CORE_FWID_KDF_521_LEN, 2, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521, RIOT_CORE_ALIAS_KDF_521_OUT_2,
		RIOT_CORE_ALIAS_KDF_521_OUT_2_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF_521, RIOT_CORE_ALIAS_KDF_521_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_521_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_FWID_KDF_521, RIOT_CORE_FWID_KDF_521_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA512_HASH_LENGTH, HASH_TYPE_SHA512, RIOT_CORE_ALIAS_SERIAL_521,
		RIOT_CORE_ALIAS_SERIAL_521_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL_521, RIOT_CORE_ALIAS_SERIAL_521_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_521_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_521_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_ALIAS_NAME_521,
		RIOT_CORE_ALIAS_NAME_521_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_ca_signed_certificate, &riot.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY_521, RIOT_CORE_ALIAS_KEY_521_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_521_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL_521, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME_521, RIOT_CORE_ALIAS_NAME_521_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_521, RIOT_CORE_DEVICE_ID_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_521_LEN), MOCK_ARG (HASH_TYPE_SHA512), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&riot.alias_ext, sizeof (riot.alias_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.alias_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID_SHA512,
		RIOT_CORE_FWID_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_static_init_ecc521 (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_521,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_521_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY_521, alias_der_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_521 (test, &riot, &test_static);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH_512, RIOT_CORE_CDI_HASH_512_LEN,
		RIOT_CORE_FWID_SHA512, RIOT_CORE_FWID_SHA512_LEN, NULL, SHA512_HASH_LENGTH,
		HASH_TYPE_SHA512, RIOT_CORE_FWID_KDF_521, RIOT_CORE_FWID_KDF_521_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA512,
		RIOT_CORE_FWID_KDF_521, RIOT_CORE_FWID_KDF_521_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521, RIOT_CORE_ALIAS_KDF_521_OUT_1,
		RIOT_CORE_ALIAS_KDF_521_OUT_1_LEN);

	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA512,
		RIOT_CORE_FWID_KDF_521, RIOT_CORE_FWID_KDF_521_LEN, 2, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_521, RIOT_CORE_ALIAS_KDF_521_OUT_2,
		RIOT_CORE_ALIAS_KDF_521_OUT_2_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF_521, RIOT_CORE_ALIAS_KDF_521_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_521_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_FWID_KDF_521, RIOT_CORE_FWID_KDF_521_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA512_HASH_LENGTH, HASH_TYPE_SHA512, RIOT_CORE_ALIAS_SERIAL_521,
		RIOT_CORE_ALIAS_SERIAL_521_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL_521, RIOT_CORE_ALIAS_SERIAL_521_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_521_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_521_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_ALIAS_NAME_521,
		RIOT_CORE_ALIAS_NAME_521_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_ca_signed_certificate, &riot.x509,
		0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY_521, RIOT_CORE_ALIAS_KEY_521_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_521_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL_521, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME_521, RIOT_CORE_ALIAS_NAME_521_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID_521, RIOT_CORE_DEVICE_ID_521_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_521_LEN), MOCK_ARG (HASH_TYPE_SHA512), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&riot.alias_ext, sizeof (riot.alias_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.alias_ext)));
	status |= mock_expect_save_arg (&riot.x509.mock, 0, 1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.generate_alias_key (&test_static.base, RIOT_CORE_FWID_SHA512,
		RIOT_CORE_FWID_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);
}
#endif

static void riot_core_common_test_generate_alias_key_null (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	status = riot.test.base.generate_alias_key (NULL, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, NULL,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		0);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_no_device_id (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, RIOT_CORE_NO_DEVICE_ID, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_alias_kdf_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_key_pair_hmac_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_key_pair_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_ALIAS_KDF,
		RIOT_CORE_ALIAS_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc,
		ECC_ENGINE_DERIVED_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF, RIOT_CORE_ALIAS_KDF_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_DERIVED_KEY_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_der_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_ALIAS_KDF,
		RIOT_CORE_ALIAS_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF, RIOT_CORE_ALIAS_KDF_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc,
		ECC_ENGINE_PRIVATE_KEY_DER_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_PRIVATE_KEY_DER_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_serial_hmac_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_ALIAS_KDF,
		RIOT_CORE_ALIAS_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF, RIOT_CORE_ALIAS_KDF_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= mock_expect (&riot.hash.mock, riot.hash.base.start_sha256, &riot.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_subject_name_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_ALIAS_KDF,
		RIOT_CORE_ALIAS_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF, RIOT_CORE_ALIAS_KDF_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64,
		BASE64_ENGINE_ENCODE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_LEN));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, BASE64_ENGINE_ENCODE_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_generate_alias_key_cert_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *alias_der;
	size_t alias_der_length = RIOT_CORE_ALIAS_KEY_LEN;

	TEST_START;

	alias_der = platform_malloc (alias_der_length);
	CuAssertPtrNotNull (test, alias_der);

	memcpy (alias_der, RIOT_CORE_ALIAS_KEY, alias_der_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	/* Calculate the Alias key. */
	status = hash_mock_expect_hmac (&riot.hash, RIOT_CORE_CDI_HASH, RIOT_CORE_CDI_HASH_LEN,
		RIOT_CORE_FWID, RIOT_CORE_FWID_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN);

	/* Derive the Alias key. */
	status |= kdf_testing_expect_nist800_108_counter_mode (&riot.hash, HASH_TYPE_SHA256,
		RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN, 1, RIOT_CORE_ALIAS_KDF_TEST_LABEL,
		RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN, RIOT_CORE_ALIAS_KDF_TEST_CONTEXT,
		RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN, ECC_KEY_LENGTH_256, RIOT_CORE_ALIAS_KDF,
		RIOT_CORE_ALIAS_KDF_LEN);

	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.generate_derived_key_pair, &riot.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KDF, RIOT_CORE_ALIAS_KDF_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KDF_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&riot.ecc.mock, 2, 1);

	/* Generate the Alias key X.509 certificate. */
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.get_private_key_der, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&riot.ecc.mock, 1, &alias_der, sizeof (alias_der), -1);
	status |= mock_expect_output (&riot.ecc.mock, 2, &alias_der_length, sizeof (alias_der_length),
		-1);

	status |= hash_mock_expect_hmac (&riot.hash, RIOT_CORE_FWID_KDF, RIOT_CORE_FWID_KDF_LEN,
		RIOT_CORE_SERIAL_KDF_TEST_DATA, RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN);

	status |= mock_expect (&riot.base64.mock, riot.base64.base.encode, &riot.base64, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_ALIAS_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_SERIAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (RIOT_CORE_ALIAS_NAME_LEN));
	status |= mock_expect_output (&riot.base64.mock, 2, RIOT_CORE_ALIAS_NAME,
		RIOT_CORE_ALIAS_NAME_LEN, 3);

	status |= mock_expect (&riot.x509.mock, riot.x509.base.create_ca_signed_certificate, &riot.x509,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_SERIAL, RIOT_CORE_SERIAL_LEN),
		MOCK_ARG (RIOT_CORE_SERIAL_LEN),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_NAME, RIOT_CORE_ALIAS_NAME_LEN),
		MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&riot.alias_ext, sizeof (riot.alias_ext)),
		MOCK_ARG (ARRAY_SIZE (riot.alias_ext)));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_alias_key (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);
	riot_core_common_testing_alias_generation_256 (test, &riot, &riot.test);

	status = riot.test.base.get_alias_key (&riot.test.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_KEY_LEN, out_length);
	CuAssertPtrNotNull (test, out);

	status = testing_validate_array (RIOT_CORE_ALIAS_KEY, out, out_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (out);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_alias_key_static_init (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &test_static);
	riot_core_common_testing_alias_generation_256 (test, &riot, &test_static);

	status = test_static.base.get_alias_key (&test_static.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_KEY_LEN, out_length);
	CuAssertPtrNotNull (test, out);

	status = testing_validate_array (RIOT_CORE_ALIAS_KEY, out, out_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (out);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);
}

static void riot_core_common_test_get_alias_key_null (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);
	riot_core_common_testing_alias_generation_256 (test, &riot, &riot.test);

	status = riot.test.base.get_alias_key (NULL, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.get_alias_key (&riot.test.base, NULL, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.get_alias_key (&riot.test.base, &out, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_alias_key_no_alias_key (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	status = riot.test.base.get_alias_key (&riot.test.base, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_NO_ALIAS_KEY, status);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_alias_key_cert (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *cert;
	size_t cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	cert = platform_malloc (cert_length);
	CuAssertPtrNotNull (test, cert);

	memcpy (cert, RIOT_CORE_ALIAS_CERT, cert_length);

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);
	riot_core_common_testing_alias_generation_256 (test, &riot, &riot.test);

	/* Encode the certificate. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.get_certificate_der, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 1, &cert, sizeof (cert), -1);
	status |= mock_expect_output (&riot.x509.mock, 2, &cert_length, sizeof (cert_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_alias_key_cert (&riot.test.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, out_length);
	CuAssertPtrEquals (test, cert, out);

	platform_free (cert);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_alias_key_cert_static_init (CuTest *test)
{
	struct riot_core_common_testing riot;
	struct riot_core_common test_static = riot_core_common_static_init (&riot.state,
		&riot.hash.base, &riot.ecc.base, &riot.x509.base, &riot.base64.base, ECC_KEY_LENGTH_256,
		riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext), riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	int status;
	uint8_t *cert;
	size_t cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	cert = platform_malloc (cert_length);
	CuAssertPtrNotNull (test, cert);

	memcpy (cert, RIOT_CORE_ALIAS_CERT, cert_length);

	riot_core_common_testing_init_static (test, &riot, &test_static);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &test_static);
	riot_core_common_testing_alias_generation_256 (test, &riot, &test_static);

	/* Encode the certificate. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.get_certificate_der, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (&out), MOCK_ARG_PTR (&out_length));
	status |= mock_expect_output (&riot.x509.mock, 1, &cert, sizeof (cert), -1);
	status |= mock_expect_output (&riot.x509.mock, 2, &cert_length, sizeof (cert_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.get_alias_key_cert (&test_static.base, &out, &out_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, out_length);
	CuAssertPtrEquals (test, cert, out);

	platform_free (cert);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &test_static);
}

static void riot_core_common_test_get_alias_key_cert_null (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);
	riot_core_common_testing_alias_generation_256 (test, &riot, &riot.test);

	status = riot.test.base.get_alias_key_cert (NULL, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.get_alias_key_cert (&riot.test.base, NULL, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = riot.test.base.get_alias_key_cert (&riot.test.base, &out, NULL);
	CuAssertIntEquals (test, RIOT_CORE_INVALID_ARGUMENT, status);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_alias_key_cert_no_alias_key (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);

	status = riot.test.base.get_alias_key_cert (&riot.test.base, &out, &out_length);
	CuAssertIntEquals (test, RIOT_CORE_NO_ALIAS_KEY, status);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_get_alias_key_cert_error (CuTest *test)
{
	struct riot_core_common_testing riot;
	int status;
	uint8_t *out;
	size_t out_length;

	TEST_START;

	riot_core_common_testing_init (test, &riot, ECC_KEY_LENGTH_256);
	riot_core_common_testing_device_id_generation_256 (test, &riot, &riot.test);
	riot_core_common_testing_alias_generation_256 (test, &riot, &riot.test);

	/* Encode the certificate. */
	status = mock_expect (&riot.x509.mock, riot.x509.base.get_certificate_der, &riot.x509,
		X509_ENGINE_CERT_DER_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (&out),
		MOCK_ARG_PTR (&out_length));

	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_alias_key_cert (&riot.test.base, &out, &out_length);
	CuAssertIntEquals (test, X509_ENGINE_CERT_DER_FAILED, status);

	riot_core_common_testing_validate_mocks (test, &riot);

	status = mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&riot.ecc.mock, riot.ecc.base.release_key_pair, &riot.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&riot.x509.mock, riot.x509.base.release_certificate, &riot.x509, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	riot_core_common_testing_release (test, &riot, &riot.test);
}

static void riot_core_common_test_authenticate_generated_keys (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	X509_TESTING_ENGINE x509;
	X509_TESTING_ENGINE x509_verify;
	BASE64_TESTING_ENGINE base64;
	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length;
	struct x509_certificate alias;
	struct x509_ca_certs ca_certs;
	uint8_t alias_priv[ECC_KEY_LENGTH_256];

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

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

	status = mock_expect (&riot.tcb.mock, riot.tcb.base.build, &riot.tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.tcb.mock, 0, 0);
	status |= mock_expect_output (&riot.tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA256), -1);

	status |= mock_expect (&riot.tcb.mock, riot.tcb.base.free, &riot.tcb, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&riot.ueid.mock, riot.ueid.base.build, &riot.ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.ueid.mock, 0, 0);
	status |= mock_expect_output (&riot.ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&riot.ueid.mock, riot.ueid.base.free, &riot.ueid, 0,
		MOCK_ARG_SAVED_ARG (0));

	status = mock_expect (&riot.alias_tcb.mock, riot.alias_tcb.base.build, &riot.alias_tcb, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.alias_tcb.mock, 0, 0);
	status |= mock_expect_output (&riot.alias_tcb.mock, 0, &RIOT_CORE_ALIAS_TCBINFO_EXTENSION,
		sizeof (RIOT_CORE_ALIAS_TCBINFO_EXTENSION), -1);

	status |= mock_expect (&riot.alias_tcb.mock, riot.alias_tcb.base.free, &riot.alias_tcb, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot.test, &riot.state, &hash.base, &ecc.base, &x509.base,
		&base64.base, ECC_KEY_LENGTH_256, riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext),
		riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID,
		RIOT_CORE_FWID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_cert (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.init_ca_cert_store (&x509_verify.base, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.add_root_ca (&x509_verify.base, &ca_certs, der, der_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	status = riot.test.base.get_alias_key_cert (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.load_certificate (&x509_verify.base, &alias, der, der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.authenticate (&x509_verify.base, &alias, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	x509_verify.base.release_certificate (&x509_verify.base, &alias);
	platform_free (der);

	status = riot.test.base.get_alias_key (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_decode_private_key (der, der_length, alias_priv, sizeof (alias_priv));
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_KDF_LEN, status);

	status = testing_validate_array (RIOT_CORE_ALIAS_KDF, alias_priv, RIOT_CORE_ALIAS_KDF_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	riot_core_common_testing_release (test, &riot, &riot.test);

	x509_verify.base.release_ca_cert_store (&x509_verify.base, &ca_certs);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	X509_TESTING_ENGINE_RELEASE (&x509);
	X509_TESTING_ENGINE_RELEASE (&x509_verify);
	BASE64_TESTING_ENGINE_RELEASE (&base64);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
static void riot_core_common_test_authenticate_generated_keys_ecc384 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	X509_TESTING_ENGINE x509;
	X509_TESTING_ENGINE x509_verify;
	BASE64_TESTING_ENGINE base64;
	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length;
	struct x509_certificate alias;
	struct x509_ca_certs ca_certs;
	uint8_t alias_priv[ECC_KEY_LENGTH_384];

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

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

	status = mock_expect (&riot.tcb.mock, riot.tcb.base.build, &riot.tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.tcb.mock, 0, 0);
	status |= mock_expect_output (&riot.tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA384), -1);

	status |= mock_expect (&riot.tcb.mock, riot.tcb.base.free, &riot.tcb, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&riot.ueid.mock, riot.ueid.base.build, &riot.ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.ueid.mock, 0, 0);
	status |= mock_expect_output (&riot.ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&riot.ueid.mock, riot.ueid.base.free, &riot.ueid, 0,
		MOCK_ARG_SAVED_ARG (0));

	status = mock_expect (&riot.alias_tcb.mock, riot.alias_tcb.base.build, &riot.alias_tcb, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.alias_tcb.mock, 0, 0);
	status |= mock_expect_output (&riot.alias_tcb.mock, 0,
		&RIOT_CORE_ALIAS_TCBINFO_EXTENSION_SHA384,
		sizeof (RIOT_CORE_ALIAS_TCBINFO_EXTENSION_SHA384), -1);

	status |= mock_expect (&riot.alias_tcb.mock, riot.alias_tcb.base.free, &riot.alias_tcb, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot.test, &riot.state, &hash.base, &ecc.base, &x509.base,
		&base64.base, ECC_KEY_LENGTH_384, riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext),
		riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID_SHA384,
		RIOT_CORE_FWID_SHA384_LEN);
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_cert (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.init_ca_cert_store (&x509_verify.base, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.add_root_ca (&x509_verify.base, &ca_certs, der, der_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	status = riot.test.base.get_alias_key_cert (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.load_certificate (&x509_verify.base, &alias, der, der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.authenticate (&x509_verify.base, &alias, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	x509_verify.base.release_certificate (&x509_verify.base, &alias);
	platform_free (der);

	status = riot.test.base.get_alias_key (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_decode_private_key (der, der_length, alias_priv, sizeof (alias_priv));
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_KDF_384_LEN, status);

	status = testing_validate_array (RIOT_CORE_ALIAS_KDF_384, alias_priv,
		RIOT_CORE_ALIAS_KDF_384_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	riot_core_common_testing_release (test, &riot, &riot.test);

	x509_verify.base.release_ca_cert_store (&x509_verify.base, &ca_certs);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	X509_TESTING_ENGINE_RELEASE (&x509);
	X509_TESTING_ENGINE_RELEASE (&x509_verify);
	BASE64_TESTING_ENGINE_RELEASE (&base64);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
static void riot_core_common_test_authenticate_generated_keys_ecc521 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	X509_TESTING_ENGINE x509;
	X509_TESTING_ENGINE x509_verify;
	BASE64_TESTING_ENGINE base64;
	struct riot_core_common_testing riot;
	int status;
	uint8_t *der;
	size_t der_length;
	struct x509_certificate alias;
	struct x509_ca_certs ca_certs;
	uint8_t alias_priv[ECC_KEY_LENGTH_521];

	TEST_START;

	riot_core_common_testing_init_dependencies (test, &riot);

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

	status = mock_expect (&riot.tcb.mock, riot.tcb.base.build, &riot.tcb, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.tcb.mock, 0, 0);
	status |= mock_expect_output (&riot.tcb.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512,
		sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_TESTING_EXTENSION_SHA512), -1);

	status |= mock_expect (&riot.tcb.mock, riot.tcb.base.free, &riot.tcb, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&riot.ueid.mock, riot.ueid.base.build, &riot.ueid, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.ueid.mock, 0, 0);
	status |= mock_expect_output (&riot.ueid.mock, 0,
		&X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION,
		sizeof (X509_EXTENSION_BUILDER_DICE_UEID_TESTING_EXTENSION), -1);

	status |= mock_expect (&riot.ueid.mock, riot.ueid.base.free, &riot.ueid, 0,
		MOCK_ARG_SAVED_ARG (0));

	status = mock_expect (&riot.alias_tcb.mock, riot.alias_tcb.base.build, &riot.alias_tcb, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&riot.alias_tcb.mock, 0, 0);
	status |= mock_expect_output (&riot.alias_tcb.mock, 0,
		&RIOT_CORE_ALIAS_TCBINFO_EXTENSION_SHA512,
		sizeof (RIOT_CORE_ALIAS_TCBINFO_EXTENSION_SHA512), -1);

	status |= mock_expect (&riot.alias_tcb.mock, riot.alias_tcb.base.free, &riot.alias_tcb, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = riot_core_common_init (&riot.test, &riot.state, &hash.base, &ecc.base, &x509.base,
		&base64.base, ECC_KEY_LENGTH_521, riot.dev_id_ext, ARRAY_SIZE (riot.dev_id_ext),
		riot.alias_ext, ARRAY_SIZE (riot.alias_ext));
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_device_id (&riot.test.base, RIOT_CORE_CDI, RIOT_CORE_CDI_LEN);
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.generate_alias_key (&riot.test.base, RIOT_CORE_FWID_SHA512,
		RIOT_CORE_FWID_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = riot.test.base.get_device_id_cert (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.init_ca_cert_store (&x509_verify.base, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.add_root_ca (&x509_verify.base, &ca_certs, der, der_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	status = riot.test.base.get_alias_key_cert (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.load_certificate (&x509_verify.base, &alias, der, der_length);
	CuAssertIntEquals (test, 0, status);

	status = x509_verify.base.authenticate (&x509_verify.base, &alias, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	x509_verify.base.release_certificate (&x509_verify.base, &alias);
	platform_free (der);

	status = riot.test.base.get_alias_key (&riot.test.base, &der, &der_length);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_decode_private_key (der, der_length, alias_priv, sizeof (alias_priv));
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_KDF_521_LEN, status);

	status = testing_validate_array (RIOT_CORE_ALIAS_KDF_521, alias_priv,
		RIOT_CORE_ALIAS_KDF_521_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	riot_core_common_testing_release (test, &riot, &riot.test);

	x509_verify.base.release_ca_cert_store (&x509_verify.base, &ca_certs);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	X509_TESTING_ENGINE_RELEASE (&x509);
	X509_TESTING_ENGINE_RELEASE (&x509_verify);
	BASE64_TESTING_ENGINE_RELEASE (&base64);
}
#endif


TEST_SUITE_START (riot_core_common);

TEST (riot_core_common_test_init);
TEST (riot_core_common_test_static_init);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (riot_core_common_test_init_ecc384);
TEST (riot_core_common_test_static_init_ecc384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (riot_core_common_test_init_ecc521);
TEST (riot_core_common_test_static_init_ecc521);
#endif
TEST (riot_core_common_test_init_null);
TEST (riot_core_common_test_init_unknown_key_length);
TEST (riot_core_common_test_static_init_null);
TEST (riot_core_common_test_static_init_unknown_key_length);
TEST (riot_core_common_test_release_null);
TEST (riot_core_common_test_release_twice);
TEST (riot_core_common_test_generate_device_id);
TEST (riot_core_common_test_generate_device_id_static_init);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (riot_core_common_test_generate_device_id_ecc384);
TEST (riot_core_common_test_generate_device_id_static_init_ecc384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (riot_core_common_test_generate_device_id_ecc521);
TEST (riot_core_common_test_generate_device_id_static_init_ecc521);
#endif
TEST (riot_core_common_test_generate_device_id_null);
TEST (riot_core_common_test_generate_device_id_cdi_hash_start_error);
TEST (riot_core_common_test_generate_device_id_cdi_hash_first_byte_error);
TEST (riot_core_common_test_generate_device_id_cdi_hash_error);
TEST (riot_core_common_test_generate_device_id_cdi_hash_finish_error);
TEST (riot_core_common_test_generate_device_id_key_pair_hmac_error);
TEST (riot_core_common_test_generate_device_id_key_pair_error);
TEST (riot_core_common_test_generate_device_id_der_error);
TEST (riot_core_common_test_generate_device_id_serial_hmac_error);
TEST (riot_core_common_test_generate_device_id_subject_name_error);
TEST (riot_core_common_test_generate_device_id_cert_error);
TEST (riot_core_common_test_get_device_id_csr);
TEST (riot_core_common_test_get_device_id_csr_with_oid);
TEST (riot_core_common_test_get_device_id_csr_static_init);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (riot_core_common_test_get_device_id_csr_ecc384);
TEST (riot_core_common_test_get_device_id_csr_static_init_ecc384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (riot_core_common_test_get_device_id_csr_ecc521);
TEST (riot_core_common_test_get_device_id_csr_static_init_ecc521);
#endif
TEST (riot_core_common_test_get_device_id_csr_null);
TEST (riot_core_common_test_get_device_id_csr_no_device_id);
TEST (riot_core_common_test_get_device_id_csr_error);
TEST (riot_core_common_test_get_device_id_cert);
TEST (riot_core_common_test_get_device_id_cert_static_init);
TEST (riot_core_common_test_get_device_id_cert_null);
TEST (riot_core_common_test_get_device_id_cert_no_device_id);
TEST (riot_core_common_test_get_device_id_cert_error);
TEST (riot_core_common_test_generate_alias_key);
TEST (riot_core_common_test_generate_alias_key_static_init);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (riot_core_common_test_generate_alias_key_ecc384);
TEST (riot_core_common_test_generate_alias_key_static_init_ecc384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (riot_core_common_test_generate_alias_key_ecc521);
TEST (riot_core_common_test_generate_alias_key_static_init_ecc521);
#endif
TEST (riot_core_common_test_generate_alias_key_null);
TEST (riot_core_common_test_generate_alias_key_no_device_id);
TEST (riot_core_common_test_generate_alias_key_alias_kdf_error);
TEST (riot_core_common_test_generate_alias_key_key_pair_hmac_error);
TEST (riot_core_common_test_generate_alias_key_key_pair_error);
TEST (riot_core_common_test_generate_alias_key_der_error);
TEST (riot_core_common_test_generate_alias_key_serial_hmac_error);
TEST (riot_core_common_test_generate_alias_key_subject_name_error);
TEST (riot_core_common_test_generate_alias_key_cert_error);
TEST (riot_core_common_test_get_alias_key);
TEST (riot_core_common_test_get_alias_key_static_init);
TEST (riot_core_common_test_get_alias_key_null);
TEST (riot_core_common_test_get_alias_key_no_alias_key);
TEST (riot_core_common_test_get_alias_key_cert);
TEST (riot_core_common_test_get_alias_key_cert_static_init);
TEST (riot_core_common_test_get_alias_key_cert_null);
TEST (riot_core_common_test_get_alias_key_cert_no_alias_key);
TEST (riot_core_common_test_get_alias_key_cert_error);
TEST (riot_core_common_test_authenticate_generated_keys);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384) && defined HASH_ENABLE_SHA384
TEST (riot_core_common_test_authenticate_generated_keys_ecc384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521) && defined HASH_ENABLE_SHA512
TEST (riot_core_common_test_authenticate_generated_keys_ecc521);
#endif

TEST_SUITE_END;
