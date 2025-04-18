// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_logging.h"
#include "acvp/backend_ecdh.h"
#include "crypto/kat/ecc_kat_vectors.h"
#include "parser/cipher_definitions.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/ecc_hw_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("backend_ecdh");


/**
 * ACVP implementation identifer.
 */
extern uint32_t acvp_implementation;


/**
 * ECDH ECC key types for testing.
 */
enum ecdh_test_ecc_key_type {
	ECDH_TEST_ECC_KEY_TYPE_256 = 0,
	ECDH_TEST_ECC_KEY_TYPE_384,
	ECDH_TEST_ECC_KEY_TYPE_521,
	ECDH_TEST_ECC_KEY_TYPE_INVALID,
};

/**
 * ECDH test types.
 */
enum ecdh_test_type {
	ECDH_TEST_TYPE_SS = 0,
	ECDH_TEST_TYPE_SS_VER,
};

/**
 * ECDH test data.
 */
union ecdh_testing_data {
	struct ecdh_ss_data ss;			/**< ECDH shared secret generation test data. */
	struct ecdh_ss_ver_data ss_ver;	/**< ECDH shared secret verification test data. */
};

/**
 * Dependencies for testing.
 */
struct backend_ecdh_testing {
	enum ecdh_test_type type;		/**< ECDH test type. */
	union ecdh_testing_data data;	/**< ECDH test data. */
	struct ecc_engine_mock engine;	/**< Mock for ECC engine. */
	struct ecc_hw_mock hw;			/**< Mock for ECC hardware engine. */
	struct logging_mock logger;		/**< Mock for debug logging. */
};


/**
 * Get the ACVP ECDH test cipher value for the specified key type.
 *
 * @param key_type The key type to use for the test.
 *
 * @return The ACVP cipher value for the specified key type.
 */
static uint64_t backend_ecdh_testing_get_cipher (enum ecdh_test_ecc_key_type key_type)
{
	uint64_t cipher;

	switch (key_type) {
		case ECDH_TEST_ECC_KEY_TYPE_256:
			cipher = ACVP_NISTP256;
			break;

		case ECDH_TEST_ECC_KEY_TYPE_384:
			cipher = ACVP_NISTP384;
			break;

		case ECDH_TEST_ECC_KEY_TYPE_521:
			cipher = ACVP_NISTP521;
			break;

		default:
			// Use unsupported cipher
			cipher = ACVP_NISTB571;
	}

	return cipher;
}

/**
 * Set the buffers for the ECDH shared secret generation test data.
 *
 * @param test The test framework.
 * @param data The ECDH shared secret generation test data.
 * @param key_type The ECC key type.
 *
 * @return 0 if the buffers were set successfully, or an error code if there was a failure.
 */
static void backend_ecdh_testing_set_ss_buffers (CuTest *test, struct ecdh_ss_data *data,
	enum ecdh_test_ecc_key_type key_type)
{
	memset (data, 0, sizeof (struct ecdh_ss_data));

	switch (key_type) {
		case ECDH_TEST_ECC_KEY_TYPE_256:
			data->Qxrem.buf = (unsigned char*) ECC_PUBKEY2_POINT.x;
			data->Qxrem.len = ECC_PUBKEY2_POINT.key_length;

			data->Qyrem.buf = (unsigned char*) ECC_PUBKEY2_POINT.y;
			data->Qyrem.len = ECC_PUBKEY2_POINT.key_length;

			data->cipher = ACVP_NISTP256;

			break;

		case ECDH_TEST_ECC_KEY_TYPE_384:
			data->Qxrem.buf = (unsigned char*) ECC384_PUBKEY2_POINT.x;
			data->Qxrem.len = ECC384_PUBKEY2_POINT.key_length;

			data->Qyrem.buf = (unsigned char*) ECC384_PUBKEY2_POINT.y;
			data->Qyrem.len = ECC384_PUBKEY2_POINT.key_length;

			data->cipher = ACVP_NISTP384;

			break;

		default:
			/* By default, set ECC521 buffers.  Invalid curve test cases are handled at a higher
			 * level by the cipher value. */
			data->Qxrem.buf = (unsigned char*) ECC521_PUBKEY2_POINT.x;
			data->Qxrem.len = ECC521_PUBKEY2_POINT.key_length;

			data->Qyrem.buf = (unsigned char*) ECC521_PUBKEY2_POINT.y;
			data->Qyrem.len = ECC521_PUBKEY2_POINT.key_length;

			data->cipher = ACVP_NISTP521;
	}
}

/**
 * Set the buffers for the ECDH shared secret verification test data.
 *
 * @param test The test framework.
 * @param data The ECDH shared secret verification test data.
 * @param key_type The ECC key type.
 *
 * @return 0 if the buffers were set successfully, or an error code if there was a failure.
 */
static void backend_ecdh_testing_set_ss_ver_buffers (CuTest *test, struct ecdh_ss_ver_data *data,
	enum ecdh_test_ecc_key_type key_type)
{
	memset (data, 0, sizeof (struct ecdh_ss_ver_data));

	data->Qxloc.buf = NULL;
	data->Qyloc.buf = NULL;

	switch (key_type) {
		case ECDH_TEST_ECC_KEY_TYPE_256:
			data->Qxrem.buf = (unsigned char*) ECC_PUBKEY_POINT.x;
			data->Qxrem.len = ECC_PUBKEY_POINT.key_length;

			data->Qyrem.buf = (unsigned char*) ECC_PUBKEY_POINT.y;
			data->Qyrem.len = ECC_PUBKEY_POINT.key_length;

			data->privloc.buf = (unsigned char*) ECC_PRIVKEY;
			data->privloc.len = ECC_PRIVKEY_LEN;

			data->hashzz.buf = (unsigned char*) ECC_DH_SECRET;
			data->hashzz.len = ECC_DH_SECRET_LEN;

			break;

		case ECDH_TEST_ECC_KEY_TYPE_384:
			data->Qxrem.buf = (unsigned char*) ECC384_PUBKEY_POINT.x;
			data->Qxrem.len = ECC384_PUBKEY_POINT.key_length;

			data->Qyrem.buf = (unsigned char*) ECC384_PUBKEY_POINT.y;
			data->Qyrem.len = ECC384_PUBKEY_POINT.key_length;

			data->privloc.buf = (unsigned char*) ECC384_PRIVKEY;
			data->privloc.len = ECC384_PRIVKEY_LEN;

			data->hashzz.buf = (unsigned char*) ECC384_DH_SECRET;
			data->hashzz.len = ECC384_DH_SECRET_LEN;

			break;

		default:
			/* By default, set ECC521 buffers.  Invalid curve test cases are handled at a higher
			 * level by the cipher value. */
			data->Qxrem.buf = (unsigned char*) ECC521_PUBKEY_POINT.x;
			data->Qxrem.len = ECC521_PUBKEY_POINT.key_length;

			data->Qyrem.buf = (unsigned char*) ECC521_PUBKEY_POINT.y;
			data->Qyrem.len = ECC521_PUBKEY_POINT.key_length;

			data->privloc.buf = (unsigned char*) ECC521_PRIVKEY;
			data->privloc.len = ECC521_PRIVKEY_LEN;

			data->hashzz.buf = (unsigned char*) ECC521_DH_SECRET;
			data->hashzz.len = ECC521_DH_SECRET_LEN;
	}
}

/**
 * Initialize the testing dependencies.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 * @param type The ECDH test type.
 */
static void backend_ecdh_testing_init (CuTest *test, struct backend_ecdh_testing *backend,
	enum ecdh_test_type type, enum ecdh_test_ecc_key_type key_type)
{
	uint64_t cipher;
	union ecdh_testing_data data;
	int status;

	cipher = backend_ecdh_testing_get_cipher (key_type);

	switch (type) {
		case ECDH_TEST_TYPE_SS:
			backend_ecdh_testing_set_ss_buffers (test, &data.ss, key_type);

			data.ss.cipher = cipher;
			break;

		case ECDH_TEST_TYPE_SS_VER:
			backend_ecdh_testing_set_ss_ver_buffers (test, &data.ss_ver, key_type);

			data.ss_ver.cipher = cipher;
			break;

		default:
			CuFail (test, "Unsupported ECDH test type");

			return;
	}

	status = ecc_mock_init (&backend->engine);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&backend->hw);
	CuAssertIntEquals (test, 0, status);

	backend->type = type;
	backend->data = data;

	status = logging_mock_init (&backend->logger);
	CuAssertIntEquals (test, 0, status);

	debug_log = &backend->logger.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param backend The testing dependencies to release.
 */
static void backend_ecdh_testing_release (CuTest *test, struct backend_ecdh_testing *backend)
{
	int status;

	switch (backend->type) {
		case ECDH_TEST_TYPE_SS:
			if (backend->data.ss.Qxloc.buf != NULL) {
				platform_free (backend->data.ss.Qxloc.buf);
			}

			if (backend->data.ss.Qyloc.buf != NULL) {
				platform_free (backend->data.ss.Qyloc.buf);
			}

			if (backend->data.ss.hashzz.buf != NULL) {
				platform_free (backend->data.ss.hashzz.buf);
			}
			break;

		case ECDH_TEST_TYPE_SS_VER:
			// Nothing to do.
			break;

		default:
			CuFail (test, "Invalid ECDH test type");

			return;
	}

	backend_ecdh_register_engines (NULL, 0);

	status = ecc_mock_validate_and_release (&backend->engine);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&backend->hw);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&backend->logger);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void backend_ecdh_test_init (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;

	TEST_START;

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);
	CuAssertPtrNotNull (test, ecdh_impl->ecdh_ss);
	CuAssertPtrNotNull (test, ecdh_impl->ecdh_ss_ver);
}

static void backend_ecdh_test_ecdh_ss (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_384);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ECC_TESTING_ENGINE_INIT (&engine);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, ECC_KEY_LENGTH_384, backend.data.ss.hashzz.len);
	CuAssertPtrNotNull (test, backend.data.ss.hashzz.buf);

	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.ss.Qxloc.len);
	CuAssertPtrNotNull (test, backend.data.ss.Qxloc.buf);

	CuAssertIntEquals (test, ECC384_PUBKEY_POINT.key_length, backend.data.ss.Qyloc.len);
	CuAssertPtrNotNull (test, backend.data.ss.Qyloc.buf);

	ECC_TESTING_ENGINE_RELEASE (&engine);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_hw (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_256);

	// Remote pubkey: ECC_PUBKEY2
	// Local key pair will be: ECC_PRIVKEY / ECC_PUBKEY

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&backend.hw.mock, 1, &ECC_PRIVKEY, ECC_PRIVKEY_LEN, -1);
	status |= mock_expect_output (&backend.hw.mock, 2, &ECC_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key), -1);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdh_compute, &backend.hw,	0,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC_PRIVKEY, ECC_PRIVKEY_LEN), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY2_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&backend.hw.mock, 3, &ECC_PRIVKEY3, ECC_KEY_LENGTH_256, -1);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, ECC_PRIVKEY3_LEN, backend.data.ss.hashzz.len);
	CuAssertPtrNotNull (test, backend.data.ss.hashzz.buf);

	status = testing_validate_array (ECC_PRIVKEY3, backend.data.ss.hashzz.buf, ECC_PRIVKEY3_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.ss.Qxloc.len);
	CuAssertPtrNotNull (test, backend.data.ss.Qxloc.buf);

	status = testing_validate_array (ECC_PUBKEY_POINT.x, backend.data.ss.Qxloc.buf,
		ECC_PUBKEY_POINT.key_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, ECC_PUBKEY_POINT.key_length, backend.data.ss.Qyloc.len);
	CuAssertPtrNotNull (test, backend.data.ss.Qyloc.buf);

	status = testing_validate_array (ECC_PUBKEY_POINT.y, backend.data.ss.Qyloc.buf,
		ECC_PUBKEY_POINT.key_length);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_null (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	int status;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDH_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_384);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	status = ecdh_impl->ecdh_ss (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null public key X coordinate buffer.
	backend.data.ss_ver.Qxrem.buf = NULL;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.Qxrem.buf = (unsigned char*) ECC384_PUBKEY_POINT.x;
	backend.data.ss_ver.Qxrem.len = 0;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.Qxrem.len = ECC384_PUBKEY_POINT.key_length;

	// Test null public key Y coordinate buffer.
	backend.data.ss_ver.Qyrem.buf = NULL;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.Qyrem.buf = (unsigned char*) ECC384_PUBKEY_POINT.y;
	backend.data.ss_ver.Qyrem.len = 0;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_no_engine (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDH_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_384);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_engine_not_found (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDH_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation + 1;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_unsupported_curve (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDH_CURVE_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_INVALID);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_generate_key_pair_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_GENERATE_KEY_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_384);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key_pair,
		&backend.engine, ECC_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_get_pubkey_der_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_PUBLIC_KEY_DER_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_384);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key_pair,
		&backend.engine, 0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&backend.engine.mock, 1, 0);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 1);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.get_public_key_der,
		&backend.engine, ECC_ENGINE_PUBLIC_KEY_DER_FAILED, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_init_pubkey_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_PUBLIC_KEY_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_384);

	// Remote pubkey: ECC384_PUBKEY2
	// Local key pair will be: ECC384_PRIVKEY / ECC384_PUBKEY

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key_pair,
		&backend.engine, 0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&backend.engine.mock, 1, 0);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 1);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.get_public_key_der,
		&backend.engine, 0, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.init_public_key,
		&backend.engine, ECC_ENGINE_PUBLIC_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC384_PUBKEY2_DER, ECC384_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY2_DER_LEN), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_compute_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_SHARED_SECRET_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_384);

	// Remote pubkey: ECC384_PUBKEY2
	// Local key pair will be: ECC384_PRIVKEY / ECC384_PUBKEY

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.engine.mock, backend.engine.base.generate_key_pair,
		&backend.engine, 0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&backend.engine.mock, 1, 0);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 1);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.get_public_key_der,
		&backend.engine, 0, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.init_public_key,
		&backend.engine, 0, MOCK_ARG_PTR_CONTAINS_TMP (ECC384_PUBKEY2_DER, ECC384_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY2_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 2);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.compute_shared_secret,
		&backend.engine, ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KEY_LENGTH_384));

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_ANY, MOCK_ARG_SAVED_ARG (2));

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_hw_generate_ecc_key_pair_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_HW_ECC_GENERATE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw,
		ECC_HW_ECC_GENERATE_FAILED,	MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}


static void backend_ecdh_test_ecdh_ss_hw_compute_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_HW_ECDH_COMPUTE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS, ECDH_TEST_ECC_KEY_TYPE_256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.hw.mock, backend.hw.base.generate_ecc_key_pair, &backend.hw, 0,
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&backend.hw.mock, 1, 0);

	status |= mock_expect (&backend.hw.mock, backend.hw.base.ecdh_compute, &backend.hw,
		ECC_HW_ECDH_COMPUTE_FAILED, MOCK_ARG_SAVED_ARG (0),	MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_PUBKEY2_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KEY_LENGTH_256));
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss (&backend.data.ss, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_521);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ECC_TESTING_ENGINE_INIT (&engine);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.ss_ver.validity_success);

	ECC_TESTING_ENGINE_RELEASE (&engine);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_hw (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_384);

	// Expected hash: ECC384_DH_SECRET
	// Remote pubkey: ECC384_PUBKEY
	// Given privkey: ECC384_PRIVKEY

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdh_compute, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&backend.hw.mock, 3, ECC384_DH_SECRET, ECC384_DH_SECRET_LEN, 4);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.ss_ver.validity_success);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_invalid_ss (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_521);

	// Expected hash: ECC521_DH_SECRET
	// Remote pubkey: ECC521_PUBKEY
	// Given privkey: ECC521_PRIVKEY

	status = mock_expect (&backend.engine.mock, backend.engine.base.init_key_pair, &backend.engine,
		0,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC521_PRIVKEY_NO_PUBKEY_DER, ECC521_PRIVKEY_NO_PUBKEY_DER_LEN),
		MOCK_ARG (ECC521_PRIVKEY_NO_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 0);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.init_public_key,
		&backend.engine, 0,	MOCK_ARG_PTR_CONTAINS_TMP (ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN),
		MOCK_ARG (ECC521_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 1);

	status = mock_expect (&backend.engine.mock, backend.engine.base.compute_shared_secret,
		&backend.engine, ECC_KEY_LENGTH_521, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&backend.engine.mock, 2, &ECC521_PRIVKEY, ECC_KEY_LENGTH_521, -1);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_ANY, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, backend.data.ss_ver.validity_success);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_hw_invalid_ss (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_384);

	// Expected hash: ECC384_DH_SECRET
	// Remote pubkey: ECC384_PUBKEY
	// Given privkey: ECC384_PRIVKEY

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdh_compute, &backend.hw, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&backend.hw.mock, 3, &ECC384_PRIVKEY2, ECC_KEY_LENGTH_384, -1);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, backend.data.ss_ver.validity_success);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_null (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	int status;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDH_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_384);

	// Testing five null cases.
	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	status = ecdh_impl->ecdh_ss_ver (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test null private key.
	backend.data.ss_ver.privloc.buf = NULL;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.privloc.buf = (void*) ECC384_PRIVKEY2;
	backend.data.ss_ver.privloc.len = 0;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.privloc.len = ECC384_PRIVKEY2_LEN;

	// Test null remote public key X coordinate buffer.
	backend.data.ss_ver.Qxrem.buf = NULL;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.Qxrem.buf = (unsigned char*) ECC384_PUBKEY_POINT.x;
	backend.data.ss_ver.Qxrem.len = 0;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.Qxrem.len = ECC384_PUBKEY_POINT.key_length;

	// Test null remote public key Y coordinate buffer.
	backend.data.ss_ver.Qyrem.buf = NULL;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.Qyrem.buf = (unsigned char*) ECC384_PUBKEY_POINT.y;
	backend.data.ss_ver.Qyrem.len = 0;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.Qyrem.len = ECC384_PUBKEY_POINT.key_length;

	// Test null expected shared secret buffer.
	backend.data.ss_ver.hashzz.buf = NULL;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.ss_ver.hashzz.buf = (unsigned char*) ECC_DH_SECRET;
	backend.data.ss_ver.hashzz.len = 0;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_no_engine (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDH_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_engine_not_found (CuTest *test)
{
	ECC_TESTING_ENGINE (engine);
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDH_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation + 1;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	ECC_TESTING_ENGINE_RELEASE (&engine);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_unsupported_curve (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_ECDH_CURVE_TYPE_UNSUPPORTED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER,
		ECDH_TEST_ECC_KEY_TYPE_INVALID);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_init_privkey_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_KEY_PAIR_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_521);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.engine.mock, backend.engine.base.init_key_pair, &backend.engine,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC521_PRIVKEY_NO_PUBKEY_DER, ECC521_PRIVKEY_NO_PUBKEY_DER_LEN),
		MOCK_ARG (ECC521_PRIVKEY_NO_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_init_pubkey_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_PUBLIC_KEY_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_521);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	// Expected hash: ECC521_DH_SECRET
	// Remote pubkey: ECC521_PUBKEY
	// Given privkey: ECC521_PRIVKEY

	status = mock_expect (&backend.engine.mock, backend.engine.base.init_key_pair, &backend.engine,
		0,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC521_PRIVKEY_NO_PUBKEY_DER, ECC521_PRIVKEY_NO_PUBKEY_DER_LEN),
		MOCK_ARG (ECC521_PRIVKEY_NO_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 0);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.init_public_key,
		&backend.engine, ECC_ENGINE_PUBLIC_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN),
		MOCK_ARG (ECC521_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_compute_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_ENGINE_SHARED_SECRET_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = false,
			.ecc.engine = &backend.engine.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_521);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	// Expected hash: ECC521_DH_SECRET
	// Remote pubkey: ECC521_PUBKEY
	// Given privkey: ECC521_PRIVKEY

	status = mock_expect (&backend.engine.mock, backend.engine.base.init_key_pair, &backend.engine,
		0,
		MOCK_ARG_PTR_CONTAINS_TMP (ECC521_PRIVKEY_NO_PUBKEY_DER, ECC521_PRIVKEY_NO_PUBKEY_DER_LEN),
		MOCK_ARG (ECC521_PRIVKEY_NO_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 0);

	status |= mock_expect (&backend.engine.mock, backend.engine.base.init_public_key,
		&backend.engine, 0,	MOCK_ARG_PTR_CONTAINS_TMP (ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN),
		MOCK_ARG (ECC521_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&backend.engine.mock, 2, 1);

	status = mock_expect (&backend.engine.mock, backend.engine.base.compute_shared_secret,
		&backend.engine, ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_MAX_KEY_LENGTH));

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_ANY, MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&backend.engine.mock, backend.engine.base.release_key_pair,
		&backend.engine, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}

static void backend_ecdh_test_ecdh_ss_ver_hw_compute_error (CuTest *test)
{
	const struct ecdh_backend *ecdh_impl;
	struct backend_ecdh_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = ECC_HW_ECDH_COMPUTE_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_ecdh_engine ecdh_engines[] = {
		{
			.impl_id = implementation,
			.is_hw = true,
			.ecc.hw = &backend.hw.base
		}
	};
	int status;

	TEST_START;

	backend_ecdh_testing_init (test, &backend, ECDH_TEST_TYPE_SS_VER, ECDH_TEST_ECC_KEY_TYPE_384);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	// Expected hash: ECC384_DH_SECRET
	// Remote pubkey: ECC384_PUBKEY
	// Given privkey: ECC384_PRIVKEY

	status = mock_expect (&backend.hw.mock, backend.hw.base.ecdh_compute, &backend.hw,
		ECC_HW_ECDH_COMPUTE_FAILED,	MOCK_ARG_PTR_CONTAINS_TMP (ECC384_PRIVKEY, ECC384_PRIVKEY_LEN),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC384_PUBKEY_POINT,
		sizeof (struct ecc_point_public_key)), MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KEY_LENGTH_384));
	CuAssertIntEquals (test, 0, status);

	backend_ecdh_register_engines (ecdh_engines, 1);

	ecdh_impl = backend_ecdh_get_impl ();
	CuAssertPtrNotNull (test, ecdh_impl);

	acvp_implementation = implementation;

	status = ecdh_impl->ecdh_ss_ver (&backend.data.ss_ver, 0);
	CuAssertIntEquals (test, -1, status);

	backend_ecdh_testing_release (test, &backend);
}


// *INDENT-OFF*
TEST_SUITE_START (backend_ecdh);

TEST (backend_ecdh_test_init);
TEST (backend_ecdh_test_ecdh_ss);
TEST (backend_ecdh_test_ecdh_ss_hw);
TEST (backend_ecdh_test_ecdh_ss_null);
TEST (backend_ecdh_test_ecdh_ss_no_engine);
TEST (backend_ecdh_test_ecdh_ss_engine_not_found);
TEST (backend_ecdh_test_ecdh_ss_unsupported_curve);
TEST (backend_ecdh_test_ecdh_ss_generate_key_pair_error);
TEST (backend_ecdh_test_ecdh_ss_get_pubkey_der_error);
TEST (backend_ecdh_test_ecdh_ss_init_pubkey_error);
TEST (backend_ecdh_test_ecdh_ss_compute_error);
TEST (backend_ecdh_test_ecdh_ss_hw_generate_ecc_key_pair_error);
TEST (backend_ecdh_test_ecdh_ss_hw_compute_error);
TEST (backend_ecdh_test_ecdh_ss_ver);
TEST (backend_ecdh_test_ecdh_ss_ver_hw);
TEST (backend_ecdh_test_ecdh_ss_ver_invalid_ss);
TEST (backend_ecdh_test_ecdh_ss_ver_hw_invalid_ss);
TEST (backend_ecdh_test_ecdh_ss_ver_null);
TEST (backend_ecdh_test_ecdh_ss_ver_no_engine);
TEST (backend_ecdh_test_ecdh_ss_ver_engine_not_found);
TEST (backend_ecdh_test_ecdh_ss_ver_unsupported_curve);
TEST (backend_ecdh_test_ecdh_ss_ver_init_privkey_error);
TEST (backend_ecdh_test_ecdh_ss_ver_init_pubkey_error);
TEST (backend_ecdh_test_ecdh_ss_ver_compute_error);
TEST (backend_ecdh_test_ecdh_ss_ver_hw_compute_error);

TEST_SUITE_END;
// *INDENT-ON*
