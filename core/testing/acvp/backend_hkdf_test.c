// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_logging.h"
#include "acvp/backend_hkdf.h"
#include "crypto/hash.h"
#include "parser/cipher_definitions.h"
#include "testing/crypto/hkdf_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/crypto/hkdf_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("backend_hkdf");


/**
 * ACVP implementation identifer.
 */
extern uint32_t acvp_implementation;


/**
 * HKDF test type.
 */
enum backend_hkdf_test_type {
	BACKEND_HKDF_TEST_TYPE_GENERATE = 0,	/**< OKM generation test. */
	BACKEND_HKDF_TEST_TYPE_VALIDATE,		/**< OKM validation test. */
};

/**
 * Dependencies for testing.
 */
struct backend_hkdf_testing {
	enum backend_hkdf_test_type type;	/**< Type of HKDF test. */
	struct hkdf_data data;				/**< HKDF test data. */
	struct hkdf_mock hkdf;				/**< Mock for HKDF. */
	struct logging_mock logger;			/**< Mock for debug logging. */
};


/**
 * Initialize the testing dependencies.
 *
 * @param test The test framework.
 * @param backend The testing components to initialize.
 * @param type The type of HKDF test to run.
 * @param hash The hash type to use for HKDF.
 */
static void backend_hkdf_testing_init (CuTest *test, struct backend_hkdf_testing *backend,
	enum backend_hkdf_test_type type, enum hash_type hash)
{
	struct hkdf_data data;
	int status;

	memset (&data, 0, sizeof (data));

	data.salt.buf = (unsigned char*) platform_malloc (HKDF_TESTING_EXTRACT_SALT_LEN);
	CuAssertPtrNotNull (test, data.salt.buf);

	memcpy (data.salt.buf, HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN);
	data.salt.len = HKDF_TESTING_EXTRACT_SALT_LEN;

	data.z.buf = (unsigned char*) platform_malloc (HKDF_TESTING_EXTRACT_IKM_LEN);
	CuAssertPtrNotNull (test, data.z.buf);

	memcpy (data.z.buf, HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN);
	data.z.len = HKDF_TESTING_EXTRACT_IKM_LEN;

	data.info.buf = (unsigned char*) platform_malloc (HKDF_TESTING_EXPAND_INFO_LEN);
	CuAssertPtrNotNull (test, data.info.buf);

	memcpy (data.info.buf, HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN);
	data.info.len = HKDF_TESTING_EXPAND_INFO_LEN;

	data.validity_success = 0;

	// Use unsupported cipher by default
	data.hash = ACVP_SHA3_512;

	switch (hash) {
		case HASH_TYPE_SHA1:
			data.hash = ACVP_SHA1;

			if (type == BACKEND_HKDF_TEST_TYPE_GENERATE) {
				data.dkm.buf = NULL;
				data.dkm.len = 0;
				data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA1_LEN * 8;
			}
			else {
				data.dkm.buf =
					(unsigned char*) platform_malloc (HKDF_TESTING_EXPAND_OKM_SHA1_LEN);
				CuAssertPtrNotNull (test, data.dkm.buf);

				memcpy (data.dkm.buf, HKDF_TESTING_EXPAND_OKM_SHA1,
					HKDF_TESTING_EXPAND_OKM_SHA1_LEN);
				data.dkm.len = HKDF_TESTING_EXPAND_OKM_SHA1_LEN;
				data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA1_LEN * 8;
			}

			break;

		case HASH_TYPE_SHA256:
			data.hash = ACVP_SHA256;

		/* fall through */ /* no break */

		default:
			if (type == BACKEND_HKDF_TEST_TYPE_GENERATE) {
				data.dkm.buf = NULL;
				data.dkm.len = 0;
				data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA256_LEN * 8;
			}
			else {
				data.dkm.buf =
					(unsigned char*) platform_malloc (HKDF_TESTING_EXPAND_OKM_SHA256_LEN);
				CuAssertPtrNotNull (test, data.dkm.buf);

				memcpy (data.dkm.buf, HKDF_TESTING_EXPAND_OKM_SHA256,
					HKDF_TESTING_EXPAND_OKM_SHA256_LEN);
				data.dkm.len = HKDF_TESTING_EXPAND_OKM_SHA256_LEN;
				data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA256_LEN * 8;
			}
	}

	backend->data = data;

	status = hkdf_mock_init (&backend->hkdf);
	CuAssertIntEquals (test, 0, status);

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
static void backend_hkdf_testing_release (CuTest *test,	struct backend_hkdf_testing *backend)
{
	int status;

	if (backend->data.salt.buf != NULL) {
		platform_free (backend->data.salt.buf);
	}

	if (backend->data.z.buf != NULL) {
		platform_free (backend->data.z.buf);
	}

	if (backend->data.info.buf != NULL) {
		platform_free (backend->data.info.buf);
	}

	if (backend->data.dkm.buf != NULL) {
		platform_free (backend->data.dkm.buf);
	}

	backend_hkdf_register_engines (NULL, 0);

	status = hkdf_mock_validate_and_release (&backend->hkdf);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&backend->logger);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void backend_hkdf_test_init (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;

	TEST_START;

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);
	CuAssertPtrNotNull (test, hkdf_impl->hkdf);
}

static void backend_hkdf_test_hkdf_sha1 (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA1);

	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA1_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN),
		MOCK_ARG (HKDF_TESTING_EXPAND_INFO_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_SHA1_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_SHA1,
		HKDF_TESTING_EXPAND_OKM_SHA1_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, HKDF_TESTING_EXPAND_OKM_SHA1_LEN, backend.data.dkm.len);

	status = testing_validate_array (HKDF_TESTING_EXPAND_OKM_SHA1, backend.data.dkm.buf,
		backend.data.dkm.len);
	CuAssertIntEquals (test, 0, status);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_sha256 (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA256);

	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA256_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN),
		MOCK_ARG (HKDF_TESTING_EXPAND_INFO_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_SHA256_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_SHA256,
		HKDF_TESTING_EXPAND_OKM_SHA256_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, HKDF_TESTING_EXPAND_OKM_SHA256_LEN, backend.data.dkm.len);

	status = testing_validate_array (HKDF_TESTING_EXPAND_OKM_SHA256, backend.data.dkm.buf,
		backend.data.dkm.len);
	CuAssertIntEquals (test, 0, status);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_no_salt (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA1);

	platform_free (backend.data.salt.buf);
	backend.data.salt.buf = NULL;
	backend.data.salt.len = 0;

	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN), MOCK_ARG_ANY, MOCK_ARG (0));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN),
		MOCK_ARG (HKDF_TESTING_EXPAND_INFO_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1,
		HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN, backend.data.dkm.len);

	status = testing_validate_array (HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1, backend.data.dkm.buf,
		backend.data.dkm.len);
	CuAssertIntEquals (test, 0, status);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_no_info (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA1);

	platform_free (backend.data.info.buf);
	backend.data.info.buf = NULL;
	backend.data.info.len = 0;

	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_ANY, MOCK_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1,
		HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN, backend.data.dkm.len);

	status = testing_validate_array (HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1, backend.data.dkm.buf,
		backend.data.dkm.len);
	CuAssertIntEquals (test, 0, status);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_validate_dkm_sha1 (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_VALIDATE,	HASH_TYPE_SHA1);

	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA1_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN),
		MOCK_ARG (HKDF_TESTING_EXPAND_INFO_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_SHA1_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_SHA1,
		HKDF_TESTING_EXPAND_OKM_SHA1_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.validity_success);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_validate_dkm_sha256 (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_VALIDATE,	HASH_TYPE_SHA256);

	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA256_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN),
		MOCK_ARG (HKDF_TESTING_EXPAND_INFO_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_SHA256_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_SHA256,
		HKDF_TESTING_EXPAND_OKM_SHA256_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.validity_success);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_validate_dkm_no_salt (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_VALIDATE,	HASH_TYPE_SHA1);

	platform_free (backend.data.salt.buf);
	backend.data.salt.buf = NULL;
	backend.data.salt.len = 0;

	platform_free (backend.data.dkm.buf);
	backend.data.dkm.buf = platform_malloc (HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN);
	CuAssertPtrNotNull (test, backend.data.dkm.buf);

	memcpy (backend.data.dkm.buf, HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1,
		HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN);

	backend.data.dkm.len = HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN;
	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN), MOCK_ARG_ANY, MOCK_ARG (0));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN),
		MOCK_ARG (HKDF_TESTING_EXPAND_INFO_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1,
		HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.validity_success);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_validate_dkm_no_info (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_VALIDATE,	HASH_TYPE_SHA1);

	platform_free (backend.data.info.buf);
	backend.data.info.buf = NULL;
	backend.data.info.len = 0;

	platform_free (backend.data.dkm.buf);
	backend.data.dkm.buf = platform_malloc (HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN);
	CuAssertPtrNotNull (test, backend.data.dkm.buf);

	memcpy (backend.data.dkm.buf, HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1,
		HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN);

	backend.data.dkm.len = HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN;
	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_ANY, MOCK_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1,
		HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, backend.data.validity_success);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_validate_dkm_fail (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_VALIDATE,	HASH_TYPE_SHA1);

	// Corrupt the input OKM.
	memset (backend.data.dkm.buf, 1, HKDF_TESTING_EXPAND_OKM_SHA1_LEN);

	backend.data.dkmlen = HKDF_TESTING_EXPAND_OKM_SHA1_LEN * 8;

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN),
		MOCK_ARG (HKDF_TESTING_EXPAND_INFO_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_SHA1_LEN));
	status |= mock_expect_output (&backend.hkdf.mock, 2, &HKDF_TESTING_EXPAND_OKM_SHA1,
		HKDF_TESTING_EXPAND_OKM_SHA1_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, backend.data.validity_success);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_null (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_HKDF_INVALID_ARGUMENT,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA1);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (NULL, 0);
	CuAssertIntEquals (test, -1, status);

	// Test invalid IKM.
	backend.data.z.len = 0;

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend.data.z.len = HKDF_TESTING_EXTRACT_IKM_LEN;

	platform_free (backend.data.z.buf);
	backend.data.z.buf = NULL;

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_no_engine (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_HKDF_NO_ENGINE,
		.arg2 = 0
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA1);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_engine_not_found (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = BACKEND_HKDF_ENGINE_NOT_FOUND,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA1);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation + 1;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_extract_error (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HKDF_EXTRACT_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf,
		HKDF_EXTRACT_FAILED, MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_hkdf_testing_release (test, &backend);
}

static void backend_hkdf_test_hkdf_expand_error (CuTest *test)
{
	const struct hkdf_backend *hkdf_impl;
	struct backend_hkdf_testing backend;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_ACVP,
		.msg_index = ACVP_LOGGING_TEST_FAILURE,
		.arg1 = HKDF_EXPAND_FAILED,
		.arg2 = 0
	};
	uint32_t implementation = 0;
	struct backend_hkdf_engine hkdf_engines[] = {
		{
			.impl_id = implementation,
			.intf = &backend.hkdf.base
		}
	};
	int status;

	TEST_START;

	backend_hkdf_testing_init (test, &backend, BACKEND_HKDF_TEST_TYPE_GENERATE,	HASH_TYPE_SHA256);

	status = mock_expect (&backend.logger.mock, backend.logger.base.create_entry, &backend.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&backend.hkdf.mock, backend.hkdf.base.extract, &backend.hkdf, 0,
		MOCK_ARG (HASH_TYPE_SHA256),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_IKM, HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_IKM_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXTRACT_SALT, HKDF_TESTING_EXTRACT_SALT_LEN),
		MOCK_ARG (HKDF_TESTING_EXTRACT_SALT_LEN));

	status |= mock_expect (&backend.hkdf.mock, backend.hkdf.base.expand, &backend.hkdf,
		HKDF_EXPAND_FAILED,
		MOCK_ARG_PTR_CONTAINS_TMP (HKDF_TESTING_EXPAND_INFO, HKDF_TESTING_EXPAND_INFO_LEN),
		MOCK_ARG (HKDF_TESTING_EXPAND_INFO_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (HKDF_TESTING_EXPAND_OKM_SHA256_LEN));
	CuAssertIntEquals (test, 0, status);

	acvp_implementation = implementation;

	backend_hkdf_register_engines (hkdf_engines, 1);

	hkdf_impl = backend_hkdf_get_impl ();
	CuAssertPtrNotNull (test, hkdf_impl);

	status = hkdf_impl->hkdf (&backend.data, 0);
	CuAssertIntEquals (test, -1, status);

	backend_hkdf_testing_release (test, &backend);
}


// *INDENT-OFF*
TEST_SUITE_START (backend_hkdf);

TEST (backend_hkdf_test_init);
TEST (backend_hkdf_test_hkdf_sha1);
TEST (backend_hkdf_test_hkdf_sha256);
TEST (backend_hkdf_test_hkdf_no_salt);
TEST (backend_hkdf_test_hkdf_no_info);
TEST (backend_hkdf_test_hkdf_validate_dkm_sha1);
TEST (backend_hkdf_test_hkdf_validate_dkm_sha256);
TEST (backend_hkdf_test_hkdf_validate_dkm_no_salt);
TEST (backend_hkdf_test_hkdf_validate_dkm_no_info);
TEST (backend_hkdf_test_hkdf_validate_dkm_fail);
TEST (backend_hkdf_test_hkdf_null);
TEST (backend_hkdf_test_hkdf_no_engine);
TEST (backend_hkdf_test_hkdf_engine_not_found);
TEST (backend_hkdf_test_hkdf_extract_error);
TEST (backend_hkdf_test_hkdf_expand_error);

TEST_SUITE_END;
// *INDENT-ON*
