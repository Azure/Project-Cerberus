// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_irq_handler.h"
#include "testing/mock/host_fw/host_processor_mock.h"
#include "testing/mock/host_fw/bmc_recovery_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"


TEST_SUITE_LABEL ("host_irq_handler");


/*******************
 * Test cases
 *******************/

static void host_irq_handler_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.power_on);
	CuAssertPtrNotNull (test, handler.enter_reset);
	CuAssertPtrNotNull (test, handler.exit_reset);
	CuAssertPtrNotNull (test, handler.assert_cs0);
	CuAssertPtrNotNull (test, handler.assert_cs1);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_init_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (NULL, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init (&handler, NULL, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init (&handler, &host.base, NULL, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, NULL, &recovery.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_release_null (CuTest *test)
{
	TEST_START;

	host_irq_handler_release (NULL);
}

static void host_irq_handler_test_enter_reset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_reset, &recovery, 0);
	status |= mock_expect (&host.mock, host.base.soft_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.enter_reset (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_enter_reset_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&host.mock, host.base.soft_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.enter_reset (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_enter_reset_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.enter_reset (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_enter_reset_host_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_reset, &recovery, 0);
	status |= mock_expect (&host.mock, host.base.soft_reset, &host,
		HOST_PROCESSOR_SOFT_RESET_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.enter_reset (&handler);
	CuAssertIntEquals (test, HOST_PROCESSOR_SOFT_RESET_FAILED, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_exit_reset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_out_of_reset, &recovery, 0);

	CuAssertIntEquals (test, 0, status);

	handler.exit_reset (&handler);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_exit_reset_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	handler.exit_reset (&handler);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_exit_reset_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	handler.exit_reset (NULL);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_assert_cs0 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_cs0, &recovery, 0);

	CuAssertIntEquals (test, 0, status);

	handler.assert_cs0 (&handler);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_assert_cs0_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	handler.assert_cs0 (&handler);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_assert_cs0_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	handler.assert_cs0 (NULL);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_assert_cs1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_cs1, &recovery, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.assert_cs1 (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_assert_cs1_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = handler.assert_cs1 (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_assert_cs1_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.assert_cs1 (NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_assert_cs1_recovery_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_cs1, &recovery,
		BMC_RECOVERY_CS1_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.assert_cs1 (&handler);
	CuAssertIntEquals (test, BMC_RECOVERY_CS1_FAILED, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_alternate_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	HASH_TESTING_ENGINE hash2;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash2);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, 0, MOCK_ARG (&hash2),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, &hash2.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	HASH_TESTING_ENGINE_RELEASE (&hash2);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_validation_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_blank_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, FLASH_UTIL_UNEXPECTED_VALUE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_unknown_version (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host,
		HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_flash_rollback (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_flash_rollback_alternate_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	HASH_TESTING_ENGINE hash2;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash2);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash2), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash2), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, 0, MOCK_ARG (&hash2),
		MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, &hash2.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	HASH_TESTING_ENGINE_RELEASE (&hash2);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_flash_rollback_validation_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_flash_rollback_blank_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, FLASH_UTIL_UNEXPECTED_VALUE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_flash_rollback_unknown_version (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_flash_rollback_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_flash_rollback_no_rollback (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host, HOST_PROCESSOR_NO_ROLLBACK,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true), MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_flash_rollback_rollback_dirty (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_DIRTY, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_apply_recovery_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_apply_recovery_image_alternate_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	HASH_TESTING_ENGINE hash2;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash2);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash2), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash2), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash2), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash2), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, &hash2.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	HASH_TESTING_ENGINE_RELEASE (&hash2);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_apply_recovery_image_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_apply_recovery_image_retry_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_IMG_FAILED, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_apply_recovery_image_unsupported (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_UNSUPPORTED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_apply_recovery_image_no_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_NO_RECOVERY_IMAGE, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, false, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_RECOVERY_IMAGE, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_apply_recovery_image_unsupported_allow_unsecure (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_UNSUPPORTED, MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.bypass_mode, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, true, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_apply_recovery_image_no_image_allow_unsecure (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_NO_RECOVERY_IMAGE, MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.bypass_mode, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, true, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_bypass_mode (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.bypass_mode, &host, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, true, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_bypass_mode_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.bypass_mode, &host, HOST_PROCESSOR_BYPASS_FAILED,
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.bypass_mode, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, true, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_bypass_mode_retry_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&host.mock, host.base.power_on_reset, &host, HOST_PROCESSOR_POR_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (true),
		MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (true));

	status |= mock_expect (&host.mock, host.base.bypass_mode, &host, HOST_PROCESSOR_BYPASS_FAILED,
		MOCK_ARG (true));
	status |= mock_expect (&host.mock, host.base.bypass_mode, &host, HOST_PROCESSOR_BYPASS_FAILED,
		MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (&handler, true, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_BYPASS_FAILED, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_power_on_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.power_on (NULL, false, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_set_host (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_processor_mock host_new;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host_new);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_set_host (&handler, &host_new.base);
	CuAssertIntEquals (test, 0, status);

	/* Check that the new instance will be called in response to an event. */
	status = mock_expect (&recovery.mock, recovery.base.on_host_reset, &recovery, 0);
	status |= mock_expect (&host_new.mock, host_new.base.soft_reset, &host_new, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	CuAssertIntEquals (test, 0, status);

	status = handler.enter_reset (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host_new);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_test_set_host_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_processor_mock host_new;
	struct bmc_recovery_mock recovery;
	struct host_irq_handler handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host_new);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_init (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_init (&handler, &host.base, &hash.base, &rsa.base, &recovery.base);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_set_host (NULL, &host_new.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_set_host (&handler, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host_new);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}


TEST_SUITE_START (host_irq_handler);

TEST (host_irq_handler_test_init);
TEST (host_irq_handler_test_init_no_recovery);
TEST (host_irq_handler_test_init_null);
TEST (host_irq_handler_test_release_null);
TEST (host_irq_handler_test_enter_reset);
TEST (host_irq_handler_test_enter_reset_no_recovery);
TEST (host_irq_handler_test_enter_reset_null);
TEST (host_irq_handler_test_enter_reset_host_error);
TEST (host_irq_handler_test_exit_reset);
TEST (host_irq_handler_test_exit_reset_no_recovery);
TEST (host_irq_handler_test_exit_reset_null);
TEST (host_irq_handler_test_assert_cs0);
TEST (host_irq_handler_test_assert_cs0_no_recovery);
TEST (host_irq_handler_test_assert_cs0_null);
TEST (host_irq_handler_test_assert_cs1);
TEST (host_irq_handler_test_assert_cs1_no_recovery);
TEST (host_irq_handler_test_assert_cs1_null);
TEST (host_irq_handler_test_assert_cs1_recovery_error);
TEST (host_irq_handler_test_power_on);
TEST (host_irq_handler_test_power_on_alternate_hash);
TEST (host_irq_handler_test_power_on_validation_fail);
TEST (host_irq_handler_test_power_on_blank_fail);
TEST (host_irq_handler_test_power_on_unknown_version);
TEST (host_irq_handler_test_power_on_error);
TEST (host_irq_handler_test_power_on_flash_rollback);
TEST (host_irq_handler_test_power_on_flash_rollback_alternate_hash);
TEST (host_irq_handler_test_power_on_flash_rollback_validation_fail);
TEST (host_irq_handler_test_power_on_flash_rollback_blank_fail);
TEST (host_irq_handler_test_power_on_flash_rollback_unknown_version);
TEST (host_irq_handler_test_power_on_flash_rollback_error);
TEST (host_irq_handler_test_power_on_flash_rollback_no_rollback);
TEST (host_irq_handler_test_power_on_flash_rollback_rollback_dirty);
TEST (host_irq_handler_test_power_on_apply_recovery_image);
TEST (host_irq_handler_test_power_on_apply_recovery_image_alternate_hash);
TEST (host_irq_handler_test_power_on_apply_recovery_image_error);
TEST (host_irq_handler_test_power_on_apply_recovery_image_retry_error);
TEST (host_irq_handler_test_power_on_apply_recovery_image_unsupported);
TEST (host_irq_handler_test_power_on_apply_recovery_image_no_image);
TEST (host_irq_handler_test_power_on_apply_recovery_image_unsupported_allow_unsecure);
TEST (host_irq_handler_test_power_on_apply_recovery_image_no_image_allow_unsecure);
TEST (host_irq_handler_test_power_on_bypass_mode);
TEST (host_irq_handler_test_power_on_bypass_mode_error);
TEST (host_irq_handler_test_power_on_bypass_mode_retry_error);
TEST (host_irq_handler_test_power_on_null);
TEST (host_irq_handler_test_set_host);
TEST (host_irq_handler_test_set_host_null);

TEST_SUITE_END;
