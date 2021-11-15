// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_irq_handler_mask_irqs.h"
#include "testing/mock/host_fw/host_processor_mock.h"
#include "testing/mock/host_fw/bmc_recovery_mock.h"
#include "testing/mock/host_fw/host_irq_control_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"


TEST_SUITE_LABEL ("host_irq_handler_mask_irqs");


/*******************
 * Test cases
 *******************/

static void host_irq_handler_mask_irqs_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.base.power_on);
	CuAssertPtrNotNull (test, handler.base.enter_reset);
	CuAssertPtrNotNull (test, handler.base.exit_reset);
	CuAssertPtrNotNull (test, handler.base.assert_cs0);
	CuAssertPtrNotNull (test, handler.base.assert_cs1);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_init_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base, NULL,
		&control.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (NULL, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init (&handler, NULL, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, NULL, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, NULL,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_release_null (CuTest *test)
{
	TEST_START;

	host_irq_handler_mask_irqs_release (NULL);
}

static void host_irq_handler_mask_irqs_test_enter_reset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (false));

	status |= mock_expect (&recovery.mock, recovery.base.on_host_reset, &recovery, 0);
	status |= mock_expect (&host.mock, host.base.soft_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	status |= mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.base.enter_reset (&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_enter_reset_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base, NULL,
		&control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (false));

	status |= mock_expect (&host.mock, host.base.soft_reset, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	status |= mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.base.enter_reset (&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_enter_reset_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.base.enter_reset (NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_enter_reset_host_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (false));

	status |= mock_expect (&recovery.mock, recovery.base.on_host_reset, &recovery, 0);
	status |= mock_expect (&host.mock, host.base.soft_reset, &host,
		HOST_PROCESSOR_SOFT_RESET_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.base.enter_reset (&handler.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_SOFT_RESET_FAILED, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_exit_reset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_out_of_reset, &recovery, 0);

	CuAssertIntEquals (test, 0, status);

	handler.base.exit_reset (&handler.base);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_exit_reset_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base, NULL,
		&control.base);
	CuAssertIntEquals (test, 0, status);

	handler.base.exit_reset (&handler.base);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_exit_reset_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	handler.base.exit_reset (NULL);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_assert_cs0 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_cs0, &recovery, 0);

	CuAssertIntEquals (test, 0, status);

	handler.base.assert_cs0 (&handler.base);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_assert_cs0_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base, NULL,
		&control.base);
	CuAssertIntEquals (test, 0, status);

	handler.base.assert_cs0 (&handler.base);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_assert_cs0_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	handler.base.assert_cs0 (NULL);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_assert_cs1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (false));

	status |= mock_expect (&recovery.mock, recovery.base.on_host_cs1, &recovery, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa));

	status |= mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.base.assert_cs1 (&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_assert_cs1_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base, NULL,
		&control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (false));
	status |= mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.base.assert_cs1 (&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_assert_cs1_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = handler.base.assert_cs1 (NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_mask_irqs_test_assert_cs1_recovery_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_irq_control_mock control;
	struct host_irq_handler_mask_irqs handler;
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

	status = host_irq_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_mask_irqs_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (false));

	status |= mock_expect (&recovery.mock, recovery.base.on_host_cs1, &recovery,
		BMC_RECOVERY_CS1_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa));

	status |= mock_expect (&control.mock, control.base.enable_notifications, &control, 0,
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = handler.base.assert_cs1 (&handler.base);
	CuAssertIntEquals (test, BMC_RECOVERY_CS1_FAILED, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_mask_irqs_release (&handler);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}


TEST_SUITE_START (host_irq_handler_mask_irqs);

TEST (host_irq_handler_mask_irqs_test_init);
TEST (host_irq_handler_mask_irqs_test_init_no_recovery);
TEST (host_irq_handler_mask_irqs_test_init_null);
TEST (host_irq_handler_mask_irqs_test_release_null);
TEST (host_irq_handler_mask_irqs_test_enter_reset);
TEST (host_irq_handler_mask_irqs_test_enter_reset_no_recovery);
TEST (host_irq_handler_mask_irqs_test_enter_reset_null);
TEST (host_irq_handler_mask_irqs_test_enter_reset_host_error);
TEST (host_irq_handler_mask_irqs_test_exit_reset);
TEST (host_irq_handler_mask_irqs_test_exit_reset_no_recovery);
TEST (host_irq_handler_mask_irqs_test_exit_reset_null);
TEST (host_irq_handler_mask_irqs_test_assert_cs0);
TEST (host_irq_handler_mask_irqs_test_assert_cs0_no_recovery);
TEST (host_irq_handler_mask_irqs_test_assert_cs0_null);
TEST (host_irq_handler_mask_irqs_test_assert_cs1);
TEST (host_irq_handler_mask_irqs_test_assert_cs1_no_recovery);
TEST (host_irq_handler_mask_irqs_test_assert_cs1_null);
TEST (host_irq_handler_mask_irqs_test_assert_cs1_recovery_error);

TEST_SUITE_END;
