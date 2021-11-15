// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_irq_handler_auth_check.h"
#include "host_fw/host_state_manager.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/host_fw/host_processor_mock.h"
#include "testing/mock/host_fw/bmc_recovery_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/host_fw/host_irq_control_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"


TEST_SUITE_LABEL ("host_irq_handler_auth_check");


/*******************
 * Test cases
 *******************/

static void host_irq_handler_auth_check_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_control_mock control;
	struct host_irq_control_mock irq;
	struct host_irq_handler_auth_check handler;
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

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base, &irq.base);
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

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&handler);

	status = host_irq_control_mock_validate_and_release (&irq);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_auth_check_test_init_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct host_control_mock control;
	struct host_irq_control_mock irq;
	struct host_irq_handler_auth_check handler;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		NULL, &control.base, &irq.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&handler);

	status = host_irq_control_mock_validate_and_release (&irq);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_auth_check_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_control_mock control;
	struct host_irq_control_mock irq;
	struct host_irq_handler_auth_check handler;
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

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (NULL, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler, NULL, &hash.base, &rsa.base,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, NULL, &rsa.base,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, NULL,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, NULL, &irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base, NULL);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_INVALID_ARGUMENT, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_auth_check_test_init_error_irq (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_control_mock control;
	struct host_irq_control_mock irq;
	struct host_irq_handler_auth_check handler;
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

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq,
		HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, HOST_IRQ_HANDLER_EXIT_RESET_FAILED, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_auth_check_test_release_null (CuTest *test)
{
	TEST_START;

	host_irq_handler_auth_check_release (NULL);
}

static void host_irq_handler_auth_check_test_release_error_irq (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_control_mock control;
	struct host_irq_control_mock irq;
	struct host_irq_handler_auth_check handler;
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

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq,
		HOST_IRQ_HANDLER_EXIT_RESET_FAILED, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&handler);

	status = host_irq_control_mock_validate_and_release (&irq);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_auth_check_test_exit_reset_no_pending_auth (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_control_mock control;
	struct host_irq_control_mock irq;
	struct host_irq_handler_auth_check handler;
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

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_out_of_reset, &recovery, 0);
	status |= mock_expect (&host.mock, host.base.get_next_reset_verification_actions, &host,
		HOST_PROCESSOR_ACTION_NONE);

	CuAssertIntEquals (test, 0, status);

	handler.base.exit_reset (&handler.base);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&handler);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_auth_check_test_exit_reset_with_pending_auth (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_control_mock control;
	struct host_irq_control_mock irq;
	struct host_irq_handler_auth_check handler;
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

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.mock, recovery.base.on_host_out_of_reset, &recovery, 0);
	status |= mock_expect (&host.mock, host.base.get_next_reset_verification_actions, &host,
		HOST_PROCESSOR_ACTION_VERIFY_UPDATE);

	status |= mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	handler.base.exit_reset (&handler.base);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&handler);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_irq_handler_auth_check_test_exit_reset_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_processor_mock host;
	struct bmc_recovery_mock recovery;
	struct host_control_mock control;
	struct host_irq_control_mock irq;
	struct host_irq_handler_auth_check handler;
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

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = host_irq_handler_auth_check_init (&handler, &host.base, &hash.base, &rsa.base,
		&recovery.base, &control.base, &irq.base);
	CuAssertIntEquals (test, 0, status);

	handler.base.exit_reset (NULL);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_mock_validate_and_release (&recovery);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	host_irq_handler_auth_check_release (&handler);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}


TEST_SUITE_START (host_irq_handler_auth_check);

TEST (host_irq_handler_auth_check_test_init);
TEST (host_irq_handler_auth_check_test_init_no_recovery);
TEST (host_irq_handler_auth_check_test_init_null);
TEST (host_irq_handler_auth_check_test_init_error_irq);
TEST (host_irq_handler_auth_check_test_release_null);
TEST (host_irq_handler_auth_check_test_release_error_irq);
TEST (host_irq_handler_auth_check_test_exit_reset_no_pending_auth);
TEST (host_irq_handler_auth_check_test_exit_reset_with_pending_auth);
TEST (host_irq_handler_auth_check_test_exit_reset_null);

TEST_SUITE_END;
