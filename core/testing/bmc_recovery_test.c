// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "host_fw/bmc_recovery.h"
#include "mock/host_irq_control_mock.h"
#include "mock/host_processor_mock.h"
#include "mock/host_control_mock.h"
#include "engines/hash_testing_engine.h"
#include "engines/rsa_testing_engine.h"


static const char *SUITE = "bmc_recovery";


/*******************
 * Test cases
 *******************/

static void bmc_recovery_test_init (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	CuAssertPtrNotNull (test, recovery.on_host_reset);
	CuAssertPtrNotNull (test, recovery.on_host_out_of_reset);
	CuAssertPtrNotNull (test, recovery.on_host_cs0);
	CuAssertPtrNotNull (test, recovery.on_host_cs1);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	status = host_irq_control_mock_validate_and_release (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);
}

static void bmc_recovery_test_init_null (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (NULL, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, BMC_RECOVERY_INVALID_ARGUMENT, status);

	status = bmc_recovery_init (&recovery, NULL, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, BMC_RECOVERY_INVALID_ARGUMENT, status);

	status = bmc_recovery_init (&recovery, &irq.base, NULL, &control.base, NULL);
	CuAssertIntEquals (test, BMC_RECOVERY_INVALID_ARGUMENT, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, NULL, NULL);
	CuAssertIntEquals (test, BMC_RECOVERY_INVALID_ARGUMENT, status);

	status = host_irq_control_mock_validate_and_release (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);
}

static void bmc_recovery_test_init_irq_error (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq,
		HOST_IRQ_CTRL_EXIT_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, HOST_IRQ_CTRL_EXIT_RESET_FAILED, status);

	status = host_irq_control_mock_validate_and_release (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);
}

static void bmc_recovery_test_init_min_wdt_too_large (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 1,
		.min_wdt = 2,
		.msec = 0,
	};
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, BMC_RECOVERY_INVALID_MIN_WDT, status);

	status = host_irq_control_mock_validate_and_release (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);
}

static void bmc_recovery_test_release_null (CuTest *test)
{
	TEST_START;

	bmc_recovery_release (NULL);
}

static void bmc_recovery_test_release_no_init (CuTest *test)
{
	struct bmc_recovery recovery;

	TEST_START;

	memset (&recovery, 0, sizeof (recovery));

	bmc_recovery_release (&recovery);
}

static void bmc_recovery_test_state_running_exit_reset_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_RUNNING;

	recovery.on_host_out_of_reset (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_running_cs0_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_RUNNING;

	status = mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	recovery.on_host_cs0 (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_running_cs1_irq (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_RUNNING;

	status = mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_running_enter_reset_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_RUNNING;

	status = mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	recovery.on_host_reset (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_IN_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_in_reset_enter_reset_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	recovery.on_host_reset (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_IN_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_in_reset_exit_reset_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	recovery.on_host_out_of_reset (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_EXIT_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_in_reset_cs0_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	recovery.on_host_cs0 (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_IN_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_in_reset_cs1_irq (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_rollback_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false),
		MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ROLLBACK_FAILED, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_rollback_auth_error_apply_recovery_image (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_rollback_auth_error_apply_recovery_image_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_IMG_FAILED, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_no_rollback_apply_recovery_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, HOST_PROCESSOR_NO_ROLLBACK,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_no_rollback_apply_recovery_image_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, HOST_PROCESSOR_NO_ROLLBACK,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_IMG_FAILED, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_rollback_dirty_apply_recovery_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_DIRTY, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false),
		MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_rollback_dirty_apply_recovery_image_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_DIRTY, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false),
		MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_IMG_FAILED, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_no_timeout_max_wdt_1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 1,
		.min_wdt = 0,
		.msec = 30000,
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 2, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_no_timeout_max_wdt_2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 2,
		.min_wdt = 0,
		.msec = 30000,
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 2, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 3, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_no_timeout_min_wdt_1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 2,
		.min_wdt = 1,
		.msec = 30000,
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset,
		&control, 0, MOCK_ARG (true));
	status |= mock_expect (&control.mock, control.base.hold_processor_in_reset,
		&control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&control.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 2, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 3, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_timeout_rollback (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 1,
		.min_wdt = 0,
		.msec = 0,
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_in_reset_cs1_irq_timeout_rollback_auth_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 1,
		.min_wdt = 0,
		.msec = 0,
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_exit_reset_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	recovery.on_host_out_of_reset (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_EXIT_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_exit_reset_enter_reset_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	recovery.on_host_reset (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_IN_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_exit_reset_cs0_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	recovery.on_host_cs0 (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0, MOCK_ARG (&hash),
		MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_rollback_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_FAILED, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false),
		MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ROLLBACK_FAILED, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_rollback_auth_error_apply_recovery_image (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_rollback_auth_error_apply_recovery_image_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_IMG_FAILED, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_no_rollback_apply_recovery_image (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, HOST_PROCESSOR_NO_ROLLBACK,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_no_rollback_apply_recovery_image_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, HOST_PROCESSOR_NO_ROLLBACK,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_IMG_FAILED, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_rollback_dirty_apply_recovery_image (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_DIRTY, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false),
		MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_rollback_dirty_apply_recovery_image_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_ROLLBACK_DIRTY, MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false),
		MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host,
		HOST_PROCESSOR_RECOVERY_IMG_FAILED, MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_IMG_FAILED, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_no_timeout_max_wdt_1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 1,
		.min_wdt = 0,
		.msec = 30000
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 2, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_no_timeout_max_wdt_2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 2,
		.min_wdt = 0,
		.msec = 30000
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 2, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 3, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_no_timeout_min_wdt_1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 2,
		.min_wdt = 1,
		.msec = 30000
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset,
		&control, 0, MOCK_ARG (true));
	status |= mock_expect (&control.mock, control.base.hold_processor_in_reset,
		&control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&control.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 2, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 3, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_timeout_rollback (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 1,
		.min_wdt = 0,
		.msec = 0,
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_exit_reset_cs1_irq_timeout_rollback_auth_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct bmc_recovery_control rec_ctrl = {
		.max_wdt = 1,
		.min_wdt = 0,
		.msec = 0,
	};
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, &rec_ctrl);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, 0,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_EXIT_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&rsa), MOCK_ARG (false), MOCK_ARG (false));
	status |= mock_expect (&host.mock, host.base.apply_recovery_image, &host, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);
	CuAssertIntEquals (test, 1, recovery.num_wdt);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_state_rollback_done_exit_reset_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_ROLLBACK_DONE;

	recovery.on_host_out_of_reset (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_EXIT_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_rollback_done_enter_reset_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_ROLLBACK_DONE;

	recovery.on_host_reset (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_rollback_done_cs0_irq (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_ROLLBACK_DONE;

	recovery.on_host_cs0 (&recovery);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_IN_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_state_rollback_done_cs1_irq (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_ROLLBACK_DONE;

	status = recovery.on_host_cs1 (&recovery, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_ROLLBACK_DONE, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_on_host_reset_null (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.on_host_reset (NULL);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_on_host_out_of_reset_null (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.on_host_out_of_reset (NULL);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_on_host_cs0_null (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.on_host_cs0 (NULL);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_on_host_cs1_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = recovery.on_host_cs1 (NULL, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_IN_RESET, recovery.state);

	status = mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_INVALID_ARGUMENT, MOCK_ARG (NULL), MOCK_ARG (&rsa), MOCK_ARG (false),
		MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, NULL, &rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&host.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	recovery.state = BMC_RECOVERY_STATE_IN_RESET;

	status = mock_expect (&host.mock, host.base.flash_rollback, &host,
		HOST_PROCESSOR_INVALID_ARGUMENT, MOCK_ARG (&hash), MOCK_ARG (NULL), MOCK_ARG (false),
		MOCK_ARG (false));
	status |= mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = recovery.on_host_cs1 (&recovery, &hash.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void bmc_recovery_test_set_initial_state_running (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_set_initial_state (&recovery, false);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, BMC_RECOVERY_STATE_RUNNING, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_set_initial_state_in_reset (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_chip_selects, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_set_initial_state (&recovery, true);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, BMC_RECOVERY_STATE_IN_RESET, recovery.state);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}

static void bmc_recovery_test_set_initial_state_null (CuTest *test)
{
	struct host_irq_control_mock irq;
	struct host_processor_mock host;
	struct bmc_recovery recovery;
	struct host_control_mock control;
	int status;

	TEST_START;

	status = host_irq_control_mock_init (&irq);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&irq.mock, irq.base.enable_exit_reset, &irq, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_init (&recovery, &irq.base, &host.base, &control.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = bmc_recovery_set_initial_state (NULL, false);
	CuAssertIntEquals (test, BMC_RECOVERY_INVALID_ARGUMENT, status);

	status = mock_validate (&irq.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	bmc_recovery_release (&recovery);

	host_irq_control_mock_release (&irq);
}


CuSuite* get_bmc_recovery_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, bmc_recovery_test_init);
	SUITE_ADD_TEST (suite, bmc_recovery_test_init_null);
	SUITE_ADD_TEST (suite, bmc_recovery_test_init_irq_error);
	SUITE_ADD_TEST (suite, bmc_recovery_test_init_min_wdt_too_large);
	SUITE_ADD_TEST (suite, bmc_recovery_test_release_null);
	SUITE_ADD_TEST (suite, bmc_recovery_test_release_no_init);

	SUITE_ADD_TEST (suite, bmc_recovery_test_state_running_exit_reset_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_running_cs0_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_running_cs1_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_running_enter_reset_irq);

	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_enter_reset_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_exit_reset_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_cs0_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_cs1_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_cs1_irq_rollback_error);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_in_reset_cs1_irq_rollback_auth_error_apply_recovery_image);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_in_reset_cs1_irq_rollback_auth_error_apply_recovery_image_error);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_in_reset_cs1_irq_no_rollback_apply_recovery_image);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_in_reset_cs1_irq_no_rollback_apply_recovery_image_error);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_in_reset_cs1_irq_rollback_dirty_apply_recovery_image);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_in_reset_cs1_irq_rollback_dirty_apply_recovery_image_error);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_cs1_irq_no_timeout_max_wdt_1);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_cs1_irq_no_timeout_max_wdt_2);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_cs1_irq_no_timeout_min_wdt_1);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_cs1_irq_timeout_rollback);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_in_reset_cs1_irq_timeout_rollback_auth_error);

	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_exit_reset_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_enter_reset_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_cs0_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_cs1_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_cs1_irq_rollback_error);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_exit_reset_cs1_irq_rollback_auth_error_apply_recovery_image);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_exit_reset_cs1_irq_rollback_auth_error_apply_recovery_image_error);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_exit_reset_cs1_irq_no_rollback_apply_recovery_image);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_exit_reset_cs1_irq_no_rollback_apply_recovery_image_error);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_exit_reset_cs1_irq_rollback_dirty_apply_recovery_image);
	SUITE_ADD_TEST (suite,
		bmc_recovery_test_state_exit_reset_cs1_irq_rollback_dirty_apply_recovery_image_error);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_cs1_irq_no_timeout_max_wdt_1);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_cs1_irq_no_timeout_max_wdt_2);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_cs1_irq_no_timeout_min_wdt_1);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_cs1_irq_timeout_rollback);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_exit_reset_cs1_irq_timeout_rollback_auth_error);

	SUITE_ADD_TEST (suite, bmc_recovery_test_state_rollback_done_exit_reset_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_rollback_done_enter_reset_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_rollback_done_cs0_irq);
	SUITE_ADD_TEST (suite, bmc_recovery_test_state_rollback_done_cs1_irq);

	SUITE_ADD_TEST (suite, bmc_recovery_test_on_host_reset_null);
	SUITE_ADD_TEST (suite, bmc_recovery_test_on_host_out_of_reset_null);
	SUITE_ADD_TEST (suite, bmc_recovery_test_on_host_cs0_null);
	SUITE_ADD_TEST (suite, bmc_recovery_test_on_host_cs1_null);

	SUITE_ADD_TEST (suite, bmc_recovery_test_set_initial_state_running);
	SUITE_ADD_TEST (suite, bmc_recovery_test_set_initial_state_in_reset);
	SUITE_ADD_TEST (suite, bmc_recovery_test_set_initial_state_null);

	return suite;
}
