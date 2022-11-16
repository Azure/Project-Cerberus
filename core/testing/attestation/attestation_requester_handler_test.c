// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform_api.h"
#include "attestation/attestation_requester_handler.h"
#include "attestation/attestation_requester_handler_static.h"


TEST_SUITE_LABEL ("attestation_requester_handler");


/**
 * Dependencies for testing.
 */
struct attestation_requester_handler_testing {
	struct attestation_requester attestation;	/**< Attestation requester. */
	struct device_manager device_mgr;			/**< Device manager. */
	struct pcr_store pcr;						/**< PCR manager. */
	struct attestation_requester_handler test;	/**< Attestation task for testing. */
};

/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void attestation_requester_handler_testing_init_dependencies (CuTest *test,
	struct attestation_requester_handler_testing *handler)
{
	uint8_t pcrs[] = {1};
	int status;

	status = device_manager_init (&handler->device_mgr, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0x51, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&handler->pcr, pcrs, sizeof (pcrs));
	CuAssertIntEquals (test, 0, status);

	/* Don't initialize the attestation requester.  Too many dependencies and complexity for this
	 * test suite. */
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void attestation_requester_handler_testing_init (CuTest *test,
	struct attestation_requester_handler_testing *handler)
{
	int status;

	attestation_requester_handler_testing_init_dependencies (test, handler);

	status = attestation_requester_handler_init (&handler->test, &handler->attestation,
		&handler->device_mgr, &handler->pcr, 0, 0);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void attestation_requester_handler_testing_release_dependencies (CuTest *test,
	struct attestation_requester_handler_testing *handler)
{
	device_manager_release (&handler->device_mgr);
	pcr_store_release (&handler->pcr);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void attestation_requester_handler_testing_validate_and_release (CuTest *test,
	struct attestation_requester_handler_testing *handler)
{
	attestation_requester_handler_testing_release_dependencies (test, handler);
	attestation_requester_handler_release (&handler->test);
}

/*******************
 * Test cases
 *******************/

static void attestation_requester_handler_test_init (CuTest *test)
{
	struct attestation_requester_handler_testing handler;
	int status;

	TEST_START;

	attestation_requester_handler_testing_init_dependencies (test, &handler);

	status = attestation_requester_handler_init (&handler.test, &handler.attestation,
		&handler.device_mgr, &handler.pcr, 0, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, handler.test.base.prepare);
	CuAssertPtrNotNull (test, handler.test.base.get_next_execution);
	CuAssertPtrNotNull (test, handler.test.base.execute);

	attestation_requester_handler_testing_validate_and_release (test, &handler);
}

static void attestation_requester_handler_test_init_null (CuTest *test)
{
	struct attestation_requester_handler_testing handler;
	int status;

	TEST_START;

	attestation_requester_handler_testing_init_dependencies (test, &handler);

	status = attestation_requester_handler_init (NULL, &handler.attestation,
		&handler.device_mgr, &handler.pcr, 0, 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_requester_handler_init (&handler.test, NULL,
		&handler.device_mgr, &handler.pcr, 0, 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_requester_handler_init (&handler.test, &handler.attestation,
		NULL, &handler.pcr, 0, 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_requester_handler_init (&handler.test, &handler.attestation,
		&handler.device_mgr, NULL, 0, 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	attestation_requester_handler_testing_release_dependencies(test, &handler);
}

static void attestation_requester_handler_test_static_init (CuTest *test)
{
	struct attestation_requester_handler_testing handler;
	struct attestation_requester_handler test_static = attestation_requester_handler_static_init (
		&handler.attestation, &handler.device_mgr, &handler.pcr, 0, 0);

	TEST_START;

	attestation_requester_handler_testing_init_dependencies (test, &handler);

	CuAssertPtrEquals (test, NULL, test_static.base.prepare);
	CuAssertPtrNotNull (test, test_static.base.get_next_execution);
	CuAssertPtrNotNull (test, test_static.base.execute);

	attestation_requester_handler_testing_validate_and_release (test, &handler);
}

static void attestation_requester_handler_test_release_null (CuTest *test)
{
	TEST_START;

	attestation_requester_handler_release (NULL);
}

static void attestation_requester_handler_test_get_next_execution (CuTest *test)
{
	struct attestation_requester_handler_testing handler;
	const platform_clock *next_time;

	TEST_START;

	attestation_requester_handler_testing_init (test, &handler);

	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	attestation_requester_handler_testing_validate_and_release (test, &handler);
}

static void attestation_requester_handler_test_get_next_execution_static_init (CuTest *test)
{
	struct attestation_requester_handler_testing handler;
	struct attestation_requester_handler test_static = attestation_requester_handler_static_init (
		&handler.attestation, &handler.device_mgr, &handler.pcr, 0, 0);
	const platform_clock *next_time;

	TEST_START;

	attestation_requester_handler_testing_init_dependencies (test, &handler);

	next_time = test_static.base.get_next_execution (&test_static.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	attestation_requester_handler_testing_release_dependencies (test, &handler);
}


TEST_SUITE_START (attestation_requester_handler);

TEST (attestation_requester_handler_test_init);
TEST (attestation_requester_handler_test_init_null);
TEST (attestation_requester_handler_test_static_init);
TEST (attestation_requester_handler_test_release_null);
TEST (attestation_requester_handler_test_get_next_execution);
TEST (attestation_requester_handler_test_get_next_execution_static_init);
/* Testing the execute call would bring in a huge amount of complexity for a very simple
 * implementation. */

TEST_SUITE_END;
