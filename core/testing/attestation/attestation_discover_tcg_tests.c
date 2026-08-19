// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "attestation/attestation.h"
#include "attestation/attestation_discover.h"
#include "attestation/attestation_discover_mctp.h"
#include "attestation/attestation_discover_tcg.h"
#include "attestation/attestation_discover_tcg_static.h"
#include "attestation/attestation_logging.h"
#include "attestation/pcr_store.h"
#include "cmd_interface/device_manager.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_interface.h"
#include "testing/mock/asn1/x509_mock.h"
#include "testing/mock/cmd_interface/cmd_channel_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/msg_transport_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/manifest/cfm/cfm_manager_mock.h"
#include "testing/mock/manifest/cfm/cfm_mock.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("attestation_discover_tcg");

struct attestation_discover_tcg_testing {
	struct attestation_requester test;
	struct attestation_requester_state state;
	struct attestation_discover_tcg_state discover_state;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	struct cmd_channel_mock channel;
	struct hash_engine_mock primary_hash;
	struct hash_engine_mock secondary_hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509_mock;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct cfm_manager_mock cfm_manager;
	struct cfm_mock cfm;
	struct msg_transport_mock mctp_control;
	struct msg_transport_mock spdm_transport;
	const struct attestation_discover *discover_list[2];
};


/**
 * Common setup function for attestation_discover_tcg tests.
 * Initializes all required mocks, device manager, and attestation components.
 *
 * @param test The test framework.
 * @param testing The testing structure to initialize.
 * @param discover The discover structure to initialize.
 * @param num_devices Number of attestable devices to initialize in device manager.
 */
static void attestation_discover_tcg_test_setup (CuTest *test,
	struct attestation_discover_tcg_testing *testing, struct attestation_discover_tcg *discover,
	uint8_t num_devices)
{
	int status;

	status = hash_mock_init (&testing->primary_hash);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&testing->primary_hash.mock, "primary hash");

	status = msg_transport_mock_init (&testing->mctp_control);
	CuAssertIntEquals (test, 0, status);

	status = msg_transport_mock_init (&testing->spdm_transport);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&testing->device_mgr, 2, num_devices, num_devices,
		DEVICE_MANAGER_PA_ROT_MODE, DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE, 100000, 100000,
		100000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&testing->device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&testing->device_mgr, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0x42, 1);
	CuAssertIntEquals (test, 0, status);

	status = attestation_discover_tcg_init (discover, &testing->discover_state);
	CuAssertIntEquals (test, 0, status);

	testing->discover_list[0] = &discover->base;
	testing->discover_list[1] = NULL;

	status = attestation_requester_init (&testing->test, &testing->state, &testing->mctp,
		&testing->channel.base, &testing->primary_hash.base, &testing->secondary_hash.base,
		&testing->ecc.base, &testing->rsa.base, &testing->x509_mock.base, &testing->rng.base,
		&testing->riot, &testing->device_mgr, &testing->cfm_manager.base,
		testing->discover_list, 1, &testing->mctp_control.base, &testing->spdm_transport.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Common release function for attestation_discover_tcg tests.
 * Validates and releases all mocks.
 *
 * @param test The test framework.
 * @param testing The testing structure to release.
 */
static void attestation_discover_tcg_test_release (CuTest *test,
	struct attestation_discover_tcg_testing *testing)
{
	int status;

	status = msg_transport_mock_validate_and_release (&testing->mctp_control);
	CuAssertIntEquals (test, 0, status);

	status = msg_transport_mock_validate_and_release (&testing->spdm_transport);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&testing->device_mgr);
}

/**
 * Helper to register a device entry and bind it to a discovery handler.
 * Uses device_manager_update_component_device_entry which copies the full entry including discover.
 */
static int device_manager_update_device_entry (struct device_manager *mgr, int device_num,
	uint16_t pci_vid, uint16_t pci_device_id, uint16_t pci_subsystem_vid, uint16_t pci_subsystem_id,
	uint8_t components_count, uint32_t component_id, uint8_t pcd_component_index,
	const struct attestation_discover *discover)
{
	struct device_manager_entry entry = {0};

	entry.pci_vid = pci_vid;
	entry.pci_device_id = pci_device_id;
	entry.pci_subsystem_vid = pci_subsystem_vid;
	entry.pci_subsystem_id = pci_subsystem_id;
	entry.component_id = component_id;
	entry.pcd_component_index = pcd_component_index;
	entry.discover = discover;

	return device_manager_update_component_device_entry (mgr, device_num, components_count, &entry);
}


/*******************
 * Test cases
 *******************/

static void attestation_discover_tcg_test_init (CuTest *test)
{
	struct attestation_discover_tcg discover;
	struct attestation_discover_tcg_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_tcg_init (&discover, &discover_state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, discover.base.discover_device);
	CuAssertPtrNotNull (test, discover.base.get_device_eid_by_device_num);
}

static void attestation_discover_tcg_test_init_null (CuTest *test)
{
	struct attestation_discover_tcg discover;
	struct attestation_discover_tcg_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_tcg_init (NULL, &discover_state);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_discover_tcg_init (&discover, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
}

static void attestation_discover_tcg_test_static_init (CuTest *test)
{
	struct attestation_discover_tcg_state discover_state;
	struct attestation_discover_tcg discover =
		attestation_discover_tcg_static_init (&discover_state);

	TEST_START;

	CuAssertPtrNotNull (test, discover.base.discover_device);
	CuAssertPtrNotNull (test, discover.base.get_device_eid_by_device_num);
}

static void attestation_discover_tcg_test_get_device_eid_by_device_num_unsupported (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	struct attestation_discover_tcg_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_tcg_init (&discover, &discover_state);
	CuAssertIntEquals (test, 0, status);

	status = discover.base.get_device_eid_by_device_num (&discover.base, &testing.test, 0);
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_OPERATION, status);
}

static void attestation_discover_tcg_test_discover_device_null (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	struct attestation_discover_tcg_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_tcg_init (&discover, &discover_state);
	CuAssertIntEquals (test, 0, status);

	status = discover.base.discover_device (NULL, &testing.test);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = discover.base.discover_device (&discover.base, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
}

static void attestation_discover_tcg_test_discover_device_single_tcg_device (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	uint32_t component_id = 100;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 1);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0, 0, 0, 0, 1,
		component_id, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	/* Device starts as UNIDENTIFIED */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	discover.state->discovery_state = ATTESTATION_DISCOVERY_TRIGGERED;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	/* After TCG discovery, device should be NEVER_ATTESTED */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_discover_device_multiple_tcg_devices (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	uint32_t component_id = 100;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 3);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&testing.device_mgr, 3, 0xAA, 0xBB, 0xCC, 0xEE, 1,
		component_id + 1, 3, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&testing.device_mgr, 4, 0xAA, 0xBB, 0xCC, 0xFF, 1,
		component_id + 2, 4, &discover.base);
	CuAssertIntEquals (test, 0, status);

	discover.state->discovery_state = ATTESTATION_DISCOVERY_TRIGGERED;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	/* All three TCG devices should transition to NEVER_ATTESTED */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	status = device_manager_get_device_state (&testing.device_mgr, 3);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	status = device_manager_get_device_state (&testing.device_mgr, 4);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_discover_device_skips_non_unidentified (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	uint32_t component_id = 100;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 2);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&testing.device_mgr, 3, 0xAA, 0xBB, 0xCC, 0xEE, 1,
		component_id + 1, 3, &discover.base);
	CuAssertIntEquals (test, 0, status);

	/* Set device 2 to NEVER_ATTESTED (already discovered) */
	status = device_manager_update_device_state (&testing.device_mgr, 2,
		DEVICE_MANAGER_NEVER_ATTESTED);
	CuAssertIntEquals (test, 0, status);

	discover.state->discovery_state = ATTESTATION_DISCOVERY_TRIGGERED;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	/* Device 2 should remain NEVER_ATTESTED (not re-discovered) */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	/* Device 3 should transition to NEVER_ATTESTED */
	status = device_manager_get_device_state (&testing.device_mgr, 3);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_discover_device_skips_non_tcg_devices (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	struct attestation_discover_mctp mctp_discover;
	struct attestation_discover_mctp_state mctp_discover_state;
	uint32_t component_id = 100;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 2);

	/* Initialize an MCTP discovery handler */
	status = attestation_discover_mctp_init (&mctp_discover, &mctp_discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Device 2 uses TCG discovery */
	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	/* Device 3 uses MCTP discovery (not TCG) */
	status = device_manager_update_device_entry (&testing.device_mgr, 3, 0xAA, 0xBB, 0xCC, 0xEE, 1,
		component_id + 1, 3, &mctp_discover.base);
	CuAssertIntEquals (test, 0, status);

	discover.state->discovery_state = ATTESTATION_DISCOVERY_TRIGGERED;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	/* Only TCG device should transition */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	/* MCTP device should remain UNIDENTIFIED */
	status = device_manager_get_device_state (&testing.device_mgr, 3);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_discover_device_no_tcg_devices (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	struct attestation_discover_mctp mctp_discover;
	struct attestation_discover_mctp_state mctp_discover_state;
	uint32_t component_id = 100;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 1);

	status = attestation_discover_mctp_init (&mctp_discover, &mctp_discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Only MCTP device, no TCG devices */
	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 2, &mctp_discover.base);
	CuAssertIntEquals (test, 0, status);

	discover.state->discovery_state = ATTESTATION_DISCOVERY_TRIGGERED;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	/* MCTP device should remain UNIDENTIFIED */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_discover_device_no_attestable_devices (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 0);

	/* No attestable devices configured, only PA-ROT and BMC */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_TRIGGERED;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_discover_device_already_attested (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	uint32_t component_id = 100;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 1);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	/* Set device to AUTHENTICATED state */
	status = device_manager_update_device_state (&testing.device_mgr, 2,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	discover.state->discovery_state = ATTESTATION_DISCOVERY_TRIGGERED;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	/* Device should remain AUTHENTICATED (not re-discovered) */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	attestation_discover_tcg_test_release (test, &testing);
}


static void attestation_discover_tcg_test_discover_device_idle_state (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	uint32_t component_id = 100;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 1);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	/* discovery_state is IDLE after init - discover should return 0 without discovering */
	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	/* Device should remain UNIDENTIFIED */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_discover_device_complete_state (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	uint32_t component_id = 100;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 1);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	/* Set discovery_state to COMPLETE - should skip discovery */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_COMPLETE;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	/* Device should remain UNIDENTIFIED */
	status = device_manager_get_device_state (&testing.device_mgr, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_timer_callback (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	struct attestation_discover_tcg_timer_context context;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 0);

	context.attestation = &testing.test;
	context.tcg_discover = &discover;

	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_IDLE, discover.state->discovery_state);

	attestation_discover_tcg_timer_callback (&context);

	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_TRIGGERED, discover.state->discovery_state);

	attestation_discover_tcg_test_release (test, &testing);
}

static void attestation_discover_tcg_test_timer_callback_null (CuTest *test)
{
	TEST_START;

	/* Should not crash with NULL context */
	attestation_discover_tcg_timer_callback (NULL);
}

static void attestation_discover_tcg_test_timer_callback_null_members (CuTest *test)
{
	struct attestation_discover_tcg_timer_context context;

	TEST_START;

	context.attestation = NULL;
	context.tcg_discover = NULL;

	/* Should not crash with NULL members */
	attestation_discover_tcg_timer_callback (&context);
}

static void attestation_discover_tcg_test_start_timer_null (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	struct attestation_discover_tcg_state discover_state;
	struct attestation_discover_tcg_timer_context context;
	platform_timer timer;
	int status;

	TEST_START;

	status = attestation_discover_tcg_init (&discover, &discover_state);
	CuAssertIntEquals (test, 0, status);

	status = attestation_discover_tcg_start_timer (NULL, &context, &testing.test, &discover, 1000);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_discover_tcg_start_timer (&timer, NULL, &testing.test, &discover, 1000);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_discover_tcg_start_timer (&timer, &context, NULL, &discover, 1000);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_discover_tcg_start_timer (&timer, &context, &testing.test, NULL, 1000);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
}

static void attestation_discover_tcg_test_start_timer_success (CuTest *test)
{
	struct attestation_discover_tcg_testing testing;
	struct attestation_discover_tcg discover;
	struct attestation_discover_tcg_timer_context context;
	platform_timer timer;
	int status;

	TEST_START;

	attestation_discover_tcg_test_setup (test, &testing, &discover, 0);

	status = attestation_discover_tcg_start_timer (&timer, &context, &testing.test, &discover,
		5000);
	CuAssertIntEquals (test, 0, status);

	/* Verify context was initialized correctly */
	CuAssertPtrEquals (test, &testing.test, (void*) context.attestation);
	CuAssertPtrEquals (test, &discover, context.tcg_discover);

	platform_timer_delete (&timer);
	attestation_discover_tcg_test_release (test, &testing);
}


/* INDENT-OFF */
TEST_SUITE_START (attestation_discover_tcg);

TEST (attestation_discover_tcg_test_init);
TEST (attestation_discover_tcg_test_init_null);
TEST (attestation_discover_tcg_test_static_init);
TEST (attestation_discover_tcg_test_get_device_eid_by_device_num_unsupported);
TEST (attestation_discover_tcg_test_discover_device_null);
TEST (attestation_discover_tcg_test_discover_device_idle_state);
TEST (attestation_discover_tcg_test_discover_device_complete_state);
TEST (attestation_discover_tcg_test_discover_device_single_tcg_device);
TEST (attestation_discover_tcg_test_discover_device_multiple_tcg_devices);
TEST (attestation_discover_tcg_test_discover_device_skips_non_unidentified);
TEST (attestation_discover_tcg_test_discover_device_skips_non_tcg_devices);
TEST (attestation_discover_tcg_test_discover_device_no_tcg_devices);
TEST (attestation_discover_tcg_test_discover_device_no_attestable_devices);
TEST (attestation_discover_tcg_test_discover_device_already_attested);
TEST (attestation_discover_tcg_test_timer_callback);
TEST (attestation_discover_tcg_test_timer_callback_null);
TEST (attestation_discover_tcg_test_timer_callback_null_members);
TEST (attestation_discover_tcg_test_start_timer_null);
TEST (attestation_discover_tcg_test_start_timer_success);

TEST_SUITE_END;
/* INDENT-ON */
