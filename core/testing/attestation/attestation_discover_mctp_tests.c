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
#include "attestation/attestation_discover_mctp_static.h"
#include "attestation/attestation_logging.h"
#include "attestation/pcr_store.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/msg_transport.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_control_protocol_commands.h"
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


TEST_SUITE_LABEL ("attestation_discover_mctp");

struct attestation_discover_mctp_testing {
	struct attestation_requester test;
	struct attestation_requester_state state;
	struct attestation_discover_mctp_state discover_state;
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
 * Common setup function for attestation_discover_mctp tests.
 * Initializes all required mocks, device manager, and attestation components.
 *
 * @param test The test framework.
 * @param testing The testing structure to initialize.
 * @param discover The discover structure to initialize.
 * @param num_devices Number of attestable devices to initialize in device manager.
 */
static void attestation_discover_mctp_test_setup (CuTest *test,
	struct attestation_discover_mctp_testing *testing, struct attestation_discover_mctp *discover,
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

	status = attestation_discover_mctp_init (discover, &testing->discover_state, NULL);
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
 * Common release function for attestation_discover_mctp tests.
 * Validates and releases all mocks.
 *
 * @param test The test framework.
 * @param testing The testing structure to release.
 */
static void attestation_discover_mctp_test_release (CuTest *test,
	struct attestation_discover_mctp_testing *testing)
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

static void attestation_discover_mctp_test_init (CuTest *test)
{
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (&discover, &discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, discover.base.discover_device);
	CuAssertPtrNotNull (test, discover.base.get_device_eid_by_device_num);
}

static void attestation_discover_mctp_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (NULL, NULL, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
}

static void attestation_discover_mctp_test_static_init (CuTest *test)
{
	struct attestation_discover_mctp_state discover_state;
	struct attestation_discover_mctp discover =
		attestation_discover_mctp_static_init (&discover_state, NULL);

	TEST_START;

	CuAssertPtrNotNull (test, discover.base.discover_device);
	CuAssertPtrNotNull (test, discover.base.get_device_eid_by_device_num);
}

static void attestation_discover_mctp_test_get_device_eid_by_device_num (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		100, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&testing.device_mgr, 2, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = discover.base.get_device_eid_by_device_num (&discover.base, &testing.test, 2);
	CuAssertIntEquals (test, 0x0A, status);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_get_device_eid_by_device_num_null_attestation (
	CuTest *test)
{
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (&discover, &discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	status = discover.base.get_device_eid_by_device_num (&discover.base, NULL, 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
}

static void attestation_discover_mctp_test_get_device_eid_by_device_num_invalid_device (
	CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	/* Query a device number that doesn't exist */
	status = discover.base.get_device_eid_by_device_num (&discover.base, &testing.test, 99);
	CuAssertTrue (test, ROT_IS_ERROR (status));

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_null (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (&discover, &discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	status = discover.base.discover_device (NULL, &testing.test);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = discover.base.discover_device (&discover.base, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
}

static void attestation_discover_mctp_test_discover_device_null_device_mgr (CuTest *test)
{
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_state discover_state;
	struct attestation_requester attestation;
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (&discover, &discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	memset (&attestation, 0, sizeof (attestation));
	attestation.device_mgr = NULL;

	status = discover.base.discover_device (&discover.base, &attestation);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
}

static void attestation_discover_mctp_test_discover_device_no_devices_available (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 0);

	/* With no attestable devices, discover should complete with no errors */
	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_get_device_eid_by_device_num_multiple_devices (
	CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 3);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		100, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&testing.device_mgr, 2, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&testing.device_mgr, 3, 0xAA, 0xBB, 0xCC, 0xEE, 1,
		101, 3, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&testing.device_mgr, 3, 0x0B);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&testing.device_mgr, 4, 0xAA, 0xBB, 0xCC, 0xFF, 1,
		102, 4, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&testing.device_mgr, 4, 0x0C);
	CuAssertIntEquals (test, 0, status);

	/* Verify EID resolution for each device */
	status = discover.base.get_device_eid_by_device_num (&discover.base, &testing.test, 2);
	CuAssertIntEquals (test, 0x0A, status);

	status = discover.base.get_device_eid_by_device_num (&discover.base, &testing.test, 3);
	CuAssertIntEquals (test, 0x0B, status);

	status = discover.base.get_device_eid_by_device_num (&discover.base, &testing.test, 4);
	CuAssertIntEquals (test, 0x0C, status);

	attestation_discover_mctp_test_release (test, &testing);
}


static void attestation_discover_mctp_test_on_set_eid_request (CuTest *test)
{
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (&discover, &discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_IDLE, discover.state->discovery_state);
	CuAssertIntEquals (test, false, discover.state->routing_table_dirty);

	attestation_requester_on_mctp_set_eid_request (&discover.mctp_rsp_observer);

	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST,
		discover.state->discovery_state);
	CuAssertIntEquals (test, true, discover.state->routing_table_dirty);
}

static void attestation_discover_mctp_test_refresh_routing_table_null (CuTest *test)
{
	TEST_START;

	/* Should not crash with NULL context */
	attestation_discover_mctp_refresh_routing_table (NULL);
}

static void attestation_discover_mctp_test_refresh_routing_table_null_members (CuTest *test)
{
	struct attestation_discover_mctp_refresh_context context;

	TEST_START;

	context.attestation = NULL;
	context.mctp_discover = NULL;

	/* Should not crash with NULL members */
	attestation_discover_mctp_refresh_routing_table (&context);
}

static void attestation_discover_mctp_test_refresh_routing_table_bridge_not_waiting (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_refresh_context context;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 0);

	context.attestation = &testing.test;
	context.mctp_discover = &discover;

	/* discovery_state is not IDLE - refresh should be a no-op */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;

	attestation_discover_mctp_refresh_routing_table (&context);

	/* State should not change to REQUIRED_REFRESH since Set EID already triggered */
	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST,
		discover.state->discovery_state);
	CuAssertIntEquals (test, false, discover.state->routing_table_dirty);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_refresh_routing_table_bridge_waiting (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_refresh_context context;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 0);

	context.attestation = &testing.test;
	context.mctp_discover = &discover;

	/* discovery_state is IDLE (waiting for bridge) - refresh should trigger */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_IDLE;

	attestation_discover_mctp_refresh_routing_table (&context);

	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_REQUIRED_REFRESH,
		discover.state->discovery_state);
	CuAssertIntEquals (test, true, discover.state->routing_table_dirty);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_complete_state (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 0);

	/* Set discovery_state to COMPLETE - should skip discovery */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_COMPLETE;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_bridge_wait (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 0);

	/* discovery_state is IDLE (bridge not ready) - should return 0 without discovering */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_IDLE;

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_start_timer_null (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_state discover_state;
	struct attestation_discover_mctp_refresh_context context;
	platform_timer timer;
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (&discover, &discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	status = attestation_discover_mctp_start_timer (NULL, &context, &testing.test, &discover, 1000);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_discover_mctp_start_timer (&timer, NULL, &testing.test, &discover, 1000);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_discover_mctp_start_timer (&timer, &context, NULL, &discover, 1000);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_discover_mctp_start_timer (&timer, &context, &testing.test, NULL, 1000);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
}

static void attestation_discover_mctp_test_start_timer_success (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_refresh_context context;
	platform_timer timer;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 0);

	status = attestation_discover_mctp_start_timer (&timer, &context, &testing.test, &discover,
		5000);
	CuAssertIntEquals (test, 0, status);

	/* Verify context was initialized correctly */
	CuAssertPtrEquals (test, &testing.test, (void*) context.attestation);
	CuAssertPtrEquals (test, &discover, context.mctp_discover);

	platform_timer_delete (&timer);
	attestation_discover_mctp_test_release (test, &testing);
}

/**
 * Helper to set up mock expectations for a Get Routing Table Entries request/response.
 * The bridge is device 1 (EID = MCTP_BASE_PROTOCOL_BMC_EID = 0x0A).
 *
 * @param test The test framework.
 * @param testing Testing instances.
 * @param entry_handle The entry handle to send in the request.
 * @param num_entries Number of routing entries in the response.
 * @param starting_eids Array of starting EIDs for entries.
 * @param eid_range_sizes Array of EID range sizes for entries.
 * @param next_entry_handle Next entry handle in response (0xFF = last page).
 * @param send_fail If true, mock send_request_message to return timeout error.
 */
static void attestation_discover_mctp_testing_send_and_receive_get_routing_table (
	CuTest *test, struct attestation_discover_mctp_testing *testing, uint8_t entry_handle,
	uint8_t num_entries, const uint8_t *starting_eids, const uint8_t *eid_range_sizes,
	uint8_t next_entry_handle, bool send_fail)
{
	struct cmd_interface_msg *req_expected = NULL;
	struct cmd_interface_msg *resp_expected = NULL;
	struct mctp_control_get_routing_table_entries *request;
	struct mctp_control_get_routing_table_entries_response *response;
	struct mctp_control_routing_table_entry *entry;
	uint8_t *tx_message = NULL;
	uint8_t *rx_message = NULL;
	uint8_t dest_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	uint32_t timeout = device_manager_get_mctp_ctrl_timeout (&testing->device_mgr);
	int status;
	uint8_t i;

	/* Request construction */
	tx_message = platform_calloc (1, sizeof (struct mctp_control_get_routing_table_entries));
	req_expected = platform_calloc (1, sizeof (struct cmd_interface_msg));
	req_expected->data = tx_message;
	req_expected->length = sizeof (struct mctp_control_get_routing_table_entries);
	req_expected->max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN;
	req_expected->payload = tx_message;
	req_expected->payload_length = sizeof (struct mctp_control_get_routing_table_entries);
	req_expected->target_eid = dest_eid;

	request = (struct mctp_control_get_routing_table_entries*) req_expected->payload;
	request->header.command_code = MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES;
	request->header.rq = 1;
	request->entry_handle = entry_handle;

	status = mock_expect (&testing->mctp_control.mock,
		testing->mctp_control.base.get_buffer_overhead, &testing->mctp_control, 0,
		MOCK_ARG (dest_eid), MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing->mctp_control.mock,
		testing->mctp_control.base.get_max_message_payload_length, &testing->mctp_control,
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN, MOCK_ARG (dest_eid));
	CuAssertIntEquals (test, 0, status);

	if (send_fail) {
		status = mock_expect (&testing->mctp_control.mock,
			testing->mctp_control.base.send_request_message, &testing->mctp_control.base,
			MSG_TRANSPORT_REQUEST_TIMEOUT,
			MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, req_expected,
			sizeof (*req_expected), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request, cmd_interface_mock_duplicate_request),
			MOCK_ARG (timeout), MOCK_ARG_NOT_NULL);
		CuAssertIntEquals (test, 0, status);

		cmd_interface_mock_free_request (req_expected);

		return;
	}

	/* Response construction */
	rx_message = platform_calloc (1,
		sizeof (struct mctp_control_get_routing_table_entries_response) +
		sizeof (struct mctp_control_routing_table_entry) * num_entries);
	resp_expected = platform_calloc (1, sizeof (struct cmd_interface_msg));
	resp_expected->data = rx_message;
	resp_expected->payload = rx_message;
	resp_expected->target_eid = dest_eid;
	resp_expected->max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN;

	response = (struct mctp_control_get_routing_table_entries_response*) resp_expected->payload;
	response->header.header.command_code = MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES;
	response->header.completion_code = 0;
	response->num_entries = num_entries;
	response->next_entry_handle = next_entry_handle;

	entry = mctp_control_get_routing_table_entries_response_get_entries (response);
	for (i = 0; i < num_entries; ++i) {
		entry[i].starting_eid = starting_eids[i];
		entry[i].eid_range_size = eid_range_sizes[i];
	}

	resp_expected->payload_length =
		sizeof (*response) + num_entries * sizeof (struct mctp_control_routing_table_entry);
	resp_expected->length = resp_expected->payload_length;

	status = mock_expect (&testing->mctp_control.mock,
		testing->mctp_control.base.send_request_message, &testing->mctp_control.base, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, req_expected,
		sizeof (*req_expected), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request), MOCK_ARG (timeout), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect_output_deep_copy_tmp (&testing->mctp_control.mock, 2, resp_expected,
		sizeof (*resp_expected), cmd_interface_mock_copy_request,
		cmd_interface_mock_duplicate_request, cmd_interface_mock_free_request);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_mock_free_request (req_expected);
	cmd_interface_mock_free_request (resp_expected);
}

/**
 * Helper to set up mock expectations for a Get Message Type request/response.
 *
 * @param test The test framework.
 * @param testing Testing instances.
 * @param eid EID of the device to query.
 * @param spdm_supported If true, include SPDM in response message types.
 * @param cerberus_supported If true, include Cerberus (vendor def) in response message types.
 * @param send_fail If true, mock send_request_message to return timeout error.
 */
static void attestation_discover_mctp_testing_send_and_receive_get_message_type (
	CuTest *test, struct attestation_discover_mctp_testing *testing, uint8_t eid,
	bool spdm_supported, bool cerberus_supported, bool send_fail)
{
	struct cmd_interface_msg *req_expected = NULL;
	struct cmd_interface_msg *resp_expected = NULL;
	struct mctp_control_get_message_type *request;
	struct mctp_control_get_message_type_response *response;
	uint8_t *tx_message = NULL;
	uint8_t *rx_message = NULL;
	uint32_t timeout = device_manager_get_mctp_ctrl_timeout (&testing->device_mgr);
	int status;
	size_t offset;

	/* Request construction */
	tx_message = platform_calloc (1, sizeof (struct mctp_control_get_message_type));
	req_expected = platform_calloc (1, sizeof (struct cmd_interface_msg));
	req_expected->data = tx_message;
	req_expected->length = sizeof (struct mctp_control_get_message_type);
	req_expected->max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN;
	req_expected->payload = tx_message;
	req_expected->payload_length = sizeof (struct mctp_control_get_message_type);
	req_expected->target_eid = eid;

	request = (struct mctp_control_get_message_type*) req_expected->payload;
	request->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;
	request->header.rq = 1;

	status = mock_expect (&testing->mctp_control.mock,
		testing->mctp_control.base.get_buffer_overhead, &testing->mctp_control, 0, MOCK_ARG (eid),
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing->mctp_control.mock,
		testing->mctp_control.base.get_max_message_payload_length, &testing->mctp_control,
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN, MOCK_ARG (eid));
	CuAssertIntEquals (test, 0, status);

	if (send_fail) {
		status = mock_expect (&testing->mctp_control.mock,
			testing->mctp_control.base.send_request_message, &testing->mctp_control.base,
			MSG_TRANSPORT_REQUEST_TIMEOUT,
			MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, req_expected,
			sizeof (*req_expected), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request, cmd_interface_mock_duplicate_request),
			MOCK_ARG (timeout), MOCK_ARG_NOT_NULL);
		CuAssertIntEquals (test, 0, status);

		cmd_interface_mock_free_request (req_expected);

		return;
	}

	/* Response construction */
	rx_message = platform_calloc (1,
		sizeof (struct mctp_control_get_message_type_response) + 1 + spdm_supported +
		cerberus_supported);
	resp_expected = platform_calloc (1, sizeof (struct cmd_interface_msg));
	resp_expected->data = rx_message;
	resp_expected->payload = rx_message;
	resp_expected->target_eid = eid;
	resp_expected->max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN;

	response = (struct mctp_control_get_message_type_response*) resp_expected->payload;
	response->header.header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;
	response->header.completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	response->message_type_count = 1 + spdm_supported + cerberus_supported;
	offset = sizeof (struct mctp_control_get_message_type_response);

	resp_expected->payload[offset++] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;

	if (cerberus_supported) {
		resp_expected->payload[offset++] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	}

	if (spdm_supported) {
		resp_expected->payload[offset++] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	}

	resp_expected->payload_length = offset;
	resp_expected->length = resp_expected->payload_length;

	status = mock_expect (&testing->mctp_control.mock,
		testing->mctp_control.base.send_request_message, &testing->mctp_control.base, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, req_expected,
		sizeof (*req_expected), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request), MOCK_ARG (timeout), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect_output_deep_copy_tmp (&testing->mctp_control.mock, 2, resp_expected,
		sizeof (*resp_expected), cmd_interface_mock_copy_request,
		cmd_interface_mock_duplicate_request, cmd_interface_mock_free_request);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_mock_free_request (req_expected);
	cmd_interface_mock_free_request (resp_expected);
}

static void attestation_discover_mctp_test_discover_device_routing_table_fetch_failure (
	CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	/* Set state to trigger routing table fetch */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	discover.state->routing_table_dirty = true;

	/* Mock routing table request that fails (timeout) */
	attestation_discover_mctp_testing_send_and_receive_get_routing_table (test, &testing, 0, 0,
		NULL, NULL, 0xFF, true);

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertTrue (test, (status != 0));

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_routing_table_no_devices (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	/* Set state to trigger routing table fetch */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	discover.state->routing_table_dirty = true;

	/* Mock routing table returns only the unattestable device EIDs (0x0B = PA_ROT_CTRL_EID) */
	{
		uint8_t starting_eids[] = {MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID};
		uint8_t eid_range_sizes[] = {1};

		attestation_discover_mctp_testing_send_and_receive_get_routing_table (test, &testing, 0, 1,
			starting_eids, eid_range_sizes, 0xFF, false);
	}

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_COMPLETE, discover.state->discovery_state);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_identify_timeout (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	/* Bypass routing table - directly add device to unidentified list */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	discover.state->routing_table_dirty = false;

	status = device_manager_restart_device_discovery (&testing.device_mgr);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&testing.device_mgr, 0xAA);
	CuAssertIntEquals (test, 0, status);

	/* Mock Get Message Type for device 0xAA - fails with timeout */
	attestation_discover_mctp_testing_send_and_receive_get_message_type (test, &testing, 0xAA,
		false, false, true);

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_COMPLETE, discover.state->discovery_state);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_routing_table_multiple_entries (
	CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	/* Bypass routing table - directly add multiple devices to unidentified list */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	discover.state->routing_table_dirty = false;

	status = device_manager_restart_device_discovery (&testing.device_mgr);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&testing.device_mgr, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&testing.device_mgr, 0xBB);
	CuAssertIntEquals (test, 0, status);

	/* Mock Get Message Type for device 0xAA - timeout (identify fails) */
	attestation_discover_mctp_testing_send_and_receive_get_message_type (test, &testing, 0xAA,
		false, false, true);

	/* Mock Get Message Type for device 0xBB - timeout (identify fails) */
	attestation_discover_mctp_testing_send_and_receive_get_message_type (test, &testing, 0xBB,
		false, false, true);

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_COMPLETE, discover.state->discovery_state);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_routing_table_eid_range (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	/* Bypass routing table - add EID range (0xAA, 0xAB) directly */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	discover.state->routing_table_dirty = false;

	status = device_manager_restart_device_discovery (&testing.device_mgr);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&testing.device_mgr, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&testing.device_mgr, 0xAB);
	CuAssertIntEquals (test, 0, status);

	/* Mock Get Message Type for device 0xAA - timeout */
	attestation_discover_mctp_testing_send_and_receive_get_message_type (test, &testing, 0xAA,
		false, false, true);

	/* Mock Get Message Type for device 0xAB - timeout */
	attestation_discover_mctp_testing_send_and_receive_get_message_type (test, &testing, 0xAB,
		false, false, true);

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_COMPLETE, discover.state->discovery_state);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_routing_table_multi_page (CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	/* Set state to trigger routing table fetch with multi-page response */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	discover.state->routing_table_dirty = true;

	/* First page: entry_handle=0, next_entry_handle=1, unattestable device */
	{
		uint8_t starting_eids[] = {MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID};
		uint8_t eid_range_sizes[] = {1};

		attestation_discover_mctp_testing_send_and_receive_get_routing_table (test, &testing, 0, 1,
			starting_eids, eid_range_sizes, 1, false);
	}

	/* Second page: entry_handle=1, next_entry_handle=0xFF (last), unattestable device */
	{
		uint8_t starting_eids[] = {MCTP_BASE_PROTOCOL_BMC_EID};
		uint8_t eid_range_sizes[] = {1};

		attestation_discover_mctp_testing_send_and_receive_get_routing_table (test, &testing, 1, 1,
			starting_eids, eid_range_sizes, 0xFF, false);
	}

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_COMPLETE, discover.state->discovery_state);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_get_device_eid_by_device_num_routing_table_dirty (
	CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		100, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&testing.device_mgr, 2, 0x0C);
	CuAssertIntEquals (test, 0, status);

	/* Mark routing table dirty */
	discover.state->routing_table_dirty = true;

	/* Mock routing table fetch (empty - only unattestable devices) */
	{
		uint8_t starting_eids[] = {MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID};
		uint8_t eid_range_sizes[] = {1};

		attestation_discover_mctp_testing_send_and_receive_get_routing_table (test, &testing, 0, 1,
			starting_eids, eid_range_sizes, 0xFF, false);
	}

	/* When routing table is dirty, should sync and return ATTESTATION_REFRESH_ROUTING_TABLE */
	status = discover.base.get_device_eid_by_device_num (&discover.base, &testing.test, 2);
	CuAssertIntEquals (test, ATTESTATION_REFRESH_ROUTING_TABLE, status);

	/* After sync, routing_table_dirty should be cleared */
	CuAssertIntEquals (test, false, discover.state->routing_table_dirty);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_get_device_eid_by_device_num_routing_table_dirty_fail (
	CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		100, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	/* Mark routing table dirty */
	discover.state->routing_table_dirty = true;

	/* Mock routing table fetch fails */
	attestation_discover_mctp_testing_send_and_receive_get_routing_table (test, &testing, 0, 0,
		NULL, NULL, 0xFF, true);

	/* When routing table sync fails, should return error */
	status = discover.base.get_device_eid_by_device_num (&discover.base, &testing.test, 2);
	CuAssertTrue (test, ROT_IS_ERROR (status));

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_discover_device_identify_no_spdm_no_cerberus (
	CuTest *test)
{
	struct attestation_discover_mctp_testing testing;
	struct attestation_discover_mctp discover;
	int status;

	TEST_START;

	attestation_discover_mctp_test_setup (test, &testing, &discover, 1);

	/* Register device entry with EID 0xAA so component_id lookup succeeds after identify */
	status = device_manager_update_device_entry (&testing.device_mgr, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		100, 2, &discover.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&testing.device_mgr, 2, 0xAA);
	CuAssertIntEquals (test, 0, status);

	/* Bypass routing table - directly add device to unidentified list */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	discover.state->routing_table_dirty = false;

	status = device_manager_restart_device_discovery (&testing.device_mgr);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&testing.device_mgr, 0xAA);
	CuAssertIntEquals (test, 0, status);

	/* Mock Get Message Type for device 0xAA - returns only MCTP control (no SPDM, no Cerberus) */
	attestation_discover_mctp_testing_send_and_receive_get_message_type (test, &testing, 0xAA,
		false, false, false);

	status = discover.base.discover_device (&discover.base, &testing.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_COMPLETE, discover.state->discovery_state);

	attestation_discover_mctp_test_release (test, &testing);
}

static void attestation_discover_mctp_test_on_set_eid_request_already_in_progress (CuTest *test)
{
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (&discover, &discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Move to COMPLETE state, then verify Set EID still updates state */
	discover.state->discovery_state = ATTESTATION_DISCOVERY_COMPLETE;
	discover.state->routing_table_dirty = false;

	attestation_requester_on_mctp_set_eid_request (&discover.mctp_rsp_observer);

	CuAssertIntEquals (test, ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST,
		discover.state->discovery_state);
	CuAssertIntEquals (test, true, discover.state->routing_table_dirty);
}

static void attestation_discover_mctp_test_release_valid (CuTest *test)
{
	struct attestation_discover_mctp discover;
	struct attestation_discover_mctp_state discover_state;
	int status;

	TEST_START;

	status = attestation_discover_mctp_init (&discover, &discover_state, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Release should not crash */
	attestation_discover_mctp_release (&discover);
}

static void attestation_discover_mctp_test_release_null (CuTest *test)
{
	TEST_START;

	/* Release null should not crash */
	attestation_discover_mctp_release (NULL);
}


/* INDENT-OFF */
TEST_SUITE_START (attestation_discover_mctp);

TEST (attestation_discover_mctp_test_init);
TEST (attestation_discover_mctp_test_init_null);
TEST (attestation_discover_mctp_test_static_init);
TEST (attestation_discover_mctp_test_on_set_eid_request);
TEST (attestation_discover_mctp_test_refresh_routing_table_null);
TEST (attestation_discover_mctp_test_refresh_routing_table_null_members);
TEST (attestation_discover_mctp_test_refresh_routing_table_bridge_not_waiting);
TEST (attestation_discover_mctp_test_refresh_routing_table_bridge_waiting);
TEST (attestation_discover_mctp_test_get_device_eid_by_device_num);
TEST (attestation_discover_mctp_test_get_device_eid_by_device_num_null_attestation);
TEST (attestation_discover_mctp_test_get_device_eid_by_device_num_invalid_device);
TEST (attestation_discover_mctp_test_discover_device_null);
TEST (attestation_discover_mctp_test_discover_device_null_device_mgr);
TEST (attestation_discover_mctp_test_discover_device_complete_state);
TEST (attestation_discover_mctp_test_discover_device_bridge_wait);
TEST (attestation_discover_mctp_test_discover_device_no_devices_available);
TEST (attestation_discover_mctp_test_get_device_eid_by_device_num_multiple_devices);
TEST (attestation_discover_mctp_test_start_timer_null);
TEST (attestation_discover_mctp_test_start_timer_success);
TEST (attestation_discover_mctp_test_discover_device_routing_table_fetch_failure);
TEST (attestation_discover_mctp_test_discover_device_routing_table_no_devices);
TEST (attestation_discover_mctp_test_discover_device_identify_timeout);
TEST (attestation_discover_mctp_test_discover_device_routing_table_multiple_entries);
TEST (attestation_discover_mctp_test_discover_device_routing_table_eid_range);
TEST (attestation_discover_mctp_test_discover_device_routing_table_multi_page);
TEST (attestation_discover_mctp_test_get_device_eid_by_device_num_routing_table_dirty);
TEST (attestation_discover_mctp_test_get_device_eid_by_device_num_routing_table_dirty_fail);
TEST (attestation_discover_mctp_test_discover_device_identify_no_spdm_no_cerberus);
TEST (attestation_discover_mctp_test_on_set_eid_request_already_in_progress);
TEST (attestation_discover_mctp_test_release_valid);
TEST (attestation_discover_mctp_test_release_null);

TEST_SUITE_END;
/* INDENT-ON */
