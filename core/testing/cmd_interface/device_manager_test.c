// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "cmd_interface/device_manager.h"
#include "mctp/mctp_base_protocol.h"
#include "testing/crypto/x509_testing.h"
#include "testing/mock/crypto/hash_mock.h"


TEST_SUITE_LABEL ("device_manager");


/*******************
 * Test cases
 *******************/

static void device_manager_test_init (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (NULL, 1, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 1, 0, NUM_BUS_HIERACHY_ROLES,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		NUM_BUS_ROLES, 1000, 1000, 1000);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_release_null (CuTest *test)
{
	device_manager_release (NULL);
}

static void device_manager_test_get_device_capabilities (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities expected;
	struct device_manager_full_capabilities out;
	int status;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	expected.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	expected.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	expected.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	expected.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	expected.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities (&manager, 0, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_capabilities_master_pa_rot (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities expected;
	struct device_manager_full_capabilities out;
	int status;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	expected.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	expected.request.bus_role = DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE;
	expected.request.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;
	expected.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	expected.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities (&manager, 0, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_capabilities_null (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities out;
	int status;

	TEST_START;

	status = device_manager_get_device_capabilities (NULL, 0, &out);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_capabilities (&manager, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_capabilities_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities out;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (&manager, 2, &out);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities expected;
	struct device_manager_full_capabilities out;
	int status;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.request.max_message_size = 50;
	expected.request.max_packet_size = 10;
	expected.request.security_mode = DEVICE_MANAGER_SECURITY_CONFIDENTIALITY;
	expected.request.bus_role = DEVICE_MANAGER_MASTER_BUS_ROLE;
	expected.request.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;
	expected.max_timeout = 100;
	expected.max_sig = 200;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &expected);
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities (&manager, 0, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities expected;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (NULL, 0, &expected);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_device_capabilities (&manager, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities expected;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 2, &expected);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_capabilities_request (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities expected;
	struct device_manager_capabilities out;
	int status;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	expected.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	expected.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	expected.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities_request (&manager, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_capabilities_request_null (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities out;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities_request (NULL, &out);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_capabilities_request (&manager, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities_request (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities expected;
	struct device_manager_capabilities out;
	int status;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.max_message_size = 50;
	expected.max_packet_size = 10;
	expected.security_mode = DEVICE_MANAGER_SECURITY_CONFIDENTIALITY;
	expected.bus_role = DEVICE_MANAGER_MASTER_BUS_ROLE;
	expected.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities_request (&manager, 0, &expected);
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities_request (&manager, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities_request_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities expected;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities_request (NULL, 0, &expected);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_device_capabilities_request (&manager, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities_request_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities expected;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities_request (&manager, 2, &expected);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB,	0xAA, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (NULL, 0, 0, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 2, 0, 0, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_mctp_bridge_device_entry (CuTest *test)
{
	struct device_manager manager;
	uint8_t component_type[SHA256_HASH_LENGTH];
	const uint8_t *device_component_type;
	size_t i_type;
	int status;

	for (i_type = 0; i_type < sizeof (component_type); ++i_type) {
		component_type[i_type] = i_type;
	}

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 0, 0xBB,	0xAA, 0xCC, 0xDD,
		2, component_type, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0xBB, 0xAA, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 0, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	device_component_type = device_manager_get_component_type_digest (&manager, 0x0C);
	CuAssertPtrNotNull (test, device_component_type);

	status = testing_validate_array (component_type, device_component_type,
		sizeof (component_type));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0xBB, 0xAA, 0xCC, 0xDD);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_device_eid (&manager, 1, 0x0D);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	device_component_type = device_manager_get_component_type_digest (&manager, 0x0C);
	CuAssertPtrNotNull (test, device_component_type);

	status = testing_validate_array (component_type, device_component_type,
		sizeof (component_type));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_mctp_bridge_device_entry_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint8_t component_type[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (NULL, 0, 0xBB,	0xAA, 0xCC, 0xDD,
		2, component_type, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 0, 0xBB,	0xAA, 0xCC, 0xDD,
		0, component_type, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 0, 0xBB,	0xAA, 0xCC, 0xDD,
		2, NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_mctp_bridge_device_entry_invalid_device (CuTest *test)
{
	struct device_manager manager;
	uint8_t component_type[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 2, 0xBB,	0xAA, 0xCC, 0xDD,
		1, component_type, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_mctp_bridge_device_entry_too_many_components (CuTest *test)
{
	struct device_manager manager;
	uint8_t component_type[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xBB,	0xAA, 0xCC, 0xDD,
		2, component_type, 1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_addr (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_addr_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr_by_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB,	0xAA, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr_by_eid (&manager, 0xBB);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr_by_eid_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_addr_by_eid (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_addr_by_eid_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_eid_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_eid (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_eid_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (NULL, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_device_state (&manager, 0, NUM_DEVICE_MANAGER_STATES);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_by_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 0, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state_by_eid (&manager, 0xAA,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_by_eid_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state_by_eid (NULL, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_device_state_by_eid (&manager, 0, NUM_DEVICE_MANAGER_STATES);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_by_eid_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state_by_eid (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_state_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_state (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_state_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_state_by_eid_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_state_by_eid (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_state_by_eid_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA,	0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num (&manager, 0xCC);
	CuAssertIntEquals (test, 1, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_num (NULL, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_num_invalid_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA,	0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num (&manager, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_resize_entries_table_add_entries (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities expected;
	struct device_manager_full_capabilities out;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t key[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key* temp_key;
	int status;

	memset (digest, 0xAA, sizeof (digest));
	memset (key, 0xBB, sizeof (key));

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	expected.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	expected.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	expected.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	expected.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	expected.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 1, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB,	0xAA, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xBB, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xBB, key, sizeof (key), 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_resize_entries_table (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xBB, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	temp_key = device_manager_get_alias_key (&manager, 0xBB);
	CuAssertPtrNotNull (test, temp_key);
	CuAssertIntEquals (test, sizeof (key), temp_key->key_len);
	CuAssertIntEquals (test, 0xEE, temp_key->key_type);

	status = testing_validate_array (key, temp_key->key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities (&manager, 0, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_resize_entries_table_remove_entries (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities expected;
	struct device_manager_full_capabilities out;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t key[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key* temp_key;
	int status;

	memset (digest, 0xAA, sizeof (digest));
	memset (key, 0xBB, sizeof (key));

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	expected.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	expected.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	expected.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	expected.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	expected.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB, 0xAA, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xBB, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xBB, key, sizeof (key), 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_resize_entries_table (&manager, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xBB, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	temp_key = device_manager_get_alias_key (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, temp_key->key);
	CuAssertIntEquals (test, sizeof (key), temp_key->key_len);
	CuAssertIntEquals (test, 0xEE, temp_key->key_type);

	status = testing_validate_array (key, temp_key->key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities (&manager, 0, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_resize_entries_table_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_resize_entries_table (NULL, 1);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_resize_entries_table (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_resize_entries_table_same_size (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities expected;
	struct device_manager_full_capabilities expected2;
	struct device_manager_full_capabilities out;
	uint8_t digest1[HASH_MAX_HASH_LEN];
	uint8_t digest2[HASH_MAX_HASH_LEN];
	uint8_t key1[DEVICE_MANAGER_MAX_KEY_LEN];
	uint8_t key2[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key* temp_key;
	int status;

	memset (digest1, 0xAA, sizeof (digest1));
	memset (digest2, 0xBB, sizeof (digest2));
	memset (key1, 0xCC, sizeof (key1));
	memset (key2, 0xDD, sizeof (key2));

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	expected.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	expected.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	expected.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	expected.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	expected.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	memset (&expected2, 0, sizeof (expected2));
	expected2.request.max_message_size = 50;
	expected2.request.max_packet_size = 10;
	expected2.request.security_mode = DEVICE_MANAGER_SECURITY_CONFIDENTIALITY;
	expected2.request.bus_role = DEVICE_MANAGER_MASTER_BUS_ROLE;
	expected2.request.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;
	expected2.max_timeout = 100;
	expected2.max_sig = 200;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB, 0xAA, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xBB, 0, digest1, sizeof (digest1));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xBB, key1, sizeof (key1), 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest2, sizeof (digest2));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key2, sizeof (key2), 0xFF);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &expected2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_resize_entries_table (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_device_addr (&manager, 1);
	CuAssertIntEquals (test, 0xDD, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_READY_FOR_ATTESTATION, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xBB, digest1, sizeof (digest1));
	CuAssertIntEquals (test, 0, status);

	temp_key = device_manager_get_alias_key (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, temp_key->key);
	CuAssertIntEquals (test, sizeof (key1), temp_key->key_len);
	CuAssertIntEquals (test, 0xEE, temp_key->key_type);

	status = testing_validate_array (key1, temp_key->key, sizeof (key1));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest2, sizeof (digest2));
	CuAssertIntEquals (test, 0, status);

	temp_key = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, temp_key->key);
	CuAssertIntEquals (test, sizeof (key2), temp_key->key_len);
	CuAssertIntEquals (test, 0xFF, temp_key->key_type);

	status = testing_validate_array (key2, temp_key->key, sizeof (key2));
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities (&manager, 0, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities (&manager, 1, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected2, (uint8_t*) &out, sizeof (expected2));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 0, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (NULL, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len (&manager, 0);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_remote_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities remote;
	int status;
	size_t length;

	TEST_START;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_remote_device_local_smaller (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	struct device_manager_full_capabilities remote;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_remote_device_no_capabilities (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_remote_device_unknown_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len (NULL, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_by_eid_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_by_eid_remote_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities remote;
	int status;
	size_t length;

	TEST_START;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_by_eid_remote_device_local_smaller (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	struct device_manager_full_capabilities remote;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_by_eid_remote_device_no_capabilities (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_by_eid_remote_device_unknown_device (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len_by_eid (NULL, 0xAA);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (&manager, 0);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_remote_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities remote;
	int status;
	size_t length;

	TEST_START;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_remote_device_local_smaller (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	struct device_manager_full_capabilities remote;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_remote_device_no_capabilities (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_remote_device_unknown_device (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (NULL, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_by_eid_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_by_eid_remote_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities remote;
	int status;
	size_t length;

	TEST_START;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_by_eid_remote_device_local_smaller (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	struct device_manager_full_capabilities remote;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_by_eid_remote_device_no_capabilities (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_by_eid_remote_device_unknown_device (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t length;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT - 16, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (NULL, 0xAA);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (&manager, 0);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_remote_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities remote;
	int status;
	size_t timeout;

	TEST_START;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = 20;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (&manager, 1);
	CuAssertIntEquals (test, 200, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_remote_device_no_capabilities (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_remote_device_unknown_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t timeout;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = (MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 10) / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 10, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (NULL, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_by_eid_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_by_eid_remote_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities remote;
	int status;
	size_t timeout;

	TEST_START;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = 20;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, 200, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_by_eid_remote_device_no_capabilities (
	CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_by_eid_remote_device_unknown_device (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t timeout;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = (MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 10) / 10;
	local.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 10, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout_by_eid (NULL, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (&manager, 0);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_remote_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities remote;
	int status;
	size_t timeout;

	TEST_START;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = 20;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (&manager, 1);
	CuAssertIntEquals (test, 2000, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_remote_device_no_capabilities (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_remote_device_unknown_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t timeout;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = (MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 100) / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 100, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (NULL, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_by_eid_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_by_eid_remote_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities remote;
	int status;
	size_t timeout;

	TEST_START;

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = 20;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, 2000, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_by_eid_remote_device_no_capabilities (
	CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_by_eid_remote_device_unknown_device (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_full_capabilities local;
	int status;
	size_t timeout;

	TEST_START;

	memset (&local, 0, sizeof (local));
	local.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	local.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	local.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	local.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	local.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	local.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	local.max_sig = (MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 100) / 100;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 100, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (NULL, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type_digest (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest[SHA256_HASH_LENGTH] = {0};
	const uint8_t *component_type;
	int status;

	TEST_START;

	digest[0] = 0xAA;
	digest[10] = 0xBB;
	digest[20] = 0xCC;
	digest[SHA256_HASH_LENGTH - 1] = 0xDD;
	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 0, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 0, 0xAA, 0xBB, 0xCC, 0xDD,
		1, digest, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	component_type = device_manager_get_component_type_digest (&manager, 0x0A);

	status = testing_validate_array (digest, component_type, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type_digest_unknown_eid (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *component_type;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	component_type = device_manager_get_component_type_digest (&manager, 0x0b);
	CuAssertPtrEquals (test, NULL, (void*) component_type);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type_digest_null (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *component_type;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	component_type = device_manager_get_component_type_digest (NULL, 0);
	CuAssertPtrEquals (test, NULL, (void*) component_type);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert_chain_digest (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest_exp[HASH_MAX_HASH_LEN];
	uint8_t digest_actual[HASH_MAX_HASH_LEN];
	int status;

	memset (digest_exp, 0xAA, sizeof (digest_exp));
	memset (digest_actual, 0xAA, sizeof (digest_actual));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest_exp,
		sizeof (digest_exp));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest_actual,
		sizeof (digest_actual));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert_chain_digest_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (NULL, 0xCC, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, NULL, sizeof (digest));
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert_chain_digest_unknown_device (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest_exp[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest_exp,
		sizeof (digest_exp));
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert_chain_digest_input_too_large (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest[HASH_MAX_HASH_LEN + 1];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, DEVICE_MGR_INPUT_TOO_LARGE, status);

	device_manager_release (&manager);
}

static void device_manager_test_compare_cert_chain_digest (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	memset (digest, 0xAA, sizeof (digest));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_compare_cert_chain_digest_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest_actual[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (NULL, 0xCC, digest_actual,
		sizeof (digest_actual));
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, NULL,
		sizeof (digest_actual));
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest_actual, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_compare_cert_chain_digest_unknown_device (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest, sizeof (digest));
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_compare_cert_chain_digest_digest_len_mismatch (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest_exp[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest_exp,
		sizeof (digest_exp));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest_exp,
		sizeof (digest_exp) - 1);
	CuAssertIntEquals (test, DEVICE_MGR_DIGEST_LEN_MISMATCH, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest_exp,
		sizeof (digest_exp) + 1);
	CuAssertIntEquals (test, DEVICE_MGR_DIGEST_LEN_MISMATCH, status);

	device_manager_release (&manager);
}

static void device_manager_test_compare_cert_chain_digest_digest_mismatch (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest_exp[HASH_MAX_HASH_LEN];
	uint8_t digest_act[HASH_MAX_HASH_LEN];
	int status;

	memset (digest_exp, 0xAA, sizeof (digest_exp));
	memset (digest_act, 0xBB, sizeof (digest_act));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest_exp,
		sizeof (digest_exp));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest_act,
		sizeof (digest_act));
	CuAssertIntEquals (test, DEVICE_MGR_DIGEST_MISMATCH, status);

	device_manager_release (&manager);
}

static void device_manager_test_compare_cert_chain_digest_digest_not_unique (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	memset (digest, 0xAA, sizeof (digest));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xAA, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, DEVICE_MGR_DIGEST_NOT_UNIQUE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_alias_key (CuTest *test)
{
	struct device_manager manager;
	uint8_t key_exp[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key* key_actual;
	int status;

	memset (key_exp, 0xAA, sizeof (key_exp));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key_exp, sizeof (key_exp), 0xAA);
	CuAssertIntEquals (test, 0, status);

	key_actual = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_actual->key);
	CuAssertIntEquals (test, sizeof (key_exp), key_actual->key_len);
	CuAssertIntEquals (test, 0xAA, key_actual->key_type);

	status = testing_validate_array (key_exp, key_actual->key, sizeof (key_exp));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_alias_key_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint8_t key[DEVICE_MANAGER_MAX_KEY_LEN];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (NULL, 0xCC, key, sizeof (key), 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_alias_key (&manager, 0xCC, NULL, sizeof (key), 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key, 0, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_alias_key_unknown_device (CuTest *test)
{
	struct device_manager manager;
	uint8_t key[DEVICE_MANAGER_MAX_KEY_LEN];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key, sizeof (key), 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_alias_key_input_too_large (CuTest *test)
{
	struct device_manager manager;
	uint8_t key[DEVICE_MANAGER_MAX_KEY_LEN + 1];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key, sizeof (key), 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INPUT_TOO_LARGE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_alias_key (CuTest *test)
{
	struct device_manager manager;
	uint8_t key_exp[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key* key_actual;
	int status;

	memset (key_exp, 0xAA, sizeof (key_exp));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key_exp, sizeof (key_exp), 0xAA);
	CuAssertIntEquals (test, 0, status);

	key_actual = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertPtrNotNull (test, key_actual->key);
	CuAssertIntEquals (test, sizeof (key_exp), key_actual->key_len);
	CuAssertIntEquals (test, 0xAA, key_actual->key_type);

	status = testing_validate_array (key_exp, key_actual->key, sizeof (key_exp));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_alias_key_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	const struct device_manager_key *key;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	key = device_manager_get_alias_key (NULL, 0xCC);
	CuAssertPtrEquals (test, NULL, (void*) key);

	device_manager_release (&manager);
}

static void device_manager_test_get_alias_key_unknown_device (CuTest *test)
{
	struct device_manager manager;
	const struct device_manager_key *key;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	key = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertPtrEquals (test, NULL, (void*) key);

	device_manager_release (&manager);
}

static void device_manager_test_get_alias_key_empty (CuTest *test)
{
	struct device_manager manager;
	const struct device_manager_key *key;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	key = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertPtrNotNull (test, key->key);
	CuAssertIntEquals (test, 0, key->key_len);
	CuAssertIntEquals (test, 0, key->key_type);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_attest_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_eid_of_next_device_to_attest (NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_eid_of_next_device_to_attest_one_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_attest_multiple (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 2, 0xEE, 0xFF, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 3, 0xA0, 0xB0, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xEE, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xA0, status);

	platform_msleep (200 + 100);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xEE, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xA0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_attest_multiple_authenticated (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 2, 0xEE,	0xFF, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 3, 0xA0,	0xB0, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	platform_msleep (200 + 100);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xEE, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xA0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_attest_no_available_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_attest_no_ready_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_attest_no_attestable_devices (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_reset_authenticated_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_reset_authenticated_devices (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_READY_FOR_ATTESTATION, status);

	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_reset_authenticated_devices_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_reset_authenticated_devices (NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_reset_discovered_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 3, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 2, 0xEE, 0xFF, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_reset_discovered_devices (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE, status);

	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	device_manager_release (&manager);
}

static void device_manager_test_reset_discovered_devices_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_reset_discovered_devices (NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}


static void device_manager_test_add_unidentified_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_add_unidentified_device_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (NULL, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_remove_unidentified_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_remove_unidentified_device_single_entry (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_remove_unidentified_device_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_remove_unidentified_device_unknown_device_multiple_entries (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_remove_unidentified_device_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_unidentified_device (NULL, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_unidentified_device_timed_out (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_unidentified_device_timed_out_single_entry (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_unidentified_device_timed_out_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xBB);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_unidentified_device_timed_out_unknown_device_multiple_entries (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xCC);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_unidentified_device_timed_out_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (NULL, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_single_entry (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_multiple_entries (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xBB, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_first_timed_out (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_second_timed_out (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_all_timed_out (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_wait_timeout_cadence (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (200 + 100);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xBB, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_no_entries (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_eid_of_next_device_to_discover (NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_num_by_device_ids (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 1, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_device_ids_no_unidentified_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_device_ids_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_num_by_device_ids (NULL, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_num_by_device_ids_device_not_found (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0xAA, 0, 0xCC, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0xCC, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_ids (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 1, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_ids_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_update_device_ids (NULL, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_update_device_ids_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 2, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_single_attestation (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 2000) && (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_attestation (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 2000) && (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_single_attestation_authenticated (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 6000) && (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_attestation_authenticated (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 6000) && (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_attestation_authenticated_and_unauthenticated (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 2000) && (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_single_discovery (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_discovery (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_single_discovery_timeout (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 11000) && (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_discovery_timeout (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 11000) && (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_discovery_some_timeout (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_attestation_and_discovery (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 2000) && (duration_ms != 0));

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms < 11000) && (duration_ms != 0));

	device_manager_release (&manager);
}


static void device_manager_test_get_time_till_next_action_no_devices (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 10000, duration_ms);

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_invalid_arg (CuTest *test)
{
	uint32_t duration_ms;

	TEST_START;

	duration_ms = device_manager_get_time_till_next_action (NULL);
	CuAssertIntEquals (test, 10000, duration_ms);
}

static void device_manager_test_get_attestation_status (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int i_pcd;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device, ++i_pcd) {
		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_pcd);

		if (i_pcd % 2) {
			status = device_manager_update_device_state (&manager, i_device,
				DEVICE_MANAGER_AUTHENTICATED);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	for (i_bitmap = 0; i_bitmap < 31; ++i_bitmap) {
		CuAssertIntEquals (test, 0x55, bitmap[i_bitmap]);
	}

	CuAssertIntEquals (test, 0x15, bitmap[31]);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_unauthenticated (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int i_pcd;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device, ++ i_pcd) {
		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_pcd);
		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	for (i_bitmap = 0; i_bitmap < 31; ++i_bitmap) {
		CuAssertIntEquals (test, 0xFF, bitmap[i_bitmap]);
	}

	CuAssertIntEquals (test, 0x3F, bitmap[31]);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_unauthenticated_not_max (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int i_pcd;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 11; ++i_device, ++ i_pcd) {
		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_pcd);
		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0xFF, bitmap[0]);
	CuAssertIntEquals (test, 0x03, bitmap[1]);

	for (i_bitmap = 2; i_bitmap < 32; ++i_bitmap) {
		CuAssertIntEquals (test, 0, bitmap[i_bitmap]);
	}

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_authenticated (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 255; ++i_device) {
		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_device);
		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	for (i_bitmap = 0; i_bitmap < 32; ++i_bitmap) {
		CuAssertIntEquals (test, 0x00, bitmap[i_bitmap]);
	}

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_authenticated_not_max (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 11; ++i_device) {
		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_device);
		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	for (i_bitmap = 0; i_bitmap < 32; ++i_bitmap) {
		CuAssertIntEquals (test, 0x00, bitmap[i_bitmap]);
	}

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_multiple_components_same_entry (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int i_pcd;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device) {
		if ((i_device % 2) == 0) {
			++i_pcd;
		}

		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_pcd);
		CuAssertIntEquals (test, 0, status);

		if ((i_pcd % 4) == 0) {
			status = device_manager_update_device_state (&manager, i_device,
				DEVICE_MANAGER_READY_FOR_ATTESTATION);
			CuAssertIntEquals (test, 0, status);
		}
		else {
			status = device_manager_update_device_state (&manager, i_device,
				DEVICE_MANAGER_AUTHENTICATED);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	for (i_bitmap = 0; i_bitmap < 16; ++i_bitmap) {
		CuAssertIntEquals (test, 0x11, bitmap[i_bitmap]);
	}

	for (i_bitmap = 16; i_bitmap < 32; ++i_bitmap) {
		CuAssertIntEquals (test, 0, bitmap[i_bitmap]);
	}

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_multiple_components_same_entry_not_max (
	CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int i_pcd;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 16, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 17; ++i_device) {
		if ((i_device % 2) == 0) {
			++i_pcd;
		}

		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_pcd);
		CuAssertIntEquals (test, 0, status);

		if ((i_device % 4) == 0) {
			status = device_manager_update_device_state (&manager, i_device,
				DEVICE_MANAGER_READY_FOR_ATTESTATION);
			CuAssertIntEquals (test, 0, status);
		}
		else {
			status = device_manager_update_device_state (&manager, i_device,
				DEVICE_MANAGER_AUTHENTICATED);
			CuAssertIntEquals (test, 0, status);
		}
	}

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x54, bitmap[0]);
	CuAssertIntEquals (test, 0x01, bitmap[1]);

	for (i_bitmap = 2; i_bitmap < 32; ++i_bitmap) {
		CuAssertIntEquals (test, 0, bitmap[i_bitmap]);
	}

	device_manager_release (&manager);
}

static void device_manager_test_mark_component_attestation_invalid_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_mark_component_attestation_invalid (NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_mark_component_attestation_invalid (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int i_pcd;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device, ++ i_pcd) {
		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_pcd);
		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_mark_component_attestation_invalid (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	for (i_bitmap = 0; i_bitmap < 32; ++i_bitmap) {
		CuAssertIntEquals (test, 0xFF, bitmap[i_bitmap]);
	}

	device_manager_release (&manager);
}

static void device_manager_test_mark_component_attestation_invalid_not_max (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int i_bitmap;
	int i_device;
	int i_pcd;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 11; ++i_device, ++ i_pcd) {
		status = device_manager_update_device_entry (&manager, i_device, 0, 0, i_pcd);
		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_mark_component_attestation_invalid (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_status (&manager, bitmap);
	CuAssertIntEquals (test, 0, status);

	for (i_bitmap = 0; i_bitmap < 32; ++i_bitmap) {
		CuAssertIntEquals (test, 0xFF, bitmap[i_bitmap]);
	}

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint8_t bitmap[32];
	int status;

	TEST_START;

	status = device_manager_get_attestation_status (NULL, bitmap);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_attestation_status (&manager, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}


TEST_SUITE_START (device_manager);

TEST (device_manager_test_init);
TEST (device_manager_test_init_invalid_arg);
TEST (device_manager_test_release_null);
TEST (device_manager_test_get_device_capabilities);
TEST (device_manager_test_get_device_capabilities_master_pa_rot);
TEST (device_manager_test_get_device_capabilities_null);
TEST (device_manager_test_get_device_capabilities_invalid_device);
TEST (device_manager_test_update_device_capabilities);
TEST (device_manager_test_update_device_capabilities_invalid_arg);
TEST (device_manager_test_update_device_capabilities_invalid_device);
TEST (device_manager_test_get_device_capabilities_request);
TEST (device_manager_test_get_device_capabilities_request_null);
TEST (device_manager_test_update_device_capabilities_request);
TEST (device_manager_test_update_device_capabilities_request_invalid_arg);
TEST (device_manager_test_update_device_capabilities_request_invalid_device);
TEST (device_manager_test_update_device_entry);
TEST (device_manager_test_update_device_entry_invalid_arg);
TEST (device_manager_test_update_device_entry_invalid_device);
TEST (device_manager_test_update_mctp_bridge_device_entry);
TEST (device_manager_test_update_mctp_bridge_device_entry_invalid_arg);
TEST (device_manager_test_update_mctp_bridge_device_entry_invalid_device);
TEST (device_manager_test_update_mctp_bridge_device_entry_too_many_components);
TEST (device_manager_test_get_device_addr_null);
TEST (device_manager_test_get_device_addr_invalid_device);
TEST (device_manager_test_get_device_addr_by_eid);
TEST (device_manager_test_get_device_addr_by_eid_null);
TEST (device_manager_test_get_device_addr_by_eid_invalid_device);
TEST (device_manager_test_get_device_eid_null);
TEST (device_manager_test_get_device_eid_invalid_device);
TEST (device_manager_test_update_device_state);
TEST (device_manager_test_update_device_state_invalid_arg);
TEST (device_manager_test_update_device_state_invalid_device);
TEST (device_manager_test_update_device_state_by_eid);
TEST (device_manager_test_update_device_state_by_eid_invalid_arg);
TEST (device_manager_test_update_device_state_by_eid_invalid_device);
TEST (device_manager_test_get_device_state_null);
TEST (device_manager_test_get_device_state_invalid_device);
TEST (device_manager_test_get_device_state_by_eid_null);
TEST (device_manager_test_get_device_state_by_eid_invalid_device);
TEST (device_manager_test_get_device_num);
TEST (device_manager_test_get_device_num_null);
TEST (device_manager_test_get_device_num_invalid_eid);
TEST (device_manager_test_resize_entries_table_add_entries);
TEST (device_manager_test_resize_entries_table_remove_entries);
TEST (device_manager_test_resize_entries_table_invalid_arg);
TEST (device_manager_test_resize_entries_table_same_size);
TEST (device_manager_test_update_device_eid);
TEST (device_manager_test_update_device_eid_invalid_arg);
TEST (device_manager_test_update_device_eid_invalid_device);
TEST (device_manager_test_get_max_message_len_local_device);
TEST (device_manager_test_get_max_message_len_remote_device);
TEST (device_manager_test_get_max_message_len_remote_device_local_smaller);
TEST (device_manager_test_get_max_message_len_remote_device_no_capabilities);
TEST (device_manager_test_get_max_message_len_remote_device_unknown_device);
TEST (device_manager_test_get_max_message_len_null);
TEST (device_manager_test_get_max_message_len_by_eid_local_device);
TEST (device_manager_test_get_max_message_len_by_eid_remote_device);
TEST (device_manager_test_get_max_message_len_by_eid_remote_device_local_smaller);
TEST (device_manager_test_get_max_message_len_by_eid_remote_device_no_capabilities);
TEST (device_manager_test_get_max_message_len_by_eid_remote_device_unknown_device);
TEST (device_manager_test_get_max_message_len_by_eid_null);
TEST (device_manager_test_get_max_transmission_unit_local_device);
TEST (device_manager_test_get_max_transmission_unit_remote_device);
TEST (device_manager_test_get_max_transmission_unit_remote_device_local_smaller);
TEST (device_manager_test_get_max_transmission_unit_remote_device_no_capabilities);
TEST (device_manager_test_get_max_transmission_unit_remote_device_unknown_device);
TEST (device_manager_test_get_max_transmission_unit_null);
TEST (device_manager_test_get_max_transmission_unit_by_eid_local_device);
TEST (device_manager_test_get_max_transmission_unit_by_eid_remote_device);
TEST (device_manager_test_get_max_transmission_unit_by_eid_remote_device_local_smaller);
TEST (device_manager_test_get_max_transmission_unit_by_eid_remote_device_no_capabilities);
TEST (device_manager_test_get_max_transmission_unit_by_eid_remote_device_unknown_device);
TEST (device_manager_test_get_max_transmission_unit_by_eid_null);
TEST (device_manager_test_get_reponse_timeout_local_device);
TEST (device_manager_test_get_reponse_timeout_remote_device);
TEST (device_manager_test_get_reponse_timeout_remote_device_no_capabilities);
TEST (device_manager_test_get_reponse_timeout_remote_device_unknown_device);
TEST (device_manager_test_get_reponse_timeout_null);
TEST (device_manager_test_get_reponse_timeout_by_eid_local_device);
TEST (device_manager_test_get_reponse_timeout_by_eid_remote_device);
TEST (device_manager_test_get_reponse_timeout_by_eid_remote_device_no_capabilities);
TEST (device_manager_test_get_reponse_timeout_by_eid_remote_device_unknown_device);
TEST (device_manager_test_get_reponse_timeout_by_eid_null);
TEST (device_manager_test_get_crypto_timeout_local_device);
TEST (device_manager_test_get_crypto_timeout_remote_device);
TEST (device_manager_test_get_crypto_timeout_remote_device_no_capabilities);
TEST (device_manager_test_get_crypto_timeout_remote_device_unknown_device);
TEST (device_manager_test_get_crypto_timeout_null);
TEST (device_manager_test_get_crypto_timeout_by_eid_local_device);
TEST (device_manager_test_get_crypto_timeout_by_eid_remote_device);
TEST (device_manager_test_get_crypto_timeout_by_eid_remote_device_no_capabilities);
TEST (device_manager_test_get_crypto_timeout_by_eid_remote_device_unknown_device);
TEST (device_manager_test_get_crypto_timeout_by_eid_null);
TEST (device_manager_test_get_component_type_digest);
TEST (device_manager_test_get_component_type_digest_unknown_eid);
TEST (device_manager_test_get_component_type_digest_null);
TEST (device_manager_test_update_cert_chain_digest);
TEST (device_manager_test_update_cert_chain_digest_invalid_arg);
TEST (device_manager_test_update_cert_chain_digest_unknown_device);
TEST (device_manager_test_update_cert_chain_digest_input_too_large);
TEST (device_manager_test_compare_cert_chain_digest);
TEST (device_manager_test_compare_cert_chain_digest_invalid_arg);
TEST (device_manager_test_compare_cert_chain_digest_unknown_device);
TEST (device_manager_test_compare_cert_chain_digest_digest_len_mismatch);
TEST (device_manager_test_compare_cert_chain_digest_digest_mismatch);
TEST (device_manager_test_compare_cert_chain_digest_digest_not_unique);
TEST (device_manager_test_update_alias_key);
TEST (device_manager_test_update_alias_key_invalid_arg);
TEST (device_manager_test_update_alias_key_unknown_device);
TEST (device_manager_test_update_alias_key_input_too_large);
TEST (device_manager_test_get_alias_key);
TEST (device_manager_test_get_alias_key_invalid_arg);
TEST (device_manager_test_get_alias_key_unknown_device);
TEST (device_manager_test_get_alias_key_empty);
TEST (device_manager_test_get_eid_of_next_device_to_attest_one_device);
TEST (device_manager_test_get_eid_of_next_device_to_attest_multiple);
TEST (device_manager_test_get_eid_of_next_device_to_attest_multiple_authenticated);
TEST (device_manager_test_get_eid_of_next_device_to_attest_invalid_arg);
TEST (device_manager_test_get_eid_of_next_device_to_attest_no_available_devices);
TEST (device_manager_test_get_eid_of_next_device_to_attest_no_ready_devices);
TEST (device_manager_test_get_eid_of_next_device_to_attest_no_attestable_devices);
TEST (device_manager_test_reset_authenticated_devices);
TEST (device_manager_test_reset_authenticated_devices_invalid_arg);
TEST (device_manager_test_reset_discovered_devices);
TEST (device_manager_test_reset_discovered_devices_invalid_arg);
TEST (device_manager_test_add_unidentified_device);
TEST (device_manager_test_add_unidentified_device_invalid_arg);
TEST (device_manager_test_remove_unidentified_device);
TEST (device_manager_test_remove_unidentified_device_single_entry);
TEST (device_manager_test_remove_unidentified_device_unknown_device);
TEST (device_manager_test_remove_unidentified_device_unknown_device_multiple_entries);
TEST (device_manager_test_remove_unidentified_device_invalid_arg);
TEST (device_manager_test_unidentified_device_timed_out);
TEST (device_manager_test_unidentified_device_timed_out_single_entry);
TEST (device_manager_test_unidentified_device_timed_out_unknown_device);
TEST (device_manager_test_unidentified_device_timed_out_unknown_device_multiple_entries);
TEST (device_manager_test_unidentified_device_timed_out_invalid_arg);
TEST (device_manager_test_get_eid_of_next_device_to_discover_single_entry);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_first_timed_out);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_second_timed_out);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_all_timed_out);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_wait_timeout_cadence);
TEST (device_manager_test_get_eid_of_next_device_to_discover_no_entries);
TEST (device_manager_test_get_eid_of_next_device_to_discover_invalid_arg);
TEST (device_manager_test_get_device_num_by_device_ids);
TEST (device_manager_test_get_device_num_by_device_ids_no_unidentified_devices);
TEST (device_manager_test_get_device_num_by_device_ids_invalid_arg);
TEST (device_manager_test_get_device_num_by_device_ids_device_not_found);
TEST (device_manager_test_update_device_ids);
TEST (device_manager_test_update_device_ids_invalid_arg);
TEST (device_manager_test_update_device_ids_unknown_device);
TEST (device_manager_test_get_time_till_next_action_single_attestation);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation);
TEST (device_manager_test_get_time_till_next_action_single_attestation_authenticated);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation_authenticated);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation_authenticated_and_unauthenticated);
TEST (device_manager_test_get_time_till_next_action_single_discovery);
TEST (device_manager_test_get_time_till_next_action_multiple_discovery);
TEST (device_manager_test_get_time_till_next_action_single_discovery_timeout);
TEST (device_manager_test_get_time_till_next_action_multiple_discovery_timeout);
TEST (device_manager_test_get_time_till_next_action_multiple_discovery_some_timeout);
TEST (device_manager_test_get_time_till_next_action_attestation_and_discovery);
TEST (device_manager_test_get_time_till_next_action_no_devices);
TEST (device_manager_test_get_time_till_next_action_invalid_arg);
TEST (device_manager_test_get_attestation_status);
TEST (device_manager_test_get_attestation_status_all_unauthenticated);
TEST (device_manager_test_get_attestation_status_all_unauthenticated_not_max);
TEST (device_manager_test_get_attestation_status_all_authenticated);
TEST (device_manager_test_get_attestation_status_all_authenticated_not_max);
TEST (device_manager_test_get_attestation_status_multiple_components_same_entry);
TEST (device_manager_test_get_attestation_status_multiple_components_same_entry_not_max);
TEST (device_manager_test_get_attestation_status_invalid_arg);
TEST (device_manager_test_mark_component_attestation_invalid);
TEST (device_manager_test_mark_component_attestation_invalid_not_max);
TEST (device_manager_test_mark_component_attestation_invalid_invalid_arg);

TEST_SUITE_END;
