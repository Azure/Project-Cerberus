// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "attestation/attestation_discover.h"
#include "attestation/attestation_logging.h"
#include "cmd_interface/device_manager.h"
#include "logging/debug_log.h"
#include "manifest/pcd/pcd.h"
#include "mctp/mctp_base_protocol.h"
#include "testing/asn1/x509_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/cmd_interface/device_manager_observer_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("device_manager");

extern const struct logging *debug_log;


/*******************
 * Test cases
 *******************/

static void device_manager_test_init (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_no_responder_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (NULL, 1, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 0, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 1, 0, 0, NUM_BUS_HIERACHY_ROLES,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 0, 0, 0, DEVICE_MANAGER_AC_ROT_MODE, NUM_BUS_ROLES,
		1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_init_invalid_responder_count (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_RESPONDER_COUNT, status);
}

static void device_manager_test_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 1, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_ac_rot_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (NULL, 1, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init_ac_rot (&manager, 0, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init_ac_rot (&manager, 1, NUM_BUS_ROLES);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_release_null (CuTest *test)
{
	device_manager_release (NULL);
}

static void device_manager_test_add_device_manager_observer (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_observer_mock observer;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_add_device_manager_observer_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_observer_mock observer;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_observer (NULL, &observer.base);
	CuAssertIntEquals (test, DEVICE_MANAGER_OBSERVER_INVALID_ARGUMENT, status);

	status = device_manager_add_observer (&manager, NULL);
	CuAssertIntEquals (test, DEVICE_MANAGER_OBSERVER_INVALID_ARGUMENT, status);

	status = device_manager_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_remove_device_manager_observer (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_observer_mock observer;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_remove_device_manager_observer_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_observer_mock observer;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_observer (NULL, &observer.base);
	CuAssertIntEquals (test, DEVICE_MANAGER_OBSERVER_INVALID_ARGUMENT, status);

	status = device_manager_remove_observer (&manager, NULL);
	CuAssertIntEquals (test, DEVICE_MANAGER_OBSERVER_INVALID_ARGUMENT, status);

	status = device_manager_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities (&manager, 0, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_capabilities_init_ac_rot (CuTest *test)
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

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (&manager, 2, &out);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_capabilities (&manager, -1, &out);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

static void device_manager_test_update_device_capabilities_init_ac_rot (CuTest *test)
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

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, -1, &expected);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	memset (&out, 0x55, sizeof (out));
	status = device_manager_get_device_capabilities_request (&manager, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected, (uint8_t*) &out, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_capabilities_request_init_ac_rot (CuTest *test)
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

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

static void device_manager_test_update_device_capabilities_request_init_ac_rot (CuTest *test)
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

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities_request (&manager, -1, &expected);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_device_capabilities_request (&manager, 2, &expected);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_not_attestable_device_entry (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xBB, 0xAA, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_not_attestable_device_entry_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xBB, 0xAA, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_not_attestable_device_entry_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (NULL, 0, 0, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_not_attestable_device_entry_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, -1, 0, 0, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 2, 0, 0, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_mctp_bridge_device_entry (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xBB, 0xAA, 0xCC, 0xDD, 2,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xBB, 0xAA, 0xCC,
		0xDD);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xBB, 0xAA, 0xCC,
		0xDD, 0);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_device_eid (&manager, 1, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id (&manager, 1, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, component_id, device_component_id);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xBB, 0xAA, 0xCC,
		0xDD);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xBB, 0xAA, 0xCC,
		0xDD, 1);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_update_device_eid (&manager, 2, 0x0D);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id (&manager, 2, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, component_id, device_component_id);

	/* Single-source matching component_id: list is NULL, accessor returns component_id */
	CuAssertIntEquals (test, 1, manager.entries[1].component_type_count);
	CuAssertPtrEquals (test, NULL, manager.entries[1].component_type_list);

	CuAssertIntEquals (test, 1, manager.entries[2].component_type_count);
	CuAssertPtrEquals (test, NULL, manager.entries[2].component_type_list);

	status = device_manager_get_component_type (&manager, 1, 0, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, component_id, device_component_id);

	status = device_manager_get_component_type (&manager, 2, 0, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, component_id, device_component_id);

	device_manager_release (&manager);
}

static void device_manager_test_update_mctp_bridge_device_entry_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (NULL, 0, 0xBB, 0xAA, 0xCC, 0xDD, 2,
		component_id, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 0, 0xBB, 0xAA, 0xCC, 0xDD, 0,
		component_id, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_mctp_bridge_device_entry_invalid_device (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 2, 0xBB, 0xAA, 0xCC, 0xDD, 1,
		component_id, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, -1, 0xBB, 0xAA, 0xCC, 0xDD,
		2, component_id, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_mctp_bridge_device_entry_too_many_components (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xBB, 0xAA, 0xCC, 0xDD, 2,
		component_id, 1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover;
	const struct device_manager_entry entry = {
		.pci_vid = 0xBB,
		.pci_device_id = 0xAA,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 50,
		.pcd_component_index = 0,
		.discover = &discover,
	};
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 1, 2, &entry);
	CuAssertIntEquals (test, 0, status);

	/* First component matches by device IDs */
	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xBB, 0xAA, 0xCC,
		0xDD);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xBB, 0xAA, 0xCC,
		0xDD, 0);
	CuAssertIntEquals (test, 1, status);

	/* Discovery object set correctly on first entry */
	CuAssertPtrEquals (test, &discover, device_manager_get_discovery_object (&manager, 1));

	/* Mark first component as attested so second can be found */
	status = device_manager_update_device_eid (&manager, 1, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id (&manager, 1, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, entry.component_id, device_component_id);

	/* Second component at index 2 */
	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xBB, 0xAA, 0xCC,
		0xDD);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xBB, 0xAA, 0xCC,
		0xDD, 1);
	CuAssertIntEquals (test, 2, status);

	/* Discovery object also set on second entry */
	CuAssertPtrEquals (test, &discover, device_manager_get_discovery_object (&manager, 2));

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover;
	const struct device_manager_entry entry = {
		.pci_vid = 0xBB,
		.pci_device_id = 0xAA,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 50,
		.pcd_component_index = 0,
		.discover = &discover,
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (NULL, 0, 1, &entry);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_component_device_entry (&manager, 0, 0, &entry);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover;
	const struct device_manager_entry entry = {
		.pci_vid = 0xBB,
		.pci_device_id = 0xAA,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 50,
		.pcd_component_index = 0,
		.discover = &discover,
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 2, 1, &entry);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_component_device_entry (&manager, -1, 1, &entry);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry_too_many_components (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover;
	const struct device_manager_entry entry = {
		.pci_vid = 0xBB,
		.pci_device_id = 0xAA,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 50,
		.pcd_component_index = 1,
		.discover = &discover,
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 1, 2, &entry);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_discovery_type (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover_mvdp;
	struct attestation_discover discover_tcg;
	const struct device_manager_entry entry_mvdp = {
		.pci_vid = 0xAA,
		.pci_device_id = 0xBB,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 50,
		.pcd_component_index = 0,
		.discover = &discover_mvdp,
	};
	const struct device_manager_entry entry_tcg = {
		.pci_vid = 0xAA,
		.pci_device_id = 0xBB,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xEE,
		.component_id = 51,
		.pcd_component_index = 1,
		.discover = &discover_tcg,
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 1, 1, &entry_mvdp);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 2, 1, &entry_tcg);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &discover_mvdp, device_manager_get_discovery_object (&manager, 1));

	CuAssertPtrEquals (test, &discover_tcg, device_manager_get_discovery_object (&manager, 2));

	device_manager_release (&manager);
}

static void device_manager_test_get_discovery_type_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, device_manager_get_discovery_object (NULL, 1));

	CuAssertPtrEquals (test, NULL, device_manager_get_discovery_object (&manager, -1));

	device_manager_release (&manager);
}

static void device_manager_test_get_discovery_type_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, device_manager_get_discovery_object (&manager, 5));

	device_manager_release (&manager);
}

static void device_manager_test_get_discovery_object (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover;
	const struct device_manager_entry entry = {
		.pci_vid = 0xAA,
		.pci_device_id = 0xBB,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 50,
		.pcd_component_index = 0,
		.discover = &discover,
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 1, 1, &entry);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &discover, device_manager_get_discovery_object (&manager, 1));

	device_manager_release (&manager);
}

static void device_manager_test_get_discovery_object_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, device_manager_get_discovery_object (NULL, 1));

	CuAssertPtrEquals (test, NULL, device_manager_get_discovery_object (&manager, -1));

	device_manager_release (&manager);
}

static void device_manager_test_get_discovery_object_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, device_manager_get_discovery_object (&manager, 5));

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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_addr (&manager, -1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr_by_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xBB, 0xAA, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr_by_eid (&manager, 0xBB);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr_by_eid_unidentified_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0x11, 0x12, 0x13, 0x14);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0x11, 0x12, 0x13,
		0x14);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_device_eid (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr_by_eid (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr_by_eid_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xBB, 0xAA, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_and_instance_ids_by_device_num (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 3,
		50, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 1, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0xAA, instance_id);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 2, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0x01, instance_id);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 3, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0x02, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_and_instance_ids_by_device_num_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (NULL, 1, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 1, NULL,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 1, &pci_vid, NULL,
		&pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 1, &pci_vid,
		&pci_device_id, NULL, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 1, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, NULL, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 1, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_and_instance_ids_by_device_num_unknown_device (
	CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, -1, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, -1, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 3, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_and_instance_ids_by_eid (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 3,
		50, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_eid (&manager, 0xA0, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0xAA, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_and_instance_ids_by_eid_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_eid (NULL, 0xAA, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_eid (&manager, 0xAA, NULL,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_eid (&manager, 0xAA, &pci_vid, NULL,
		&pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_eid (&manager, 0xAA, &pci_vid,
		&pci_device_id, NULL, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_eid (&manager, 0xAA, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, NULL, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_and_instance_ids_by_eid (&manager, 0xAA, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_and_instance_ids_by_eid_unknown_device (
	CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_eid (&manager, 0xB0, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr_by_eid_unidentified_device_null (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0x11, 0x12, 0x13, 0x14);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0x11, 0x12, 0x13,
		0x14);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_device_eid (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr_by_eid (&manager, 0xBB);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr_by_eid_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0x11, 0x12, 0x13, 0x14);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0x11, 0x12, 0x13,
		0x14);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_device_eid (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr_by_eid (&manager, 0xDD);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, -1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_eid (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (NULL, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_device_state (&manager, 0, MAX_DEVICE_MANAGER_STATES);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, -1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_invalid_prev_state (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, DEVICE_MGR_STATE_UPDATE_UNSUPPORTED, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, DEVICE_MGR_STATE_UPDATE_UNSUPPORTED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_by_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state_by_eid (&manager, 0xAA,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_by_eid_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xAA);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state_by_eid (NULL, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_device_state_by_eid (&manager, 0, MAX_DEVICE_MANAGER_STATES);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_by_eid_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, -1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_prev_state (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_prev_state (&manager, 1,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_summary_prev_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_prev_state_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_prev_state (&manager, 1,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_summary_prev_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_prev_state_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_prev_state (NULL, 0,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_prev_state_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_prev_state (&manager, 2,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_attestation_summary_prev_state (&manager, -1,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_prev_state_by_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_prev_state_by_eid (&manager, 0xAA,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_summary_prev_state_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_prev_state_by_eid_init_ac_rot (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_prev_state_by_eid (&manager, 0xAA,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_summary_prev_state_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_prev_state_by_eid_invalid_arg (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_prev_state_by_eid (NULL, 0,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_prev_state_by_eid_invalid_device (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_prev_state_by_eid (&manager, 2,
		DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_summary_prev_state_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_attestation_summary_prev_state (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_attestation_summary_prev_state_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_summary_prev_state (&manager, -1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_attestation_summary_prev_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_summary_prev_state_by_eid_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_attestation_summary_prev_state_by_eid (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_attestation_summary_prev_state_by_eid_invalid_device (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_event_counters (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_attestation_summary_event_counters event_counters;
	int device_state;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (device_state = 0;
		device_state <= DEVICE_MANAGER_AUTHENTICATED_WITH_SPDM_TRANSIENT;
		++device_state) {
		if (device_state == DEVICE_MANAGER_NOT_ATTESTABLE) {
			continue;
		}

		status = device_manager_update_device_state (&manager, 1, device_state);
		CuAssertIntEquals (test, 0, status);

		status = device_manager_update_attestation_summary_event_counters (&manager, 1);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_summary_event_counters (&manager, 1, &event_counters);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, event_counters.status_success_count);
	CuAssertIntEquals (test, 3, event_counters.status_success_timeout_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_internal_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_timeout_count);
	CuAssertIntEquals (test, 0, event_counters.status_fail_invalid_response_count);
	CuAssertIntEquals (test, 0, event_counters.status_fail_invalid_config_count);

	for (device_state = DEVICE_MANAGER_ATTESTATION_INVALID_VERSION;
		device_state <= DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE; ++device_state) {
		if (device_state == DEVICE_MANAGER_NOT_ATTESTABLE) {
			continue;
		}

		status = device_manager_update_device_state (&manager, 1, device_state);
		CuAssertIntEquals (test, 0, status);

		status = device_manager_update_attestation_summary_event_counters (&manager, 1);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_summary_event_counters (&manager, 1, &event_counters);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, event_counters.status_success_count);
	CuAssertIntEquals (test, 3, event_counters.status_success_timeout_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_internal_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_timeout_count);
	CuAssertIntEquals (test, 8, event_counters.status_fail_invalid_response_count);
	CuAssertIntEquals (test, 0, event_counters.status_fail_invalid_config_count);

	for (device_state = DEVICE_MANAGER_ATTESTATION_MEASUREMENT_MISMATCH;
		device_state < MAX_DEVICE_MANAGER_STATES; ++device_state) {
		if (device_state == DEVICE_MANAGER_NOT_ATTESTABLE) {
			continue;
		}

		status = device_manager_update_device_state (&manager, 1, device_state);
		CuAssertIntEquals (test, 0, status);

		status = device_manager_update_attestation_summary_event_counters (&manager, 1);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_summary_event_counters (&manager, 1, &event_counters);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, event_counters.status_success_count);
	CuAssertIntEquals (test, 3, event_counters.status_success_timeout_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_internal_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_timeout_count);
	CuAssertIntEquals (test, 8, event_counters.status_fail_invalid_response_count);
	CuAssertIntEquals (test, 3, event_counters.status_fail_invalid_config_count);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_event_counters_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_attestation_summary_event_counters event_counters;
	int device_state;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	for (device_state = 0;
		device_state <= DEVICE_MANAGER_AUTHENTICATED_WITH_SPDM_TRANSIENT;
		++device_state) {
		if (device_state == DEVICE_MANAGER_NOT_ATTESTABLE) {
			continue;
		}

		status = device_manager_update_device_state (&manager, 1, device_state);
		CuAssertIntEquals (test, 0, status);

		status = device_manager_update_attestation_summary_event_counters (&manager, 1);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_summary_event_counters (&manager, 1, &event_counters);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, event_counters.status_success_count);
	CuAssertIntEquals (test, 3, event_counters.status_success_timeout_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_internal_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_timeout_count);
	CuAssertIntEquals (test, 0, event_counters.status_fail_invalid_response_count);
	CuAssertIntEquals (test, 0, event_counters.status_fail_invalid_config_count);

	for (device_state = DEVICE_MANAGER_ATTESTATION_INVALID_VERSION;
		device_state <= DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE; ++device_state) {
		if (device_state == DEVICE_MANAGER_NOT_ATTESTABLE) {
			continue;
		}

		status = device_manager_update_device_state (&manager, 1, device_state);
		CuAssertIntEquals (test, 0, status);

		status = device_manager_update_attestation_summary_event_counters (&manager, 1);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_summary_event_counters (&manager, 1, &event_counters);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, event_counters.status_success_count);
	CuAssertIntEquals (test, 3, event_counters.status_success_timeout_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_internal_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_timeout_count);
	CuAssertIntEquals (test, 8, event_counters.status_fail_invalid_response_count);
	CuAssertIntEquals (test, 0, event_counters.status_fail_invalid_config_count);

	for (device_state = DEVICE_MANAGER_ATTESTATION_MEASUREMENT_MISMATCH;
		device_state < MAX_DEVICE_MANAGER_STATES; ++device_state) {
		if (device_state == DEVICE_MANAGER_NOT_ATTESTABLE) {
			continue;
		}

		status = device_manager_update_device_state (&manager, 1, device_state);
		CuAssertIntEquals (test, 0, status);

		status = device_manager_update_attestation_summary_event_counters (&manager, 1);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_summary_event_counters (&manager, 1, &event_counters);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, event_counters.status_success_count);
	CuAssertIntEquals (test, 3, event_counters.status_success_timeout_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_internal_count);
	CuAssertIntEquals (test, 1, event_counters.status_fail_timeout_count);
	CuAssertIntEquals (test, 8, event_counters.status_fail_invalid_response_count);
	CuAssertIntEquals (test, 3, event_counters.status_fail_invalid_config_count);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_event_counters_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_event_counters (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_event_counters_invalid_device (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_event_counters (&manager, -1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_attestation_summary_event_counters (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}


static void device_manager_test_get_attestation_summary_event_counters_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_attestation_summary_event_counters (NULL, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_attestation_summary_event_counters_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_attestation_summary_event_counters event_counters;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 0, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_summary_event_counters (&manager, 2, &event_counters);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_attestation_summary_event_counters (&manager, -1, &event_counters);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_summary_event_counters_by_eid_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_attestation_summary_event_counters_by_eid (NULL, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_attestation_summary_event_counters_by_eid_invalid_device (
	CuTest *test)
{
	struct device_manager manager;
	struct device_manager_attestation_summary_event_counters event_counters;
	int device_state;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 0, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (device_state = 0; device_state < MAX_DEVICE_MANAGER_STATES; ++device_state) {
		status = device_manager_get_attestation_summary_event_counters_by_eid (&manager, 0xAA,
			&event_counters);
		CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	}

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num (&manager, 0xCC);
	CuAssertIntEquals (test, 1, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num (&manager, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_component (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint32_t component_id = 50;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 3,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_component (&manager, component_id, 0);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_device_num_by_component (&manager, component_id, 1);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_get_device_num_by_component (&manager, component_id, 2);
	CuAssertIntEquals (test, 3, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_component_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint32_t component_id = 50;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_component (&manager, component_id, 0);
	CuAssertIntEquals (test, 1, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_component_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_num_by_component (NULL, 50, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_num_by_component_invalid_component_id (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint32_t component_id = 50;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_component (&manager, 51, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_component_invalid_instance_id (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint32_t component_id = 50;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_component (&manager, component_id, 1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 0, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, -1, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_device_eid (&manager, 2, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid_notify_observers_self (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_observer_mock observer;
	int status;
	uint8_t eid = 0xAA;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_set_eid, &observer, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&eid, sizeof (eid)));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, DEVICE_MANAGER_SELF_DEVICE_NUM, eid);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, DEVICE_MANAGER_SELF_DEVICE_NUM);
	CuAssertIntEquals (test, eid, status);

	status = device_manager_remove_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid_notify_observers_others (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_observer_mock observer;
	int status;
	uint8_t eid = 0xAA;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM,
		eid);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
	CuAssertIntEquals (test, eid, status);

	status = device_manager_remove_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid_removed_observer_self (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_observer_mock observer;
	int status;
	int eid = 0xAA;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, DEVICE_MANAGER_SELF_DEVICE_NUM, eid);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, DEVICE_MANAGER_SELF_DEVICE_NUM);
	CuAssertIntEquals (test, eid, status);

	status = device_manager_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid_removed_observer_others (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_observer_mock observer;
	int status;
	int eid = 0xAA;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM,
		eid);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
	CuAssertIntEquals (test, eid, status);

	status = device_manager_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_instance_id (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 1, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0xAA, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_update_instance_id_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 0, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 0, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0xAA, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_update_instance_id_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (NULL, 1, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_instance_id_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, -1, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_device_instance_id (&manager, 2, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_instance_id_by_eid (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id_by_eid (&manager, 0xA0, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 1, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0xAA, instance_id);

	status = device_manager_update_device_instance_id_by_eid (&manager, 0xA0, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_eid (&manager, 0xA0, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0xBB, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_update_instance_id_by_eid_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;
	uint16_t pci_vid;
	uint16_t pci_device_id;
	uint16_t pci_subsystem_vid;
	uint16_t pci_subsystem_id;
	uint8_t instance_id;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 0, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id_by_eid (&manager, 0xA0, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_and_instance_ids_by_device_num (&manager, 0, &pci_vid,
		&pci_device_id, &pci_subsystem_vid, &pci_subsystem_id, &instance_id);
	CuAssertIntEquals (test, 0xAA, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_update_instance_id_by_eid_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id_by_eid (NULL, 0xA0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_instance_id_by_eid_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id_by_eid (&manager, 0xBB, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_update_device_instance_id_by_eid (&manager, 0x0A, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len (&manager, 0);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_message_len (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	length = device_manager_get_max_message_len (&manager, -1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_message_len_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (&manager, 0);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (&manager, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT, length);

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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT, length);

	length = device_manager_get_max_transmission_unit (&manager, -1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit (NULL, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_by_eid_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT, length);

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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_max_transmission_unit_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t length;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	length = device_manager_get_max_transmission_unit_by_eid (NULL, 0xAA);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT, length);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_local_device (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (&manager, 0);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 10, timeout);

	timeout = device_manager_get_reponse_timeout (&manager, -1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 10, timeout);

	device_manager_release (&manager);
}

static void
device_manager_test_get_reponse_timeout_remote_device_unknown_device_mctp_bridge_adjustment (
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 50, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 60, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_remote_device_mctp_bridge_adjustment (
	CuTest *test)
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 50, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout (&manager, 1);
	CuAssertIntEquals (test, 250, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 10, timeout);

	device_manager_release (&manager);
}

static void
device_manager_test_get_reponse_timeout_by_eid_remote_device_unknown_device_mctp_bridge_adjustment (
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 50, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS + 60, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_by_eid_remote_device_mctp_bridge_adjustment (
	CuTest *test)
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 50, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_reponse_timeout_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, 250, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_reponse_timeout_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (&manager, 0);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_init_ac_rot (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init_ac_rot (&manager, 2, DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 100, timeout);

	timeout = device_manager_get_crypto_timeout (&manager, -1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 100, timeout);

	device_manager_release (&manager);
}

static void
device_manager_test_get_crypto_timeout_remote_device_unknown_device_mctp_bridge_adjustment (
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 50, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (&manager, 2);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 150, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_remote_device_mctp_bridge_adjustment (
	CuTest *test)
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 50, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout (&manager, 1);
	CuAssertIntEquals (test, 2050, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 100, timeout);

	device_manager_release (&manager);
}

static void
device_manager_test_get_crypto_timeout_by_eid_remote_device_unknown_device_mctp_bridge_adjustment (
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 50, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &local);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (&manager, 0xEE);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS + 150, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_by_eid_remote_device_mctp_bridge_adjustment (
	CuTest *test)
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 50, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (&manager, 0xCC);
	CuAssertIntEquals (test, 2050, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_crypto_timeout_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	int status;
	size_t timeout;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (NULL, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_id (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id (&manager, 1, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, component_id, device_component_id);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_id_unknown_eid (CuTest *test)
{
	struct device_manager manager;
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id (&manager, 0x0b, &device_component_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_id_null (CuTest *test)
{
	struct device_manager manager;
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id (NULL, 0, &device_component_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_component_id (&manager, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_id_by_eid (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id_by_eid (&manager, 0x0A, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, component_id, device_component_id);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_id_by_eid_unknown_eid (CuTest *test)
{
	struct device_manager manager;
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id_by_eid (&manager, 0x0B, &device_component_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_id_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_id_by_eid (NULL, 0x0A, &device_component_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_component_id_by_eid (&manager, 0x0A, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_id_by_eid (CuTest *test)
{
	struct device_manager manager;
	uint8_t instance_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		50, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 7);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_id_by_eid (&manager, 0x0A, &instance_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 7, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_id_by_eid_unknown_eid (CuTest *test)
{
	struct device_manager manager;
	uint8_t instance_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_id_by_eid (&manager, 0x0B, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_id_by_eid_null (CuTest *test)
{
	struct device_manager manager;
	uint8_t instance_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_id_by_eid (NULL, 0x0A, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_instance_id_by_eid (&manager, 0x0A, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_id_by_device_num (CuTest *test)
{
	struct device_manager manager;
	uint8_t instance_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		50, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 12);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_id (&manager, 1, &instance_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 12, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_id_by_device_num_unknown_device (CuTest *test)
{
	struct device_manager manager;
	uint8_t instance_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_id (&manager, 5, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_instance_id (&manager, -1, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_id_by_device_num_null (CuTest *test)
{
	struct device_manager manager;
	uint8_t instance_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_id (NULL, 1, &instance_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_instance_id (&manager, 1, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_info_by_component_id (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	struct device_manager_instance_info instance_info[20];
	struct device_manager_instance_info min_instance_info[2];
	int status;
	uint8_t exp_instance_info[] = {
		0x00, 0x0A, 0x01, 0x0B,	0x02, 0x0C
	};

	TEST_START;

	status = device_manager_init (&manager, 1, 4, 4, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 3,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 4, 0xAA, 0xBB, 0xCC, 0xEE, 1,
		component_id + 1, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0x0B);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 3, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 4, 0x0D);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_info_by_component_id (&manager, component_id,
		instance_info, 20 * sizeof (struct device_manager_instance_info));
	CuAssertIntEquals (test, 3, status);
	status = testing_validate_array ((uint8_t*) exp_instance_info, (uint8_t*) instance_info, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_info_by_component_id (&manager, component_id + 1,
		min_instance_info, 2 * sizeof (struct device_manager_instance_info));
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, min_instance_info[0].eid, 0x0D);
	CuAssertIntEquals (test, min_instance_info[0].instance_id, 0);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_info_by_component_id_buffer_too_small (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	struct device_manager_instance_info min_instance_info[2];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 4, 4, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 3,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_info_by_component_id (&manager, component_id,
		min_instance_info, 2 * sizeof (struct device_manager_instance_info));
	CuAssertIntEquals (test, DEVICE_MGR_BUF_TOO_SMALL, status);

	status = device_manager_get_instance_info_by_component_id (&manager, component_id,
		min_instance_info, 5);
	CuAssertIntEquals (test, DEVICE_MGR_BUF_TOO_SMALL, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_info_by_component_id_unknown_component_id (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	struct device_manager_instance_info instance_info[2];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		component_id, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_info_by_component_id (&manager, component_id,
		instance_info, 2 * sizeof (struct device_manager_instance_info));
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_instance_info_by_component_id (&manager, component_id + 1,
		instance_info, 2 * sizeof (struct device_manager_instance_info));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_instance_info_by_component_id_invalid_args (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id = 50;
	struct device_manager_instance_info instance_info;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_instance_info_by_component_id (NULL, component_id, &instance_info,
		2);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_instance_info_by_component_id (&manager, component_id, NULL, 2);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_instance_info_by_component_id (&manager, component_id, NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

static void device_manager_test_compare_cert_chain_digest_digest_eid_mismatch (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest_exp[HASH_MAX_HASH_LEN];
	uint8_t digest_act[HASH_MAX_HASH_LEN];
	int status;

	memset (digest_exp, 0xAA, sizeof (digest_exp));
	memset (digest_act, 0xBB, sizeof (digest_act));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest_exp,
		sizeof (digest_exp));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xAA, digest_act,
		sizeof (digest_act));
	CuAssertIntEquals (test, DEVICE_MGR_DIGEST_MISMATCH, status);

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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest_exp,
		sizeof (digest_exp));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest_act,
		sizeof (digest_act));
	CuAssertIntEquals (test, DEVICE_MGR_DIGEST_MISMATCH, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_cert_chain_digest (CuTest *test)
{
	struct device_manager manager;
	uint8_t digest[HASH_MAX_HASH_LEN];
	int status;

	memset (digest, 0xAA, sizeof (digest));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert_chain_digest (&manager, 0xCC, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_clear_cert_chain_digest (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_compare_cert_chain_digest (&manager, 0xCC, digest, sizeof (digest));
	CuAssertIntEquals (test, DEVICE_MGR_DIGEST_LEN_MISMATCH, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_cert_chain_digest_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_clear_cert_chain_digest (NULL, 0xCC);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_cert_chain_digest_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_clear_cert_chain_digest (&manager, 0xCC);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_alias_key (CuTest *test)
{
	struct device_manager manager;
	uint8_t key_exp[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key *key_actual;
	int status;

	memset (key_exp, 0xAA, sizeof (key_exp));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key, sizeof (key), 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INPUT_TOO_LARGE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_alias_key (CuTest *test)
{
	struct device_manager manager;
	uint8_t key_exp[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key *key_actual;
	int status;

	memset (key_exp, 0xAA, sizeof (key_exp));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	key = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertPtrEquals (test, NULL, (void*) key);

	device_manager_release (&manager);
}

static void device_manager_test_get_alias_key_not_updated (CuTest *test)
{
	struct device_manager manager;
	const struct device_manager_key *key;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	key = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertPtrEquals (test, NULL, (void*) key);

	device_manager_release (&manager);
}

static void device_manager_test_clear_alias_key (CuTest *test)
{
	struct device_manager manager;
	uint8_t key_exp[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key *key_actual;
	int status;

	memset (key_exp, 0xAA, sizeof (key_exp));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key_exp, sizeof (key_exp), 0xAA);
	CuAssertIntEquals (test, 0, status);

	key_actual = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertPtrNotNull (test, key_actual->key);
	CuAssertIntEquals (test, sizeof (key_exp), key_actual->key_len);
	CuAssertIntEquals (test, 0xAA, key_actual->key_type);

	status = device_manager_clear_alias_key (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (key_exp, key_actual->key, sizeof (key_exp));
	CuAssertIntEquals (test, 0, status);

	key_actual = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertPtrEquals (test, NULL, (void*) key_actual);

	device_manager_release (&manager);
}

static void device_manager_test_clear_alias_key_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint8_t key_exp[DEVICE_MANAGER_MAX_KEY_LEN];
	const struct device_manager_key *key_actual;
	int status;

	memset (key_exp, 0xAA, sizeof (key_exp));

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_alias_key (&manager, 0xCC, key_exp, sizeof (key_exp), 0xAA);
	CuAssertIntEquals (test, 0, status);

	key_actual = device_manager_get_alias_key (&manager, 0xCC);
	CuAssertPtrNotNull (test, key_actual->key);
	CuAssertIntEquals (test, sizeof (key_exp), key_actual->key_len);
	CuAssertIntEquals (test, 0xAA, key_actual->key_type);

	status = device_manager_clear_alias_key (NULL, 0xCC);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = testing_validate_array (key_exp, key_actual->key, sizeof (key_exp));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_alias_key_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_clear_alias_key (&manager, 0xCC);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

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

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
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

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 3, 0xA0);
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

static void device_manager_test_get_eid_of_next_device_to_attest_multiple_attestation_failed (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 3, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_ATTESTATION_FAILED);
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

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 3, 0xA0);
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

static void device_manager_test_get_eid_of_next_device_to_attest_multiple_unauthenticated (
	CuTest *test)
{
	struct device_manager manager;
	int status;
	int i_device = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 14, 14, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 14; i_device++) {
		status = device_manager_update_device_eid (&manager, i_device, 0xAA + i_device);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2,
		DEVICE_MANAGER_ATTESTATION_INTERRUPTED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3,
		DEVICE_MANAGER_ATTESTATION_INVALID_VERSION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 4,
		DEVICE_MANAGER_ATTESTATION_INVALID_CAPS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 5,
		DEVICE_MANAGER_ATTESTATION_INVALID_ALGORITHM);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 6,
		DEVICE_MANAGER_ATTESTATION_INVALID_DIGESTS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 7,
		DEVICE_MANAGER_ATTESTATION_INVALID_CERTS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 8,
		DEVICE_MANAGER_ATTESTATION_INVALID_CHALLENGE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 9,
		DEVICE_MANAGER_ATTESTATION_INVALID_MEASUREMENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 10,
		DEVICE_MANAGER_ATTESTATION_MEASUREMENT_MISMATCH);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 11,
		DEVICE_MANAGER_ATTESTATION_UNTRUSTED_CERTS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 12,
		DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 13,
		DEVICE_MANAGER_ATTESTATION_INVALID_CFM);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 14; i_device++) {
		status = device_manager_get_eid_of_next_device_to_attest (&manager);
		CuAssertIntEquals (test, 0xAA + i_device, status);
	}

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_attest_no_available_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
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

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_one_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 1, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_multiple (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 3, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 3, status);

	platform_msleep (200 + 100);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 3, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_multiple_attestation_failed
(
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 3, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 3, status);

	platform_msleep (200 + 100);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 3, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_multiple_authenticated (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 3, 0xA0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	platform_msleep (200 + 100);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 2, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 3, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_multiple_unauthenticated (
	CuTest *test)
{
	struct device_manager manager;
	int status;
	int i_device = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 14, 14, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 14; i_device++) {
		status = device_manager_update_device_eid (&manager, i_device, 0xAA + i_device);
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2,
		DEVICE_MANAGER_ATTESTATION_INTERRUPTED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3,
		DEVICE_MANAGER_ATTESTATION_INVALID_VERSION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 4,
		DEVICE_MANAGER_ATTESTATION_INVALID_CAPS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 5,
		DEVICE_MANAGER_ATTESTATION_INVALID_ALGORITHM);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 6,
		DEVICE_MANAGER_ATTESTATION_INVALID_DIGESTS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 7,
		DEVICE_MANAGER_ATTESTATION_INVALID_CERTS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 8,
		DEVICE_MANAGER_ATTESTATION_INVALID_CHALLENGE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 9,
		DEVICE_MANAGER_ATTESTATION_INVALID_MEASUREMENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 10,
		DEVICE_MANAGER_ATTESTATION_MEASUREMENT_MISMATCH);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 11,
		DEVICE_MANAGER_ATTESTATION_UNTRUSTED_CERTS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 12,
		DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 13,
		DEVICE_MANAGER_ATTESTATION_INVALID_CFM);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 14; i_device++) {
		status = device_manager_get_device_num_of_next_device_to_attest (&manager);
		CuAssertIntEquals (test, i_device, status);
	}

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_no_available_devices (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_no_ready_devices (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_no_attestable_devices (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_of_next_device_to_attest (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_of_next_device_to_attest_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_num_of_next_device_to_attest (NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_reset_authenticated_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_reset_authenticated_devices (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE, status);

	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	device_manager_release (&manager);
}

static void device_manager_test_reset_authenticated_without_certs_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1,
		DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_reset_authenticated_devices (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED, status);

	status = device_manager_get_device_state (&manager, 0);
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

	status = device_manager_init (&manager, 1, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 3, 0xAB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_reset_discovered_devices (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE, status);

	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED, status);

	status = device_manager_get_device_state (&manager, 3);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_unidentified_device (NULL, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_remove_unidentified_device_unidentified_null (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_remove_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_unidentified_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_clear_unidentified_devices (&manager);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_unidentified_devices_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	device_manager_clear_unidentified_devices (NULL);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_unidentified_devices_no_unidentified_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	device_manager_clear_unidentified_devices (&manager);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_unidentified_device_timed_out (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_unidentified_device_timed_out_unidentified_null (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_unidentified_device_timed_out_single_entry (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
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

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_multiple_entries (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 4, DEVICE_MANAGER_UNIDENTIFIED);
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

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_first_timed_out
(
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 4, DEVICE_MANAGER_UNIDENTIFIED);
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

static void device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_second_timed_out
(
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 4, DEVICE_MANAGER_UNIDENTIFIED);
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

	status = device_manager_init (&manager, 2, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 4, DEVICE_MANAGER_UNIDENTIFIED);
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

static void
device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_wait_timeout_cadence (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 200, 200, 200, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_UNIDENTIFIED);
	status |= device_manager_update_device_state (&manager, 4, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	platform_msleep (200 + 100);

	status = device_manager_unidentified_device_timed_out (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	platform_msleep (200 + 100);

	status = device_manager_unidentified_device_timed_out (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, 0xBB, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_no_entries (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_no_responders (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 0));
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 1));

	device_manager_release (&manager);
}

static void device_manager_test_get_eid_of_next_device_to_discover_none_unidentified (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_NEVER_ATTESTED);
	status |= device_manager_update_device_state (&manager, 3,
		DEVICE_MANAGER_READY_FOR_ATTESTATION);
	status |= device_manager_update_device_state (&manager, 4,
		DEVICE_MANAGER_ATTESTATION_INTERRUPTED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_eid_of_next_device_to_discover (&manager);
	CuAssertIntEquals (test, DEVICE_MGR_NO_DEVICES_AVAILABLE, status);

	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 0));
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 1));
	CuAssertIntEquals (test, DEVICE_MANAGER_NEVER_ATTESTED,
		device_manager_get_device_state (&manager, 2));
	CuAssertIntEquals (test, DEVICE_MANAGER_READY_FOR_ATTESTATION,
		device_manager_get_device_state (&manager, 3));
	CuAssertIntEquals (test, DEVICE_MANAGER_ATTESTATION_INTERRUPTED,
		device_manager_get_device_state (&manager, 4));

	/* Prove the unidentified list was cleared. */
	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
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

static void device_manager_test_restart_device_discovery (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_restart_device_discovery (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 0));
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 1));
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED,
		device_manager_get_device_state (&manager, 2));

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_no_responders (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_restart_device_discovery (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 0));
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 1));

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_mark_devices_unidentified (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 3, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_NEVER_ATTESTED);
	status |= device_manager_update_device_state (&manager, 3,
		DEVICE_MANAGER_READY_FOR_ATTESTATION);
	status |= device_manager_update_device_state (&manager, 4,
		DEVICE_MANAGER_ATTESTATION_INTERRUPTED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_restart_device_discovery (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 0));
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 1));
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED,
		device_manager_get_device_state (&manager, 2));
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED,
		device_manager_get_device_state (&manager, 3));
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED,
		device_manager_get_device_state (&manager, 4));

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_null (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	status |= device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_restart_device_discovery (NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}
static void device_manager_test_get_device_num_by_device_ids (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0xCC,
		0xDD);
	CuAssertIntEquals (test, 1, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_device_ids_no_unidentified_devices (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0xCC,
		0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_device_ids_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_unidentified_device_num_by_device_ids (NULL, 0xAA, 0xBB, 0xCC,
		0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_num_by_device_ids_device_not_found (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0, 0xBB, 0xCC,
		0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xAA, 0, 0xCC,
		0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0,
		0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0xCC,
		0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_instance_ids (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xAA, 0xBB, 0xCC,
		0xDD, 0xEE);
	CuAssertIntEquals (test, 1, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_instance_ids_no_unidentified_devices (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xAA, 0xBB, 0xCC,
		0xDD, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num_by_instance_ids_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_num_by_device_and_instance_ids (NULL, 0xAA, 0xBB, 0xCC, 0xDD,
		0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_num_by_instance_ids_device_not_found (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 1, 0xEE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0, 0xBB, 0xCC,
		0xDD, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xAA, 0, 0xCC,
		0xDD, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xAA, 0xBB, 0,
		0xDD, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xAA, 0xBB, 0xCC,
		0, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_get_device_num_by_device_and_instance_ids (&manager, 0xAA, 0xBB, 0xCC,
		0xDD, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_ids (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_unidentified_device_num_by_device_ids (&manager, 0xAA, 0xBB, 0xCC,
		0xDD);
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

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, -1, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

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

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_attestation (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_single_attestation_failed (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_attestation_failed (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms != 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_single_attestation_authenticated (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 5000));
	CuAssertTrue (test, (duration_ms > 1000));

	device_manager_release (&manager);
}

static void
device_manager_test_get_time_till_next_action_single_attestation_authenticated_without_certs (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1,
		DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 5000));
	CuAssertTrue (test, (duration_ms > 1000));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_single_attestation_device_not_present (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NEVER_ATTESTED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_PRESENT);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms > 0));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_attestation_authenticated (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 5000));
	CuAssertTrue (test, (duration_ms > 1000));

	device_manager_release (&manager);
}

static void
device_manager_test_get_time_till_next_action_multiple_attestation_authenticated_without_certs (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1,
		DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2,
		DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 5000));
	CuAssertTrue (test, (duration_ms > 1000));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_attestation_device_not_present (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NEVER_ATTESTED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_NEVER_ATTESTED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_PRESENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_NOT_PRESENT);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms > 0));

	device_manager_release (&manager);
}

static void
device_manager_test_get_time_till_next_action_multiple_attestation_authenticated_and_unauthenticated
(
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms != 0));

	device_manager_release (&manager);
}

static void
device_manager_test_get_time_till_next_action_multiple_attestation_authenticated_without_certs_and_unauthenticated
(
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 2, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2,
		DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms != 0));

	device_manager_release (&manager);
}


static void device_manager_test_get_time_till_next_action_single_discovery (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
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

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
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

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 10000));
	CuAssertTrue (test, (duration_ms > 5000));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_discovery_timeout (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
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
	CuAssertTrue (test, (duration_ms <= 10000));
	CuAssertTrue (test, (duration_ms > 5000));

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_multiple_discovery_some_timeout (
	CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_UNIDENTIFIED);
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

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 1, 0xCC);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms != 0));

	status = device_manager_add_unidentified_device (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	status = device_manager_unidentified_device_timed_out (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms <= 1000));
	CuAssertTrue (test, (duration_ms != 0));

	device_manager_release (&manager);
}


static void device_manager_test_get_time_till_next_action_no_devices (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, DEVICE_MANAGER_MIN_ACTIVITY_CHECK, duration_ms);

	device_manager_release (&manager);
}

static void device_manager_test_get_time_till_next_action_invalid_arg (CuTest *test)
{
	uint32_t duration_ms;

	TEST_START;

	duration_ms = device_manager_get_time_till_next_action (NULL);
	CuAssertIntEquals (test, DEVICE_MANAGER_MIN_ACTIVITY_CHECK, duration_ms);
}

static void device_manager_test_get_attestation_status (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[1524];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device, ++i_pcd) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_pcd);
		CuAssertIntEquals (test, 0, status);

		switch (i_pcd % 5) {
			case 0:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_AUTHENTICATED);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED;
				break;

			case 1:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_READY_FOR_ATTESTATION);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_READY_FOR_ATTESTATION;
				break;

			case 2:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_UNIDENTIFIED);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_UNIDENTIFIED;
				break;

			case 3:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_ATTESTATION_FAILED);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_ATTESTATION_FAILED;
				break;

			default:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_NEVER_ATTESTED);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_NEVER_ATTESTED;
		}

		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_no_responder_devices (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, (void*) attestation_status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_unauthenticated (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[1524];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device, ++i_pcd) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_pcd);
		status |= device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_READY_FOR_ATTESTATION;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_unauthenticated_not_max (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[60];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 10, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 11; ++i_device, ++i_pcd) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_pcd);
		status |= device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_READY_FOR_ATTESTATION;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_authenticated (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[1524];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 255; ++i_device) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_device);
		status |= device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_authenticated_without_certs (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[1524];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 255; ++i_device) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_device);
		status |= device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_authenticated_not_max (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[60];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 10, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 11; ++i_device) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_device);
		status |= device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_authenticated_without_certs_not_max (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[60];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 10, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1; i_device < 11; ++i_device) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_device);
		status |= device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_non_unique_components (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[889];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 127, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		switch (i_pcd % 5) {
			case 0:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_AUTHENTICATED);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED;
				break;

			case 1:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_READY_FOR_ATTESTATION);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_READY_FOR_ATTESTATION;
				break;

			case 2:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_UNIDENTIFIED);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_UNIDENTIFIED;
				break;

			case 3:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_ATTESTATION_FAILED);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_ATTESTATION_FAILED;
				break;

			default:
				status = device_manager_update_device_state (&manager, i_device,
					DEVICE_MANAGER_NEVER_ATTESTED);
				attestation_status_expected[i_entry++] = DEVICE_MANAGER_NEVER_ATTESTED;
		}
		CuAssertIntEquals (test, 0, status);
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_unauthenticated_non_unique_components (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[889];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 127, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_READY_FOR_ATTESTATION;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void
device_manager_test_get_attestation_status_all_unauthenticated_not_max_non_unique_components (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[35];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 5, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 11; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_READY_FOR_ATTESTATION;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_all_authenticated_non_unique_components (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[889];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 127, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void
device_manager_test_get_attestation_status_all_authenticated_without_certs_non_unique_components (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[889];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 127, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void
device_manager_test_get_attestation_status_all_authenticated_not_max_non_unique_components (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[35];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 5, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 11; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void
device_manager_test_get_attestation_status_all_authenticated_without_certs_not_max_non_unique_components
(
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[35];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 5, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 11; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_mark_component_attestation_invalid_non_unique_components (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[889];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 127, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = 0xFF;
	}

	status = device_manager_mark_component_attestation_invalid (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_mark_component_attestation_invalid_not_max_non_unique_components (
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[35];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 5, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 11; ++i_device) {
		if (i_device % 2) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 2;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = 0xFF;
	}

	status = device_manager_mark_component_attestation_invalid (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void
device_manager_test_get_attestation_status_all_unauthenticated_non_unique_components_different_ratio
(
	CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[672];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 84, 252, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 253; ++i_device) {
		if ((i_device - 1) % 3 == 0) {
			supported_component =
				(struct pcd_supported_component*) &attestation_status_expected[i_entry];
			supported_component->component_id = component_id + i_device;
			supported_component->component_count = 3;
			i_entry += sizeof (struct pcd_supported_component);

			status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
				0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
				i_pcd);
			CuAssertIntEquals (test, 0, status);

			++i_pcd;
		}

		status = device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = DEVICE_MANAGER_READY_FOR_ATTESTATION;
	}

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

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
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[1524];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 254, 254, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 255; ++i_device, ++i_pcd) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_pcd);
		status |= device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = 0xFF;
	}

	status = device_manager_mark_component_attestation_invalid (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_mark_component_attestation_invalid_not_max (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int i_device;
	int i_pcd;
	int status;
	uint32_t component_id = 50;
	uint8_t attestation_status_expected[60];
	struct pcd_supported_component *supported_component;
	int i_entry = 0;

	TEST_START;

	status = device_manager_init (&manager, 1, 10, 10, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	for (i_device = 1, i_pcd = 0; i_device < 11; ++i_device, ++i_pcd) {
		supported_component =
			(struct pcd_supported_component*) &attestation_status_expected[i_entry];
		supported_component->component_id = component_id + i_device;
		supported_component->component_count = 1;
		i_entry += sizeof (struct pcd_supported_component);

		status = device_manager_update_mctp_bridge_device_entry (&manager, i_device, 0xBB, 0xAA,
			0xCC, 0xDD, supported_component->component_count, supported_component->component_id,
			i_pcd);
		status |= device_manager_update_device_state (&manager, i_device,
			DEVICE_MANAGER_AUTHENTICATED);
		CuAssertIntEquals (test, 0, status);

		attestation_status_expected[i_entry++] = 0xFF;
	}

	status = device_manager_mark_component_attestation_invalid (&manager);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_status (&manager, &attestation_status);
	CuAssertIntEquals (test, sizeof (attestation_status_expected), status);

	status = testing_validate_array (attestation_status_expected, attestation_status,
		sizeof (attestation_status_expected));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_attestation_status_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *attestation_status;
	int status;

	TEST_START;

	status = device_manager_get_attestation_status (NULL, (const uint8_t**) &attestation_status);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_attestation_status (&manager, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_is_device_unattestable (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_is_device_unattestable (&manager, 0xAA);
	CuAssertIntEquals (test, true, status);

	status = device_manager_is_device_unattestable (&manager, 0xCC);
	CuAssertIntEquals (test, true, status);

	status = device_manager_is_device_unattestable (&manager, 0xBB);
	CuAssertIntEquals (test, false, status);

	device_manager_release (&manager);
}

static void device_manager_test_is_device_unattestable_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_is_device_unattestable (NULL, 0xBB);
	CuAssertIntEquals (test, false, status);
}

static void device_manager_test_get_rsp_not_ready_limits (CuTest *test)
{
	struct device_manager manager;
	uint32_t max_timeout_ms;
	uint8_t max_retries;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 100, 10);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_rsp_not_ready_limits (&manager, &max_timeout_ms, &max_retries);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 100, max_timeout_ms);
	CuAssertIntEquals (test, 10, max_retries);

	device_manager_release (&manager);
}

static void device_manager_test_get_rsp_not_ready_limits_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint32_t max_timeout_ms;
	uint8_t max_retries;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 100, 10);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_rsp_not_ready_limits (NULL, &max_timeout_ms, &max_retries);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_rsp_not_ready_limits (&manager, NULL, &max_retries);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_rsp_not_ready_limits (&manager, &max_timeout_ms, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_mctp_ctrl_timeout (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 10, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_mctp_ctrl_timeout (&manager);
	CuAssertIntEquals (test, 10, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_mctp_ctrl_timeout_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_mctp_ctrl_timeout (NULL);
	CuAssertIntEquals (test, DEVICE_MANAGER_MCTP_CTRL_PROTOCOL_TIMEOUT_MS, status);
}

static void device_manager_test_set_force_action (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint8_t data[10];
	int status;

	TEST_START;

	memset (data, 0xAA, sizeof (data));
	data[0] = 1;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	memcpy (&action_data, data, sizeof (data));

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION,
		manager.force_action.type);
	status = testing_validate_array (data, (uint8_t*) &manager.force_action.action_data,
		manager.force_action.data_size);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, manager.force_action.data_size);

	device_manager_release (&manager);
}

static void device_manager_test_set_force_action_bad_data_size (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	int num_actions;
	int status;
	uint8_t data_comp[] = {3, 0x11, 0, 0, 0, 1};
	uint8_t data_dev[] = {4, 0x11, 0, 0, 0, 1, 0, 0, 0, 2};

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_FAILED;
	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);
	device_manager_process_force_action (&manager, &num_actions);
	device_manager_clear_force_action_set_state (&manager, DEVICE_MANAGER_FORCE_ACTION_IDLE);

	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_FAILED;
	status = device_manager_set_force_action (&manager, &action_data, 2,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_INVALID_DATA, status);

	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_PASSED;
	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);
	device_manager_process_force_action (&manager, &num_actions);
	device_manager_clear_force_action_set_state (&manager, DEVICE_MANAGER_FORCE_ACTION_IDLE);

	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_PASSED;
	status = device_manager_set_force_action (&manager, &action_data, 6,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_INVALID_DATA, status);

	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;
	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);
	device_manager_process_force_action (&manager, &num_actions);
	device_manager_clear_force_action_set_state (&manager, DEVICE_MANAGER_FORCE_ACTION_IDLE);

	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;
	status = device_manager_set_force_action (&manager, &action_data, 10,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_INVALID_DATA, status);

	memcpy (&action_data, data_comp, sizeof (data_comp));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_COMPONENT_ID;
	status = device_manager_set_force_action (&manager, &action_data, 6,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	device_manager_clear_force_action_set_state (&manager, DEVICE_MANAGER_FORCE_ACTION_IDLE);

	memcpy (&action_data, data_comp, sizeof (data_comp));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_COMPONENT_ID;
	status = device_manager_set_force_action (&manager, &action_data, 10,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_INVALID_DATA, status);

	memcpy (&action_data, data_dev, sizeof (data_dev));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_DEVICE_IDS;
	status = device_manager_set_force_action (&manager, &action_data, 10,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	device_manager_clear_force_action_set_state (&manager, DEVICE_MANAGER_FORCE_ACTION_IDLE);

	memcpy (&action_data, data_dev, sizeof (data_dev));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_DEVICE_IDS;
	status = device_manager_set_force_action (&manager, &action_data, 6,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_INVALID_DATA, status);

	device_manager_release (&manager);
}

static void device_manager_test_set_force_action_replace_existing (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data1;
	struct device_manager_force_action_data action_data2;
	uint8_t data1[] = {4, 0xaa, 0, 0xbb, 0, 0xcc, 0, 0xdd, 0, 6};
	uint8_t data2[] = {4, 0xee, 0, 0xff, 0, 0xee, 0, 0xff, 0, 7};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 2, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 2, 0xAA, 0xBB, 0xCC, 0xDD);
	status |= device_manager_update_device_instance_id (&manager, 2, 6);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_ids (&manager, 3, 0xee, 0xff, 0xee, 0xff);
	status |= device_manager_update_device_instance_id (&manager, 3, 7);
	CuAssertIntEquals (test, 0, status);

	/* Set first action */
	memcpy (&action_data1, data1, 10);

	status = device_manager_set_force_action (&manager, &action_data1, 10,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	/* Attempt to replace with second action - should be rejected */
	memcpy (&action_data2, data2, 10);

	status = device_manager_set_force_action (&manager, &action_data2, 10,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_PENDING, status);

	/* Verify first action is still pending */
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION,
		manager.force_action.type);
	status = testing_validate_array (data1, (uint8_t*) &manager.force_action.action_data, 10);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, manager.force_action.data_size);

	device_manager_release (&manager);
}

static void device_manager_test_set_force_action_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Test NULL manager */
	struct device_manager_force_action_data action_data_null;

	status = device_manager_set_force_action (NULL, &action_data_null, 0,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_set_force_action_data_bad_device_ids (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Set up a device with known IDs */
	status = device_manager_update_device_ids (&manager, 2, 0xAA, 0xBB, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_instance_id (&manager, 2, 0x55);
	CuAssertIntEquals (test, 0, status);

	/* Try to set force action with device IDs that don't match any device */
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_DEVICE_IDS;
	action_data.target.device_ids.pci_vid = 0x0011;
	action_data.target.device_ids.pci_device_id = 0x0022;
	action_data.target.device_ids.pci_subsystem_vid = 0x0033;
	action_data.target.device_ids.pci_subsystem_id = 0x0044;
	action_data.target.device_ids.instance_id = 0x66;

	status = device_manager_set_force_action (&manager, &action_data, 10,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_DEVICE_IDS;
	action_data.target.device_ids.pci_vid = 0x00AA;
	action_data.target.device_ids.pci_device_id = 0x00BB;
	action_data.target.device_ids.pci_subsystem_vid = 0x00CC;
	action_data.target.device_ids.pci_subsystem_id = 0x00DD;
	action_data.target.device_ids.instance_id = 0x55;

	status = device_manager_set_force_action (&manager, &action_data, 10,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_set_force_action_data_bad_component_ids (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 2, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		50, 0);
	CuAssertIntEquals (test, 0, status);

	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_COMPONENT_ID;
	action_data.target.component.component_id = 0x11;
	action_data.target.component.instance_id = 4;

	status = device_manager_set_force_action (&manager, &action_data, 6,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_COMPONENT_ID;
	action_data.target.component.component_id = 50;
	action_data.target.component.instance_id = 0;

	status = device_manager_set_force_action (&manager, &action_data, 6,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_force_action (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint8_t data = 1;
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	action_data.mode = data;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_clear_force_action_set_state (&manager,
		DEVICE_MANAGER_FORCE_ACTION_IDLE);
	CuAssertIntEquals (test, 0, status);

	/* Verify action is cleared */
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_IDLE, manager.force_action.state);

	device_manager_release (&manager);
}

static void device_manager_test_clear_force_action_no_action (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Test clearing when no action exists - should succeed */
	status = device_manager_clear_force_action_set_state (&manager,
		DEVICE_MANAGER_FORCE_ACTION_IDLE);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_force_action_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_clear_force_action_set_state (NULL, DEVICE_MANAGER_FORCE_ACTION_IDLE);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Out-of-range state value must be rejected */
	status = device_manager_clear_force_action_set_state (&manager,
		(enum device_manager_force_action_state) (DEVICE_MANAGER_FORCE_ACTION_IN_PROGRESS + 1));
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_INVALID_STATE, status);

	device_manager_release (&manager);
}

static void device_manager_test_clear_force_action_pending_to_idle_rejected (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Queue a force action to transition to PENDING */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_PENDING, manager.force_action.state);

	/* Attempting PENDING -> IDLE directly must be rejected */
	status = device_manager_clear_force_action_set_state (&manager,
		DEVICE_MANAGER_FORCE_ACTION_IDLE);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_INVALID_STATE_CHANGE, status);

	/* State must remain PENDING */
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_PENDING, manager.force_action.state);

	device_manager_release (&manager);
}

static void device_manager_test_clear_force_action_idle_to_in_progress_rejected (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* State starts as IDLE - jumping directly to IN_PROGRESS must be rejected */
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_IDLE, manager.force_action.state);

	status = device_manager_clear_force_action_set_state (&manager,
		DEVICE_MANAGER_FORCE_ACTION_IN_PROGRESS);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_INVALID_STATE_CHANGE, status);

	/* State must remain IDLE */
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_IDLE, manager.force_action.state);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_force_attestation_failed (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint8_t data;
	int num_actions;
	int status;

	TEST_START;

	data = DEVICE_MANAGER_FORCE_ATTESTATION_FAILED;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Setup device entries */
	status = device_manager_update_device_eid (&manager, 1, 0x0B);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	action_data.mode = data;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	num_actions = 0;
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_actions);

	/* Check device 1 (failed) was reset */
	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ATTESTATION, status);

	/* Check device 2 (authenticated) was not reset */
	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_force_attestation_passed (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint8_t data;
	int num_actions;
	int status;

	TEST_START;

	data = DEVICE_MANAGER_FORCE_ATTESTATION_PASSED;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Setup device entries */
	status = device_manager_update_device_eid (&manager, 1, 0x0B);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	action_data.mode = data;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	num_actions = 0;
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, num_actions);

	/* Check device 1 (failed) was not reset */
	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_ATTESTATION_FAILED, status);

	/* Check device 2 (authenticated) was reset */
	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ATTESTATION, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_force_attestation_all (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint8_t data;
	int num_actions;
	int status;

	TEST_START;

	data = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Setup device entries */
	status = device_manager_update_device_eid (&manager, 1, 0x0B);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	action_data.mode = data;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	num_actions = 0;
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, num_actions);

	/* Check both devices were reset */
	status = device_manager_get_device_state (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ATTESTATION, status);

	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ATTESTATION, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_no_action (CuTest *test)
{
	struct device_manager manager;
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Process when no action is set - should succeed */
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int num_actions;
	int status;

	TEST_START;

	/* Test NULL manager */
	status = device_manager_process_force_action (NULL, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	/* Test NULL num_actions with valid manager */
	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_process_force_action (&manager, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	/* Confirm num_actions still works normally */
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}


static void device_manager_test_update_component_device_entry_multi_source (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[2] = {
		{.cfm_component_id = 100, .min_usage = 0, .max_usage = 0},
		{.cfm_component_id = 200, .min_usage = 2, .max_usage = 3}
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 3, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 2;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 3, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	/* Verify each instance got its own deep copy of the type list */
	CuAssertIntEquals (test, 2, manager.entries[2].component_type_count);
	CuAssertPtrNotNull (test, manager.entries[2].component_type_list);
	CuAssertIntEquals (test, 100, manager.entries[2].component_type_list[0].cfm_component_id);
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[0].min_usage);
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[0].max_usage);
	CuAssertIntEquals (test, 200, manager.entries[2].component_type_list[1].cfm_component_id);
	CuAssertIntEquals (test, 2, manager.entries[2].component_type_list[1].min_usage);
	CuAssertIntEquals (test, 3, manager.entries[2].component_type_list[1].max_usage);

	/* Verify instance IDs are sequential */
	CuAssertIntEquals (test, 0, manager.entries[2].instance_id);
	CuAssertIntEquals (test, 1, manager.entries[3].instance_id);
	CuAssertIntEquals (test, 2, manager.entries[4].instance_id);

	/* Verify second instance also has deep-copied type list */
	CuAssertIntEquals (test, 2, manager.entries[3].component_type_count);
	CuAssertPtrNotNull (test, manager.entries[3].component_type_list);
	CuAssertIntEquals (test, 100, manager.entries[3].component_type_list[0].cfm_component_id);
	CuAssertIntEquals (test, 200, manager.entries[3].component_type_list[1].cfm_component_id);
	CuAssertIntEquals (test, 2, manager.entries[3].component_type_list[1].min_usage);
	CuAssertIntEquals (test, 3, manager.entries[3].component_type_list[1].max_usage);

	/* Verify each instance got its own allocation (not sharing pointers) */
	CuAssertTrue (test,
		manager.entries[2].component_type_list != manager.entries[3].component_type_list);
	CuAssertTrue (test,
		manager.entries[3].component_type_list != manager.entries[4].component_type_list);

	/* Verify component_id is propagated */
	CuAssertIntEquals (test, 50, manager.entries[2].component_id);
	CuAssertIntEquals (test, 50, manager.entries[3].component_id);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_device_entry_single_source (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	uint32_t device_component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 75;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 0;
	comp_entry.component_type_list = NULL;

	status = device_manager_update_component_device_entry (&manager, 2, 2, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	/* Single-source with NULL list: skip allocation, accessor returns component_id */
	CuAssertIntEquals (test, 1, manager.entries[2].component_type_count);
	CuAssertPtrEquals (test, NULL, manager.entries[2].component_type_list);
	CuAssertIntEquals (test, 75, manager.entries[2].component_id);

	CuAssertIntEquals (test, 1, manager.entries[3].component_type_count);
	CuAssertPtrEquals (test, NULL, manager.entries[3].component_type_list);

	status = device_manager_get_component_type (&manager, 2, 0, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 75, device_component_id);

	status = device_manager_get_component_type (&manager, 3, 0, &device_component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 75, device_component_id);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_device_entry_single_source_redirect (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[1] = {
		{.cfm_component_id = 300, .min_usage = 0, .max_usage = 0}
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* component_type_count=1 means single source redirect: generic ID differs from CFM policy ID */
	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 1;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, manager.entries[2].component_type_count);
	CuAssertPtrNotNull (test, manager.entries[2].component_type_list);
	CuAssertIntEquals (test, 300, manager.entries[2].component_type_list[0].cfm_component_id);
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[0].min_usage);
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[0].max_usage);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_device_entry_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* NULL manager */
	status = device_manager_update_component_device_entry (NULL, 2, 2, &comp_entry);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	/* Zero components_count */
	status = device_manager_update_component_device_entry (&manager, 2, 0, &comp_entry);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	/* NULL entry */
	status = device_manager_update_component_device_entry (&manager, 2, 2, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_device_entry_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* device_num out of range */
	status = device_manager_update_component_device_entry (&manager, 10, 2, &comp_entry);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	/* negative device_num */
	status = device_manager_update_component_device_entry (&manager, -1, 2, &comp_entry);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_device_entry_too_many_components (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* components_count exceeds available entries */
	status = device_manager_update_component_device_entry (&manager, 2, 5, &comp_entry);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_device_entry_min_max_enforcement (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[3] = {
		{.cfm_component_id = 100, .min_usage = 1, .max_usage = 3},
		{.cfm_component_id = 200, .min_usage = 0, .max_usage = 5},
		{.cfm_component_id = 300, .min_usage = 2, .max_usage = 2}
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 3;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 2, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	/* Verify min/max values are preserved correctly for all entries in the type list */
	CuAssertIntEquals (test, 3, manager.entries[2].component_type_count);

	CuAssertIntEquals (test, 100, manager.entries[2].component_type_list[0].cfm_component_id);
	CuAssertIntEquals (test, 1, manager.entries[2].component_type_list[0].min_usage);
	CuAssertIntEquals (test, 3, manager.entries[2].component_type_list[0].max_usage);

	CuAssertIntEquals (test, 200, manager.entries[2].component_type_list[1].cfm_component_id);
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[1].min_usage);
	CuAssertIntEquals (test, 5, manager.entries[2].component_type_list[1].max_usage);

	CuAssertIntEquals (test, 300, manager.entries[2].component_type_list[2].cfm_component_id);
	CuAssertIntEquals (test, 2, manager.entries[2].component_type_list[2].min_usage);
	CuAssertIntEquals (test, 2, manager.entries[2].component_type_list[2].max_usage);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_device_entry_no_enforcement (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[2] = {
		{.cfm_component_id = 100, .min_usage = 0, .max_usage = 0},
		{.cfm_component_id = 200, .min_usage = 0, .max_usage = 0}
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 2;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	/* min=0, max=0 means no enforcement per design doc */
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[0].min_usage);
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[0].max_usage);
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[1].min_usage);
	CuAssertIntEquals (test, 0, manager.entries[2].component_type_list[1].max_usage);

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_by_handler (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover_a;
	struct attestation_discover discover_b;
	const struct device_manager_entry entry_a = {
		.pci_vid = 0xAA,
		.pci_device_id = 0xBB,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 10,
		.pcd_component_index = 0,
		.discover = &discover_a,
	};
	const struct device_manager_entry entry_b = {
		.pci_vid = 0x11,
		.pci_device_id = 0x22,
		.pci_subsystem_vid = 0x33,
		.pci_subsystem_id = 0x44,
		.component_id = 20,
		.pcd_component_index = 1,
		.discover = &discover_b,
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 2, 4, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0x10, 0x20,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 2, 2, &entry_a);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 4, 2, &entry_b);
	CuAssertIntEquals (test, 0, status);

	/* Move handler_a devices to NEVER_ATTESTED */
	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_NEVER_ATTESTED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_NEVER_ATTESTED);
	/* Move handler_b devices to AUTHENTICATED */
	status |= device_manager_update_device_state (&manager, 4, DEVICE_MANAGER_AUTHENTICATED);
	status |= device_manager_update_device_state (&manager, 5, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	/* Reset only handler_a devices */
	status = device_manager_restart_device_discovery_by_handler (&manager, &discover_a);
	CuAssertIntEquals (test, 0, status);

	/* Non-attestable stays unchanged */
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 0));
	CuAssertIntEquals (test, DEVICE_MANAGER_NOT_ATTESTABLE,
		device_manager_get_device_state (&manager, 1));

	/* Handler_a devices reset to UNIDENTIFIED */
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED,
		device_manager_get_device_state (&manager, 2));
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED,
		device_manager_get_device_state (&manager, 3));

	/* Handler_b devices remain AUTHENTICATED */
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED,
		device_manager_get_device_state (&manager, 4));
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED,
		device_manager_get_device_state (&manager, 5));

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_by_handler_no_matching_devices (
	CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover_a;
	struct attestation_discover discover_b;
	const struct device_manager_entry entry_a = {
		.pci_vid = 0xAA,
		.pci_device_id = 0xBB,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 10,
		.pcd_component_index = 0,
		.discover = &discover_a,
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 2, 2, &entry_a);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	/* Reset with a handler that no device uses */
	status = device_manager_restart_device_discovery_by_handler (&manager, &discover_b);
	CuAssertIntEquals (test, 0, status);

	/* All devices unchanged */
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED,
		device_manager_get_device_state (&manager, 2));
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED,
		device_manager_get_device_state (&manager, 3));

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_by_handler_null (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_restart_device_discovery_by_handler (NULL, &discover);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_restart_device_discovery_by_handler (&manager, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_force_attestation_component_id (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	struct logging_mock logger;
	struct debug_log_entry_info entry_started = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_ACTION_STARTED,
		.arg1 = 1,
		.arg2 = DEVICE_MANAGER_FORCE_ATTESTATION_COMPONENT_ID
	};
	struct debug_log_entry_info entry_initiated = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_INITIATED,
		.arg1 = 0x030C,
		.arg2 = 50
	};
	struct debug_log_entry_info entry_completed = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_ACTION_COMPLETED,
		.arg1 = 1,
		.arg2 = 0
	};
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 2, 3, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Setup MCTP bridge device entries with specific component IDs */
	status = device_manager_update_mctp_bridge_device_entry (&manager, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		50, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 2, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 3, 0xEE, 0xFF, 0x11, 0x22, 1,
		75, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 3, 1);
	CuAssertIntEquals (test, 0, status);

	/* Set device 2 to authenticated state */
	status = device_manager_update_device_eid (&manager, 2, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	/* Set device 3 to failed state */
	status = device_manager_update_device_eid (&manager, 3, 0x0D);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	/* Create force action for component ID 50, instance 3 */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_COMPONENT_ID;
	action_data.target.component.component_id = 50;
	action_data.target.component.instance_id = 3;

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_started, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_started)));
	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_initiated, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_initiated)));
	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_completed, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_completed)));

	CuAssertIntEquals (test, 0, status);

	status = device_manager_set_force_action (&manager, &action_data, 6,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	num_actions = 0;
	status = device_manager_process_force_action (&manager, &num_actions);

	debug_log = NULL;

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_actions);

	/* Check device 2 (component 50, instance 3) was reset */
	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ATTESTATION, status);

	/* Check device 3 (component 75, instance 1) was not reset */
	status = device_manager_get_device_state (&manager, 3);
	CuAssertIntEquals (test, DEVICE_MANAGER_ATTESTATION_FAILED, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_force_attestation_device_ids (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	struct logging_mock logger;
	struct debug_log_entry_info entry_started = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_ACTION_STARTED,
		.arg1 = 1,
		.arg2 = DEVICE_MANAGER_FORCE_ATTESTATION_DEVICE_IDS
	};
	struct debug_log_entry_info entry_initiated = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_INITIATED,
		.arg1 = 0x050C,
		.arg2 = 60
	};
	struct debug_log_entry_info entry_completed = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_ACTION_COMPLETED,
		.arg1 = 1,
		.arg2 = 0
	};
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 2, 3, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Setup device entries with specific device IDs and component IDs */
	status = device_manager_update_mctp_bridge_device_entry (&manager, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		60, 0);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_instance_id (&manager, 2, 0x05);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 3, 0xEE, 0xFF, 0x11, 0x22, 1,
		80, 1);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_instance_id (&manager, 3, 0x06);
	CuAssertIntEquals (test, 0, status);

	/* Set device 2 to authenticated state */
	status = device_manager_update_device_eid (&manager, 2, 0x0C);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	/* Set device 3 to failed state */
	status = device_manager_update_device_eid (&manager, 3, 0x0D);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	/* Create force action for device IDs matching device 2 */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_DEVICE_IDS;
	action_data.target.device_ids.pci_vid = 0x00AA;
	action_data.target.device_ids.pci_device_id = 0x00BB;
	action_data.target.device_ids.pci_subsystem_vid = 0x00CC;
	action_data.target.device_ids.pci_subsystem_id = 0x00DD;
	action_data.target.device_ids.instance_id = 0x05;

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_started, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_started)));
	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_initiated, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_initiated)));
	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_completed, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_completed)));

	CuAssertIntEquals (test, 0, status);

	status = device_manager_set_force_action (&manager, &action_data, 10,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	num_actions = 0;
	status = device_manager_process_force_action (&manager, &num_actions);

	debug_log = NULL;

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_actions);

	/* Check device 2 (matching device IDs) was reset */
	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ATTESTATION, status);

	/* Check device 3 (different device IDs) was not reset */
	status = device_manager_get_device_state (&manager, 3);
	CuAssertIntEquals (test, DEVICE_MANAGER_ATTESTATION_FAILED, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_check_force_action_idle (CuTest *test)
{
	struct device_manager manager;
	uint32_t action_id = 0xFF;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, action_id);

	device_manager_release (&manager);
}

static void device_manager_test_check_force_action_pending (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint32_t action_id = 0;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_PENDING, status);
	CuAssertIntEquals (test, 1, action_id);

	device_manager_release (&manager);
}

static void device_manager_test_check_force_action_in_progress (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint32_t action_id = 0xFF;
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Transition to IN_PROGRESS via set + process to simulate attestation loop running */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_IN_PROGRESS, status);
	CuAssertIntEquals (test, 1, action_id);

	device_manager_release (&manager);
}

static void device_manager_test_check_force_action_null_action_id (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_force_action_state (&manager, NULL);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_set_force_action_in_progress_rejected (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Transition to IN_PROGRESS via set + process to simulate attestation loop running */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);

	/* Attempt to queue a new action while force attestation is in progress */
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_IN_PROGRESS, status);

	device_manager_release (&manager);
}

static void device_manager_test_set_force_action_action_id_increments (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint32_t action_id = 0;
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Queue first action */
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	/* Verify action_id is 1 */
	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_PENDING, status);
	CuAssertIntEquals (test, 1, action_id);

	/* Process and clear the pending action */
	device_manager_process_force_action (&manager, &num_actions);
	device_manager_clear_force_action_set_state (&manager, DEVICE_MANAGER_FORCE_ACTION_IDLE);

	/* Queue second action */
	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	/* Verify action_id incremented to 2 */
	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_PENDING, status);
	CuAssertIntEquals (test, 2, action_id);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state_force_attestation_timeout_zero (CuTest *test)
{
	struct device_manager manager;
	uint32_t duration_ms;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 5000, 10000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* First set to authenticated with non-zero timeout */
	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertTrue (test, (duration_ms != 0));

	/* Now set to FORCE_ATTESTATION - should have timeout 0 (immediate) */
	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	duration_ms = device_manager_get_time_till_next_action (&manager);
	CuAssertIntEquals (test, 0, duration_ms);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_noop_when_in_progress (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint32_t action_id = 0;
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Queue and process a force attestation to transition to IN_PROGRESS */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	num_actions = 0;
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (num_actions > 0));

	/* Verify state is IN_PROGRESS */
	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_IN_PROGRESS, status);

	/* Call process_force_action again while IN_PROGRESS - should be a no-op returning 0 */
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);

	/* Verify state remains IN_PROGRESS (no-op does not change state) */
	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_IN_PROGRESS, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_sets_in_progress (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint32_t action_id = 0;
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Queue a force attestation */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	/* Process it - should apply actions and transition to IN_PROGRESS */
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);

	/* Verify check_force_action now returns IN_PROGRESS with correct action_id */
	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_IN_PROGRESS, status);
	CuAssertIntEquals (test, 1, action_id);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_sets_none_when_zero_actions (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	uint32_t action_id = 0;
	int num_actions;
	int status;

	TEST_START;

	/* Init with only 1 requester (self) and 0 responders — no attestable devices */
	status = device_manager_init_ac_rot (&manager, 1, DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	/* Queue a force attestation ALL — but there are no attestable devices */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	/* Verify action was queued */
	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_PENDING, status);
	CuAssertIntEquals (test, 1, action_id);

	/* Process it — always transitions to IN_PROGRESS regardless of num_actions */
	status = device_manager_process_force_action (&manager, &num_actions);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_actions);

	/* Verify state is IN_PROGRESS (process always sets this) */
	status = device_manager_get_force_action_state (&manager, &action_id);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ACTION_IN_PROGRESS, status);

	/* Verify a new action cannot be queued while IN_PROGRESS */
	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, DEVICE_MGR_FORCE_ACTION_IN_PROGRESS, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_logging_start_and_complete (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	struct logging_mock logger;
	int num_actions;
	struct debug_log_entry_info entry_started = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_ACTION_STARTED,
		.arg1 = 1,
		.arg2 = DEVICE_MANAGER_FORCE_ATTESTATION_ALL
	};
	struct debug_log_entry_info entry_completed = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_ACTION_COMPLETED,
		.arg1 = 1,
		.arg2 = 0
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1, 0, 0, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Only the self device exists, which is NOT_ATTESTABLE — no INITIATED logs expected */
	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_started, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_started)));
	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_completed, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_completed)));

	CuAssertIntEquals (test, 0, status);

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	status = device_manager_process_force_action (&manager, &num_actions);

	debug_log = NULL;

	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_process_force_action_logging_per_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_force_action_data action_data;
	struct logging_mock logger;
	struct debug_log_entry_info entry_started = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_ACTION_STARTED,
		.arg1 = 1,
		.arg2 = DEVICE_MANAGER_FORCE_ATTESTATION_ALL
	};
	struct debug_log_entry_info entry_dev1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_INITIATED,
		.arg1 = 0x030B,
		.arg2 = 50
	};
	struct debug_log_entry_info entry_dev2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_INITIATED,
		.arg1 = 0x040C,
		.arg2 = 75
	};
	struct debug_log_entry_info entry_completed = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_ATTESTATION,
		.msg_index = ATTESTATION_LOGGING_FORCE_ATTESTATION_ACTION_COMPLETED,
		.arg1 = 1,
		.arg2 = 0
	};
	int num_actions;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 2, 3, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	/* Mark non-target devices as NOT_ATTESTABLE so only devices 2 and 3 produce INITIATED logs */
	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_state (&manager, 4, DEVICE_MANAGER_NOT_ATTESTABLE);
	CuAssertIntEquals (test, 0, status);

	/* Setup two MCTP bridge device entries */
	status = device_manager_update_mctp_bridge_device_entry (&manager, 2, 0xAA, 0xBB, 0xCC, 0xDD, 1,
		50, 0);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_instance_id (&manager, 2, 3);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_eid (&manager, 2, 0x0B);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_READY_FOR_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_mctp_bridge_device_entry (&manager, 3, 0xEE, 0xFF, 0x11, 0x22, 1,
		75, 1);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_instance_id (&manager, 3, 4);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_eid (&manager, 3, 0x0C);
	CuAssertIntEquals (test, 0, status);
	status = device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_ATTESTATION_FAILED);
	CuAssertIntEquals (test, 0, status);

	memset (&action_data, 0, sizeof (action_data));
	action_data.mode = DEVICE_MANAGER_FORCE_ATTESTATION_ALL;

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_started, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_started)));
	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_dev1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_dev1)));
	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_dev2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_dev2)));
	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_completed, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_completed)));

	CuAssertIntEquals (test, 0, status);

	status = device_manager_set_force_action (&manager, &action_data, 1,
		DEVICE_MANAGER_FORCE_ACTION_FORCE_ATTESTATION);
	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;

	num_actions = 0;
	status = device_manager_process_force_action (&manager, &num_actions);

	debug_log = NULL;

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, num_actions);

	/* Verify both devices transitioned */
	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ATTESTATION, status);
	status = device_manager_get_device_state (&manager, 3);
	CuAssertIntEquals (test, DEVICE_MANAGER_FORCE_ATTESTATION, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_and_instances_by_handler (CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover_a;
	struct attestation_discover discover_b;
	const struct device_manager_entry entry_a = {
		.pci_vid = 0xAA,
		.pci_device_id = 0xBB,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 10,
		.pcd_component_index = 0,
		.discover = &discover_a,
	};
	const struct device_manager_entry entry_b = {
		.pci_vid = 0x11,
		.pci_device_id = 0x22,
		.pci_subsystem_vid = 0x33,
		.pci_subsystem_id = 0x44,
		.component_id = 20,
		.pcd_component_index = 1,
		.discover = &discover_b,
	};
	uint8_t instance_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 2, 4, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&manager, 1, 0x10, 0x20,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 2, 2, &entry_a);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 4, 2, &entry_b);
	CuAssertIntEquals (test, 0, status);

	/* Set instance IDs and move to NEVER_ATTESTED */
	status = device_manager_update_device_instance_id (&manager, 2, 5);
	status |= device_manager_update_device_instance_id (&manager, 3, 6);
	status |= device_manager_update_device_instance_id (&manager, 4, 7);
	status |= device_manager_update_device_instance_id (&manager, 5, 8);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_NEVER_ATTESTED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_NEVER_ATTESTED);
	status |= device_manager_update_device_state (&manager, 4, DEVICE_MANAGER_AUTHENTICATED);
	status |= device_manager_update_device_state (&manager, 5, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	/* Reset only handler_a devices (state + instance_id) */
	status = device_manager_restart_device_discovery_and_instances_by_handler (&manager,
		&discover_a);
	CuAssertIntEquals (test, 0, status);

	/* Handler_a devices reset to UNIDENTIFIED with instance_id = 0 */
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED,
		device_manager_get_device_state (&manager, 2));
	CuAssertIntEquals (test, DEVICE_MANAGER_UNIDENTIFIED,
		device_manager_get_device_state (&manager, 3));

	status = device_manager_get_instance_id (&manager, 2, &instance_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, instance_id);

	status = device_manager_get_instance_id (&manager, 3, &instance_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, instance_id);

	/* Handler_b devices remain AUTHENTICATED with original instance_ids */
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED,
		device_manager_get_device_state (&manager, 4));
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED,
		device_manager_get_device_state (&manager, 5));

	status = device_manager_get_instance_id (&manager, 4, &instance_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 7, instance_id);

	status = device_manager_get_instance_id (&manager, 5, &instance_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 8, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_and_instances_by_handler_no_matching (
	CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover_a;
	struct attestation_discover discover_b;
	const struct device_manager_entry entry_a = {
		.pci_vid = 0xAA,
		.pci_device_id = 0xBB,
		.pci_subsystem_vid = 0xCC,
		.pci_subsystem_id = 0xDD,
		.component_id = 10,
		.pcd_component_index = 0,
		.discover = &discover_a,
	};
	uint8_t instance_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_device_entry (&manager, 2, 2, &entry_a);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_instance_id (&manager, 2, 5);
	status |= device_manager_update_device_instance_id (&manager, 3, 6);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	status |= device_manager_update_device_state (&manager, 3, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	/* Reset with a handler that no device uses */
	status = device_manager_restart_device_discovery_and_instances_by_handler (&manager,
		&discover_b);
	CuAssertIntEquals (test, 0, status);

	/* All devices unchanged */
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED,
		device_manager_get_device_state (&manager, 2));
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED,
		device_manager_get_device_state (&manager, 3));

	status = device_manager_get_instance_id (&manager, 2, &instance_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, instance_id);

	status = device_manager_get_instance_id (&manager, 3, &instance_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 6, instance_id);

	device_manager_release (&manager);
}

static void device_manager_test_restart_device_discovery_and_instances_by_handler_null (
	CuTest *test)
{
	struct device_manager manager;
	struct attestation_discover discover;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_restart_device_discovery_and_instances_by_handler (NULL, &discover);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_restart_device_discovery_and_instances_by_handler (&manager, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_event_counters_by_eid (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_attestation_summary_event_counters event_counters;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_event_counters_by_eid (&manager, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_attestation_summary_event_counters (&manager, 2, &event_counters);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, event_counters.status_success_count);

	device_manager_release (&manager);
}

static void device_manager_test_update_attestation_summary_event_counters_by_eid_invalid_arg (
	CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_update_attestation_summary_event_counters_by_eid (NULL, 0xAA);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_update_attestation_summary_event_counters_by_eid_unknown_device (
	CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_attestation_summary_event_counters_by_eid (&manager, 0xFF);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_num_component_types (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[3] = {
		{.cfm_component_id = 100, .min_usage = 0, .max_usage = 0},
		{.cfm_component_id = 200, .min_usage = 0, .max_usage = 0},
		{.cfm_component_id = 300, .min_usage = 0, .max_usage = 0}
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 3;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_num_component_types (&manager, 2);
	CuAssertIntEquals (test, 3, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_num_component_types_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_num_component_types (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_num_component_types_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_num_component_types (&manager, 10);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[2] = {
		{.cfm_component_id = 100, .min_usage = 0, .max_usage = 0},
		{.cfm_component_id = 200, .min_usage = 0, .max_usage = 0}
	};
	uint32_t component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 2;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_type (&manager, 2, 0, &component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 100, (int) component_id);

	status = device_manager_get_component_type (&manager, 2, 1, &component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 200, (int) component_id);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_type (NULL, 2, 0, &component_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_component_type (&manager, 2, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type_unknown_device (CuTest *test)
{
	struct device_manager manager;
	uint32_t component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_type (&manager, 10, 0, &component_id);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type_invalid_index (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[2] = {
		{.cfm_component_id = 100, .min_usage = 0, .max_usage = 0},
		{.cfm_component_id = 200, .min_usage = 0, .max_usage = 0}
	};
	uint32_t component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 2;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_component_type (&manager, 2, 5, &component_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_component_type (&manager, 2, -1, &component_id);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_promote_matched_component_type (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[3] = {
		{.cfm_component_id = 100, .min_usage = 1, .max_usage = 5},
		{.cfm_component_id = 200, .min_usage = 2, .max_usage = 6},
		{.cfm_component_id = 300, .min_usage = 3, .max_usage = 7}
	};
	uint32_t component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 3;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	/* Promote index 2 to front */
	status = device_manager_promote_matched_component_type (&manager, 2, 2);
	CuAssertIntEquals (test, 0, status);

	/* Verify swap: index 0 should now be 300, index 2 should be 100 */
	status = device_manager_get_component_type (&manager, 2, 0, &component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 300, (int) component_id);

	status = device_manager_get_component_type (&manager, 2, 1, &component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 200, (int) component_id);

	status = device_manager_get_component_type (&manager, 2, 2, &component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 100, (int) component_id);

	/* Verify min/max were also swapped */
	CuAssertIntEquals (test, 3, manager.entries[2].component_type_list[0].min_usage);
	CuAssertIntEquals (test, 7, manager.entries[2].component_type_list[0].max_usage);
	CuAssertIntEquals (test, 1, manager.entries[2].component_type_list[2].min_usage);
	CuAssertIntEquals (test, 5, manager.entries[2].component_type_list[2].max_usage);

	device_manager_release (&manager);
}

static void device_manager_test_promote_matched_component_type_index_zero_noop (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[2] = {
		{.cfm_component_id = 100, .min_usage = 0, .max_usage = 0},
		{.cfm_component_id = 200, .min_usage = 0, .max_usage = 0}
	};
	uint32_t component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 2;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	/* Promote index 0 — should be a no-op */
	status = device_manager_promote_matched_component_type (&manager, 2, 0);
	CuAssertIntEquals (test, 0, status);

	/* Verify no change */
	status = device_manager_get_component_type (&manager, 2, 0, &component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 100, (int) component_id);

	status = device_manager_get_component_type (&manager, 2, 1, &component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 200, (int) component_id);

	device_manager_release (&manager);
}

static void device_manager_test_promote_matched_component_type_single_count_noop (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[1] = {
		{.cfm_component_id = 100, .min_usage = 0, .max_usage = 0}
	};
	uint32_t component_id;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 1;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	/* Promote index 0 with count=1 — should be a no-op */
	status = device_manager_promote_matched_component_type (&manager, 2, 0);
	CuAssertIntEquals (test, 0, status);

	/* Verify no change */
	status = device_manager_get_component_type (&manager, 2, 0, &component_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 100, (int) component_id);

	device_manager_release (&manager);
}

static void device_manager_test_promote_matched_component_type_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_promote_matched_component_type (NULL, 2, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_promote_matched_component_type_unknown_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_promote_matched_component_type (&manager, 10, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_promote_matched_component_type_invalid_index (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_entry comp_entry = {0};
	struct pcd_allowed_component_type_info type_list[2] = {
		{.cfm_component_id = 100, .min_usage = 0, .max_usage = 0},
		{.cfm_component_id = 200, .min_usage = 0, .max_usage = 0}
	};
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, 1, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	comp_entry.component_id = 50;
	comp_entry.pci_vid = 0xAA;
	comp_entry.pci_device_id = 0xBB;
	comp_entry.pci_subsystem_vid = 0xCC;
	comp_entry.pci_subsystem_id = 0xDD;
	comp_entry.pcd_component_index = 0;
	comp_entry.component_type_count = 2;
	comp_entry.component_type_list = type_list;

	status = device_manager_update_component_device_entry (&manager, 2, 1, &comp_entry);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_promote_matched_component_type (&manager, 2, 5);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

// *INDENT-OFF*
TEST_SUITE_START (device_manager);

TEST (device_manager_test_init);
TEST (device_manager_test_init_no_responder_devices);
TEST (device_manager_test_init_invalid_arg);
TEST (device_manager_test_init_invalid_responder_count);
TEST (device_manager_test_init_ac_rot);
TEST (device_manager_test_init_ac_rot_invalid_arg);
TEST (device_manager_test_release_null);
TEST (device_manager_test_add_device_manager_observer);
TEST (device_manager_test_add_device_manager_observer_invalid_arg);
TEST (device_manager_test_remove_device_manager_observer);
TEST (device_manager_test_remove_device_manager_observer_invalid_arg);
TEST (device_manager_test_get_device_capabilities);
TEST (device_manager_test_get_device_capabilities_init_ac_rot);
TEST (device_manager_test_get_device_capabilities_master_pa_rot);
TEST (device_manager_test_get_device_capabilities_null);
TEST (device_manager_test_get_device_capabilities_invalid_device);
TEST (device_manager_test_update_device_capabilities);
TEST (device_manager_test_update_device_capabilities_init_ac_rot);
TEST (device_manager_test_update_device_capabilities_invalid_arg);
TEST (device_manager_test_update_device_capabilities_invalid_device);
TEST (device_manager_test_get_device_capabilities_request);
TEST (device_manager_test_get_device_capabilities_request_init_ac_rot);
TEST (device_manager_test_get_device_capabilities_request_null);
TEST (device_manager_test_update_device_capabilities_request);
TEST (device_manager_test_update_device_capabilities_request_init_ac_rot);
TEST (device_manager_test_update_device_capabilities_request_invalid_arg);
TEST (device_manager_test_update_device_capabilities_request_invalid_device);
TEST (device_manager_test_update_not_attestable_device_entry);
TEST (device_manager_test_update_not_attestable_device_entry_init_ac_rot);
TEST (device_manager_test_update_not_attestable_device_entry_invalid_arg);
TEST (device_manager_test_update_not_attestable_device_entry_invalid_device);
TEST (device_manager_test_update_mctp_bridge_device_entry);
TEST (device_manager_test_update_mctp_bridge_device_entry_invalid_arg);
TEST (device_manager_test_update_mctp_bridge_device_entry_invalid_device);
TEST (device_manager_test_update_mctp_bridge_device_entry_too_many_components);
TEST (device_manager_test_update_device_entry);
TEST (device_manager_test_update_device_entry_invalid_arg);
TEST (device_manager_test_update_device_entry_invalid_device);
TEST (device_manager_test_update_device_entry_too_many_components);
TEST (device_manager_test_get_discovery_type);
TEST (device_manager_test_get_discovery_type_invalid_arg);
TEST (device_manager_test_get_discovery_type_unknown_device);
TEST (device_manager_test_get_discovery_object);
TEST (device_manager_test_get_discovery_object_invalid_arg);
TEST (device_manager_test_get_discovery_object_unknown_device);
TEST (device_manager_test_update_component_device_entry_multi_source);
TEST (device_manager_test_update_component_device_entry_single_source);
TEST (device_manager_test_update_component_device_entry_single_source_redirect);
TEST (device_manager_test_update_component_device_entry_invalid_arg);
TEST (device_manager_test_update_component_device_entry_invalid_device);
TEST (device_manager_test_update_component_device_entry_too_many_components);
TEST (device_manager_test_update_component_device_entry_min_max_enforcement);
TEST (device_manager_test_update_component_device_entry_no_enforcement);
TEST (device_manager_test_get_device_addr_null);
TEST (device_manager_test_get_device_addr_invalid_device);
TEST (device_manager_test_get_device_addr_by_eid);
TEST (device_manager_test_get_device_addr_by_eid_unidentified_device);
TEST (device_manager_test_get_device_addr_by_eid_init_ac_rot);
TEST (device_manager_test_get_device_addr_by_eid_null);
TEST (device_manager_test_get_device_addr_by_eid_invalid_device);
TEST (device_manager_test_get_device_and_instance_ids_by_device_num);
TEST (device_manager_test_get_device_and_instance_ids_by_device_num_invalid_arg);
TEST (device_manager_test_get_device_and_instance_ids_by_device_num_unknown_device);
TEST (device_manager_test_get_device_and_instance_ids_by_eid);
TEST (device_manager_test_get_device_and_instance_ids_by_eid_invalid_arg);
TEST (device_manager_test_get_device_and_instance_ids_by_eid_unknown_device);
TEST (device_manager_test_get_device_addr_by_eid_unidentified_device_null);
TEST (device_manager_test_get_device_addr_by_eid_unknown_device);
TEST (device_manager_test_get_device_eid_null);
TEST (device_manager_test_get_device_eid_invalid_device);
TEST (device_manager_test_update_device_state);
TEST (device_manager_test_update_device_state_init_ac_rot);
TEST (device_manager_test_update_device_state_invalid_arg);
TEST (device_manager_test_update_device_state_invalid_device);
TEST (device_manager_test_update_device_state_invalid_prev_state);
TEST (device_manager_test_update_device_state_by_eid);
TEST (device_manager_test_update_device_state_by_eid_init_ac_rot);
TEST (device_manager_test_update_device_state_by_eid_invalid_arg);
TEST (device_manager_test_update_device_state_by_eid_invalid_device);
TEST (device_manager_test_get_device_state_null);
TEST (device_manager_test_get_device_state_invalid_device);
TEST (device_manager_test_get_device_state_by_eid_null);
TEST (device_manager_test_get_device_state_by_eid_invalid_device);
TEST (device_manager_test_update_attestation_summary_prev_state);
TEST (device_manager_test_update_attestation_summary_prev_state_init_ac_rot);
TEST (device_manager_test_update_attestation_summary_prev_state_invalid_arg);
TEST (device_manager_test_update_attestation_summary_prev_state_invalid_device);
TEST (device_manager_test_update_attestation_summary_prev_state_by_eid);
TEST (device_manager_test_update_attestation_summary_prev_state_by_eid_init_ac_rot);
TEST (device_manager_test_update_attestation_summary_prev_state_by_eid_invalid_arg);
TEST (device_manager_test_update_attestation_summary_prev_state_by_eid_invalid_device);
TEST (device_manager_test_get_attestation_summary_prev_state_null);
TEST (device_manager_test_get_attestation_summary_prev_state_invalid_device);
TEST (device_manager_test_get_attestation_summary_prev_state_by_eid_null);
TEST (device_manager_test_get_attestation_summary_prev_state_by_eid_invalid_device);
TEST (device_manager_test_update_attestation_summary_event_counters);
TEST (device_manager_test_update_attestation_summary_event_counters_init_ac_rot);
TEST (device_manager_test_update_attestation_summary_event_counters_invalid_arg);
TEST (device_manager_test_update_attestation_summary_event_counters_invalid_device);
TEST (device_manager_test_get_attestation_summary_event_counters_null);
TEST (device_manager_test_get_attestation_summary_event_counters_invalid_device);
TEST (device_manager_test_get_attestation_summary_event_counters_by_eid_null);
TEST (device_manager_test_get_attestation_summary_event_counters_by_eid_invalid_device);
TEST (device_manager_test_get_device_num);
TEST (device_manager_test_get_device_num_init_ac_rot);
TEST (device_manager_test_get_device_num_null);
TEST (device_manager_test_get_device_num_invalid_eid);
TEST (device_manager_test_get_device_num_by_component);
TEST (device_manager_test_get_device_num_by_component_init_ac_rot);
TEST (device_manager_test_get_device_num_by_component_null);
TEST (device_manager_test_get_device_num_by_component_invalid_component_id);
TEST (device_manager_test_get_device_num_by_component_invalid_instance_id);
TEST (device_manager_test_update_device_eid);
TEST (device_manager_test_update_device_eid_init_ac_rot);
TEST (device_manager_test_update_device_eid_notify_observers_self);
TEST (device_manager_test_update_device_eid_notify_observers_others);
TEST (device_manager_test_update_device_eid_removed_observer_self);
TEST (device_manager_test_update_device_eid_removed_observer_others);
TEST (device_manager_test_update_device_eid_invalid_arg);
TEST (device_manager_test_update_device_eid_invalid_device);
TEST (device_manager_test_update_instance_id);
TEST (device_manager_test_update_instance_id_init_ac_rot);
TEST (device_manager_test_update_instance_id_invalid_arg);
TEST (device_manager_test_update_instance_id_invalid_device);
TEST (device_manager_test_update_instance_id_by_eid);
TEST (device_manager_test_update_instance_id_by_eid_init_ac_rot);
TEST (device_manager_test_update_instance_id_by_eid_invalid_arg);
TEST (device_manager_test_update_instance_id_by_eid_invalid_device);
TEST (device_manager_test_get_instance_id_by_eid);
TEST (device_manager_test_get_instance_id_by_eid_unknown_eid);
TEST (device_manager_test_get_instance_id_by_eid_null);
TEST (device_manager_test_get_instance_id_by_device_num);
TEST (device_manager_test_get_instance_id_by_device_num_unknown_device);
TEST (device_manager_test_get_instance_id_by_device_num_null);
TEST (device_manager_test_get_component_id_by_eid);
TEST (device_manager_test_get_component_id_by_eid_unknown_eid);
TEST (device_manager_test_get_component_id_by_eid_null);
TEST (device_manager_test_get_max_message_len_local_device);
TEST (device_manager_test_get_max_message_len_init_ac_rot);
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
TEST (device_manager_test_get_max_transmission_unit_init_ac_rot);
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
TEST (device_manager_test_get_reponse_timeout_init_ac_rot);
TEST (device_manager_test_get_reponse_timeout_remote_device);
TEST (device_manager_test_get_reponse_timeout_remote_device_no_capabilities);
TEST (device_manager_test_get_reponse_timeout_remote_device_unknown_device);
TEST (device_manager_test_get_reponse_timeout_remote_device_unknown_device_mctp_bridge_adjustment);
TEST (device_manager_test_get_reponse_timeout_remote_device_mctp_bridge_adjustment);
TEST (device_manager_test_get_reponse_timeout_null);
TEST (device_manager_test_get_reponse_timeout_by_eid_local_device);
TEST (device_manager_test_get_reponse_timeout_by_eid_remote_device);
TEST (device_manager_test_get_reponse_timeout_by_eid_remote_device_no_capabilities);
TEST (device_manager_test_get_reponse_timeout_by_eid_remote_device_unknown_device);
TEST (device_manager_test_get_reponse_timeout_by_eid_remote_device_unknown_device_mctp_bridge_adjustment);
TEST (device_manager_test_get_reponse_timeout_by_eid_remote_device_mctp_bridge_adjustment);
TEST (device_manager_test_get_reponse_timeout_by_eid_null);
TEST (device_manager_test_get_crypto_timeout_local_device);
TEST (device_manager_test_get_crypto_timeout_init_ac_rot);
TEST (device_manager_test_get_crypto_timeout_remote_device);
TEST (device_manager_test_get_crypto_timeout_remote_device_no_capabilities);
TEST (device_manager_test_get_crypto_timeout_remote_device_unknown_device);
TEST (device_manager_test_get_crypto_timeout_remote_device_unknown_device_mctp_bridge_adjustment);
TEST (device_manager_test_get_crypto_timeout_remote_device_mctp_bridge_adjustment);
TEST (device_manager_test_get_crypto_timeout_null);
TEST (device_manager_test_get_crypto_timeout_by_eid_local_device);
TEST (device_manager_test_get_crypto_timeout_by_eid_remote_device);
TEST (device_manager_test_get_crypto_timeout_by_eid_remote_device_no_capabilities);
TEST (device_manager_test_get_crypto_timeout_by_eid_remote_device_unknown_device);
TEST (device_manager_test_get_crypto_timeout_by_eid_remote_device_unknown_device_mctp_bridge_adjustment);
TEST (device_manager_test_get_crypto_timeout_by_eid_remote_device_mctp_bridge_adjustment);
TEST (device_manager_test_get_crypto_timeout_by_eid_null);
TEST (device_manager_test_get_component_id);
TEST (device_manager_test_get_component_id_unknown_eid);
TEST (device_manager_test_get_component_id_null);
TEST (device_manager_test_get_instance_info_by_component_id);
TEST (device_manager_test_get_instance_info_by_component_id_buffer_too_small);
TEST (device_manager_test_get_instance_info_by_component_id_unknown_component_id);
TEST (device_manager_test_get_instance_info_by_component_id_invalid_args);
TEST (device_manager_test_update_cert_chain_digest);
TEST (device_manager_test_update_cert_chain_digest_invalid_arg);
TEST (device_manager_test_update_cert_chain_digest_unknown_device);
TEST (device_manager_test_update_cert_chain_digest_input_too_large);
TEST (device_manager_test_compare_cert_chain_digest);
TEST (device_manager_test_compare_cert_chain_digest_invalid_arg);
TEST (device_manager_test_compare_cert_chain_digest_unknown_device);
TEST (device_manager_test_compare_cert_chain_digest_digest_len_mismatch);
TEST (device_manager_test_compare_cert_chain_digest_digest_eid_mismatch);
TEST (device_manager_test_compare_cert_chain_digest_digest_mismatch);
TEST (device_manager_test_clear_cert_chain_digest);
TEST (device_manager_test_clear_cert_chain_digest_invalid_arg);
TEST (device_manager_test_clear_cert_chain_digest_unknown_device);
TEST (device_manager_test_update_alias_key);
TEST (device_manager_test_update_alias_key_invalid_arg);
TEST (device_manager_test_update_alias_key_unknown_device);
TEST (device_manager_test_update_alias_key_input_too_large);
TEST (device_manager_test_get_alias_key);
TEST (device_manager_test_get_alias_key_invalid_arg);
TEST (device_manager_test_get_alias_key_unknown_device);
TEST (device_manager_test_get_alias_key_not_updated);
TEST (device_manager_test_clear_alias_key);
TEST (device_manager_test_clear_alias_key_invalid_arg);
TEST (device_manager_test_clear_alias_key_unknown_device);
TEST (device_manager_test_get_eid_of_next_device_to_attest_one_device);
TEST (device_manager_test_get_eid_of_next_device_to_attest_multiple);
TEST (device_manager_test_get_eid_of_next_device_to_attest_multiple_attestation_failed);
TEST (device_manager_test_get_eid_of_next_device_to_attest_multiple_authenticated);
TEST (device_manager_test_get_eid_of_next_device_to_attest_multiple_unauthenticated);
TEST (device_manager_test_get_eid_of_next_device_to_attest_invalid_arg);
TEST (device_manager_test_get_eid_of_next_device_to_attest_no_available_devices);
TEST (device_manager_test_get_eid_of_next_device_to_attest_no_ready_devices);
TEST (device_manager_test_get_eid_of_next_device_to_attest_no_attestable_devices);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_one_device);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_multiple);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_multiple_attestation_failed);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_multiple_authenticated);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_multiple_unauthenticated);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_invalid_arg);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_no_available_devices);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_no_ready_devices);
TEST (device_manager_test_get_device_num_of_next_device_to_attest_no_attestable_devices);
TEST (device_manager_test_reset_authenticated_devices);
TEST (device_manager_test_reset_authenticated_without_certs_devices);
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
TEST (device_manager_test_remove_unidentified_device_unidentified_null);
TEST (device_manager_test_clear_unidentified_devices);
TEST (device_manager_test_clear_unidentified_devices_invalid_arg);
TEST (device_manager_test_clear_unidentified_devices_no_unidentified_devices);
TEST (device_manager_test_unidentified_device_timed_out);
TEST (device_manager_test_unidentified_device_timed_out_single_entry);
TEST (device_manager_test_unidentified_device_timed_out_unknown_device);
TEST (device_manager_test_unidentified_device_timed_out_unknown_device_multiple_entries);
TEST (device_manager_test_unidentified_device_timed_out_invalid_arg);
TEST (device_manager_test_unidentified_device_timed_out_unidentified_null);
TEST (device_manager_test_get_eid_of_next_device_to_discover_single_entry);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_first_timed_out);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_second_timed_out);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_all_timed_out);
TEST (device_manager_test_get_eid_of_next_device_to_discover_multiple_entries_wait_timeout_cadence);
TEST (device_manager_test_get_eid_of_next_device_to_discover_no_entries);
TEST (device_manager_test_get_eid_of_next_device_to_discover_no_responders);
TEST (device_manager_test_get_eid_of_next_device_to_discover_none_unidentified);
TEST (device_manager_test_get_eid_of_next_device_to_discover_invalid_arg);
TEST (device_manager_test_restart_device_discovery);
TEST (device_manager_test_restart_device_discovery_no_responders);
TEST (device_manager_test_restart_device_discovery_mark_devices_unidentified);
TEST (device_manager_test_restart_device_discovery_null);
TEST (device_manager_test_restart_device_discovery_by_handler);
TEST (device_manager_test_restart_device_discovery_by_handler_no_matching_devices);
TEST (device_manager_test_restart_device_discovery_by_handler_null);
TEST (device_manager_test_restart_device_discovery_and_instances_by_handler);
TEST (device_manager_test_restart_device_discovery_and_instances_by_handler_no_matching);
TEST (device_manager_test_restart_device_discovery_and_instances_by_handler_null);
TEST (device_manager_test_get_device_num_by_device_ids);
TEST (device_manager_test_get_device_num_by_device_ids_no_unidentified_devices);
TEST (device_manager_test_get_device_num_by_device_ids_invalid_arg);
TEST (device_manager_test_get_device_num_by_device_ids_device_not_found);
TEST (device_manager_test_get_device_num_by_instance_ids);
TEST (device_manager_test_get_device_num_by_instance_ids_no_unidentified_devices);
TEST (device_manager_test_get_device_num_by_instance_ids_invalid_arg);
TEST (device_manager_test_get_device_num_by_instance_ids_device_not_found);
TEST (device_manager_test_update_device_ids);
TEST (device_manager_test_update_device_ids_invalid_arg);
TEST (device_manager_test_update_device_ids_unknown_device);
TEST (device_manager_test_get_time_till_next_action_single_attestation);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation);
TEST (device_manager_test_get_time_till_next_action_single_attestation_failed);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation_failed);
TEST (device_manager_test_get_time_till_next_action_single_attestation_authenticated);
TEST (device_manager_test_get_time_till_next_action_single_attestation_authenticated_without_certs);
TEST (device_manager_test_get_time_till_next_action_single_attestation_device_not_present);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation_authenticated);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation_authenticated_without_certs);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation_device_not_present);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation_authenticated_and_unauthenticated);
TEST (device_manager_test_get_time_till_next_action_multiple_attestation_authenticated_without_certs_and_unauthenticated);
TEST (device_manager_test_get_time_till_next_action_single_discovery);
TEST (device_manager_test_get_time_till_next_action_multiple_discovery);
TEST (device_manager_test_get_time_till_next_action_single_discovery_timeout);
TEST (device_manager_test_get_time_till_next_action_multiple_discovery_timeout);
TEST (device_manager_test_get_time_till_next_action_multiple_discovery_some_timeout);
TEST (device_manager_test_get_time_till_next_action_attestation_and_discovery);
TEST (device_manager_test_get_time_till_next_action_no_devices);
TEST (device_manager_test_get_time_till_next_action_invalid_arg);
TEST (device_manager_test_get_attestation_status);
TEST (device_manager_test_get_attestation_status_no_responder_devices);
TEST (device_manager_test_get_attestation_status_all_unauthenticated);
TEST (device_manager_test_get_attestation_status_all_unauthenticated_not_max);
TEST (device_manager_test_get_attestation_status_all_authenticated);
TEST (device_manager_test_get_attestation_status_all_authenticated_without_certs);
TEST (device_manager_test_get_attestation_status_all_authenticated_not_max);
TEST (device_manager_test_get_attestation_status_all_authenticated_without_certs_not_max);
TEST (device_manager_test_get_attestation_status_non_unique_components);
TEST (device_manager_test_get_attestation_status_all_unauthenticated_non_unique_components);
TEST (device_manager_test_get_attestation_status_all_unauthenticated_not_max_non_unique_components);
TEST (device_manager_test_get_attestation_status_all_authenticated_non_unique_components);
TEST (device_manager_test_get_attestation_status_all_authenticated_without_certs_non_unique_components);
TEST (device_manager_test_get_attestation_status_all_authenticated_not_max_non_unique_components);
TEST (device_manager_test_get_attestation_status_all_authenticated_without_certs_not_max_non_unique_components);
TEST (device_manager_test_mark_component_attestation_invalid_non_unique_components);
TEST (device_manager_test_mark_component_attestation_invalid_not_max_non_unique_components);
TEST (device_manager_test_get_attestation_status_all_unauthenticated_non_unique_components_different_ratio);
TEST (device_manager_test_get_attestation_status_invalid_arg);
TEST (device_manager_test_mark_component_attestation_invalid);
TEST (device_manager_test_mark_component_attestation_invalid_not_max);
TEST (device_manager_test_mark_component_attestation_invalid_invalid_arg);
TEST (device_manager_test_is_device_unattestable);
TEST (device_manager_test_is_device_unattestable_invalid_arg);
TEST (device_manager_test_get_rsp_not_ready_limits);
TEST (device_manager_test_get_rsp_not_ready_limits_invalid_arg);
TEST (device_manager_test_get_mctp_ctrl_timeout);
TEST (device_manager_test_get_mctp_ctrl_timeout_invalid_arg);
TEST (device_manager_test_set_force_action);
TEST (device_manager_test_set_force_action_bad_data_size);
TEST (device_manager_test_set_force_action_replace_existing);
TEST (device_manager_test_set_force_action_invalid_arg);
TEST (device_manager_test_set_force_action_data_bad_device_ids);
TEST (device_manager_test_set_force_action_data_bad_component_ids);
TEST (device_manager_test_clear_force_action);
TEST (device_manager_test_clear_force_action_no_action);
TEST (device_manager_test_clear_force_action_invalid_arg);
TEST (device_manager_test_clear_force_action_pending_to_idle_rejected);
TEST (device_manager_test_clear_force_action_idle_to_in_progress_rejected);
TEST (device_manager_test_process_force_action_force_attestation_failed);
TEST (device_manager_test_process_force_action_force_attestation_passed);
TEST (device_manager_test_process_force_action_force_attestation_all);
TEST (device_manager_test_process_force_action_force_attestation_component_id);
TEST (device_manager_test_process_force_action_force_attestation_device_ids);
TEST (device_manager_test_check_force_action_idle);
TEST (device_manager_test_check_force_action_pending);
TEST (device_manager_test_check_force_action_in_progress);
TEST (device_manager_test_check_force_action_null_action_id);
TEST (device_manager_test_set_force_action_in_progress_rejected);
TEST (device_manager_test_set_force_action_action_id_increments);
TEST (device_manager_test_update_device_state_force_attestation_timeout_zero);
TEST (device_manager_test_process_force_action_noop_when_in_progress);
TEST (device_manager_test_process_force_action_sets_in_progress);
TEST (device_manager_test_process_force_action_sets_none_when_zero_actions);
TEST (device_manager_test_process_force_action_logging_start_and_complete);
TEST (device_manager_test_process_force_action_logging_per_device);
TEST (device_manager_test_process_force_action_no_action);
TEST (device_manager_test_process_force_action_invalid_arg);
TEST (device_manager_test_update_attestation_summary_event_counters_by_eid);
TEST (device_manager_test_update_attestation_summary_event_counters_by_eid_invalid_arg);
TEST (device_manager_test_update_attestation_summary_event_counters_by_eid_unknown_device);
TEST (device_manager_test_get_num_component_types);
TEST (device_manager_test_get_num_component_types_invalid_arg);
TEST (device_manager_test_get_num_component_types_unknown_device);
TEST (device_manager_test_get_component_type);
TEST (device_manager_test_get_component_type_invalid_arg);
TEST (device_manager_test_get_component_type_unknown_device);
TEST (device_manager_test_get_component_type_invalid_index);
TEST (device_manager_test_promote_matched_component_type);
TEST (device_manager_test_promote_matched_component_type_index_zero_noop);
TEST (device_manager_test_promote_matched_component_type_single_count_noop);
TEST (device_manager_test_promote_matched_component_type_invalid_arg);
TEST (device_manager_test_promote_matched_component_type_unknown_device);
TEST (device_manager_test_promote_matched_component_type_invalid_index);

TEST_SUITE_END;
// *INDENT-ON*
