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

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (NULL, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 1, NUM_BUS_HIERACHY_ROLES,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 0, DEVICE_MANAGER_AC_ROT_MODE,
		NUM_BUS_ROLES);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB,	0xAA);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (NULL, 0, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 2, 0, 0);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 2);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_cert_chain (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 3);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_cert_chain_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (NULL, 0, 3);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init_cert_chain (&manager, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_cert_chain_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 2, 3);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_cert_chain chain;
	int status;


	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 1, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_cert_chain (&manager, 0, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[1].length, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, chain.cert[1].cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert_2_devices (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_cert_chain chain;
	int status;


	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 1, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 1, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 1, 1, X509_CERTCA_RSA_CA_NOPL_DER,
		X509_CERTCA_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_cert_chain (&manager, 0, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[1].length, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, chain.cert[1].cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_cert_chain (&manager, 1, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[1].length, X509_CERTCA_RSA_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_RSA_CA_NOPL_DER, chain.cert[1].cert,
		X509_CERTCA_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	uint8_t buf[10];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (NULL, 0, 1, buf, sizeof (buf));
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_cert (&manager, 0, 1, NULL, sizeof (buf));
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_cert (&manager, 0, 1, buf, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert_invalid_cert_num (CuTest *test)
{
	struct device_manager manager;
	uint8_t buf[10];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 3, buf, sizeof (buf));
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_CERT_NUM, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_cert_invalid_device (CuTest *test)
{
	struct device_manager manager;
	uint8_t buf[10];
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 2, 1, buf, sizeof (buf));
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_cert_chain_null (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_cert_chain chain;
	int status;

	TEST_START;

	status = device_manager_get_device_cert_chain (NULL, 0, &chain);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_cert_chain (&manager, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_cert_chain_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_cert_chain chain;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_cert_chain (&manager, 2, &chain);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA,	0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA,	0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num (&manager, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_resize_entries_table_add_entries (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_cert_chain chain;
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

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB,	0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 0, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
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

	status = device_manager_get_device_cert_chain (&manager, 0, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[0].length, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, chain.cert[0].cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
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
	struct device_manager_cert_chain chain;
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 0, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
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

	status = device_manager_get_device_cert_chain (&manager, 0, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[0].length, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, chain.cert[0].cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
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
	struct device_manager_cert_chain chain;
	struct device_manager_full_capabilities expected;
	struct device_manager_full_capabilities expected2;
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

	memset (&expected2, 0, sizeof (expected2));
	expected2.request.max_message_size = 50;
	expected2.request.max_packet_size = 10;
	expected2.request.security_mode = DEVICE_MANAGER_SECURITY_CONFIDENTIALITY;
	expected2.request.bus_role = DEVICE_MANAGER_MASTER_BUS_ROLE;
	expected2.request.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;
	expected2.max_timeout = 100;
	expected2.max_sig = 200;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xBB, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 1, DEVICE_MANAGER_AVAILABLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 1, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 0, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 1, 0, X509_CERTCA_RSA_CA_NOPL_DER,
		X509_CERTCA_RSA_CA_NOPL_DER_LEN);
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
	CuAssertIntEquals (test, DEVICE_MANAGER_AVAILABLE, status);

	status = device_manager_get_device_cert_chain (&manager, 0, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[0].length, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, chain.cert[0].cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_cert_chain (&manager, 1, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[0].length, X509_CERTCA_RSA_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_RSA_CA_NOPL_DER, chain.cert[0].cert,
		X509_CERTCA_RSA_CA_NOPL_DER_LEN);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD);
	CuAssertIntEquals (test, 0, status);

	timeout = device_manager_get_crypto_timeout_by_eid (NULL, 0xCC);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS, timeout);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_type (CuTest *test)
{
	struct device_manager manager;
	struct hash_engine_mock hash;
	uint8_t digest[SHA256_HASH_LENGTH] = {0};
	const uint8_t *component_type;
	int status;

	TEST_START;

	digest[0] = 0xAA;
	digest[10] = 0xBB;
	digest[20] = 0xCC;
	digest[SHA256_HASH_LENGTH - 1] = 0xDD;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ("Component1", strlen ("Component1")),
		MOCK_ARG (strlen ("Component1")), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 2, digest, SHA256_HASH_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 0, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_type (&manager, &hash.base, 0x0A, "Component1");
	CuAssertIntEquals (test, 0, status);

	component_type = device_manager_get_component_type (&manager, 0x0A);

	status = testing_validate_array (digest, component_type, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_type_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_type (NULL, &hash.base, 0, "Component1");
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_component_type (&manager, NULL, 0, "Component1");
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_component_type (&manager, &hash.base, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_component_type (&manager, &hash.base, 0,
		"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
		"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
		"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_type_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_type (&manager, &hash.base, 0x0A, "Component1");
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_component_type_hash_fail (CuTest *test)
{
	struct device_manager manager;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS ("Component1", strlen ("Component1")),
		MOCK_ARG (strlen ("Component1")), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_type (&manager, &hash.base, 0, "Component1");
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type (CuTest *test)
{
	struct device_manager manager;
	struct hash_engine_mock hash;
	uint8_t digest[SHA256_HASH_LENGTH] = {0};
	const uint8_t *component_type;
	int status;

	TEST_START;

	digest[0] = 0xAA;
	digest[10] = 0xBB;
	digest[20] = 0xCC;
	digest[SHA256_HASH_LENGTH - 1] = 0xDD;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ("Component1", strlen ("Component1")),
		MOCK_ARG (strlen ("Component1")), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash.mock, 2, digest, SHA256_HASH_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 0, 0x0A);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_component_type (&manager, &hash.base, 0x0A, "Component1");
	CuAssertIntEquals (test, 0, status);

	component_type = device_manager_get_component_type (&manager, 0x0A);

	status = testing_validate_array (digest, component_type, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type_unknown_eid (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *component_type;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	component_type = device_manager_get_component_type (&manager, 0x0b);
	CuAssertPtrEquals (test, NULL, (void*) component_type);

	device_manager_release (&manager);
}

static void device_manager_test_get_component_type_null (CuTest *test)
{
	struct device_manager manager;
	const uint8_t *component_type;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	component_type = device_manager_get_component_type (NULL, 0);
	CuAssertPtrEquals (test, NULL, (void*) component_type);

	device_manager_release (&manager);
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
TEST (device_manager_test_get_device_addr_null);
TEST (device_manager_test_get_device_addr_invalid_device);
TEST (device_manager_test_get_device_eid_null);
TEST (device_manager_test_get_device_eid_invalid_device);
TEST (device_manager_test_update_device_state);
TEST (device_manager_test_update_device_state_invalid_arg);
TEST (device_manager_test_update_device_state_invalid_device);
TEST (device_manager_test_get_device_state_null);
TEST (device_manager_test_get_device_state_invalid_device);
TEST (device_manager_test_init_cert_chain);
TEST (device_manager_test_init_cert_chain_invalid_arg);
TEST (device_manager_test_init_cert_chain_invalid_device);
TEST (device_manager_test_update_cert);
TEST (device_manager_test_update_cert_2_devices);
TEST (device_manager_test_update_cert_invalid_arg);
TEST (device_manager_test_update_cert_invalid_cert_num);
TEST (device_manager_test_update_cert_invalid_device);
TEST (device_manager_test_get_device_cert_chain_null);
TEST (device_manager_test_get_device_cert_chain_invalid_device);
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
TEST (device_manager_test_update_component_type);
TEST (device_manager_test_update_component_type_invalid_arg);
TEST (device_manager_test_update_component_type_invalid_device);
TEST (device_manager_test_update_component_type_hash_fail);
TEST (device_manager_test_get_component_type);
TEST (device_manager_test_get_component_type_unknown_eid);
TEST (device_manager_test_get_component_type_null);

TEST_SUITE_END;
