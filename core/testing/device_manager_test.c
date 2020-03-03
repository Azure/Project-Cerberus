// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "x509_testing.h"
#include "cmd_interface/device_manager.h"


static const char *SUITE = "device_manager";


/*******************
 * Test cases
 *******************/

static void device_manager_test_init (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 1);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (NULL, 1);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_init (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_release_null (CuTest *test)
{
	device_manager_release (NULL);
}

static void device_manager_test_update_device_entry (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager,2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0xBB, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_device_direction (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_DOWNSTREAM, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (NULL, 0, DEVICE_MANAGER_DOWNSTREAM, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_device_entry (&manager, 0, NUM_DEVICE_DIRECTIONS, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_entry_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 2, DEVICE_MANAGER_DOWNSTREAM, 0, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities device_capabilities = {0};
	struct device_manager_capabilities out_capabilities;
	int status;

	device_capabilities.max_payload_size = 1;
	device_capabilities.security_mode = 2;
	device_capabilities.rsa_key_strength = 3;
	device_capabilities.ecc_key_strength = 4;
	device_capabilities.aes_enc_key_strength = 5;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &device_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (&manager, 0, &out_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*)&device_capabilities, (uint8_t*)&out_capabilities, 
		sizeof (struct device_manager_capabilities));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities_invalid_arg (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities device_capabilities;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (NULL, 0, &device_capabilities);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_update_device_capabilities (&manager, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_capabilities_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities device_capabilities;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 2, &device_capabilities);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_state (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 2, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_init_cert_chain (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 3);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 2, 1, buf, sizeof (buf));
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_num (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, DEVICE_MANAGER_DOWNSTREAM, 0xCC, 0xDD);
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

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, DEVICE_MANAGER_DOWNSTREAM, 0xCC, 0xDD);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_num (&manager, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_direction (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_direction (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_DOWNSTREAM, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_direction_null (CuTest *test)
{
	int status;

	TEST_START;

	status = device_manager_get_device_direction (NULL, 0);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_direction_invalid_device (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_direction (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_addr (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0, 0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

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

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

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

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_capabilities (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities device_capabilities = {0};
	struct device_manager_capabilities out_capabilities = {0};
	int status;

	device_capabilities.max_payload_size = 1;
	device_capabilities.security_mode = 2;
	device_capabilities.rsa_key_strength = 3;
	device_capabilities.ecc_key_strength = 4;
	device_capabilities.aes_enc_key_strength = 5;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &device_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (&manager, 0, &out_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*)&device_capabilities, (uint8_t*)&out_capabilities, 
		sizeof (struct device_manager_capabilities));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_capabilities_null (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities out_capabilities;
	int status;

	TEST_START;

	status = device_manager_get_device_capabilities (NULL, 0, &out_capabilities);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);

	status = device_manager_get_device_capabilities (&manager, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_ARGUMENT, status);
}

static void device_manager_test_get_device_capabilities_invalid_device (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_capabilities out_capabilities;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (&manager, 2, &out_capabilities);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_cert_chain (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_cert_chain out_chain;
	int status;
	

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 0, X509_CERTCA_ECC_CA_NOPL_DER, 
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 1, X509_CERTCA_RSA_CA_NOPL_DER, 
		X509_CERTCA_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_cert_chain (&manager, 0, &out_chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, out_chain.num_cert);
	CuAssertIntEquals (test, X509_CERTCA_ECC_CA_NOPL_DER_LEN, out_chain.cert[0].length);
	CuAssertIntEquals (test, X509_CERTCA_RSA_CA_NOPL_DER_LEN, out_chain.cert[1].length);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, out_chain.cert[0].cert, 
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_CERTCA_RSA_CA_NOPL_DER, out_chain.cert[1].cert, 
		X509_CERTCA_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

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

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_cert_chain (&manager, 2, &chain);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_get_device_state (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

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

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_state (&manager, 2);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

static void device_manager_test_resize_entries_table_add_entries (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_cert_chain chain;
	struct device_manager_capabilities device_capabilities = {0};
	struct device_manager_capabilities out_capabilities = {0};
	int status;

	device_capabilities.max_payload_size = 1;
	device_capabilities.security_mode = 2;
	device_capabilities.rsa_key_strength = 3;
	device_capabilities.ecc_key_strength = 4;
	device_capabilities.aes_enc_key_strength = 5;

	TEST_START;

	status = device_manager_init (&manager, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0xBB, 
		0xAA);
	CuAssertIntEquals (test, 0, status);
	
	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 0, X509_CERTCA_ECC_CA_NOPL_DER, 
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &device_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	status = device_manager_resize_entries_table (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_device_direction (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_DOWNSTREAM, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	status = device_manager_get_device_cert_chain (&manager, 0, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[0].length, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, chain.cert[0].cert, 
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (&manager, 0, &out_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*)&device_capabilities, (uint8_t*)&out_capabilities, 
		sizeof (struct device_manager_capabilities));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_resize_entries_table_remove_entries (CuTest *test)
{
	struct device_manager manager;
	struct device_manager_cert_chain chain;
	struct device_manager_capabilities device_capabilities = {0};
	struct device_manager_capabilities out_capabilities = {0};
	int status;

	device_capabilities.max_payload_size = 1;
	device_capabilities.security_mode = 2;
	device_capabilities.rsa_key_strength = 3;
	device_capabilities.ecc_key_strength = 4;
	device_capabilities.aes_enc_key_strength = 5;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0xBB, 
		0xAA);
	CuAssertIntEquals (test, 0, status);
	
	status = device_manager_update_device_state (&manager, 0, DEVICE_MANAGER_AUTHENTICATED);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init_cert_chain (&manager, 0, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (&manager, 0, 0, X509_CERTCA_ECC_CA_NOPL_DER, 
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 0, &device_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_resize_entries_table (&manager, 1);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_device_direction (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_DOWNSTREAM, status);

	status = device_manager_get_device_state (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_AUTHENTICATED, status);

	status = device_manager_get_device_cert_chain (&manager, 0, &chain);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, chain.num_cert);
	CuAssertIntEquals (test, chain.cert[0].length, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, chain.cert[0].cert, 
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (&manager, 0, &out_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*)&device_capabilities, (uint8_t*)&out_capabilities, 
		sizeof (struct device_manager_capabilities));
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
	struct device_manager_capabilities device_capabilities = {0};
	struct device_manager_capabilities device_capabilities2 = {0};
	struct device_manager_capabilities out_capabilities = {0};
	int status;

	device_capabilities.max_payload_size = 1;
	device_capabilities.security_mode = 2;
	device_capabilities.rsa_key_strength = 3;
	device_capabilities.ecc_key_strength = 4;
	device_capabilities.aes_enc_key_strength = 5;

	device_capabilities2.max_payload_size = 6;
	device_capabilities2.security_mode = 7;
	device_capabilities2.rsa_key_strength = 5;
	device_capabilities2.ecc_key_strength = 4;
	device_capabilities2.aes_enc_key_strength = 3;

	TEST_START;

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, DEVICE_MANAGER_DOWNSTREAM, 0xBB, 
		0xAA);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, DEVICE_MANAGER_UPSTREAM, 0xCC, 
		0xDD);
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

	status = device_manager_update_device_capabilities (&manager, 0, &device_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (&manager, 1, &device_capabilities2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_resize_entries_table (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_addr (&manager, 0);
	CuAssertIntEquals (test, 0xAA, status);

	status = device_manager_get_device_eid (&manager, 0);
	CuAssertIntEquals (test, 0xBB, status);

	status = device_manager_get_device_direction (&manager, 0);
	CuAssertIntEquals (test, DEVICE_MANAGER_DOWNSTREAM, status);

	status = device_manager_get_device_addr (&manager, 1);
	CuAssertIntEquals (test, 0xDD, status);

	status = device_manager_get_device_eid (&manager, 1);
	CuAssertIntEquals (test, 0xCC, status);

	status = device_manager_get_device_direction (&manager, 1);
	CuAssertIntEquals (test, DEVICE_MANAGER_UPSTREAM, status);

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

	status = device_manager_get_device_capabilities (&manager, 0, &out_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*)&device_capabilities, (uint8_t*)&out_capabilities, 
		sizeof (struct device_manager_capabilities));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (&manager, 1, &out_capabilities);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*)&device_capabilities2, (uint8_t*)&out_capabilities, 
		sizeof (struct device_manager_capabilities));
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void device_manager_test_update_device_eid (CuTest *test)
{
	struct device_manager manager;
	int status;

	TEST_START;

	status = device_manager_init (&manager,2);
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

	status = device_manager_init (&manager, 2);
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

	status = device_manager_init (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_eid (&manager, 2, 0);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	device_manager_release (&manager);
}

CuSuite* get_device_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, device_manager_test_init);
	SUITE_ADD_TEST (suite, device_manager_test_init_invalid_arg);
	SUITE_ADD_TEST (suite, device_manager_test_release_null);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_entry);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_entry_invalid_arg);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_entry_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_capabilities);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_capabilities_invalid_arg);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_capabilities_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_state);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_state_invalid_arg);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_state_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_init_cert_chain);
	SUITE_ADD_TEST (suite, device_manager_test_init_cert_chain_invalid_arg);
	SUITE_ADD_TEST (suite, device_manager_test_init_cert_chain_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_update_cert);
	SUITE_ADD_TEST (suite, device_manager_test_update_cert_2_devices);
	SUITE_ADD_TEST (suite, device_manager_test_update_cert_invalid_arg);
	SUITE_ADD_TEST (suite, device_manager_test_update_cert_invalid_cert_num);
	SUITE_ADD_TEST (suite, device_manager_test_update_cert_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_num);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_num_null);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_num_invalid_eid);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_direction);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_direction_null);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_direction_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_addr);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_addr_null);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_addr_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_eid);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_eid_null);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_eid_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_capabilities);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_capabilities_null);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_capabilities_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_cert_chain);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_cert_chain_null);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_cert_chain_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_state);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_state_null);
	SUITE_ADD_TEST (suite, device_manager_test_get_device_state_invalid_device);
	SUITE_ADD_TEST (suite, device_manager_test_resize_entries_table_add_entries);
	SUITE_ADD_TEST (suite, device_manager_test_resize_entries_table_remove_entries);
	SUITE_ADD_TEST (suite, device_manager_test_resize_entries_table_invalid_arg);
	SUITE_ADD_TEST (suite, device_manager_test_resize_entries_table_same_size);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_eid);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_eid_invalid_arg);
	SUITE_ADD_TEST (suite, device_manager_test_update_device_eid_invalid_device);

	return suite;
}
