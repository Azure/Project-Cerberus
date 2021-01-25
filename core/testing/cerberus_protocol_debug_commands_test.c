// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_debug_commands.h"
#include "mock/ecc_mock.h"
#include "mock/rsa_mock.h"
#include "mock/rng_mock.h"
#include "mock/x509_mock.h"
#include "cerberus_protocol_debug_commands_testing.h"
#include "x509_testing.h"


//static const char *SUITE = "cerberus_protocol_debug_commands";


void cerberus_protocol_debug_commands_testing_process_debug_fill_log (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_FILL_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.debug_log_fill, background, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_debug_commands_testing_process_get_device_certificate (CuTest *test,
	struct cmd_interface *cmd, struct device_manager *device_manager)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init_cert_chain (device_manager, 1, 3);
	status |= device_manager_update_cert (device_manager, 1, 2, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 + X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, 2, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 3], X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_debug_commands_testing_process_get_device_certificate_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 4;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_debug_commands_testing_process_get_device_certificate_invalid_cert_num (
	CuTest *test, struct cmd_interface *cmd, struct device_manager *device_manager)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init_cert_chain (device_manager, 1, 3);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_CERT_NUM, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_debug_commands_testing_process_get_device_certificate_get_chain_fail (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 3;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest (CuTest *test,
	struct cmd_interface *cmd, struct hash_engine_mock *hash, struct device_manager *device_manager)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&hash->mock, hash->base.calculate_sha256, hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash->mock, 2, X509_CERTCA_ECC_CA2_NOPL_DER, SHA256_HASH_LENGTH,
		3);

	status |= device_manager_init_cert_chain (device_manager, 1, 3);
	status |= device_manager_update_cert (device_manager, 1, 2, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 + SHA256_HASH_LENGTH,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, 2, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA2_NOPL_DER,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 3], SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 4;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest_invalid_cert_num (
	CuTest *test, struct cmd_interface *cmd, struct device_manager *device_manager)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init_cert_chain (device_manager, 1, 3);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_CERT_NUM, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest_get_chain_fail (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 3;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_debug_commands_testing_process_get_device_cert_digest_hash_fail (
	CuTest *test, struct cmd_interface *cmd, struct hash_engine_mock *hash,
	struct device_manager *device_manager)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&hash->mock, hash->base.calculate_sha256, hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&hash->mock, 2, X509_CERTCA_ECC_CA2_NOPL_DER, SHA256_HASH_LENGTH,
		3);

	status |= device_manager_init_cert_chain (device_manager, 1, 3);
	status |= device_manager_update_cert (device_manager, 1, 2, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_debug_commands_testing_process_get_device_challenge (CuTest *test,
	struct cmd_interface *cmd, struct riot_key_manager *riot, struct hash_engine_mock *hash,
	struct attestation_master_mock *master_attestation, struct device_manager *device_manager)
{
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct rng_engine_mock rng;
	struct x509_engine_mock x509;
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (&master_attestation->base, riot, &hash->base, &ecc.base,
		&rsa.base, &x509.base, &rng.base, device_manager, 1);
	CuAssertIntEquals (test, 0, status);

	memcpy (master_attestation->base.challenge[1].nonce, X509_CERTCA_ECC_CA_NOPL_DER,
		ATTESTATION_NONCE_LEN);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + ATTESTATION_NONCE_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CHALLENGE,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], ATTESTATION_NONCE_LEN);
	CuAssertIntEquals (test, 0, status);

	attestation_master_release (&master_attestation->base);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_debug_commands_testing_process_get_device_challenge_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}


/*******************
 * Test cases
 *******************/


CuSuite* get_cerberus_protocol_debug_commands_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	return suite;
}
