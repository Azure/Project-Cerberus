// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/session_manager_mock.h"
#include "testing/cmd_interface/cerberus_protocol_required_commands_testing.h"
#include "testing/cmd_interface/cmd_interface_system_testing.h"
#include "testing/crypto/x509_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("cerberus_protocol_required_commands");


void cerberus_protocol_required_commands_testing_supports_all_required_commands (CuTest *test,
	struct cmd_interface *cmd, const char *version,
	struct attestation_slave_mock *slave_attestation, struct device_manager *device_manager,
	struct cmd_background_mock *background, struct keystore_mock *keystore,
	struct cmd_device_mock *cmd_device, const uint8_t* csr, size_t csr_length, uint16_t vendor_id,
	uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id,
	struct session_manager_mock *session)
{
	cerberus_protocol_required_commands_testing_process_get_fw_version (test, cmd, version);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest (test, cmd,
		slave_attestation, session);
	cerberus_protocol_required_commands_testing_process_get_certificate (test, cmd,
		slave_attestation);
	cerberus_protocol_required_commands_testing_process_get_capabilities (test, cmd,
		device_manager);
	cerberus_protocol_required_commands_testing_process_get_devid_csr (test, cmd, csr, csr_length);
	cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert (test, cmd,
		keystore, background);
	cerberus_protocol_required_commands_testing_process_get_signed_cert_state (test, cmd,
		background);
	cerberus_protocol_required_commands_testing_process_get_device_info (test, cmd, cmd_device);
	cerberus_protocol_required_commands_testing_process_get_device_id (test, cmd, vendor_id,
		device_id, subsystem_vid, subsystem_id);
	cerberus_protocol_required_commands_testing_process_reset_counter (test, cmd, cmd_device);
	cerberus_protocol_required_commands_testing_generate_error_packet (test, cmd);
	cerberus_protocol_required_commands_testing_generate_error_packet_invalid_arg (test, cmd);

	if (session) {
		cerberus_protocol_required_commands_testing_process_get_challenge_response (test, cmd,
			slave_attestation, session);
		cerberus_protocol_required_commands_testing_generate_error_packet_encrypted (test, cmd,
			session);
		cerberus_protocol_required_commands_testing_generate_error_packet_encrypted_fail (test,
			cmd, session);
	}
	else {
		cerberus_protocol_required_commands_testing_process_get_challenge_response_no_session_mgr (
			test, cmd, slave_attestation);
	}
}

void cerberus_protocol_required_commands_testing_process_get_fw_version (CuTest *test,
	struct cmd_interface *cmd, const char *version)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	struct cerberus_protocol_get_fw_version_response *resp =
		(struct cerberus_protocol_get_fw_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 0;
	request.length = sizeof (struct cerberus_protocol_get_fw_version);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_fw_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_FW_VERSION, resp->header.command);
	CuAssertStrEquals (test, version, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_fw_version_riot (CuTest *test,
	struct cmd_interface *cmd, const char *version)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	struct cerberus_protocol_get_fw_version_response *resp =
		(struct cerberus_protocol_get_fw_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 1;
	request.length = sizeof (struct cerberus_protocol_get_fw_version);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_fw_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_FW_VERSION, resp->header.command);
	CuAssertStrEquals (test, version, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_fw_version_unset_version (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	struct cerberus_protocol_get_fw_version_response *resp =
		(struct cerberus_protocol_get_fw_version_response*) data;
	uint8_t zero[32] = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 0;
	request.length = sizeof (struct cerberus_protocol_get_fw_version);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_fw_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_FW_VERSION, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (zero, (uint8_t*) resp->version, sizeof (resp->version));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_fw_version_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 0;
	request.length = sizeof (struct cerberus_protocol_get_fw_version) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_fw_version) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_fw_version_unsupported_area (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 2;
	request.length = sizeof (struct cerberus_protocol_get_fw_version);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_fw_version_bad_count (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 0;
	request.length = sizeof (struct cerberus_protocol_get_fw_version);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation,
	struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	struct cerberus_protocol_get_certificate_digest_response *resp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	uint8_t cert_buf[64] = {0};
	uint8_t num_cert = 2;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 0;
	req->key_alg = 1;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cert_buf[0] = 0xAA;
	cert_buf[1] = 0xBB;
	cert_buf[62] = 0xCC;
	cert_buf[63] = 0xDD;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (0), MOCK_ARG (&request.data[sizeof (*resp)]),
		MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 1, cert_buf, sizeof (cert_buf), -1);
	status |= mock_expect_output (&slave_attestation->mock, 3, &num_cert, sizeof (num_cert), -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.reset_session, session, 0,
		MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_certificate_digest_response) + sizeof (cert_buf),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, resp->header.command);
	CuAssertIntEquals (test, 1, resp->capabilities);
	CuAssertIntEquals (test, 2, resp->num_digests);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (cert_buf, cerberus_protocol_certificate_digests (resp),
		sizeof (cert_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_no_key_exchange (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	struct cerberus_protocol_get_certificate_digest_response *resp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	uint8_t cert_buf[64] = {0};
	uint8_t num_cert = 2;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 0;
	req->key_alg = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cert_buf[0] = 0xAA;
	cert_buf[1] = 0xBB;
	cert_buf[62] = 0xCC;
	cert_buf[63] = 0xDD;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (0), MOCK_ARG (&request.data[sizeof (*resp)]),
		MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 1, cert_buf, sizeof (cert_buf), -1);
	status |= mock_expect_output (&slave_attestation->mock, 3, &num_cert, sizeof (num_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_certificate_digest_response) + sizeof (cert_buf),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, resp->header.command);
	CuAssertIntEquals (test, 1, resp->capabilities);
	CuAssertIntEquals (test, 2, resp->num_digests);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (cert_buf, cerberus_protocol_certificate_digests (resp),
		sizeof (cert_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_in_session (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	struct cerberus_protocol_get_certificate_digest_response *resp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	uint8_t cert_buf[64] = {0};
	uint8_t num_cert = 2;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;
	req->header.crypt = 1;

	req->slot_num = 0;
	req->key_alg = 1;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cert_buf[0] = 0xAA;
	cert_buf[1] = 0xBB;
	cert_buf[62] = 0xCC;
	cert_buf[63] = 0xDD;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (0), MOCK_ARG (&request.data[sizeof (*resp)]),
		MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 1, cert_buf, sizeof (cert_buf), -1);
	status |= mock_expect_output (&slave_attestation->mock, 3, &num_cert, sizeof (num_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_certificate_digest_response) + sizeof (cert_buf),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, resp->header.command);
	CuAssertIntEquals (test, 1, resp->capabilities);
	CuAssertIntEquals (test, 2, resp->num_digests);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (cert_buf, cerberus_protocol_certificate_digests (resp),
		sizeof (cert_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_aux_slot (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	struct cerberus_protocol_get_certificate_digest_response *resp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	uint8_t cert_buf[64] = {0};
	uint8_t num_cert = 2;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 1;
	req->key_alg = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cert_buf[0] = 0xAA;
	cert_buf[1] = 0xBB;
	cert_buf[62] = 0xCC;
	cert_buf[63] = 0xDD;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (1), MOCK_ARG (&request.data[sizeof (*resp)]),
		MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 1, cert_buf, sizeof (cert_buf), -1);
	status |= mock_expect_output (&slave_attestation->mock, 3, &num_cert, sizeof (num_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_certificate_digest_response) + sizeof (cert_buf),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, resp->header.command);
	CuAssertIntEquals (test, 1, resp->capabilities);
	CuAssertIntEquals (test, 2, resp->num_digests);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (cert_buf, cerberus_protocol_certificate_digests (resp),
		sizeof (cert_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	struct cerberus_protocol_get_certificate_digest_response *resp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	uint8_t cert_buf[64] = {0};
	uint8_t num_cert = 2;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 128 - 2;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 0;
	req->key_alg = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cert_buf[0] = 0xAA;
	cert_buf[1] = 0xBB;
	cert_buf[62] = 0xCC;
	cert_buf[63] = 0xDD;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (0), MOCK_ARG (&request.data[sizeof (*resp)]),
		MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 1, cert_buf, sizeof (cert_buf), -1);
	status |= mock_expect_output (&slave_attestation->mock, 3, &num_cert, sizeof (num_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_certificate_digest_response) + sizeof (cert_buf),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, resp->header.command);
	CuAssertIntEquals (test, 1, resp->capabilities);
	CuAssertIntEquals (test, 2, resp->num_digests);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (cert_buf, cerberus_protocol_certificate_digests (resp),
		sizeof (cert_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_slot (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	struct cerberus_protocol_get_certificate_digest_response *resp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 2;
	req->key_alg = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, ATTESTATION_INVALID_SLOT_NUM, MOCK_ARG (2),
		MOCK_ARG (&request.data[sizeof (*resp)]), MOCK_ARG (max), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_digest_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, resp->header.command);
	CuAssertIntEquals (test, 1, resp->capabilities);
	CuAssertIntEquals (test, 0, resp->num_digests);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_unavailable_cert (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	struct cerberus_protocol_get_certificate_digest_response *resp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 1;
	req->key_alg = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, ATTESTATION_CERT_NOT_AVAILABLE, MOCK_ARG (1),
		MOCK_ARG (&request.data[sizeof (*resp)]), MOCK_ARG (max), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_digest_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, resp->header.command);
	CuAssertIntEquals (test, 1, resp->capabilities);
	CuAssertIntEquals (test, 0, resp->num_digests);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_encryption_unsupported (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 2;
	req->key_alg = 1;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 0;
	req->key_alg = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_certificate_digest) - 1;
	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_algo (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 0;
	req->key_alg = NUM_ATTESTATION_KEY_EXCHANGE_ALGORITHMS;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_slot (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 8;
	req->key_alg = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_digest_fail (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_digest *req =
		(struct cerberus_protocol_get_certificate_digest*) data;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	req->slot_num = 0;
	req->key_alg = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, ATTESTATION_INVALID_ARGUMENT, MOCK_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (max), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = 0;
	req->length = 10;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_response) + 10,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 0, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		cerberus_protocol_certificate (resp), 10);
	CuAssertIntEquals (test, 0, status);

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = 10;
	req->length = 10;
	request.length = sizeof (struct cerberus_protocol_get_certificate);

	status |= mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_response) + 10,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 0, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (&X509_CERTCA_ECC_CA_NOPL_DER[10],
		cerberus_protocol_certificate (resp), 10);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_length_0 (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = 0;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_certificate_response) +
			X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 0, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		cerberus_protocol_certificate (resp), X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_aux_slot (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 1;
	req->cert_num = 1;
	req->offset = 0;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, 0, MOCK_ARG (1), MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_certificate_response) +
			X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 1, resp->slot_num);
	CuAssertIntEquals (test, 1, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		cerberus_protocol_certificate (resp), X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;
	int max = X509_CERTCA_ECC_CA_NOPL_DER_LEN - 10 -
		sizeof (struct cerberus_protocol_get_certificate_response);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = 0;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = X509_CERTCA_ECC_CA_NOPL_DER_LEN - 10;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_response) + max,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 0, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		cerberus_protocol_certificate (resp), max);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_invalid_offset (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = X509_CERTCA_ECC_CA_NOPL_DER_LEN + 1;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 0, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_valid_offset_and_length_beyond_cert_len (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = X509_CERTCA_ECC_CA_NOPL_DER_LEN - 2;
	req->length = X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_response) + 2,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 0, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (
		&X509_CERTCA_ECC_CA_NOPL_DER[X509_CERTCA_ECC_CA_NOPL_DER_LEN - 2],
		cerberus_protocol_certificate (resp), 2);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_length_too_big (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = 0;
	req->length = 6000;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_certificate_response) +
			X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 0, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		cerberus_protocol_certificate (resp), X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_slot (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 2;
	req->cert_num = 1;
	req->offset = 0;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, ATTESTATION_INVALID_SLOT_NUM, MOCK_ARG (2), MOCK_ARG (1),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 2, resp->slot_num);
	CuAssertIntEquals (test, 1, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_cert (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 4;
	req->offset = 0;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, ATTESTATION_INVALID_CERT_NUM, MOCK_ARG (0), MOCK_ARG (4),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 0, resp->slot_num);
	CuAssertIntEquals (test, 4, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_unavailable_cert (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct cerberus_protocol_get_certificate_response *resp =
		(struct cerberus_protocol_get_certificate_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 1;
	req->cert_num = 1;
	req->offset = 0;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, ATTESTATION_CERT_NOT_AVAILABLE, MOCK_ARG (1), MOCK_ARG (1),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);
	CuAssertIntEquals (test, 1, resp->slot_num);
	CuAssertIntEquals (test, 1, resp->cert_num);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = 0;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_certificate) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_invalid_slot_num (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 8;
	req->cert_num = 0;
	req->offset = 0;
	req->length = 0;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_certificate_fail (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate *req =
		(struct cerberus_protocol_get_certificate*) data;
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	req->slot_num = 0;
	req->cert_num = 0;
	req->offset = 0;
	req->length = 6000;
	request.length = sizeof (struct cerberus_protocol_get_certificate);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_certificate,
		slave_attestation, ATTESTATION_NO_MEMORY, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&slave_attestation->mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_challenge_response (CuTest *test,
	struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation,
	struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t digest_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg digest_request;
	struct cerberus_protocol_challenge *req = (struct cerberus_protocol_challenge*) data;
	struct cerberus_protocol_challenge_response *resp =
		(struct cerberus_protocol_challenge_response*) data;
	struct cerberus_protocol_get_certificate_digest *digest_req =
		(struct cerberus_protocol_get_certificate_digest*) digest_data;
	uint8_t nonce[ATTESTATION_NONCE_LEN];
	uint8_t response_buf[136] = {0};
	struct attestation_response *response = (struct attestation_response*) response_buf;
	int status;
	int max_digest = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG;

	memset (&digest_request, 0, sizeof (digest_request));
	memset (digest_data, 0, sizeof (digest_data));
	digest_request.data = digest_data;
	digest_req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	digest_req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	digest_req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	digest_req->slot_num = 0;
	digest_req->key_alg = ATTESTATION_ECDHE_KEY_EXCHANGE;
	digest_request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	digest_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	digest_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	digest_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (*response)] = 0xCC;
	response_buf[sizeof (*response) + 31] = 0xDD;
	response_buf[sizeof (*response) + 32] = 0xEE;
	response_buf[sizeof (*response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memset (nonce, 0x55, 32);
	memcpy (req->challenge.nonce, nonce, sizeof (req->challenge.nonce));

	req->challenge.slot_num = 0;
	request.length = sizeof (struct cerberus_protocol_challenge);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.reset_session, session, 0,
		MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG (NULL), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (0),
		MOCK_ARG (
			&digest_request.data[sizeof (struct cerberus_protocol_get_certificate_digest_response)]),
		MOCK_ARG (max_digest), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd->process_request (cmd, &digest_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.challenge_response,
		slave_attestation, sizeof (response_buf), MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&slave_attestation->mock, 0, response_buf, sizeof (response_buf),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.add_session, session, 0,
		MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG_PTR_CONTAINS_TMP (nonce, sizeof (nonce)),
		MOCK_ARG_PTR_CONTAINS_TMP (response->nonce, sizeof (response->nonce)));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (response_buf, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (response_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_challenge_response_no_session_mgr (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_challenge *req = (struct cerberus_protocol_challenge*) data;
	struct cerberus_protocol_challenge_response *resp =
		(struct cerberus_protocol_challenge_response*) data;
	uint8_t response_buf[136] = {0};
	struct attestation_response *response = (struct attestation_response*) response_buf;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (*response)] = 0xCC;
	response_buf[sizeof (*response) + 31] = 0xDD;
	response_buf[sizeof (*response) + 32] = 0xEE;
	response_buf[sizeof (*response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memset (&req->challenge.nonce, 0x55, 32);
	req->challenge.slot_num = 0;
	request.length = sizeof (struct cerberus_protocol_challenge);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.challenge_response,
		slave_attestation, sizeof (response_buf), MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&slave_attestation->mock, 0, response_buf, sizeof (response_buf),
		-1);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (response_buf, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (response_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_challenge_response_key_exchange_not_requested (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t digest_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg digest_request;
	struct cerberus_protocol_challenge *req = (struct cerberus_protocol_challenge*) data;
	struct cerberus_protocol_challenge_response *resp =
		(struct cerberus_protocol_challenge_response*) data;
	struct cerberus_protocol_get_certificate_digest *digest_req =
		(struct cerberus_protocol_get_certificate_digest*) digest_data;
	uint8_t nonce[ATTESTATION_NONCE_LEN];
	uint8_t response_buf[136] = {0};
	struct attestation_response *response = (struct attestation_response*) response_buf;
	int status;
	int max_digest = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG;

	memset (&digest_request, 0, sizeof (digest_request));
	memset (digest_data, 0, sizeof (digest_data));
	digest_request.data = digest_data;
	digest_req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	digest_req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	digest_req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	digest_req->slot_num = 0;
	digest_req->key_alg = ATTESTATION_KEY_EXCHANGE_NONE;
	digest_request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	digest_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	digest_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	digest_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (*response)] = 0xCC;
	response_buf[sizeof (*response) + 31] = 0xDD;
	response_buf[sizeof (*response) + 32] = 0xEE;
	response_buf[sizeof (*response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memset (nonce, 0x55, 32);
	memcpy (req->challenge.nonce, nonce, sizeof (req->challenge.nonce));

	req->challenge.slot_num = 0;
	request.length = sizeof (struct cerberus_protocol_challenge);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (0),
		MOCK_ARG (
			&digest_request.data[sizeof (struct cerberus_protocol_get_certificate_digest_response)]),
		MOCK_ARG (max_digest), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd->process_request (cmd, &digest_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.challenge_response,
		slave_attestation, sizeof (response_buf), MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&slave_attestation->mock, 0, response_buf, sizeof (response_buf),
		-1);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (response_buf, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (response_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation,
	struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t digest_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg digest_request;
	struct cerberus_protocol_challenge *req = (struct cerberus_protocol_challenge*) data;
	struct cerberus_protocol_challenge_response *resp =
		(struct cerberus_protocol_challenge_response*) data;
	struct cerberus_protocol_get_certificate_digest *digest_req =
		(struct cerberus_protocol_get_certificate_digest*) digest_data;
	uint8_t response_buf[136] = {0};
	uint8_t nonce[ATTESTATION_NONCE_LEN];
	struct attestation_response *response = (struct attestation_response*) response_buf;
	int status;
	int max_digest = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 128;

	memset (&digest_request, 0, sizeof (digest_request));
	memset (digest_data, 0, sizeof (digest_data));
	digest_request.data = digest_data;
	digest_req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	digest_req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	digest_req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	digest_req->slot_num = 0;
	digest_req->key_alg = ATTESTATION_ECDHE_KEY_EXCHANGE;
	digest_request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	digest_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	digest_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	digest_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (*response)] = 0xCC;
	response_buf[sizeof (*response) + 31] = 0xDD;
	response_buf[sizeof (*response) + 32] = 0xEE;
	response_buf[sizeof (*response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memset (nonce, 0x55, 32);
	memcpy (req->challenge.nonce, nonce, sizeof (req->challenge.nonce));

	req->challenge.slot_num = 0;
	request.length = sizeof (struct cerberus_protocol_challenge);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.reset_session, session, 0,
		MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG (NULL), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (0),
		MOCK_ARG (
			&digest_request.data[sizeof (struct cerberus_protocol_get_certificate_digest_response)]),
		MOCK_ARG (max_digest), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd->process_request (cmd, &digest_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.challenge_response,
		slave_attestation, sizeof (response_buf), MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&slave_attestation->mock, 0, response_buf, sizeof (response_buf),
		-1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.add_session, session, 0,
		MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG_PTR_CONTAINS_TMP (nonce, sizeof (nonce)),
		MOCK_ARG_PTR_CONTAINS_TMP (response->nonce, sizeof (response->nonce)));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (response_buf, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (response_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_no_session_mgr (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_challenge *req = (struct cerberus_protocol_challenge*) data;
	struct cerberus_protocol_challenge_response *resp =
		(struct cerberus_protocol_challenge_response*) data;
	uint8_t response_buf[136] = {0};
	struct attestation_response *response = (struct attestation_response*) response_buf;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 128;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (*response)] = 0xCC;
	response_buf[sizeof (*response) + 31] = 0xDD;
	response_buf[sizeof (*response) + 32] = 0xEE;
	response_buf[sizeof (*response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memset (req->challenge.nonce, 0x55, sizeof (req->challenge.nonce));

	req->challenge.slot_num = 0;
	request.length = sizeof (struct cerberus_protocol_challenge);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.challenge_response,
		slave_attestation, sizeof (response_buf), MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&slave_attestation->mock, 0, response_buf, sizeof (response_buf),
		-1);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (response_buf, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (response_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_key_exchange_not_requested (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t digest_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg digest_request;
	struct cerberus_protocol_challenge *req = (struct cerberus_protocol_challenge*) data;
	struct cerberus_protocol_challenge_response *resp =
		(struct cerberus_protocol_challenge_response*) data;
	struct cerberus_protocol_get_certificate_digest *digest_req =
		(struct cerberus_protocol_get_certificate_digest*) digest_data;
	uint8_t response_buf[136] = {0};
	uint8_t nonce[ATTESTATION_NONCE_LEN];
	struct attestation_response *response = (struct attestation_response*) response_buf;
	int status;
	int max_digest = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 2;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 128;

	memset (&digest_request, 0, sizeof (digest_request));
	memset (digest_data, 0, sizeof (digest_data));
	digest_request.data = digest_data;
	digest_req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	digest_req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	digest_req->header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	digest_req->slot_num = 0;
	digest_req->key_alg = ATTESTATION_KEY_EXCHANGE_NONE;
	digest_request.length = sizeof (struct cerberus_protocol_get_certificate_digest);
	digest_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	digest_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	digest_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (*response)] = 0xCC;
	response_buf[sizeof (*response) + 31] = 0xDD;
	response_buf[sizeof (*response) + 32] = 0xEE;
	response_buf[sizeof (*response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memset (nonce, 0x55, 32);
	memcpy (req->challenge.nonce, nonce, sizeof (req->challenge.nonce));

	req->challenge.slot_num = 0;
	request.length = sizeof (struct cerberus_protocol_challenge);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.get_digests,
		slave_attestation, 64, MOCK_ARG (0),
		MOCK_ARG (
			&digest_request.data[sizeof (struct cerberus_protocol_get_certificate_digest_response)]),
		MOCK_ARG (max_digest), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd->process_request (cmd, &digest_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.challenge_response,
		slave_attestation, sizeof (response_buf), MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&slave_attestation->mock, 0, response_buf, sizeof (response_buf),
		-1);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (response_buf, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (response_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_challenge_response_fail (
	CuTest *test, struct cmd_interface *cmd, struct attestation_slave_mock *slave_attestation)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_challenge *req = (struct cerberus_protocol_challenge*) data;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memset (&req->challenge.nonce, 0x55, 32);
	req->challenge.slot_num = 0;
	request.length = sizeof (struct cerberus_protocol_challenge);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&slave_attestation->mock, slave_attestation->base.challenge_response,
		slave_attestation, ATTESTATION_NO_MEMORY, MOCK_ARG_NOT_NULL, MOCK_ARG (max));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_challenge_response_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_challenge *req = (struct cerberus_protocol_challenge*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memset (&req->challenge.nonce, 0x55, 32);
	req->challenge.slot_num = 0;
	request.length = sizeof (struct cerberus_protocol_challenge) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_challenge) - 1;
	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_capabilities (CuTest *test,
	struct cmd_interface *cmd, struct device_manager *device_manager)
{
	struct device_manager_full_capabilities expected_in;
	struct device_manager_full_capabilities expected_out;
	struct device_manager_full_capabilities out;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_device_capabilities *req =
		(struct cerberus_protocol_device_capabilities*) data;
	struct cerberus_protocol_device_capabilities_response *resp =
		(struct cerberus_protocol_device_capabilities_response*) data;
	int status;

	memset (&expected_in, 0, sizeof (expected_in));
	expected_in.request.max_message_size = 1024;
	expected_in.request.max_packet_size = 128;
	expected_in.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	expected_in.request.bus_role = DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE;
	expected_in.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;

	memset (&expected_out, 0, sizeof (expected_out));
	expected_out.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected_out.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	expected_out.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	expected_out.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	expected_out.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	expected_out.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	expected_out.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES;

	memcpy ((uint8_t*) &req->capabilities, (uint8_t*) &expected_in.request,
		sizeof (expected_in.request));
	request.length = sizeof (struct cerberus_protocol_device_capabilities);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_device_capabilities_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) &expected_out, (uint8_t*) &resp->capabilities,
		sizeof (expected_out));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_get_device_capabilities (device_manager, 1, &out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &expected_in, (uint8_t*) &out,
		sizeof (expected_in));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_device (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_device_capabilities *req =
		(struct cerberus_protocol_device_capabilities*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES;

	request.length =  sizeof (struct cerberus_protocol_device_capabilities);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = 0xEE;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_device_capabilities *req =
		(struct cerberus_protocol_device_capabilities*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES;

	request.length = sizeof (struct cerberus_protocol_device_capabilities) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_device_capabilities) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_devid_csr (CuTest *test,
	struct cmd_interface *cmd, const uint8_t* csr, size_t csr_length)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_export_csr *req = (struct cerberus_protocol_export_csr*) data;
	struct cerberus_protocol_export_csr_response *resp =
		(struct cerberus_protocol_export_csr_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	req->index = 0;
	request.length = sizeof (struct cerberus_protocol_export_csr);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_export_csr) + csr_length - 1,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXPORT_CSR, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (csr, &resp->csr, csr_length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_devid_csr_limited_response (
	CuTest *test, struct cmd_interface *cmd, const uint8_t* csr, size_t csr_length)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_export_csr *req = (struct cerberus_protocol_export_csr*) data;
	struct cerberus_protocol_export_csr_response *resp =
		(struct cerberus_protocol_export_csr_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	req->index = 0;
	request.length = sizeof (struct cerberus_protocol_export_csr);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_export_csr) + csr_length - 1,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXPORT_CSR, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (csr, &resp->csr, csr_length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_devid_csr_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_export_csr *req = (struct cerberus_protocol_export_csr*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	req->index = 0;
	request.length = sizeof (struct cerberus_protocol_export_csr) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_export_csr) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_devid_csr_unsupported_index (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_export_csr *req = (struct cerberus_protocol_export_csr*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	req->index = 1;
	request.length = sizeof (struct cerberus_protocol_export_csr);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big (CuTest *test,
	struct cmd_interface *cmd, struct riot_key_manager *riot)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_export_csr *req = (struct cerberus_protocol_export_csr*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	req->index = 0;
	request.length = sizeof (struct cerberus_protocol_export_csr);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	riot->keys.devid_csr_length = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big_limited_response (
	CuTest *test, struct cmd_interface *cmd, const uint8_t* csr, size_t csr_length)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_export_csr *req = (struct cerberus_protocol_export_csr*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	req->index = 0;
	request.length = sizeof (struct cerberus_protocol_export_csr);
	request.max_response = csr_length + sizeof (struct cerberus_protocol_export_csr_response) - 2;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_RESPONSE_TOO_SMALL, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert (CuTest *test,
	struct cmd_interface *cmd, struct keystore_mock *keystore,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 0;
	req->cert_length = RIOT_CORE_DEVID_SIGNED_CERT_LEN;
	memcpy (&req->certificate, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + RIOT_CORE_DEVID_SIGNED_CERT_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&keystore->mock, keystore->base.save_key, keystore, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN));

	status |= mock_expect (&background->mock, background->base.authenticate_riot_certs, background,
		0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_root_ca_cert (CuTest *test,
	struct cmd_interface *cmd, struct keystore_mock *keystore,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 1;
	req->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&req->certificate, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + X509_CERTSS_RSA_CA_NOPL_DER_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&keystore->mock, keystore->base.save_key, keystore, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));

	status |= mock_expect (&background->mock, background->base.authenticate_riot_certs, background,
		0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_intermediate_cert (CuTest *test,
	struct cmd_interface *cmd, struct keystore_mock *keystore,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 2;
	req->cert_length = X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&req->certificate, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + X509_CERTCA_ECC_CA_NOPL_DER_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&keystore->mock, keystore->base.save_key, keystore, 0, MOCK_ARG (2),
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));

	status |= mock_expect (&background->mock, background->base.authenticate_riot_certs, background,
		0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 1;
	req->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&req->certificate, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	request.length = sizeof (struct cerberus_protocol_import_certificate) - 2;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_no_cert (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 1;
	request.length = sizeof (struct cerberus_protocol_import_certificate) - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_bad_cert_length (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 1;
	req->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&req->certificate, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + X509_CERTSS_RSA_CA_NOPL_DER_LEN - 2;
	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_unsupported_index (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 3;
	req->cert_length = RIOT_CORE_DEVID_SIGNED_CERT_LEN;
	memcpy (&req->certificate, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + RIOT_CORE_DEVID_SIGNED_CERT_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert_save_error (
	CuTest *test, struct cmd_interface *cmd, struct keystore_mock *keystore)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 0;
	req->cert_length = RIOT_CORE_DEVID_SIGNED_CERT_LEN;
	memcpy (&req->certificate, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + RIOT_CORE_DEVID_SIGNED_CERT_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&keystore->mock, keystore->base.save_key, keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_root_ca_cert_save_error (
	CuTest *test, struct cmd_interface *cmd, struct keystore_mock *keystore)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 1;
	req->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&req->certificate, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + X509_CERTSS_RSA_CA_NOPL_DER_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&keystore->mock, keystore->base.save_key, keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_intermediate_cert_save_error (
	CuTest *test, struct cmd_interface *cmd, struct keystore_mock *keystore)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 2;
	req->cert_length = X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&req->certificate, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + X509_CERTCA_ECC_CA_NOPL_DER_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&keystore->mock, keystore->base.save_key, keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (2),
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_authenticate_error (
	CuTest *test, struct cmd_interface *cmd, struct keystore_mock *keystore,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	req->index = 0;
	req->cert_length = RIOT_CORE_DEVID_SIGNED_CERT_LEN;
	memcpy (&req->certificate, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	request.length =
		sizeof (struct cerberus_protocol_import_certificate) + RIOT_CORE_DEVID_SIGNED_CERT_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&keystore->mock, keystore->base.save_key, keystore, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN));

	status |= mock_expect (&background->mock, background->base.authenticate_riot_certs, background,
		CMD_BACKGROUND_TASK_BUSY);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_signed_cert_state (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_state *req =
		(struct cerberus_protocol_get_certificate_state*) data;
	struct cerberus_protocol_get_certificate_state_response *resp =
		(struct cerberus_protocol_get_certificate_state_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE;

	request.length = sizeof (struct cerberus_protocol_get_certificate_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.get_riot_cert_chain_state, background,
		RIOT_CERT_STATE_CHAIN_INVALID);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_certificate_state_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE, resp->header.command);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, resp->cert_state);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_signed_cert_state_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_certificate_state *req =
		(struct cerberus_protocol_get_certificate_state*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE;

	request.length = sizeof (struct cerberus_protocol_get_certificate_state) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_device_info (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_device_info *req =
		(struct cerberus_protocol_get_device_info*) data;
	struct cerberus_protocol_get_device_info_response *resp =
		(struct cerberus_protocol_get_device_info_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	req->info_index = 0;
	request.length = sizeof (struct cerberus_protocol_get_device_info);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd_device->mock, cmd_device->base.get_uuid, cmd_device,
		CMD_DEVICE_UUID_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG));
	status |= mock_expect_output (&cmd_device->mock, 0, CMD_DEVICE_UUID, CMD_DEVICE_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_device_info_response) + CMD_DEVICE_UUID_LEN - 1,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_INFO, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

    status = testing_validate_array (CMD_DEVICE_UUID, &resp->info, CMD_DEVICE_UUID_LEN);
    CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_device_info_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct cmd_device_mock *cmd_device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_device_info *req =
		(struct cerberus_protocol_get_device_info*) data;
	struct cerberus_protocol_get_device_info_response *resp =
		(struct cerberus_protocol_get_device_info_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	req->info_index = 0;
	request.length = sizeof (struct cerberus_protocol_get_device_info);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd_device->mock, cmd_device->base.get_uuid, cmd_device,
		CMD_DEVICE_UUID_LEN, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 128));
	status |= mock_expect_output (&cmd_device->mock, 0, CMD_DEVICE_UUID, CMD_DEVICE_UUID_LEN, 1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_device_info_response) + CMD_DEVICE_UUID_LEN - 1,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_INFO, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

    status = testing_validate_array (CMD_DEVICE_UUID, &resp->info, CMD_DEVICE_UUID_LEN);
    CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_required_commands_testing_process_get_device_info_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_device_info *req =
		(struct cerberus_protocol_get_device_info*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	req->info_index = 0;
	request.length = sizeof (struct cerberus_protocol_get_device_info) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_device_info) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_device_info_bad_info_index (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_device_info *req =
		(struct cerberus_protocol_get_device_info*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	req->info_index = 1;
	request.length = sizeof (struct cerberus_protocol_get_device_info);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_device_info_fail (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_device_info *req =
		(struct cerberus_protocol_get_device_info*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	req->info_index = 0;
	request.length = sizeof (struct cerberus_protocol_get_device_info);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd_device->mock, cmd_device->base.get_uuid, cmd_device,
		CMD_DEVICE_UUID_BUFFER_TOO_SMALL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_DEVICE_UUID_BUFFER_TOO_SMALL, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_device_id (CuTest *test,
	struct cmd_interface *cmd, uint16_t vendor_id, uint16_t device_id, uint16_t subsystem_vid,
	uint16_t subsystem_id)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_device_id *req = (struct cerberus_protocol_get_device_id*) data;
	struct cerberus_protocol_get_device_id_response *resp =
		(struct cerberus_protocol_get_device_id_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_ID;

	request.length = sizeof (struct cerberus_protocol_get_device_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_device_id_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_ID, resp->header.command);
	CuAssertIntEquals (test, vendor_id, resp->vendor_id);
	CuAssertIntEquals (test, device_id, resp->device_id);
	CuAssertIntEquals (test, subsystem_vid, resp->subsystem_vid);
	CuAssertIntEquals (test, subsystem_id, resp->subsystem_id);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_get_device_id_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_device_id *req = (struct cerberus_protocol_get_device_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_DEVICE_ID;

	request.length = sizeof (struct cerberus_protocol_get_device_id) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_reset_counter (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	struct cerberus_protocol_reset_counter_response *resp =
		(struct cerberus_protocol_reset_counter_response*) data;
	uint16_t counter = 4;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_counter);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd_device->mock, cmd_device->base.get_reset_counter, cmd_device, 0,
		MOCK_ARG (CERBERUS_PROTOCOL_CERBERUS_RESET), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd_device->mock, 2, &counter, sizeof (uint16_t), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_counter_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_COUNTER, resp->header.command);
	CuAssertIntEquals (test, counter, resp->counter);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_reset_counter_port0 (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	struct cerberus_protocol_reset_counter_response *resp =
		(struct cerberus_protocol_reset_counter_response*) data;
	uint16_t counter = 4;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;

	req->type = 1;
	req->port = 0;
	request.length = sizeof (struct cerberus_protocol_reset_counter);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd_device->mock, cmd_device->base.get_reset_counter, cmd_device, 0,
		MOCK_ARG (CERBERUS_PROTOCOL_COMPONENT_RESET), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd_device->mock, 2, &counter, sizeof (uint16_t), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_counter_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_COUNTER, resp->header.command);
	CuAssertIntEquals (test, counter, resp->counter);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_reset_counter_port1 (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *cmd_device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	struct cerberus_protocol_reset_counter_response *resp =
		(struct cerberus_protocol_reset_counter_response*) data;
	uint16_t counter = 4;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;

	req->type = 1;
	req->port = 1;
	request.length = sizeof (struct cerberus_protocol_reset_counter);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd_device->mock, cmd_device->base.get_reset_counter, cmd_device, 0,
		MOCK_ARG (CERBERUS_PROTOCOL_COMPONENT_RESET), MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd_device->mock, 2, &counter, sizeof (uint16_t), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_counter_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_COUNTER, resp->header.command);
	CuAssertIntEquals (test, counter, resp->counter);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_reset_counter_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;

	req->type = 1;
	req->port = 1;
	request.length = sizeof (struct cerberus_protocol_reset_counter) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_reset_counter) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_required_commands_testing_process_reset_counter_invalid_counter (
	CuTest *test, struct cmd_interface *cmd, struct cmd_device_mock *cmd_device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;

	req->type = 2;
	req->port = 0;
	request.length = sizeof (struct cerberus_protocol_reset_counter);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd_device->mock, cmd_device->base.get_reset_counter, cmd_device,
		CMD_DEVICE_INVALID_COUNTER, MOCK_ARG (2), MOCK_ARG (0), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_DEVICE_INVALID_COUNTER, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_master_commands_testing_process_error_response (CuTest *test,
	struct cmd_interface *cmd, struct cmd_interface_msg *response)
{
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) response->data;
	int status;

	error->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	error->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	error->header.command = CERBERUS_PROTOCOL_ERROR;

	response->length = sizeof (struct cerberus_protocol_error);
	response->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response->target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = cmd->process_response (cmd, response);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_master_commands_testing_process_error_response_invalid_len (CuTest *test,
	struct cmd_interface *cmd, struct cmd_interface_msg *response)
{
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) response->data;
	int status;

	error->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	error->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	error->header.command = CERBERUS_PROTOCOL_ERROR;

	response->length = sizeof (struct cerberus_protocol_error) - 1;
	response->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response->target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = cmd->process_response (cmd, response);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ERROR_MSG, status);
}

void cerberus_protocol_required_commands_testing_generate_error_packet (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg error_packet;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;

	memset (&error_packet, 0, sizeof (error_packet));
	memset (data, 0, sizeof (data));
	error_packet.data = data;

	status = cmd->generate_error_packet (cmd, &error_packet, CERBERUS_PROTOCOL_NO_ERROR, 0, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_error), error_packet.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);
}

void cerberus_protocol_required_commands_testing_generate_error_packet_encrypted (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	struct cerberus_protocol_key_exchange *rq =
		(struct cerberus_protocol_key_exchange*) data;
	struct cerberus_protocol_key_exchange *decrypted_rq =
		(struct cerberus_protocol_key_exchange*) decrypted_data;
	uint8_t hmac_buf[SHA256_HASH_LENGTH] = {0};
	uint8_t error_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg error_packet;
	uint8_t encrypted_error_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg encrypted_error_packet;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	memset (&error_packet, 0, sizeof (error_packet));
	memset (error_data, 0, sizeof (error_data));
	error_packet.data = error_data;

	memset (&encrypted_error_packet, 0, sizeof (encrypted_error_packet));
	memset (encrypted_error_data, 0, sizeof (encrypted_error_data));
	encrypted_error_packet.data = encrypted_error_data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.crypt = 1;
	rq->header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->key_type = 0xAA;

	memset (cerberus_protocol_key_exchange_type_2_hmac_data (rq), 0xCC, sizeof (hmac_buf));

	request.length = cerberus_protocol_key_exchange_type_2_length (sizeof (hmac_buf));
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	decrypted_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	decrypted_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	decrypted_rq->header.crypt = 1;
	decrypted_rq->header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	decrypted_rq->key_type = CERBERUS_PROTOCOL_DELETE_SESSION_KEY;

	memcpy (cerberus_protocol_key_exchange_type_2_hmac_data (decrypted_rq), hmac_buf,
		sizeof (hmac_buf));

	decrypted_request.length = cerberus_protocol_key_exchange_type_2_length (SHA256_HASH_LENGTH);
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	error_packet.length = sizeof (struct cerberus_protocol_error);
	error_packet.max_response = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;
	error_packet.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	error_packet.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	error = (struct cerberus_protocol_error*) encrypted_error_packet.data;
	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 1;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = 0xAA;
	error->error_data = 0xBB;

	encrypted_error_packet.length = sizeof (struct cerberus_protocol_error) +
		SESSION_MANAGER_TRAILER_LEN;
	encrypted_error_packet.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted_error_packet.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.reset_session, session,
		SESSION_MANAGER_NO_MEMORY, MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID),
		MOCK_ARG_PTR_CONTAINS_TMP (hmac_buf, sizeof (hmac_buf)), MOCK_ARG (sizeof (hmac_buf)));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = mock_expect (&session->mock, session->base.encrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &error_packet,
			sizeof (error_packet), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request, cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &encrypted_error_packet,
		sizeof (encrypted_error_packet), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	error = (struct cerberus_protocol_error*) error_packet.data;
	memset (error_data, 0, sizeof (error_data));
	error_packet.length = 0;
	error_packet.max_response = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;

	status = cmd->generate_error_packet (cmd, &error_packet, CERBERUS_PROTOCOL_NO_ERROR, 0, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_error) + SESSION_MANAGER_TRAILER_LEN,
		error_packet.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 1, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, 0xAA, error->error_code);
	CuAssertIntEquals (test, 0xBB, error->error_data);
}

void cerberus_protocol_required_commands_testing_generate_error_packet_encrypted_fail (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	struct cerberus_protocol_key_exchange *rq =
		(struct cerberus_protocol_key_exchange*) data;
	struct cerberus_protocol_key_exchange *decrypted_rq =
		(struct cerberus_protocol_key_exchange*) decrypted_data;
	uint8_t hmac_buf[SHA256_HASH_LENGTH] = {0};
	uint8_t error_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg error_packet;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	memset (&error_packet, 0, sizeof (error_packet));
	memset (error_data, 0, sizeof (error_data));
	error_packet.data = error_data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.crypt = 1;
	rq->header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->key_type = 0xAA;

	memset (cerberus_protocol_key_exchange_type_2_hmac_data (rq), 0xCC, sizeof (hmac_buf));

	request.length = cerberus_protocol_key_exchange_type_2_length (sizeof (hmac_buf));
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	decrypted_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	decrypted_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	decrypted_rq->header.crypt = 1;
	decrypted_rq->header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	decrypted_rq->key_type = CERBERUS_PROTOCOL_DELETE_SESSION_KEY;

	memcpy (cerberus_protocol_key_exchange_type_2_hmac_data (decrypted_rq), hmac_buf,
		sizeof (hmac_buf));

	decrypted_request.length = cerberus_protocol_key_exchange_type_2_length (SHA256_HASH_LENGTH);
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	error_packet.length = sizeof (struct cerberus_protocol_error);
	error_packet.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	error_packet.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.reset_session, session,
		SESSION_MANAGER_NO_MEMORY, MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID),
		MOCK_ARG_PTR_CONTAINS_TMP (hmac_buf, sizeof (hmac_buf)), MOCK_ARG (sizeof (hmac_buf)));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = mock_expect (&session->mock, session->base.encrypt_message, session,
		SESSION_MANAGER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &error_packet,
			sizeof (error_packet), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request, cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd->generate_error_packet (cmd, &error_packet, CERBERUS_PROTOCOL_NO_ERROR, 0, 0);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
}

void cerberus_protocol_required_commands_testing_generate_error_packet_invalid_arg (CuTest *test,
	struct cmd_interface *cmd)
{
	struct cmd_interface_msg error_packet;
	int status;

	status = cmd->generate_error_packet (NULL, &error_packet, CERBERUS_PROTOCOL_NO_ERROR, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd->generate_error_packet (cmd, NULL, CERBERUS_PROTOCOL_NO_ERROR, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
}


/*******************
 * Test cases
 *******************/

static void cerberus_protocol_required_commands_test_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x7e,0x14,0x13,0xf5,0xaa
	};
	struct cerberus_protocol_header *header;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct cerberus_protocol_header));

	header = (struct cerberus_protocol_header*) raw_buffer;
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0x7e, header->msg_type);
	CuAssertIntEquals (test, 0x1314, header->pci_vendor_id);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 1, header->reserved2);
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0x15, header->reserved1);
	CuAssertIntEquals (test, 0xaa, header->command);

	raw_buffer[0] = 0xfe;
	CuAssertIntEquals (test, 1, header->integrity_check);
	CuAssertIntEquals (test, 0x7e, header->msg_type);

	raw_buffer[3] = 0x75;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->reserved2);
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0x15, header->reserved1);

	raw_buffer[3] = 0x35;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0x15, header->reserved1);

	raw_buffer[3] = 0x15;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0x15, header->reserved1);
}

static void cerberus_protocol_required_commands_test_error_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x7e,0x14,0x13,0x03,0x7f,
		0x01,0x02,0x03,0x04,0x05
	};
	struct cerberus_protocol_error *error;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct cerberus_protocol_error));

	error = (struct cerberus_protocol_error*) raw_buffer;
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, error->header.msg_type);
	CuAssertIntEquals (test, 0x1314, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0x03, error->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);

	CuAssertIntEquals (test, 0x01, error->error_code);
	CuAssertIntEquals (test, 0x05040302, error->error_data);
}

static void cerberus_protocol_required_commands_test_device_capabilities_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x7e,0x14,0x13,0x03,0x02,
		0x04,0x03,0x02,0x01,0x51,0xe0,0xd2,0x84,
		0x10,0x20
	};
	struct cerberus_protocol_device_capabilities *req;
	struct cerberus_protocol_device_capabilities_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer) - 2,
		sizeof (struct cerberus_protocol_device_capabilities));
	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct cerberus_protocol_device_capabilities_response));

	req = (struct cerberus_protocol_device_capabilities*) raw_buffer;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, req->header.command);

	CuAssertIntEquals (test, 0x0304, req->capabilities.max_message_size);
	CuAssertIntEquals (test, 0x0102, req->capabilities.max_packet_size);
	CuAssertIntEquals (test, DEVICE_MANAGER_PA_ROT_MODE, req->capabilities.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_BUS_ROLE, req->capabilities.bus_role);
	CuAssertIntEquals (test, 0, req->capabilities.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_HASH_KDF, req->capabilities.security_mode);
	CuAssertIntEquals (test, 1, req->capabilities.pfm_support);
	CuAssertIntEquals (test, 1, req->capabilities.policy_support);
	CuAssertIntEquals (test, 1, req->capabilities.fw_protection);
	CuAssertIntEquals (test, 0x00, req->capabilities.reserved2);
	CuAssertIntEquals (test, 1, req->capabilities.rsa);
	CuAssertIntEquals (test, 1, req->capabilities.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_256, req->capabilities.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_3072, req->capabilities.rsa_key_strength);
	CuAssertIntEquals (test, 1, req->capabilities.ecc);
	CuAssertIntEquals (test, 0x00, req->capabilities.reserved3);
	CuAssertIntEquals (test, DEVICE_MANAGER_AES_KEY_384, req->capabilities.aes_enc_key_strength);

	resp = (struct cerberus_protocol_device_capabilities_response*) raw_buffer;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, resp->header.command);

	CuAssertIntEquals (test, 0x0304, resp->capabilities.request.max_message_size);
	CuAssertIntEquals (test, 0x0102, resp->capabilities.request.max_packet_size);
	CuAssertIntEquals (test, DEVICE_MANAGER_PA_ROT_MODE, resp->capabilities.request.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_BUS_ROLE, resp->capabilities.request.bus_role);
	CuAssertIntEquals (test, 0, resp->capabilities.request.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_HASH_KDF,
		resp->capabilities.request.security_mode);
	CuAssertIntEquals (test, 1, resp->capabilities.request.pfm_support);
	CuAssertIntEquals (test, 1, resp->capabilities.request.policy_support);
	CuAssertIntEquals (test, 1, resp->capabilities.request.fw_protection);
	CuAssertIntEquals (test, 0x00, resp->capabilities.request.reserved2);
	CuAssertIntEquals (test, 1, resp->capabilities.request.rsa);
	CuAssertIntEquals (test, 1, resp->capabilities.request.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_256,
		resp->capabilities.request.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_3072,
		resp->capabilities.request.rsa_key_strength);
	CuAssertIntEquals (test, 1, resp->capabilities.request.ecc);
	CuAssertIntEquals (test, 0x00, resp->capabilities.request.reserved3);
	CuAssertIntEquals (test, DEVICE_MANAGER_AES_KEY_384,
		resp->capabilities.request.aes_enc_key_strength);
	CuAssertIntEquals (test, 0x10, resp->capabilities.max_timeout);
	CuAssertIntEquals (test, 0x20, resp->capabilities.max_sig);

	raw_buffer[9] = 0x11;
	CuAssertIntEquals (test, DEVICE_MANAGER_AC_ROT_MODE, req->capabilities.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_BUS_ROLE, req->capabilities.bus_role);
	CuAssertIntEquals (test, 0, req->capabilities.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_HASH_KDF, req->capabilities.security_mode);

	CuAssertIntEquals (test, DEVICE_MANAGER_AC_ROT_MODE, resp->capabilities.request.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_BUS_ROLE, resp->capabilities.request.bus_role);
	CuAssertIntEquals (test, 0, resp->capabilities.request.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_HASH_KDF,
		resp->capabilities.request.security_mode);

	raw_buffer[9] = 0x31;
	CuAssertIntEquals (test, DEVICE_MANAGER_AC_ROT_MODE, req->capabilities.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE, req->capabilities.bus_role);
	CuAssertIntEquals (test, 0, req->capabilities.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_HASH_KDF, req->capabilities.security_mode);

	CuAssertIntEquals (test, DEVICE_MANAGER_AC_ROT_MODE, resp->capabilities.request.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE,
		 resp->capabilities.request.bus_role);
	CuAssertIntEquals (test, 0, resp->capabilities.request.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_HASH_KDF,
		resp->capabilities.request.security_mode);

	raw_buffer[9] = 0x39;
	CuAssertIntEquals (test, DEVICE_MANAGER_AC_ROT_MODE, req->capabilities.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE, req->capabilities.bus_role);
	CuAssertIntEquals (test, 1, req->capabilities.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_HASH_KDF, req->capabilities.security_mode);

	CuAssertIntEquals (test, DEVICE_MANAGER_AC_ROT_MODE, resp->capabilities.request.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE,
		 resp->capabilities.request.bus_role);
	CuAssertIntEquals (test, 1, resp->capabilities.request.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_HASH_KDF,
		resp->capabilities.request.security_mode);

	raw_buffer[9] = 0x3a;
	CuAssertIntEquals (test, DEVICE_MANAGER_AC_ROT_MODE, req->capabilities.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE, req->capabilities.bus_role);
	CuAssertIntEquals (test, 1, req->capabilities.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_AUTHENTICATION,
		 req->capabilities.security_mode);

	CuAssertIntEquals (test, DEVICE_MANAGER_AC_ROT_MODE, resp->capabilities.request.hierarchy_role);
	CuAssertIntEquals (test, DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE,
		 resp->capabilities.request.bus_role);
	CuAssertIntEquals (test, 1, resp->capabilities.request.reserved1);
	CuAssertIntEquals (test, DEVICE_MANAGER_SECURITY_AUTHENTICATION,
		resp->capabilities.request.security_mode);

	raw_buffer[10] = 0x60;
	CuAssertIntEquals (test, 0, req->capabilities.pfm_support);
	CuAssertIntEquals (test, 1, req->capabilities.policy_support);
	CuAssertIntEquals (test, 1, req->capabilities.fw_protection);
	CuAssertIntEquals (test, 0x00, req->capabilities.reserved2);

	CuAssertIntEquals (test, 0, resp->capabilities.request.pfm_support);
	CuAssertIntEquals (test, 1, resp->capabilities.request.policy_support);
	CuAssertIntEquals (test, 1, resp->capabilities.request.fw_protection);
	CuAssertIntEquals (test, 0x00, resp->capabilities.request.reserved2);

	raw_buffer[10] = 0x20;
	CuAssertIntEquals (test, 0, req->capabilities.pfm_support);
	CuAssertIntEquals (test, 0, req->capabilities.policy_support);
	CuAssertIntEquals (test, 1, req->capabilities.fw_protection);
	CuAssertIntEquals (test, 0x00, req->capabilities.reserved2);

	CuAssertIntEquals (test, 0, resp->capabilities.request.pfm_support);
	CuAssertIntEquals (test, 0, resp->capabilities.request.policy_support);
	CuAssertIntEquals (test, 1, resp->capabilities.request.fw_protection);
	CuAssertIntEquals (test, 0x00, resp->capabilities.request.reserved2);

	raw_buffer[10] = 0x00;
	CuAssertIntEquals (test, 0, req->capabilities.pfm_support);
	CuAssertIntEquals (test, 0, req->capabilities.policy_support);
	CuAssertIntEquals (test, 0, req->capabilities.fw_protection);
	CuAssertIntEquals (test, 0x00, req->capabilities.reserved2);

	CuAssertIntEquals (test, 0, resp->capabilities.request.pfm_support);
	CuAssertIntEquals (test, 0, resp->capabilities.request.policy_support);
	CuAssertIntEquals (test, 0, resp->capabilities.request.fw_protection);
	CuAssertIntEquals (test, 0x00, resp->capabilities.request.reserved2);

	raw_buffer[10] = 0x10;
	CuAssertIntEquals (test, 0, req->capabilities.pfm_support);
	CuAssertIntEquals (test, 0, req->capabilities.policy_support);
	CuAssertIntEquals (test, 0, req->capabilities.fw_protection);
	CuAssertIntEquals (test, 0x10, req->capabilities.reserved2);

	CuAssertIntEquals (test, 0, resp->capabilities.request.pfm_support);
	CuAssertIntEquals (test, 0, resp->capabilities.request.policy_support);
	CuAssertIntEquals (test, 0, resp->capabilities.request.fw_protection);
	CuAssertIntEquals (test, 0x10, resp->capabilities.request.reserved2);

	raw_buffer[11] = 0x52;
	CuAssertIntEquals (test, 0, req->capabilities.rsa);
	CuAssertIntEquals (test, 1, req->capabilities.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_256, req->capabilities.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_3072, req->capabilities.rsa_key_strength);

	CuAssertIntEquals (test, 0, resp->capabilities.request.rsa);
	CuAssertIntEquals (test, 1, resp->capabilities.request.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_256,
		resp->capabilities.request.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_3072,
		resp->capabilities.request.rsa_key_strength);

	raw_buffer[11] = 0x12;
	CuAssertIntEquals (test, 0, req->capabilities.rsa);
	CuAssertIntEquals (test, 0, req->capabilities.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_256, req->capabilities.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_3072, req->capabilities.rsa_key_strength);

	CuAssertIntEquals (test, 0, resp->capabilities.request.rsa);
	CuAssertIntEquals (test, 0, resp->capabilities.request.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_256,
		resp->capabilities.request.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_3072,
		resp->capabilities.request.rsa_key_strength);

	raw_buffer[11] = 0x0a;
	CuAssertIntEquals (test, 0, req->capabilities.rsa);
	CuAssertIntEquals (test, 0, req->capabilities.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_160, req->capabilities.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_3072, req->capabilities.rsa_key_strength);

	CuAssertIntEquals (test, 0, resp->capabilities.request.rsa);
	CuAssertIntEquals (test, 0, resp->capabilities.request.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_160,
		resp->capabilities.request.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_3072,
		resp->capabilities.request.rsa_key_strength);

	raw_buffer[11] = 0x09;
	CuAssertIntEquals (test, 0, req->capabilities.rsa);
	CuAssertIntEquals (test, 0, req->capabilities.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_160, req->capabilities.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_2048, req->capabilities.rsa_key_strength);

	CuAssertIntEquals (test, 0, resp->capabilities.request.rsa);
	CuAssertIntEquals (test, 0, resp->capabilities.request.ecdsa);
	CuAssertIntEquals (test, DEVICE_MANAGER_ECC_KEY_160,
		resp->capabilities.request.ecc_key_strength);
	CuAssertIntEquals (test, DEVICE_MANAGER_RSA_KEY_2048,
		resp->capabilities.request.rsa_key_strength);

	raw_buffer[12] = 0x04;
	CuAssertIntEquals (test, 0, req->capabilities.ecc);
	CuAssertIntEquals (test, 0x00, req->capabilities.reserved3);
	CuAssertIntEquals (test, DEVICE_MANAGER_AES_KEY_384, req->capabilities.aes_enc_key_strength);

	CuAssertIntEquals (test, 0, resp->capabilities.request.ecc);
	CuAssertIntEquals (test, 0x00, resp->capabilities.request.reserved3);
	CuAssertIntEquals (test, DEVICE_MANAGER_AES_KEY_384,
		resp->capabilities.request.aes_enc_key_strength);

	raw_buffer[12] = 0x1c;
	CuAssertIntEquals (test, 0, req->capabilities.ecc);
	CuAssertIntEquals (test, 0x03, req->capabilities.reserved3);
	CuAssertIntEquals (test, DEVICE_MANAGER_AES_KEY_384, req->capabilities.aes_enc_key_strength);

	CuAssertIntEquals (test, 0, resp->capabilities.request.ecc);
	CuAssertIntEquals (test, 0x03, resp->capabilities.request.reserved3);
	CuAssertIntEquals (test, DEVICE_MANAGER_AES_KEY_384,
		resp->capabilities.request.aes_enc_key_strength);

	raw_buffer[12] = 0x1a;
	CuAssertIntEquals (test, 0, req->capabilities.ecc);
	CuAssertIntEquals (test, 0x03, req->capabilities.reserved3);
	CuAssertIntEquals (test, DEVICE_MANAGER_AES_KEY_256, req->capabilities.aes_enc_key_strength);

	CuAssertIntEquals (test, 0, resp->capabilities.request.ecc);
	CuAssertIntEquals (test, 0x03, resp->capabilities.request.reserved3);
	CuAssertIntEquals (test, DEVICE_MANAGER_AES_KEY_256,
		resp->capabilities.request.aes_enc_key_strength);
}

static void cerberus_protocol_required_commands_test_get_digest_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x81,
		0x01,0x02
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x81,
		0x03,0x01,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	struct cerberus_protocol_get_certificate_digest *req;
	struct cerberus_protocol_get_certificate_digest_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_certificate_digest));

	req = (struct cerberus_protocol_get_certificate_digest*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, req->header.command);

	CuAssertIntEquals (test, 0x01, req->slot_num);
	CuAssertIntEquals (test, 0x02, req->key_alg);

	resp = (struct cerberus_protocol_get_certificate_digest_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, resp->header.command);

	CuAssertIntEquals (test, 0x03, resp->capabilities);
	CuAssertIntEquals (test, 0x01, resp->num_digests);
	CuAssertPtrEquals (test, &raw_buffer_resp[7], cerberus_protocol_certificate_digests (resp));
}

static void cerberus_protocol_required_commands_test_get_certificate_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x82,
		0x00,0x01,0x02,0x03,0x04,0x05
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x82,
		0x01,0x02,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	struct cerberus_protocol_get_certificate *req;
	struct cerberus_protocol_get_certificate_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_certificate));

	req = (struct cerberus_protocol_get_certificate*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, req->header.command);

	CuAssertIntEquals (test, 0x00, req->slot_num);
	CuAssertIntEquals (test, 0x01, req->cert_num);
	CuAssertIntEquals (test, 0x0302, req->offset);
	CuAssertIntEquals (test, 0x0504, req->length);

	resp = (struct cerberus_protocol_get_certificate_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, resp->header.command);

	CuAssertIntEquals (test, 0x01, resp->slot_num);
	CuAssertIntEquals (test, 0x02, resp->cert_num);
	CuAssertPtrEquals (test, &raw_buffer_resp[7], cerberus_protocol_certificate (resp));
}

static void cerberus_protocol_required_commands_test_challenge_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x83,
		0x01,0x02,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x83,
		0x01,0x02,0x03,0x04,0x05,0x06,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54,
		0x07,0x20,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x30,0x46,0x02,0x21,0x00,0x86,0x1d,0x0e,0x39,0x20,0xdc,0xae,0x77,0xcc,0xb0,0x33,
		0x38,0xb7,0xd8,0x47,0xb9,0x7a,0x6b,0x65,0x3b,0xe2,0x72,0x52,0x8f,0x77,0x82,0x00,
		0x82,0x8f,0x6f,0xc5,0x9e,0x02,0x21,0x00,0xf8,0xf9,0x96,0xaf,0xd5,0xc5,0x50,0x16,
		0xa9,0x31,0x2d,0xad,0x1e,0xec,0x61,0x3a,0x80,0xe5,0x7a,0x1f,0xa0,0xc3,0x0c,0x35,
		0x41,0x00,0x96,0xcf,0x71,0x24,0x08,0x43
	};
	struct cerberus_protocol_challenge *req;
	struct cerberus_protocol_challenge_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct cerberus_protocol_challenge));

	req = (struct cerberus_protocol_challenge*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, req->header.command);

	CuAssertIntEquals (test, 0x01, req->challenge.slot_num);
	CuAssertIntEquals (test, 0x02, req->challenge.reserved);
	CuAssertPtrEquals (test, &raw_buffer_req[7], &req->challenge.nonce);

	resp = (struct cerberus_protocol_challenge_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, resp->header.command);

	CuAssertIntEquals (test, 0x01, resp->challenge.slot_num);
	CuAssertIntEquals (test, 0x02, resp->challenge.slot_mask);
	CuAssertIntEquals (test, 0x03, resp->challenge.min_protocol_version);
	CuAssertIntEquals (test, 0x04, resp->challenge.max_protocol_version);
	CuAssertIntEquals (test, 0x0605, resp->challenge.reserved);
	CuAssertPtrEquals (test, &raw_buffer_resp[11], &resp->challenge.nonce);
	CuAssertIntEquals (test, 0x07, resp->challenge.num_digests);
	CuAssertIntEquals (test, 0x20, resp->challenge.digests_size);
	CuAssertPtrEquals (test, &raw_buffer_resp[45], &resp->digest);
	CuAssertPtrEquals (test, &raw_buffer_resp[77], cerberus_protocol_challenge_get_signature (resp));
}

static void cerberus_protocol_required_commands_test_import_certificate_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x21,
		0x00,0x01,0x02,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	struct cerberus_protocol_import_certificate *req;

	TEST_START;

	req = (struct cerberus_protocol_import_certificate*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT, req->header.command);

	CuAssertIntEquals (test, 0x00, req->index);
	CuAssertIntEquals (test, 0x0201, req->cert_length);
	CuAssertPtrEquals (test, &raw_buffer_req[8], &req->certificate);
}

static void cerberus_protocol_required_commands_test_export_csr_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x20,
		0x01
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x20,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	struct cerberus_protocol_export_csr *req;
	struct cerberus_protocol_export_csr_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct cerberus_protocol_export_csr));

	req = (struct cerberus_protocol_export_csr*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXPORT_CSR, req->header.command);

	CuAssertIntEquals (test, 0x01, req->index);

	resp = (struct cerberus_protocol_export_csr_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXPORT_CSR, resp->header.command);

	CuAssertPtrEquals (test, &raw_buffer_resp[5], &resp->csr);
}

static void cerberus_protocol_required_commands_test_get_certificate_state_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x22,
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x22,
		0x00,0x01,0x02,0x03
	};
	struct cerberus_protocol_get_certificate_state *req;
	struct cerberus_protocol_get_certificate_state_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_certificate_state));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct cerberus_protocol_get_certificate_state_response));

	req = (struct cerberus_protocol_get_certificate_state*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE, req->header.command);

	resp = (struct cerberus_protocol_get_certificate_state_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE, resp->header.command);

	CuAssertIntEquals (test, 0x03020100, resp->cert_state);
}

static void cerberus_protocol_required_commands_test_get_device_info_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x04,
		0x01
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x04,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	struct cerberus_protocol_get_device_info *req;
	struct cerberus_protocol_get_device_info_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_device_info));

	req = (struct cerberus_protocol_get_device_info*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_INFO, req->header.command);

	CuAssertIntEquals (test, 0x01, req->info_index);

	resp = (struct cerberus_protocol_get_device_info_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_INFO, resp->header.command);

	CuAssertPtrEquals (test, &raw_buffer_resp[5], &resp->info);
}

static void cerberus_protocol_required_commands_test_get_fw_version_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x01,
		0x01
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x01,
		0x30,0x31,0x32,0x33,0x34,0x35,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};
	struct cerberus_protocol_get_fw_version *req;
	struct cerberus_protocol_get_fw_version_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_fw_version));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct cerberus_protocol_get_fw_version_response));

	req = (struct cerberus_protocol_get_fw_version*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_FW_VERSION, req->header.command);

	CuAssertIntEquals (test, 0x01, req->area);

	resp = (struct cerberus_protocol_get_fw_version_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_FW_VERSION, resp->header.command);

	CuAssertStrEquals (test, "012345", resp->version);
}

static void cerberus_protocol_required_commands_test_get_device_id_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x03,
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x03,
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	};
	struct cerberus_protocol_get_device_id *req;
	struct cerberus_protocol_get_device_id_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_device_id));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct cerberus_protocol_get_device_id_response));

	req = (struct cerberus_protocol_get_device_id*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_ID, req->header.command);

	resp = (struct cerberus_protocol_get_device_id_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_ID, resp->header.command);

	CuAssertIntEquals (test, 0x0100, resp->vendor_id);
	CuAssertIntEquals (test, 0x0302, resp->device_id);
	CuAssertIntEquals (test, 0x0504, resp->subsystem_vid);
	CuAssertIntEquals (test, 0x0706, resp->subsystem_id);
}

static void cerberus_protocol_required_commands_test_reset_counter_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x87,
		0x01,0x02
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x87,
		0x02,0x03
	};
	struct cerberus_protocol_reset_counter *req;
	struct cerberus_protocol_reset_counter_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_reset_counter));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct cerberus_protocol_reset_counter_response));

	req = (struct cerberus_protocol_reset_counter*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_COUNTER, req->header.command);

	CuAssertIntEquals (test, 0x01, req->type);
	CuAssertIntEquals (test, 0x02, req->port);

	resp = (struct cerberus_protocol_reset_counter_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_COUNTER, resp->header.command);

	CuAssertIntEquals (test, 0x0302, resp->counter);
}


TEST_SUITE_START (cerberus_protocol_required_commands);

TEST (cerberus_protocol_required_commands_test_header_format);
TEST (cerberus_protocol_required_commands_test_error_format);
TEST (cerberus_protocol_required_commands_test_device_capabilities_format);
TEST (cerberus_protocol_required_commands_test_get_digest_format);
TEST (cerberus_protocol_required_commands_test_get_certificate_format);
TEST (cerberus_protocol_required_commands_test_challenge_format);
TEST (cerberus_protocol_required_commands_test_import_certificate_format);
TEST (cerberus_protocol_required_commands_test_export_csr_format);
TEST (cerberus_protocol_required_commands_test_get_certificate_state_format);
TEST (cerberus_protocol_required_commands_test_get_device_info_format);
TEST (cerberus_protocol_required_commands_test_get_fw_version_format);
TEST (cerberus_protocol_required_commands_test_get_device_id_format);
TEST (cerberus_protocol_required_commands_test_reset_counter_format);

TEST_SUITE_END;
