// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "attestation/pcr_store.h"
#include "attestation/pcr_data.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_optional_commands.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "cmd_interface/attestation_cmd_interface.h"
#include "logging/debug_log.h"
#include "recovery/recovery_image_header.h"
#include "attestation/aux_attestation.h"
#include "testing/mock/cmd_interface/session_manager_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/recovery/recovery_image_mock.h"
#include "testing/attestation/aux_attestation_testing.h"
#include "testing/cmd_interface/cerberus_protocol_optional_commands_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/manifest/pfm_testing.h"
#include "testing/recovery/recovery_image_header_testing.h"


TEST_SUITE_LABEL ("cerberus_protocol_optional_commands");


/**
 * Callback function to simulate failed callback to retrieve PCR measurement data.
 *
 * @param context The data to return from the callback.  It is assumed to be 4 bytes of data.
 * @param offset The offset for the requested data.
 * @param buffer Output buffer for the data.
 * @param length Size of the output buffer.
 * @param total_len Total length of measurement data.
 *
 * @return The number of bytes returned or error if failed.
 */
static int cerberus_protocol_optional_commands_testing_measurement_callback_fail (void *context,
	size_t offset, uint8_t *buffer, size_t length, uint32_t *total_len)
{
	return PCR_NO_MEMORY;
}

void cerberus_protocol_optional_commands_testing_process_fw_update_init (CuTest *test,
	struct cmd_interface *cmd, struct firmware_update_control_mock *update)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_fw_update *req =
		(struct cerberus_protocol_prepare_fw_update*) data;
	uint32_t size = 0x31EEAABB;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_FW_UPDATE;

	req->total_size = size;
	request.length = sizeof (struct cerberus_protocol_prepare_fw_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&update->mock, update->base.prepare_staging, update, 0, MOCK_ARG (size));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_fw_update_init_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_fw_update *req =
		(struct cerberus_protocol_prepare_fw_update*) data;
	uint32_t size = 0x31EEAABB;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_FW_UPDATE;

	req->total_size = size;
	request.length = sizeof (struct cerberus_protocol_prepare_fw_update) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_prepare_fw_update) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_fw_update_init_fail (CuTest *test,
	struct cmd_interface *cmd, struct firmware_update_control_mock *update)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_fw_update *req =
		(struct cerberus_protocol_prepare_fw_update*) data;
	uint32_t size = 0x31EEAABB;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_FW_UPDATE;

	req->total_size = size;
	request.length = sizeof (struct cerberus_protocol_prepare_fw_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&update->mock, update->base.prepare_staging, update,
		FIRMWARE_UPDATE_NO_MEMORY, MOCK_ARG (size));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_fw_update (CuTest *test,
	struct cmd_interface *cmd, struct firmware_update_control_mock *update)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_fw_update *req = (struct cerberus_protocol_fw_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_FW_UPDATE;

	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_fw_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&update->mock, update->base.write_staging, update, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_fw_update_no_data (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_fw_update *req = (struct cerberus_protocol_fw_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_FW_UPDATE;

	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_fw_update) - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_fw_update_fail (CuTest *test,
	struct cmd_interface *cmd, struct firmware_update_control_mock *update)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_fw_update *req = (struct cerberus_protocol_fw_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_FW_UPDATE;

	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_fw_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&update->mock, update->base.write_staging, update,
		FIRMWARE_UPDATE_NO_MEMORY, MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_complete_fw_update (CuTest *test,
	struct cmd_interface *cmd, struct firmware_update_control_mock *update)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_fw_update *req =
		(struct cerberus_protocol_complete_fw_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE;

	request.length = sizeof (struct cerberus_protocol_complete_fw_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&update->mock, update->base.start_update, update, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_complete_fw_update_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_fw_update *req =
		(struct cerberus_protocol_complete_fw_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE;

	request.length = sizeof (struct cerberus_protocol_complete_fw_update) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_complete_fw_update_fail (CuTest *test,
	struct cmd_interface *cmd, struct firmware_update_control_mock *update)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_fw_update *req =
		(struct cerberus_protocol_complete_fw_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE;

	request.length = sizeof (struct cerberus_protocol_complete_fw_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&update->mock, update->base.start_update, update,
		FIRMWARE_UPDATE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_init_port0 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_pfm_update *req =
		(struct cerberus_protocol_prepare_pfm_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	req->port_id = 0;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_0->mock, pfm_0->base.prepare_manifest, pfm_0, 0, MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_init_port1 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_pfm_update *req =
		(struct cerberus_protocol_prepare_pfm_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	req->port_id = 1;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_1->mock, pfm_1->base.prepare_manifest, pfm_1, 0, MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_init_port0_null (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_pfm_update *req =
		(struct cerberus_protocol_prepare_pfm_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	req->port_id = 0;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_init_port1_null (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_pfm_update *req =
		(struct cerberus_protocol_prepare_pfm_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	req->port_id = 1;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_init_invalid_port (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_pfm_update *req =
		(struct cerberus_protocol_prepare_pfm_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	req->port_id = 2;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_init_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_pfm_update *req =
		(struct cerberus_protocol_prepare_pfm_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	req->port_id = 0;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_init_fail_port0 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_pfm_update *req =
		(struct cerberus_protocol_prepare_pfm_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	req->port_id = 0;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_0->mock, pfm_0->base.prepare_manifest, pfm_0, PFM_INVALID_ARGUMENT,
		MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_init_fail_port1 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_pfm_update *req =
		(struct cerberus_protocol_prepare_pfm_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	req->port_id = 1;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_1->mock, pfm_1->base.prepare_manifest, pfm_1, PFM_INVALID_ARGUMENT,
		MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_port0 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_pfm_update *req = (struct cerberus_protocol_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PFM_UPDATE;

	req->port_id = 0;
	req->payload = 1;
	request.length = sizeof (struct cerberus_protocol_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_0->mock, pfm_0->base.store_manifest, pfm_0, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_port1 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_pfm_update *req = (struct cerberus_protocol_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PFM_UPDATE;

	req->port_id = 1;
	req->payload = 1;
	request.length = sizeof (struct cerberus_protocol_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_1->mock, pfm_1->base.store_manifest, pfm_1, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_port0_null (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_pfm_update *req = (struct cerberus_protocol_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PFM_UPDATE;

	req->port_id = 0;
	req->payload = 1;
	request.length = sizeof (struct cerberus_protocol_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_port1_null (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_pfm_update *req = (struct cerberus_protocol_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PFM_UPDATE;

	req->port_id = 1;
	req->payload = 1;
	request.length = sizeof (struct cerberus_protocol_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_no_data (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_pfm_update *req = (struct cerberus_protocol_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PFM_UPDATE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_pfm_update) - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_invalid_port (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_pfm_update *req = (struct cerberus_protocol_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PFM_UPDATE;

	req->port_id = 2;
	req->payload = 1;
	request.length = sizeof (struct cerberus_protocol_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_fail_port0 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_pfm_update *req = (struct cerberus_protocol_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PFM_UPDATE;

	req->port_id = 0;
	req->payload = 1;
	request.length = sizeof (struct cerberus_protocol_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_0->mock, pfm_0->base.store_manifest, pfm_0,
		MANIFEST_MANAGER_NO_MEMORY, MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_fail_port1 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_pfm_update *req = (struct cerberus_protocol_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PFM_UPDATE;

	req->port_id = 1;
	req->payload = 1;
	request.length = sizeof (struct cerberus_protocol_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_1->mock, pfm_1->base.store_manifest, pfm_1,
		MANIFEST_MANAGER_NO_MEMORY, MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port0 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 0;
	req->activation = 0;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_0->mock, pfm_0->base.finish_manifest, pfm_0, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port1 (CuTest *test,
	struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 1;
	req->activation = 0;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_1->mock, pfm_1->base.finish_manifest, pfm_1, 0, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port0_immediate (
	CuTest *test, struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 0;
	req->activation = 1;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_0->mock, pfm_0->base.finish_manifest, pfm_0, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port1_immediate (
	CuTest *test, struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 1;
	req->activation = 1;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_1->mock, pfm_1->base.finish_manifest, pfm_1, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 0;
	req->activation = 0;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 1;
	req->activation = 0;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 0;
	req->activation = 0;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_complete_pfm_update) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_invalid_port (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 2;
	req->activation = 0;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_fail_port0 (
	CuTest *test, struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 0;
	req->activation = 0;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_0->mock, pfm_0->base.finish_manifest, pfm_0,
		MANIFEST_MANAGER_NO_MEMORY, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_pfm_update_complete_fail_port1 (
	CuTest *test, struct cmd_interface *cmd, struct manifest_cmd_interface_mock *pfm_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_pfm_update *req =
		(struct cerberus_protocol_complete_pfm_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	req->port_id = 1;
	req->activation = 0;
	request.length =  sizeof (struct cerberus_protocol_complete_pfm_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_1->mock, pfm_1->base.finish_manifest, pfm_1,
		MANIFEST_MANAGER_NO_MEMORY, MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_port0_region0 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	uint32_t pfm_id = 0xABCD;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_port0_region1 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	uint32_t pfm_id = 0xABCD;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 1;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_pending_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_port1_region0 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	uint32_t pfm_id = 0xABCD;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_port1_region1 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	uint32_t pfm_id = 0xABCD;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 1;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_pending_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_id_type_port0 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	uint32_t pfm_id = 0xABCD;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id) - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_id_type_port1 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	uint32_t pfm_id = 0xABCD;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id) - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_port0_region0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, 0, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_port0_region1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 1;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, 0, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_port1_region0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, 0, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_port1_region1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 1;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, 0, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_active_pfm_port0 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_active_pfm_port1 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_pending_pfm_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 1;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_pending_pfm, pfm_manager_0,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_pending_pfm_port1 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_version_response *resp =
		(struct cerberus_protocol_get_pfm_id_version_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 1;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_pending_pfm, pfm_manager_1,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_version_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_fail_port0 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, PFM_NO_MEMORY, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_fail_port1 (CuTest *test,
	struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, PFM_NO_MEMORY, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_pfm_id) - sizeof (req->id) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_invalid_port (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 2;
	req->region = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_invalid_region (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 2;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_invalid_id (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 1;
	req->id = 2;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port0_region0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	size_t id_length = PFM_PLATFORM_ID_LEN + 1;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output_ptr (&pfm.mock, 0, PFM_PLATFORM_ID, id_length, -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		cerberus_protocol_get_pfm_id_platform_response_length (id_length), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertStrEquals (test, PFM_PLATFORM_ID, (char *)&resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port0_region1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	size_t id_length = PFM_PLATFORM_ID_LEN + 1;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 1;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_pending_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output_ptr (&pfm.mock, 0, PFM_PLATFORM_ID, id_length, -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		cerberus_protocol_get_pfm_id_platform_response_length (id_length), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertStrEquals (test, PFM_PLATFORM_ID, (char *)&resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port1_region0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	size_t id_length = PFM_PLATFORM_ID_LEN + 1;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output_ptr (&pfm.mock, 0, PFM_PLATFORM_ID, id_length, -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		cerberus_protocol_get_pfm_id_platform_response_length (id_length), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertStrEquals (test, PFM_PLATFORM_ID, (char *)&resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port1_region1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	size_t id_length = PFM_PLATFORM_ID_LEN + 1;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 1;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_pending_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output_ptr (&pfm.mock, 0, PFM_PLATFORM_ID, id_length, -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		cerberus_protocol_get_pfm_id_platform_response_length (id_length), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertStrEquals (test, PFM_PLATFORM_ID, (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port0_region0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_platform_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertStrEquals (test, "", (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port0_region1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 1;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_platform_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertStrEquals (test, "", (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port1_region0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_platform_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertStrEquals (test, "", (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port1_region1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 1;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_id_platform_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertStrEquals (test, "", (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_fail_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, PFM_NO_MEMORY,
		MOCK_ARG_PTR_PTR_NOT_NULL, MOCK_ARG (max));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_fail_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	struct pfm_mock pfm;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, PFM_NO_MEMORY,
		MOCK_ARG_PTR_PTR_NOT_NULL, MOCK_ARG (max));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_no_active_pfm_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 0;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, cerberus_protocol_get_pfm_id_platform_response_length (1),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertStrEquals (test, "", (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_no_active_pfm_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 0;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, cerberus_protocol_get_pfm_id_platform_response_length (1),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertStrEquals (test, "", (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_no_pending_pfm_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 0;
	req->region = 1;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_pending_pfm, pfm_manager_0,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, cerberus_protocol_get_pfm_id_platform_response_length (1),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertStrEquals (test, "", (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_no_pending_pfm_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_id *req = (struct cerberus_protocol_get_pfm_id*) data;
	struct cerberus_protocol_get_pfm_id_platform_response *resp =
		(struct cerberus_protocol_get_pfm_id_platform_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_ID;

	req->port_id = 1;
	req->region = 1;
	req->id = 1;
	request.length = sizeof (struct cerberus_protocol_get_pfm_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_pending_pfm, pfm_manager_1,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, cerberus_protocol_get_pfm_id_platform_response_length (1),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertStrEquals (test, "", (char*) &resp->platform);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port0_region0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, sizeof (version),
		MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, version, (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port0_region1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_pending_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, sizeof (version),
		MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, version, (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port1_region0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, sizeof (version),
		MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, version, (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port1_region1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_pending_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, sizeof (version),
		MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, version, (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_with_firmware_id_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char fw_id[] = "Firmware";
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	cerberus_protocol_get_pfm_supported_fw_id_length (req) = sizeof (fw_id);
	strcpy (cerberus_protocol_get_pfm_supported_fw_id (req), fw_id);
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw) + 1 + sizeof (fw_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, sizeof (version),
		MOCK_ARG_PTR_CONTAINS (fw_id, sizeof (fw_id)), MOCK_ARG (offset), MOCK_ARG (max),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, version, (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_with_firmware_id_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char fw_id[] = "Firmware";
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	cerberus_protocol_get_pfm_supported_fw_id_length (req) = sizeof (fw_id);
	strcpy (cerberus_protocol_get_pfm_supported_fw_id (req), fw_id);
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw) + 1 + sizeof (fw_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, sizeof (version),
		MOCK_ARG_PTR_CONTAINS (fw_id, sizeof (fw_id)), MOCK_ARG (offset), MOCK_ARG (max),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, version, (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_zero_length_firmware_id_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	cerberus_protocol_get_pfm_supported_fw_id_length (req) = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, sizeof (version),
		MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, version, (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_zero_length_firmware_id_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	cerberus_protocol_get_pfm_supported_fw_id_length (req) = 0;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, sizeof (version),
		MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, version, (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_nonzero_offset_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 3;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm,
		sizeof (version) - offset, MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, &version[offset], sizeof (version) - offset, -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version) - offset,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, &version[offset], (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_nonzero_offset_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char version[] = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 3;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm,
		sizeof (version) - offset, MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, &version[offset], sizeof (version) - offset, -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version) - offset,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertStrEquals (test, &version[offset], (char*) cerberus_protocol_pfm_supported_fw (resp));

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_limited_response_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char *version = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = sizeof (version) - 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response =
		(sizeof (version) - 1) + sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm,
		sizeof (version) - 1, MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version) - 1,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((const uint8_t*) version,
		cerberus_protocol_pfm_supported_fw (resp), sizeof (version) - 1);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_limited_response_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	const char *version = "1.2.3.4";
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = sizeof (version) - 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response =
		(sizeof (version) - 1) + sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm,
		sizeof (version) - 1, MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 3, version, sizeof (version), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response) + sizeof (version) - 1,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((const uint8_t*) version,
		cerberus_protocol_pfm_supported_fw (resp), sizeof (version) - 1);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_empty_list_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, 0, MOCK_ARG (NULL),
		MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_empty_list_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, 0, MOCK_ARG (NULL),
		MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_empty_list_nonzero_offset_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 1;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, 0, MOCK_ARG (NULL),
		MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_empty_list_nonzero_offset_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	struct pfm_mock pfm;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 1;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm, 0, MOCK_ARG (NULL),
		MOCK_ARG (offset), MOCK_ARG (max), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 1, resp->valid);
	CuAssertIntEquals (test, pfm_id, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port0_region0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, 0, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port0_region1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, 0, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port1_region0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, 0, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port1_region1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, 0, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_no_active_pfm_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_no_active_pfm_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_no_pending_pfm_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_pending_pfm, pfm_manager_0,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_no_pending_pfm_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_pending_pfm, pfm_manager_1,
		(intptr_t) NULL);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_pfm_supported_fw_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);
	CuAssertIntEquals (test, 0, resp->valid);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_fail_id_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct pfm_mock pfm;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, PFM_NO_MEMORY, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_fail_id_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct pfm_mock pfm;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, PFM_NO_MEMORY, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_fail_port0 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct pfm_mock pfm;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;


	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.get_active_pfm, pfm_manager_0,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_0->mock, pfm_manager_0->base.free_pfm, pfm_manager_0, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm,
		PFM_UNKNOWN_FIRMWARE, MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_fail_port1 (
	CuTest *test, struct cmd_interface *cmd, struct pfm_manager_mock *pfm_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	struct pfm_mock pfm;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_response);
	int status;


	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 1;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.get_active_pfm, pfm_manager_1,
		(intptr_t) &pfm.base);
	status |= mock_expect (&pfm_manager_1->mock, pfm_manager_1->base.free_pfm, pfm_manager_1, 0,
		MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.buffer_supported_versions, &pfm,
		PFM_UNKNOWN_FIRMWARE, MOCK_ARG (NULL), MOCK_ARG (offset), MOCK_ARG (max),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	uint32_t offset = 0;
	const char fw_id[] = "Firmware";
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 0;
	req->offset = offset;
	cerberus_protocol_get_pfm_supported_fw_id_length (req) = sizeof (fw_id);
	strcpy (cerberus_protocol_get_pfm_supported_fw_id (req), fw_id);
	request.length =
		sizeof (struct cerberus_protocol_get_pfm_supported_fw) + 1 + sizeof (fw_id) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_invalid_region (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 0;
	req->region = 2;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_invalid_port (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_pfm_supported_fw *req =
		(struct cerberus_protocol_get_pfm_supported_fw*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	req->port_id = 2;
	req->region = 0;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_pfm_supported_fw);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_log_clear_debug (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_clear_log *req = (struct cerberus_protocol_clear_log*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	req->log_type = 1;
	request.length = sizeof (struct cerberus_protocol_clear_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.debug_log_clear, background, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_log_clear_attestation (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_clear_log *req = (struct cerberus_protocol_clear_log*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	req->log_type = 2;
	request.length = sizeof (struct cerberus_protocol_clear_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_log_clear_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_clear_log *req = (struct cerberus_protocol_clear_log*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	req->log_type = 2;
	request.length = sizeof (struct cerberus_protocol_clear_log) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_clear_log) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_log_clear_invalid_type (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_clear_log *req = (struct cerberus_protocol_clear_log*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	req->log_type = 3;
	request.length = sizeof (struct cerberus_protocol_clear_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_log_clear_debug_fail (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_clear_log *req = (struct cerberus_protocol_clear_log*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	req->log_type = 1;
	request.length = sizeof (struct cerberus_protocol_clear_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.debug_log_clear, background,
		CMD_BACKGROUND_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_log_info (CuTest *test,
	struct cmd_interface *cmd, struct logging_mock *debug, int attestation_entries)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log_info *req = (struct cerberus_protocol_get_log_info*) data;
	struct cerberus_protocol_get_log_info_response *resp =
		(struct cerberus_protocol_get_log_info_response*) data;
	uint32_t debug_size = 15;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_LOG_INFO;

	request.length = sizeof (struct cerberus_protocol_get_log_info);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	debug_log = &debug->base;

	status = mock_expect (&debug->mock, debug->base.get_size, debug, debug_size);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_info_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_LOG_INFO, resp->header.command);
	CuAssertIntEquals (test, debug_size, resp->debug_log_length);
	CuAssertIntEquals (test, attestation_entries * sizeof (struct pcr_store_attestation_log_entry),
		resp->attestation_log_length);
	CuAssertIntEquals (test, 0, resp->tamper_log_length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	debug_log = NULL;
}

void cerberus_protocol_optional_commands_testing_process_get_log_info_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log_info *req = (struct cerberus_protocol_get_log_info*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_LOG_INFO;

	request.length = sizeof (struct cerberus_protocol_get_log_info) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_log_info_fail_debug (CuTest *test,
	struct cmd_interface *cmd, struct logging_mock *debug, int attestation_entries)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log_info *req = (struct cerberus_protocol_get_log_info*) data;
	struct cerberus_protocol_get_log_info_response *resp =
		(struct cerberus_protocol_get_log_info_response*) data;
	uint32_t debug_size = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_LOG_INFO;

	request.length = sizeof (struct cerberus_protocol_get_log_info);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	debug_log = &debug->base;

	status = mock_expect (&debug->mock, debug->base.get_size, debug, LOGGING_GET_SIZE_FAILED);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_info_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_LOG_INFO, resp->header.command);
	CuAssertIntEquals (test, debug_size, resp->debug_log_length);
	CuAssertIntEquals (test, attestation_entries * sizeof (struct pcr_store_attestation_log_entry),
		resp->attestation_log_length);
	CuAssertIntEquals (test, 0, resp->tamper_log_length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	debug_log = NULL;
}

void cerberus_protocol_optional_commands_testing_process_log_read_debug (CuTest *test,
	struct cmd_interface *cmd, struct logging_mock *debug)
{
	uint8_t entry[256 * sizeof (struct debug_log_entry)];
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	struct cerberus_protocol_get_log_response *resp =
		(struct cerberus_protocol_get_log_response*) data;
	uint32_t offset = 0;
	int status;
	int i_entry;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG;
	int remain = sizeof (entry) - max;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i_entry = 0; i_entry < 256; ++i_entry) {
		struct debug_log_entry *contents =
			(struct debug_log_entry*) &entry[i_entry * sizeof (struct debug_log_entry)];
		contents->header.log_magic = 0xCB;
		contents->header.length = sizeof (struct debug_log_entry);
		contents->header.entry_id = i_entry;
		contents->entry.format = DEBUG_LOG_ENTRY_FORMAT;
		contents->entry.severity = 1;
		contents->entry.component = 2;
		contents->entry.msg_index = 3;
		contents->entry.arg1 = 4;
		contents->entry.arg2 = 5;
		contents->entry.time = 6;
	}

	debug_log = &debug->base;

	status = mock_expect (&debug->mock, debug->base.read_contents, debug, max, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&debug->mock, 1, entry, sizeof (entry), 2);

	status |= mock_expect (&debug->mock, debug->base.read_contents, debug, remain, MOCK_ARG (max),
		MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&debug->mock, 1, &entry[max], remain, 2);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_response) + max,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (entry, cerberus_protocol_log_data (resp), max);
	CuAssertIntEquals (test, 0, status);

	offset = max;
	req->log_type = CERBERUS_PROTOCOL_DEBUG_LOG;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_response) + remain,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (&entry[offset], cerberus_protocol_log_data (resp), remain);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;
}

void cerberus_protocol_optional_commands_testing_process_log_read_debug_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct logging_mock *debug)
{
	uint8_t entry[256 * sizeof (struct debug_log_entry)];
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	struct cerberus_protocol_get_log_response *resp =
		(struct cerberus_protocol_get_log_response*) data;
	uint32_t offset = 0;
	int status;
	int i_entry;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG - 128;
	int remain = sizeof (entry) - max;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i_entry = 0; i_entry < 256; ++i_entry) {
		struct debug_log_entry *contents =
			(struct debug_log_entry*) &entry[i_entry * sizeof (struct debug_log_entry)];
		contents->header.log_magic = 0xCB;
		contents->header.length = sizeof (struct debug_log_entry);
		contents->header.entry_id = i_entry;
		contents->entry.format = DEBUG_LOG_ENTRY_FORMAT;
		contents->entry.severity = 1;
		contents->entry.component = 2;
		contents->entry.msg_index = 3;
		contents->entry.arg1 = 4;
		contents->entry.arg2 = 5;
		contents->entry.time = 6;
	}

	debug_log = &debug->base;

	status = mock_expect (&debug->mock, debug->base.read_contents, debug, max, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&debug->mock, 1, entry, sizeof (entry), 2);

	status |= mock_expect (&debug->mock, debug->base.read_contents, debug, remain, MOCK_ARG (max),
		MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&debug->mock, 1, &entry[max], remain, 2);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_response) + max,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (entry, cerberus_protocol_log_data (resp), max);
	CuAssertIntEquals (test, 0, status);

	offset = max;
	req->log_type = CERBERUS_PROTOCOL_DEBUG_LOG;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_response) + remain,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (&entry[offset], cerberus_protocol_log_data (resp), remain);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;
}

void cerberus_protocol_optional_commands_testing_process_log_read_attestation (CuTest *test,
	struct cmd_interface *cmd, struct hash_engine_mock *hash, struct pcr_store *store)
{
	struct pcr_store_attestation_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	uint32_t offset = 0;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	struct cerberus_protocol_get_log_response *resp =
		(struct cerberus_protocol_get_log_response*) data;
	int status;
	int i_measurement;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 2;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	memset (exp_buf, 0, sizeof (exp_buf));
	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_attestation_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;
		exp_buf[i_measurement].entry.event_type = 0xA + i_measurement;
		exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));
	}

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		pcr_store_update_digest (store, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], PCR_DIGEST_LENGTH);
		pcr_store_update_event_type (store, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
	}

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_response) + sizeof (exp_buf),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) exp_buf, cerberus_protocol_log_data (resp),
		sizeof (exp_buf));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_log_read_attestation_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct hash_engine_mock *hash, struct pcr_store *store)
{
	struct pcr_store_attestation_log_entry exp_buf[6];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	uint32_t offset = 0;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	struct cerberus_protocol_get_log_response *resp =
		(struct cerberus_protocol_get_log_response*) data;
	int status;
	int max = sizeof (exp_buf) - 10 - sizeof (struct cerberus_protocol_get_log_response);
	int i_measurement;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 2;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = sizeof (exp_buf) - 10;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	memset (exp_buf, 0, sizeof (exp_buf));
	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_attestation_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;
		exp_buf[i_measurement].entry.event_type = 0xA + i_measurement;
		exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));
	}

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, 0);
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&hash->mock, hash->base.finish, hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash->mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		pcr_store_update_digest (store, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], PCR_DIGEST_LENGTH);
		pcr_store_update_event_type (store, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
	}

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_response) + max,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) exp_buf, cerberus_protocol_log_data (resp), max);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_log_read_debug_fail (CuTest *test,
	struct cmd_interface *cmd, struct logging_mock *debug)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	uint32_t offset = 0;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	debug_log = &debug->base;

	status = mock_expect (&debug->mock, debug->base.read_contents, debug,
		LOGGING_READ_CONTENTS_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (max));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, LOGGING_READ_CONTENTS_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	debug_log = NULL;
}

void cerberus_protocol_optional_commands_testing_process_log_read_attestation_fail (CuTest *test,
	struct cmd_interface *cmd, struct hash_engine_mock *hash, struct pcr_store *store)
{
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint32_t offset = 0;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 2;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&hash->mock, hash->base.start_sha256, hash, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	pcr_store_update_digest (store, PCR_MEASUREMENT (0, 0), buffer0, PCR_DIGEST_LENGTH);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_log_read_invalid_offset (CuTest *test,
	struct cmd_interface *cmd, struct logging_mock *debug)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	struct cerberus_protocol_get_log_response *resp =
		(struct cerberus_protocol_get_log_response*) data;
	uint32_t offset = 500;
	int status;
	int max = CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 1;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	debug_log = &debug->base;

	status = mock_expect (&debug->mock, debug->base.read_contents, debug, 0, MOCK_ARG (500),
		MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_response), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	debug_log = NULL;
}

void cerberus_protocol_optional_commands_testing_process_log_read_invalid_type (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 5;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_log_read_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	uint32_t offset = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = 4;
	req->offset = offset;
	request.length = sizeof (struct cerberus_protocol_get_log) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_log) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_log_read_tcg (CuTest *test,
	struct cmd_interface *cmd, struct pcr_store *store)
{
	uint8_t digests[6][PCR_DIGEST_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x45,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	struct cerberus_protocol_get_log_response *resp =
		(struct cerberus_protocol_get_log_response*) data;
	struct pcr_tcg_event *v1_event =
		(struct pcr_tcg_event*) (data + sizeof (struct cerberus_protocol_header));
	struct pcr_tcg_log_header *header =
		(struct pcr_tcg_log_header*) ((uint8_t*) v1_event + sizeof (struct pcr_tcg_event));
	struct pcr_tcg_event2 *event =
		(struct pcr_tcg_event2*) ((uint8_t*) header + sizeof (struct pcr_tcg_log_header));
	struct pcr_measured_data measurement;
	uint8_t v1_event_pcr[20] = {0};
	int i_measurement;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = CERBERUS_PROTOCOL_TCG_LOG;
	req->offset = 0;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	measurement.type = PCR_DATA_TYPE_1BYTE;
	measurement.data.value_1byte = 0xAA;

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		status = pcr_store_update_digest (store, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], PCR_DIGEST_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_update_event_type (store, PCR_MEASUREMENT (0, i_measurement),
			0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_store_set_measurement_data (store, PCR_MEASUREMENT (0, i_measurement),
			&measurement);
		CuAssertIntEquals (test, 0, status);
	}

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_log_response) +
		sizeof (struct pcr_tcg_event) + sizeof (struct pcr_tcg_log_header) +
		sizeof (struct pcr_tcg_event2) * 6 + sizeof (uint8_t) * 6, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertIntEquals (test, PCR_TCG_EFI_NO_ACTION_EVENT_TYPE, v1_event->event_type);
	CuAssertIntEquals (test, sizeof (struct pcr_tcg_log_header), v1_event->event_size);
	CuAssertIntEquals (test, 0, v1_event->pcr_bank);

	status = testing_validate_array (v1_event_pcr, v1_event->pcr, sizeof (v1_event_pcr));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((const uint8_t*) PCR_TCG_LOG_SIGNATURE, header->signature,
		sizeof (PCR_TCG_LOG_SIGNATURE));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, PCR_TCG_SERVER_PLATFORM_CLASS, header->platform_class);
	CuAssertIntEquals (test, 0, header->spec_version_minor);
	CuAssertIntEquals (test, 2, header->spec_version_major);
	CuAssertIntEquals (test, 0, header->spec_errata);
	CuAssertIntEquals (test, PCR_TCG_UINT_SIZE_32, header->uintn_size);
	CuAssertIntEquals (test, 1, header->num_algorithms);
	CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, header->digest_size.digest_algorithm_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, header->digest_size.digest_size);
	CuAssertIntEquals (test, 0, header->vendor_info_size);

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->pcr_bank);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->event_type);
		CuAssertIntEquals (test, 1, event->digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, PCR_DIGEST_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2*) ((uint8_t*) (event + 1) + 1);
	}
}

void cerberus_protocol_optional_commands_testing_process_log_read_tcg_fail (CuTest *test,
	struct cmd_interface *cmd, struct pcr_store *store)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_log *req = (struct cerberus_protocol_get_log*) data;
	struct pcr_measured_data measurement;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_READ_LOG;

	req->log_type = CERBERUS_PROTOCOL_TCG_LOG;
	req->offset = 0;
	request.length = sizeof (struct cerberus_protocol_get_log);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	measurement.type = PCR_DATA_TYPE_CALLBACK;
	measurement.data.callback.get_data =
		cerberus_protocol_optional_commands_testing_measurement_callback_fail;
	measurement.data.callback.context = NULL;

	status = pcr_store_set_measurement_data (store, PCR_MEASUREMENT (0, 0), &measurement);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_event_type (store, PCR_MEASUREMENT (0, 0), 0x0A);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_rsa (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.unseal_start, background, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (request.data, request.length), MOCK_ARG (request.length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_ecc (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_ECDH;
	req->seed_length = ECC_PUBKEY_DER_LEN;
	memcpy (&req->seed, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		ECC_PUBKEY_DER_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.unseal_start, background, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (request.data, request.length), MOCK_ARG (request.length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_fail (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.unseal_start, background,
		CMD_BACKGROUND_UNSEAL_FAILED, MOCK_ARG_PTR_CONTAINS_TMP (request.data, request.length),
		MOCK_ARG (request.length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSEAL_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_invalid_hmac (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = 1;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_invalid_seed (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = 2;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_rsa_invalid_padding (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_params.rsa.padding = 3;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_no_seed (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = 0;
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) + 2 + CIPHER_TEXT_LEN +
		2 + PAYLOAD_HMAC_LEN + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_incomplete_seed (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_no_ciphertext (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = 0;
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_incomplete_ciphertext (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_no_hmac (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = 0;
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_bad_hmac_length (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN + 1;
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + 1 +
		sizeof (sealing);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN - 1;
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + (PAYLOAD_HMAC_LEN - 1) +
		sizeof (sealing);
	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_incomplete_hmac (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal *req = (struct cerberus_protocol_message_unseal*) data;
	struct cerberus_protocol_unseal_pmrs sealing;
	int status;

	memset (sealing.pmr[0], 0, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[1], 1, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[2], 2, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[3], 3, sizeof (sealing.pmr[0]));
	memset (sealing.pmr[4], 4, sizeof (sealing.pmr[0]));

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	req->hmac_type = CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256;
	req->seed_type = CERBERUS_PROTOCOL_UNSEAL_SEED_RSA;
	req->seed_length = KEY_SEED_ENCRYPT_OAEP_LEN;
	memcpy (&req->seed, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN);
	cerberus_protocol_unseal_ciphertext_length (req) = CIPHER_TEXT_LEN;
	memcpy (cerberus_protocol_unseal_ciphertext (req), CIPHER_TEXT, CIPHER_TEXT_LEN);
	cerberus_protocol_unseal_hmac_length (req) = PAYLOAD_HMAC_LEN;
	memcpy (cerberus_protocol_unseal_hmac (req), PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	memcpy ((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (req), &sealing, sizeof (sealing));
	request.length = sizeof (struct cerberus_protocol_message_unseal) - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing) -
		1;
	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length = (sizeof (struct cerberus_protocol_message_unseal) - 1) +
		KEY_SEED_ENCRYPT_OAEP_LEN + 2 + CIPHER_TEXT_LEN + 2 + PAYLOAD_HMAC_LEN + sizeof (sealing) +
		1;
	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_result (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal_result *req =
		(struct cerberus_protocol_message_unseal_result*) data;
	struct cerberus_protocol_message_unseal_result_completed_response *resp =
		(struct cerberus_protocol_message_unseal_result_completed_response*) data;
	size_t max_buf_len = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_message_unseal_result_completed_response) + 1;
	uint32_t attestation_status = 0;
	uint8_t key[] = {
		0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,
		0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xEE,0xDD
	};
	uint16_t key_len = sizeof (key);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	request.length = sizeof (struct cerberus_protocol_message_unseal_result);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.unseal_result, background,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS_TMP (&max_buf_len, sizeof (max_buf_len)),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&background->mock, 0, key, sizeof (key), -1);
	status |= mock_expect_output (&background->mock, 1, &key_len, sizeof (key_len), -1);
	status |= mock_expect_output (&background->mock, 2, &attestation_status,
		sizeof (attestation_status), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_message_unseal_result_completed_response) -
			sizeof (resp->key) + key_len,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT, resp->header.command);
	CuAssertIntEquals (test, attestation_status, resp->unseal_status);
	CuAssertIntEquals (test, key_len, resp->key_length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (key, &resp->key, sizeof (key));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_result_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal_result *req =
		(struct cerberus_protocol_message_unseal_result*) data;
	struct cerberus_protocol_message_unseal_result_completed_response *resp =
		(struct cerberus_protocol_message_unseal_result_completed_response*) data;
	size_t max_buf_len = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128 -
		sizeof (struct cerberus_protocol_message_unseal_result_completed_response) + 1;
	uint32_t attestation_status = 0;
	uint8_t key[] = {
		0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,
		0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xEE,0xDD
	};
	uint16_t key_len = sizeof (key);
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	request.length = sizeof (struct cerberus_protocol_message_unseal_result);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.unseal_result, background,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS_TMP (&max_buf_len, sizeof (max_buf_len)),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&background->mock, 0, key, sizeof (key), -1);
	status |= mock_expect_output (&background->mock, 1, &key_len, sizeof (key_len), -1);
	status |= mock_expect_output (&background->mock, 2, &attestation_status,
		sizeof (attestation_status), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_message_unseal_result_completed_response) -
			sizeof (resp->key) + key_len,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT, resp->header.command);
	CuAssertIntEquals (test, attestation_status, resp->unseal_status);
	CuAssertIntEquals (test, key_len, resp->key_length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (key, &resp->key, sizeof (key));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_result_busy (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal_result *req =
		(struct cerberus_protocol_message_unseal_result*) data;
	struct cerberus_protocol_message_unseal_result_response *resp =
		(struct cerberus_protocol_message_unseal_result_response*) data;
	size_t max_buf_len = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_message_unseal_result_completed_response) + 1;
	uint32_t attestation_status = ATTESTATION_CMD_STATUS_RUNNING;
	uint16_t key_len = 0;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	request.length = sizeof (struct cerberus_protocol_message_unseal_result);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.unseal_result, background,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS_TMP (&max_buf_len, sizeof (max_buf_len)),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&background->mock, 1, &key_len, sizeof (key_len), -1);
	status |= mock_expect_output (&background->mock, 2, &attestation_status,
		sizeof (attestation_status), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_message_unseal_result_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT, resp->header.command);
	CuAssertIntEquals (test, attestation_status, resp->unseal_status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_result_fail (CuTest *test,
	struct cmd_interface *cmd, struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal_result *req =
		(struct cerberus_protocol_message_unseal_result*) data;
	size_t max_buf_len = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_message_unseal_result_completed_response) + 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	request.length = sizeof (struct cerberus_protocol_message_unseal_result);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&background->mock, background->base.unseal_result, background,
		CMD_BACKGROUND_UNSEAL_RESULT_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS_TMP (&max_buf_len, sizeof (max_buf_len)), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSEAL_RESULT_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_request_unseal_result_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_message_unseal_result *req =
		(struct cerberus_protocol_message_unseal_result*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	request.length = sizeof (struct cerberus_protocol_message_unseal_result) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port0_out_of_reset (
	CuTest *test, struct cmd_interface *cmd, struct host_control_mock *host_ctrl_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	struct cerberus_protocol_get_host_state_response *resp =
		(struct cerberus_protocol_get_host_state_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&host_ctrl_0->mock, host_ctrl_0->base.is_processor_in_reset, host_ctrl_0,
		0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_host_state_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, resp->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_HOST_RUNNING, resp->reset_status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port0_held_in_reset (
	CuTest *test, struct cmd_interface *cmd, struct host_control_mock *host_ctrl_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	struct cerberus_protocol_get_host_state_response *resp =
		(struct cerberus_protocol_get_host_state_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&host_ctrl_0->mock, host_ctrl_0->base.is_processor_in_reset, host_ctrl_0,
		1);
	status |= mock_expect (&host_ctrl_0->mock, host_ctrl_0->base.is_processor_held_in_reset,
		host_ctrl_0, 1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_host_state_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, resp->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_HOST_HELD_IN_RESET, resp->reset_status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port0_not_held_in_reset (
	CuTest *test, struct cmd_interface *cmd, struct host_control_mock *host_ctrl_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	struct cerberus_protocol_get_host_state_response *resp =
		(struct cerberus_protocol_get_host_state_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&host_ctrl_0->mock, host_ctrl_0->base.is_processor_in_reset, host_ctrl_0,
		1);
	status |= mock_expect (&host_ctrl_0->mock, host_ctrl_0->base.is_processor_held_in_reset,
		host_ctrl_0, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_host_state_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, resp->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_HOST_IN_RESET, resp->reset_status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port1_out_of_reset (
	CuTest *test, struct cmd_interface *cmd, struct host_control_mock *host_ctrl_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	struct cerberus_protocol_get_host_state_response *resp =
		(struct cerberus_protocol_get_host_state_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 1;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&host_ctrl_1->mock, host_ctrl_1->base.is_processor_in_reset, host_ctrl_1,
		0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_host_state_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, resp->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_HOST_RUNNING, resp->reset_status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port1_held_in_reset (
	CuTest *test, struct cmd_interface *cmd, struct host_control_mock *host_ctrl_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	struct cerberus_protocol_get_host_state_response *resp =
		(struct cerberus_protocol_get_host_state_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 1;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&host_ctrl_1->mock, host_ctrl_1->base.is_processor_in_reset, host_ctrl_1,
		1);
	status |= mock_expect (&host_ctrl_1->mock, host_ctrl_1->base.is_processor_held_in_reset,
		host_ctrl_1, 1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_host_state_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, resp->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_HOST_HELD_IN_RESET, resp->reset_status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port1_not_held_in_reset (
	CuTest *test, struct cmd_interface *cmd, struct host_control_mock *host_ctrl_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	struct cerberus_protocol_get_host_state_response *resp =
		(struct cerberus_protocol_get_host_state_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 1;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&host_ctrl_1->mock, host_ctrl_1->base.is_processor_in_reset, host_ctrl_1,
		1);
	status |= mock_expect (&host_ctrl_1->mock, host_ctrl_1->base.is_processor_held_in_reset,
		host_ctrl_1, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_get_host_state_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, resp->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_HOST_IN_RESET, resp->reset_status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 1;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_get_host_state) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_host_state) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_invalid_port (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 2;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_check_error (
	CuTest *test, struct cmd_interface *cmd, struct host_control_mock *host_ctrl_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 1;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&host_ctrl_1->mock, host_ctrl_1->base.is_processor_in_reset, host_ctrl_1,
		HOST_CONTROL_RESET_CHECK_FAILED);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, HOST_CONTROL_RESET_CHECK_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_host_reset_status_hold_check_error (
	CuTest *test, struct cmd_interface *cmd, struct host_control_mock *host_ctrl_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_host_state *req = (struct cerberus_protocol_get_host_state*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_get_host_state);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&host_ctrl_0->mock, host_ctrl_0->base.is_processor_in_reset, host_ctrl_0,
		1);
	status |= mock_expect (&host_ctrl_0->mock, host_ctrl_0->base.is_processor_held_in_reset,
		host_ctrl_0, HOST_CONTROL_HOLD_CHECK_FAILED);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, HOST_CONTROL_HOLD_CHECK_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect (&background->mock, background->base.reset_bypass, background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	struct cerberus_protocol_reset_config_response *resp =
		(struct cerberus_protocol_reset_config_response*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[32];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_config_response) + length,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, cerberus_protocol_reset_authorization (resp), length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_max_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	struct cerberus_protocol_reset_config_response *resp =
		(struct cerberus_protocol_reset_config_response*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_config_response) + length,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, cerberus_protocol_reset_authorization (resp), length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_not_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth,
		AUTHORIZATION_NOT_AUTHORIZED, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_with_nonce_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	size_t length = 253;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	for (i = 0; i < (int) length; i++) {
		cerberus_protocol_reset_authorization (req)[i] = i;
	}

	request.length = sizeof (struct cerberus_protocol_reset_config) + length;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth, 0,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (cerberus_protocol_reset_authorization (req), length),
		MOCK_ARG_PTR_CONTAINS_TMP (&length, sizeof (length)));
	status |= mock_expect (&background->mock, background->base.reset_bypass, background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_with_nonce_not_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	size_t length = 253;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	for (i = 0; i < (int) length; i++) {
		cerberus_protocol_reset_authorization (req)[i] = i;
	}

	request.length = sizeof (struct cerberus_protocol_reset_config) + length;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth,
		AUTHORIZATION_NOT_AUTHORIZED,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (cerberus_protocol_reset_authorization (req), length),
		MOCK_ARG_PTR_CONTAINS_TMP (&length, sizeof (length)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_invalid_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_invalid_challenge_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1 - 128];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_bypass_error (CuTest *test,
	struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_revert_bypass, auth, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect (&background->mock, background->base.reset_bypass, background,
		CMD_BACKGROUND_BYPASS_FAILED);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_BYPASS_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect (&background->mock, background->base.restore_defaults, background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	struct cerberus_protocol_reset_config_response *resp =
		(struct cerberus_protocol_reset_config_response*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[32];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_config_response) + length,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, cerberus_protocol_reset_authorization (resp), length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_max_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	struct cerberus_protocol_reset_config_response *resp =
		(struct cerberus_protocol_reset_config_response*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_config_response) + length,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, cerberus_protocol_reset_authorization (resp), length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_not_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth,
		AUTHORIZATION_NOT_AUTHORIZED, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_with_nonce_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	size_t length = 253;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	for (i = 0; i < (int) length; i++) {
		cerberus_protocol_reset_authorization (req)[i] = i;
	}

	request.length = sizeof (struct cerberus_protocol_reset_config) + length;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth, 0,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (cerberus_protocol_reset_authorization (req), length),
		MOCK_ARG_PTR_CONTAINS_TMP (&length, sizeof (length)));
	status |= mock_expect (&background->mock, background->base.restore_defaults, background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_with_nonce_not_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	size_t length = 253;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	for (i = 0; i < (int) length; i++) {
		cerberus_protocol_reset_authorization (req)[i] = i;
	}

	request.length = sizeof (struct cerberus_protocol_reset_config) + length;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth,
		AUTHORIZATION_NOT_AUTHORIZED,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (cerberus_protocol_reset_authorization (req), length),
		MOCK_ARG_PTR_CONTAINS_TMP (&length, sizeof (length)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_invalid_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_invalid_challenge_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1 - 128];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_restore_defaults_error (CuTest *test,
	struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 1;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_defaults, auth, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect (&background->mock, background->base.restore_defaults, background,
		CMD_BACKGROUND_DEFAULT_FAILED);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_DEFAULT_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect (&background->mock, background->base.clear_platform_config, background,
		0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	struct cerberus_protocol_reset_config_response *resp =
		(struct cerberus_protocol_reset_config_response*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[32];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_config_response) + length,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, cerberus_protocol_reset_authorization (resp), length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_max_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	struct cerberus_protocol_reset_config_response *resp =
		(struct cerberus_protocol_reset_config_response*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_config_response) + length,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, cerberus_protocol_reset_authorization (resp), length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_not_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth,
		AUTHORIZATION_NOT_AUTHORIZED, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_with_nonce_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	size_t length = 253;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	for (i = 0; i < (int) length; i++) {
		cerberus_protocol_reset_authorization (req)[i] = i;
	}

	request.length = sizeof (struct cerberus_protocol_reset_config) + length;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth, 0,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (cerberus_protocol_reset_authorization (req), length),
		MOCK_ARG_PTR_CONTAINS_TMP (&length, sizeof (length)));
	status |= mock_expect (&background->mock, background->base.clear_platform_config, background,
		0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_with_nonce_not_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	size_t length = 253;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	for (i = 0; i < (int) length; i++) {
		cerberus_protocol_reset_authorization (req)[i] = i;
	}

	request.length = sizeof (struct cerberus_protocol_reset_config) + length;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth,
		AUTHORIZATION_NOT_AUTHORIZED,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (cerberus_protocol_reset_authorization (req), length),
		MOCK_ARG_PTR_CONTAINS_TMP (&length, sizeof (length)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_invalid_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_invalid_challenge_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1 - 128];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_clear_platform_config_error (CuTest *test,
	struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 2;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_clear_platform_config, auth, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect (&background->mock, background->base.clear_platform_config, background,
		CMD_BACKGROUND_PLATFORM_CFG_FAILED);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_PLATFORM_CFG_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect (&background->mock, background->base.reset_intrusion, background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	struct cerberus_protocol_reset_config_response *resp =
		(struct cerberus_protocol_reset_config_response*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[32];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_config_response) + length,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, cerberus_protocol_reset_authorization (resp), length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_max_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	struct cerberus_protocol_reset_config_response *resp =
		(struct cerberus_protocol_reset_config_response*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_config_response) + length,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, cerberus_protocol_reset_authorization (resp), length);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_not_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth,
		AUTHORIZATION_NOT_AUTHORIZED, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_with_nonce_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	size_t length = 253;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	for (i = 0; i < (int) length; i++) {
		cerberus_protocol_reset_authorization (req)[i] = i;
	}

	request.length = sizeof (struct cerberus_protocol_reset_config) + length;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth, 0,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (cerberus_protocol_reset_authorization (req), length),
		MOCK_ARG_PTR_CONTAINS_TMP (&length, sizeof (length)));
	status |= mock_expect (&background->mock, background->base.reset_intrusion, background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_with_nonce_not_authorized (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	size_t length = 253;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	for (i = 0; i < (int) length; i++) {
		cerberus_protocol_reset_authorization (req)[i] = i;
	}

	request.length = sizeof (struct cerberus_protocol_reset_config) + length;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth,
		AUTHORIZATION_NOT_AUTHORIZED,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (cerberus_protocol_reset_authorization (req), length),
		MOCK_ARG_PTR_CONTAINS_TMP (&length, sizeof (length)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_invalid_challenge (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_invalid_challenge_limited_response (
	CuTest *test, struct cmd_interface *cmd, struct cmd_authorization_mock *auth)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG + 1 - 128];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < (int) sizeof (nonce); i++) {
		nonce[i] = i;
	}

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect_output (&auth->mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&auth->mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_intrusion_error (CuTest *test,
	struct cmd_interface *cmd, struct cmd_authorization_mock *auth,
	struct cmd_background_mock *background)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 4;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&auth->mock, auth->base.authorize_reset_intrusion, auth, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS_TMP (&zero, sizeof (zero)));
	status |= mock_expect (&background->mock, background->base.reset_intrusion, background,
		CMD_BACKGROUND_INTRUSION_FAILED);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_INTRUSION_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_config_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 0;
	request.length = sizeof (struct cerberus_protocol_reset_config) - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_reset_config_invalid_request_subtype (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_config *req = (struct cerberus_protocol_reset_config*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	req->type = 5;
	request.length = sizeof (struct cerberus_protocol_reset_config);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_port0 (CuTest *test,
	struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_recovery_image_update *req =
		(struct cerberus_protocol_prepare_recovery_image_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;

	req->port_id = 0;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_0->mock, recovery_0->base.prepare_recovery_image, recovery_0, 0,
		MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_port1 (CuTest *test,
	struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_recovery_image_update *req =
		(struct cerberus_protocol_prepare_recovery_image_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;

	req->port_id = 1;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_1->mock, recovery_1->base.prepare_recovery_image, recovery_1, 0,
		MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_port0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_recovery_image_update *req =
		(struct cerberus_protocol_prepare_recovery_image_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;

	req->port_id = 0;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_port1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_recovery_image_update *req =
		(struct cerberus_protocol_prepare_recovery_image_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;

	req->port_id = 1;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_recovery_image_update *req =
		(struct cerberus_protocol_prepare_recovery_image_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;

	req->port_id = 0;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_recovery_image_update) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_prepare_recovery_image_update) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_fail (CuTest *test,
	struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_recovery_image_update *req =
		(struct cerberus_protocol_prepare_recovery_image_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;

	req->port_id = 0;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_0->mock, recovery_0->base.prepare_recovery_image, recovery_0,
		RECOVERY_IMAGE_INVALID_ARGUMENT, MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_bad_port_index (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_prepare_recovery_image_update *req =
		(struct cerberus_protocol_prepare_recovery_image_update*) data;
	uint32_t length = 1;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;

	req->port_id = 2;
	req->size = length;
	request.length = sizeof (struct cerberus_protocol_prepare_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_update_recovery_image_port0 (CuTest *test,
	struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_recovery_image_update *req =
		(struct cerberus_protocol_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;

	req->port_id = 0;
	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_0->mock, recovery_0->base.update_recovery_image, recovery_0, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_update_recovery_image_port1 (CuTest *test,
	struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_recovery_image_update *req =
		(struct cerberus_protocol_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;

	req->port_id = 1;
	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_1->mock, recovery_1->base.update_recovery_image, recovery_1, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_update_recovery_image_port0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_recovery_image_update *req =
		(struct cerberus_protocol_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;

	req->port_id = 0;
	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_update_recovery_image_port1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_recovery_image_update *req =
		(struct cerberus_protocol_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;

	req->port_id = 1;
	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_update_recovery_image_no_data (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_recovery_image_update *req =
		(struct cerberus_protocol_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;

	req->port_id = 0;
	request.length =
		sizeof (struct cerberus_protocol_recovery_image_update) - sizeof (req->payload);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_update_recovery_image_bad_port_index (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_recovery_image_update *req =
		(struct cerberus_protocol_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;

	req->port_id = 2;
	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_update_recovery_image_fail (CuTest *test,
	struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_recovery_image_update *req =
		(struct cerberus_protocol_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;

	req->port_id = 0;
	req->payload = 0xAA;
	request.length = sizeof (struct cerberus_protocol_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_0->mock, recovery_0->base.update_recovery_image, recovery_0,
		RECOVERY_IMAGE_INVALID_ARGUMENT, MOCK_ARG_PTR_CONTAINS_TMP (&req->payload, 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_activate_recovery_image_port0 (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_recovery_image_update *req =
		(struct cerberus_protocol_complete_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_complete_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_0->mock, recovery_0->base.activate_recovery_image, recovery_0,
		0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_activate_recovery_image_port1 (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_recovery_image_update *req =
		(struct cerberus_protocol_complete_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;

	req->port_id = 1;
	request.length = sizeof (struct cerberus_protocol_complete_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_1->mock, recovery_1->base.activate_recovery_image, recovery_1,
		0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_activate_recovery_image_port0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_recovery_image_update *req =
		(struct cerberus_protocol_complete_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_complete_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_activate_recovery_image_port1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_recovery_image_update *req =
		(struct cerberus_protocol_complete_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;

	req->port_id = 1;
	request.length = sizeof (struct cerberus_protocol_complete_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_activate_recovery_image_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_recovery_image_update *req =
		(struct cerberus_protocol_complete_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_complete_recovery_image_update) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_complete_recovery_image_update) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_activate_recovery_image_bad_port_index (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_recovery_image_update *req =
		(struct cerberus_protocol_complete_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;

	req->port_id = 2;
	request.length = sizeof (struct cerberus_protocol_complete_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_activate_recovery_image_fail (CuTest *test,
	struct cmd_interface *cmd, struct recovery_image_cmd_interface_mock *recovery_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_complete_recovery_image_update *req =
		(struct cerberus_protocol_complete_recovery_image_update*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_complete_recovery_image_update);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_0->mock, recovery_0->base.activate_recovery_image, recovery_0,
		RECOVERY_IMAGE_INVALID_ARGUMENT);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_port0 (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_manager_mock *recovery_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	struct cerberus_protocol_get_recovery_image_id_version_response *resp =
		(struct cerberus_protocol_get_recovery_image_id_version_response*) data;
	struct recovery_image_mock image;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery_manager_0->mock,
		recovery_manager_0->base.get_active_recovery_image, recovery_manager_0,
		(intptr_t) &image.base);

	status |= mock_expect (&image.mock, image.base.get_version, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_FW_VERSION_LEN));
	status |= mock_expect_output (&image.mock, 0, RECOVERY_IMAGE_HEADER_VERSION_ID,
		RECOVERY_IMAGE_HEADER_VERSION_ID_LEN, 1);

	status |= mock_expect (&recovery_manager_0->mock, recovery_manager_0->base.free_recovery_image,
		recovery_manager_0, 0, MOCK_ARG (&image));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_recovery_image_id_version_response), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION, resp->header.command);
	CuAssertStrEquals (test, RECOVERY_IMAGE_HEADER_VERSION_ID, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_port1 (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_manager_mock *recovery_manager_1)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	struct cerberus_protocol_get_recovery_image_id_version_response *resp =
		(struct cerberus_protocol_get_recovery_image_id_version_response*) data;
	struct recovery_image_mock image;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 1;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery_manager_1->mock,
		recovery_manager_1->base.get_active_recovery_image, recovery_manager_1,
		(intptr_t) &image.base);

	status |= mock_expect (&image.mock, image.base.get_version, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_FW_VERSION_LEN));
	status |= mock_expect_output (&image.mock, 0, RECOVERY_IMAGE_HEADER_VERSION_ID,
		RECOVERY_IMAGE_HEADER_VERSION_ID_LEN, 1);

	status |= mock_expect (&recovery_manager_1->mock, recovery_manager_1->base.free_recovery_image,
		recovery_manager_1, 0, MOCK_ARG (&image));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_recovery_image_id_version_response), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION, resp->header.command);
	CuAssertStrEquals (test, RECOVERY_IMAGE_HEADER_VERSION_ID, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_no_id_type (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_manager_mock *recovery_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	struct cerberus_protocol_get_recovery_image_id_version_response *resp =
		(struct cerberus_protocol_get_recovery_image_id_version_response*) data;
	struct recovery_image_mock image;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id) - 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery_manager_0->mock,
		recovery_manager_0->base.get_active_recovery_image, recovery_manager_0,
		(intptr_t) &image.base);

	status |= mock_expect (&image.mock, image.base.get_version, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_FW_VERSION_LEN));
	status |= mock_expect_output (&image.mock, 0, RECOVERY_IMAGE_HEADER_VERSION_ID,
		RECOVERY_IMAGE_HEADER_VERSION_ID_LEN, 1);

	status |= mock_expect (&recovery_manager_0->mock, recovery_manager_0->base.free_recovery_image,
		recovery_manager_0, 0, MOCK_ARG (&image));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_recovery_image_id_version_response), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION, resp->header.command);
	CuAssertStrEquals (test, RECOVERY_IMAGE_HEADER_VERSION_ID, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_port0_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_port1_null (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 1;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_no_image (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_manager_mock *recovery_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	struct cerberus_protocol_get_recovery_image_id_version_response *resp =
		(struct cerberus_protocol_get_recovery_image_id_version_response*) data;
	char empty_string[CERBERUS_PROTOCOL_FW_VERSION_LEN] = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&recovery_manager_0->mock,
		recovery_manager_0->base.get_active_recovery_image, recovery_manager_0,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_recovery_image_id_version_response), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION, resp->header.command);
	CuAssertStrEquals (test, empty_string, resp->version);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_fail (
	CuTest *test, struct cmd_interface *cmd, struct recovery_image_manager_mock *recovery_manager_0)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	struct recovery_image_mock image;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery_manager_0->mock,
		recovery_manager_0->base.get_active_recovery_image, recovery_manager_0,
		(intptr_t) &image.base);

	status |= mock_expect (&image.mock, image.base.get_version, &image,
		RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_FW_VERSION_LEN));

	status |= mock_expect (&recovery_manager_0->mock, recovery_manager_0->base.free_recovery_image,
		recovery_manager_0, 0, MOCK_ARG (&image));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 0;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id) - 2;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_bad_port_index (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_recovery_image_id *req =
		(struct cerberus_protocol_get_recovery_image_id*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	req->port_id = 2;
	req->id = 0;
	request.length = sizeof (struct cerberus_protocol_get_recovery_image_id);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_attestation_data (CuTest *test,
	struct cmd_interface *cmd, struct pcr_store *store)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_attestation_data *req =
		(struct cerberus_protocol_get_attestation_data*) data;
	struct cerberus_protocol_get_attestation_data_response *resp =
		(struct cerberus_protocol_get_attestation_data_response*) data;
	struct pcr_measured_data measured_data;
	uint8_t data_1byte = 0x11;
	int status;

	measured_data.type = PCR_DATA_TYPE_1BYTE;
	measured_data.data.value_1byte = data_1byte;

	status = pcr_store_set_measurement_data (store, PCR_MEASUREMENT (0, 0), &measured_data);
	CuAssertIntEquals (test, 0, status);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_ATTESTATION_DATA;

	req->pmr = 0;
	req->entry = 0;
	req->offset = 0;

	request.length = sizeof (struct cerberus_protocol_get_attestation_data);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_attestation_data_response) + sizeof (uint8_t),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_ATTESTATION_DATA, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (&data_1byte, cerberus_protocol_attestation_data (resp),
		sizeof (uint8_t));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_attestation_data_with_offset (
	CuTest *test, struct cmd_interface *cmd, struct pcr_store *store)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_attestation_data *req =
		(struct cerberus_protocol_get_attestation_data*) data;
	struct cerberus_protocol_get_attestation_data_response *resp =
		(struct cerberus_protocol_get_attestation_data_response*) data;
	struct pcr_measured_data measured_data;
	uint64_t data_8byte = 0x1122334455667788;
	int status;

	measured_data.type = PCR_DATA_TYPE_8BYTE;
	measured_data.data.value_8byte = data_8byte;

	status = pcr_store_set_measurement_data (store, PCR_MEASUREMENT (1, 2), &measured_data);
	CuAssertIntEquals (test, 0, status);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_ATTESTATION_DATA;

	req->pmr = 1;
	req->entry = 2;
	req->offset = 3;

	request.length = sizeof (struct cerberus_protocol_get_attestation_data);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_attestation_data_response) + sizeof (data_8byte) - 3,
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_ATTESTATION_DATA, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) &data_8byte + 3,
		cerberus_protocol_attestation_data (resp), sizeof (data_8byte) - 3);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_attestation_data_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_attestation_data *req =
		(struct cerberus_protocol_get_attestation_data*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_ATTESTATION_DATA;

	req->pmr = 0;
	req->entry = 0;
	req->offset = 0;

	request.length = sizeof (struct cerberus_protocol_get_attestation_data) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct cerberus_protocol_get_attestation_data) - 1;
	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_attestation_data_fail (CuTest *test,
	struct cmd_interface *cmd, struct pcr_store *store, struct flash_mock *flash)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_attestation_data *req =
		(struct cerberus_protocol_get_attestation_data*) data;
	struct pcr_measured_data measured_data;
	int status;

	measured_data.type = PCR_DATA_TYPE_FLASH;
	measured_data.data.flash.flash = &flash->base;
	measured_data.data.flash.addr = 0x11223344;
	measured_data.data.flash.length = 100;

	status = pcr_store_set_measurement_data (store, PCR_MEASUREMENT (0, 4), &measured_data);
	CuAssertIntEquals (test, 0, status);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_ATTESTATION_DATA;

	req->pmr = 0;
	req->entry = 4;
	req->offset = 0;

	request.length = sizeof (struct cerberus_protocol_get_attestation_data);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&flash->mock, flash->base.read, flash, FLASH_MASTER_XFER_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL,  MOCK_ARG (100));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_attestation_data_no_data (
	CuTest *test, struct cmd_interface *cmd, struct pcr_store *store)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_attestation_data *req =
		(struct cerberus_protocol_get_attestation_data*) data;
	struct cerberus_protocol_get_attestation_data_response *resp =
		(struct cerberus_protocol_get_attestation_data_response*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_ATTESTATION_DATA;

	req->pmr = 0;
	req->entry = 0;
	req->offset = 0;

	request.length = sizeof (struct cerberus_protocol_get_attestation_data);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_attestation_data_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_ATTESTATION_DATA, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_0 (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_key_exchange_type_0 *rq =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	struct cerberus_protocol_key_exchange_response_type_0 *resp =
		(struct cerberus_protocol_key_exchange_response_type_0*) response_data;
	uint8_t hmac_buf[SHA256_HASH_LENGTH] = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;

	rq->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (cerberus_protocol_key_exchange_type_0_key_data (rq), ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);

	request.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	resp->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	resp->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	resp->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	resp->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	resp->reserved = 0;
	resp->key_len = ECC_PUBKEY_DER_LEN;

	memcpy (cerberus_protocol_key_exchange_type_0_response_key_data (resp),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	cerberus_protocol_key_exchange_type_0_response_sig_len (resp) = ECC_SIG_TEST_LEN;

	memcpy (cerberus_protocol_key_exchange_type_0_response_sig_data (resp), ECC_SIGNATURE_TEST,
		ECC_SIG_TEST_LEN);

	cerberus_protocol_key_exchange_type_0_response_hmac_len (resp) = SHA256_HASH_LENGTH;

	memcpy (cerberus_protocol_key_exchange_type_0_response_hmac_data (resp), hmac_buf,
		SHA256_HASH_LENGTH);

	response.length = cerberus_protocol_key_exchange_type_0_response_length (ECC_PUBKEY_DER_LEN,
		ECC_SIG_TEST_LEN, SHA256_HASH_LENGTH);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = true;

	status = mock_expect (&session->mock, session->base.establish_session, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &response, sizeof (response),
		cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	resp = (struct cerberus_protocol_key_exchange_response_type_0*) request.data;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		cerberus_protocol_key_exchange_type_0_response_length (ECC_PUBKEY_DER_LEN, ECC_SIG_TEST_LEN,
		SHA256_HASH_LENGTH), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->common.header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->common.header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->common.header.crypt);
	CuAssertIntEquals (test, 0, resp->common.header.reserved2);
	CuAssertIntEquals (test, 0, resp->common.header.integrity_check);
	CuAssertIntEquals (test, 0, resp->common.header.reserved1);
	CuAssertIntEquals (test, 0, resp->common.header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, resp->common.header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_SESSION_KEY, resp->common.key_type);
	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, resp->key_len);
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN,
		cerberus_protocol_key_exchange_type_0_response_sig_len (resp));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH,
		cerberus_protocol_key_exchange_type_0_response_hmac_len (resp));
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (ECC_PUBKEY_DER,
		cerberus_protocol_key_exchange_type_0_response_key_data (resp), ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST,
		cerberus_protocol_key_exchange_type_0_response_sig_data (resp), ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hmac_buf,
		cerberus_protocol_key_exchange_type_0_response_hmac_data (resp), SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_0_fail (
	CuTest *test, struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_key_exchange_type_0 *rq =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (cerberus_protocol_key_exchange_type_0_key_data (rq), ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);

	request.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.establish_session, session,
		SESSION_MANAGER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1 (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	uint8_t encrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg encrypted_response;
	struct cerberus_protocol_key_exchange_type_1 *rq =
		(struct cerberus_protocol_key_exchange_type_1*) data;
	struct cerberus_protocol_key_exchange_type_1 *decrypted_rq =
		(struct cerberus_protocol_key_exchange_type_1*) decrypted_data;
	struct cerberus_protocol_key_exchange_response *resp =
		(struct cerberus_protocol_key_exchange_response*) response_data;
	uint8_t hmac_buf[SHA256_HASH_LENGTH] = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	memset (&encrypted_response, 0, sizeof (encrypted_response));
	memset (encrypted_data, 0, sizeof (encrypted_data));
	encrypted_response.data = encrypted_data;

	rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->common.header.crypt = 1;
	rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->common.key_type = 0xAA;
	rq->pairing_key_len = 0xBB;

	memset (cerberus_protocol_key_exchange_type_1_hmac_data (rq), 0xCC, sizeof (hmac_buf));

	request.length = cerberus_protocol_key_exchange_type_1_length (sizeof (hmac_buf));
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	decrypted_rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	decrypted_rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	decrypted_rq->common.header.crypt = 1;
	decrypted_rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	decrypted_rq->common.key_type = CERBERUS_PROTOCOL_PAIRED_KEY_HMAC;
	decrypted_rq->pairing_key_len = ECC_PUBKEY_DER_LEN;

	memcpy (cerberus_protocol_key_exchange_type_1_hmac_data (decrypted_rq), hmac_buf,
		sizeof (hmac_buf));

	decrypted_request.length = cerberus_protocol_key_exchange_type_1_length (sizeof (hmac_buf));
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	resp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	resp->header.crypt = 1;
	resp->header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	resp->key_type = CERBERUS_PROTOCOL_PAIRED_KEY_HMAC;

	response.length = sizeof (struct cerberus_protocol_key_exchange_response);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = true;

	resp = (struct cerberus_protocol_key_exchange_response*) encrypted_response.data;

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	resp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	resp->header.crypt = 1;
	resp->header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	resp->key_type = 0xBB;

	encrypted_response.length = sizeof (struct cerberus_protocol_key_exchange_response);
	encrypted_response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted_response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	encrypted_response.crypto_timeout = true;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.setup_paired_session, session, 0,
		MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (hmac_buf, sizeof (hmac_buf)), MOCK_ARG (sizeof (hmac_buf)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.encrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &encrypted_response,
		sizeof (encrypted_response), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	resp = (struct cerberus_protocol_key_exchange_response*) request.data;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_key_exchange_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 1, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, resp->header.command);
	CuAssertIntEquals (test, 0xBB, resp->key_type);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1_unencrypted (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_key_exchange_type_1 *rq =
		(struct cerberus_protocol_key_exchange_type_1*) data;
	uint8_t hmac_buf[SHA256_HASH_LENGTH] = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->common.header.crypt = 0;
	rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->common.key_type = CERBERUS_PROTOCOL_PAIRED_KEY_HMAC;
	rq->pairing_key_len = ECC_PUBKEY_DER_LEN;

	memcpy (cerberus_protocol_key_exchange_type_1_hmac_data (rq), hmac_buf, sizeof (hmac_buf));

	request.length = cerberus_protocol_key_exchange_type_1_length (sizeof (hmac_buf));
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_CMD_SHOULD_BE_ENCRYPTED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1_fail (
	CuTest *test, struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	struct cerberus_protocol_key_exchange_type_1 *rq =
		(struct cerberus_protocol_key_exchange_type_1*) data;
	struct cerberus_protocol_key_exchange_type_1 *decrypted_rq =
		(struct cerberus_protocol_key_exchange_type_1*) decrypted_data;
	uint8_t hmac_buf[SHA256_HASH_LENGTH] = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->common.header.crypt = 1;
	rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->common.key_type = 0xAA;
	rq->pairing_key_len = 0xBB;

	memset (cerberus_protocol_key_exchange_type_1_hmac_data (rq), 0xCC, sizeof (hmac_buf));

	request.length = cerberus_protocol_key_exchange_type_1_length (sizeof (hmac_buf));
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	decrypted_rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	decrypted_rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	decrypted_rq->common.header.crypt = 1;
	decrypted_rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	decrypted_rq->common.key_type = CERBERUS_PROTOCOL_PAIRED_KEY_HMAC;
	decrypted_rq->pairing_key_len = ECC_PUBKEY_DER_LEN;

	memcpy (cerberus_protocol_key_exchange_type_1_hmac_data (decrypted_rq), hmac_buf,
		sizeof (hmac_buf));

	decrypted_request.length = cerberus_protocol_key_exchange_type_1_length (sizeof (hmac_buf));
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.setup_paired_session, session,
		SESSION_MANAGER_NO_MEMORY, MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS_TMP (hmac_buf, sizeof (hmac_buf)), MOCK_ARG (sizeof (hmac_buf)));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2 (CuTest *test,
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
	struct cerberus_protocol_key_exchange_response *resp =
		(struct cerberus_protocol_key_exchange_response*) data;
	uint8_t hmac_buf[SHA256_HASH_LENGTH] = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

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

	decrypted_request.length = cerberus_protocol_key_exchange_type_2_length (sizeof (hmac_buf));
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.reset_session, session, 0,
		MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG_PTR_CONTAINS_TMP (hmac_buf, sizeof (hmac_buf)),
		MOCK_ARG (sizeof (hmac_buf)));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_key_exchange_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, resp->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DELETE_SESSION_KEY, resp->key_type);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2_unencrypted (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_key_exchange *rq = (struct cerberus_protocol_key_exchange*) data;
	uint8_t hmac_buf[SHA256_HASH_LENGTH] = {0};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->key_type = CERBERUS_PROTOCOL_DELETE_SESSION_KEY;

	memcpy (cerberus_protocol_key_exchange_type_2_hmac_data (rq), hmac_buf, sizeof (hmac_buf));

	request.length = cerberus_protocol_key_exchange_type_2_length (sizeof (hmac_buf));
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_CMD_SHOULD_BE_ENCRYPTED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2_fail (
	CuTest *test, struct cmd_interface *cmd, struct session_manager_mock *session)
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
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

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

	decrypted_request.length = cerberus_protocol_key_exchange_type_2_length (sizeof (hmac_buf));
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

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
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_unsupported (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_key_exchange_type_0 *rq =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->common.key_type = CERBERUS_PROTOCOL_SESSION_KEY;
	rq->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (cerberus_protocol_key_exchange_type_0_key_data (rq), ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);

	request.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_unsupported_index (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_key_exchange_type_0 *rq =
		(struct cerberus_protocol_key_exchange_type_0*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->common.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->common.header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->common.header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->common.key_type = 3;
	rq->hmac_type = CERBERUS_PROTOCOL_HMAC_SHA256;

	memcpy (cerberus_protocol_key_exchange_type_0_key_data (rq), ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);

	request.length = cerberus_protocol_key_exchange_type_0_length (ECC_PUBKEY_DER_LEN);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_get_key_exchange_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_key_exchange *rq = (struct cerberus_protocol_key_exchange*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.crypt = 0;
	rq->header.command = CERBERUS_PROTOCOL_EXCHANGE_KEYS;

	rq->key_type = CERBERUS_PROTOCOL_SESSION_KEY;

	request.length = sizeof (struct cerberus_protocol_key_exchange);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_session_sync (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	uint8_t encrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg encrypted_response;
	struct cerberus_protocol_session_sync *rq = (struct cerberus_protocol_session_sync*) data;
	struct cerberus_protocol_session_sync *decrypted_rq =
		(struct cerberus_protocol_session_sync*) decrypted_data;
	struct cerberus_protocol_session_sync_response *resp =
		(struct cerberus_protocol_session_sync_response*) response_data;
	struct cerberus_protocol_session_sync_response *encrypted_resp =
		(struct cerberus_protocol_session_sync_response*) encrypted_data;
	uint8_t hmac_expected[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,
		0xd6,0x41,0x20,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6
	};
	uint8_t hmac_expected_encrypted[] = {
		0xd6,0x41,0x20,0xfa,0x1a,0x0e,0x0a,0x04,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34
	};
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	memset (&encrypted_response, 0, sizeof (encrypted_response));
	memset (encrypted_data, 0, sizeof (encrypted_data));
	encrypted_response.data = encrypted_data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.crypt = 1;
	rq->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	rq->rn_req = 0xeeff0011;

	request.length = sizeof (struct cerberus_protocol_session_sync);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	decrypted_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	decrypted_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	decrypted_rq->header.crypt = 1;
	decrypted_rq->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	decrypted_rq->rn_req = 0xaabbccdd;

	decrypted_request.length = sizeof (struct cerberus_protocol_session_sync);
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	resp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	resp->header.crypt = 1;
	resp->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	response.length = sizeof (struct cerberus_protocol_session_sync_response) +
		sizeof (hmac_expected);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = true;

	memcpy (cerberus_protocol_session_sync_hmac_data (resp), hmac_expected,
		sizeof (hmac_expected));

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	resp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	resp->header.crypt = 1;
	resp->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	memcpy (cerberus_protocol_session_sync_hmac_data (encrypted_resp), hmac_expected_encrypted,
		sizeof (hmac_expected_encrypted));

	encrypted_response.length = sizeof (struct cerberus_protocol_session_sync_response) +
		sizeof (hmac_expected_encrypted);
	encrypted_response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted_response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	encrypted_response.crypto_timeout = true;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.session_sync, session,
		sizeof (hmac_expected), MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG (0xaabbccdd),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_output (&session->mock, 2, hmac_expected, sizeof (hmac_expected), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.encrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &encrypted_response,
		sizeof (encrypted_response), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_session_sync_response) +
		sizeof (hmac_expected_encrypted), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 1, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_SESSION_SYNC, resp->header.command);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (hmac_expected_encrypted,
		cerberus_protocol_session_sync_hmac_data (rq), sizeof (hmac_expected_encrypted));
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_optional_commands_testing_process_session_sync_no_session_mgr (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_session_sync *rq = (struct cerberus_protocol_session_sync*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.crypt = 0;
	rq->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	rq->rn_req = 0xeeff0011;

	request.length = sizeof (struct cerberus_protocol_session_sync);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_session_sync_fail (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	struct cerberus_protocol_session_sync *rq = (struct cerberus_protocol_session_sync*) data;
	struct cerberus_protocol_session_sync *decrypted_rq =
		(struct cerberus_protocol_session_sync*) decrypted_data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.crypt = 1;
	rq->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	rq->rn_req = 0xeeff0011;

	request.length = sizeof (struct cerberus_protocol_session_sync);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	decrypted_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	decrypted_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	decrypted_rq->header.crypt = 1;
	decrypted_rq->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	decrypted_rq->rn_req = 0xaabbccdd;

	decrypted_request.length = sizeof (struct cerberus_protocol_session_sync);
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&session->mock, session->base.session_sync, session,
		SESSION_MANAGER_NO_MEMORY, MOCK_ARG (MCTP_BASE_PROTOCOL_BMC_EID), MOCK_ARG (0xaabbccdd),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_session_sync_unencrypted (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_session_sync *rq = (struct cerberus_protocol_session_sync*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.crypt = 0;
	rq->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	request.length = sizeof (struct cerberus_protocol_session_sync);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rq->rn_req = 0xaabbccdd;

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_CMD_SHOULD_BE_ENCRYPTED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

void cerberus_protocol_optional_commands_testing_process_session_sync_invalid_len (CuTest *test,
	struct cmd_interface *cmd, struct session_manager_mock *session)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	struct cerberus_protocol_session_sync *rq = (struct cerberus_protocol_session_sync*) data;
	struct cerberus_protocol_session_sync *decrypted_rq =
		(struct cerberus_protocol_session_sync*) decrypted_data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rq->header.crypt = 1;
	rq->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	rq->rn_req = 0xeeff0011;

	request.length = sizeof (struct cerberus_protocol_session_sync);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	decrypted_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	decrypted_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	decrypted_rq->header.crypt = 1;
	decrypted_rq->header.command = CERBERUS_PROTOCOL_SESSION_SYNC;

	decrypted_rq->rn_req = 0xaabbccdd;

	decrypted_request.length = sizeof (struct cerberus_protocol_session_sync) - 1;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	decrypted_request.length = sizeof (struct cerberus_protocol_session_sync) + 1;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&session->mock, session->base.decrypt_message, session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&session->mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);
}

/*******************
 * Test cases
 *******************/

static void cerberus_protocol_optional_commands_test_prepare_pfm_update_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x5b,
		0x01,0x02,0x03,0x04,0x05
	};
	struct cerberus_protocol_prepare_pfm_update *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_prepare_pfm_update));

	req = (struct cerberus_protocol_prepare_pfm_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_INIT_PFM_UPDATE, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
	CuAssertIntEquals (test, 0x05040302, req->size);
}

static void cerberus_protocol_optional_commands_test_pfm_update_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x5c,
		0x01,
		0x02,0x03,0x04,0x05
	};
	struct cerberus_protocol_pfm_update *req;

	TEST_START;

	req = (struct cerberus_protocol_pfm_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_PFM_UPDATE, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
	CuAssertPtrEquals (test, &raw_buffer_req[6], &req->payload);
}

static void cerberus_protocol_optional_commands_test_complete_pfm_update_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x5d,
		0x01,0x02
	};
	struct cerberus_protocol_complete_pfm_update *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_complete_pfm_update));

	req = (struct cerberus_protocol_complete_pfm_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
	CuAssertIntEquals (test, 0x02, req->activation);
}

static void cerberus_protocol_optional_commands_test_get_pfm_id_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x59,
		0x01,0x02,0x03
	};
	uint8_t raw_buffer_resp_version[] = {
		0x7e,0x14,0x13,0x03,0x59,
		0x03,0x04,0x05,0x06,0x07
	};
	uint8_t raw_buffer_resp_platform[] = {
		0x7e,0x14,0x13,0x03,0x59,
		0x08,
		0x30,0x31,0x32,0x33,0x34,0x35,0x00
	};
	struct cerberus_protocol_get_pfm_id *req;
	struct cerberus_protocol_get_pfm_id_version_response *resp1;
	struct cerberus_protocol_get_pfm_id_platform_response *resp2;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct cerberus_protocol_get_pfm_id));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp_version),
		sizeof (struct cerberus_protocol_get_pfm_id_version_response));

	req = (struct cerberus_protocol_get_pfm_id*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
	CuAssertIntEquals (test, 0x02, req->region);
	CuAssertIntEquals (test, 0x03, req->id);

	resp1 = (struct cerberus_protocol_get_pfm_id_version_response*) raw_buffer_resp_version;
	CuAssertIntEquals (test, 0, resp1->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp1->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp1->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp1->header.rq);
	CuAssertIntEquals (test, 0, resp1->header.reserved2);
	CuAssertIntEquals (test, 0, resp1->header.crypt);
	CuAssertIntEquals (test, 0x03, resp1->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp1->header.command);

	CuAssertIntEquals (test, 0x03, resp1->valid);
	CuAssertIntEquals (test, 0x07060504, resp1->version);

	resp2 = (struct cerberus_protocol_get_pfm_id_platform_response*) raw_buffer_resp_platform;
	CuAssertIntEquals (test, 0, resp2->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp2->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp2->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp2->header.rq);
	CuAssertIntEquals (test, 0, resp2->header.reserved2);
	CuAssertIntEquals (test, 0, resp2->header.crypt);
	CuAssertIntEquals (test, 0x03, resp2->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, resp2->header.command);

	CuAssertIntEquals (test, 0x08, resp2->valid);
	CuAssertStrEquals (test, "012345", (char*) &resp2->platform);
}

static void cerberus_protocol_optional_commands_test_get_pfm_supported_fw_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x5a,
		0x01,0x02,0x03,0x04,0x05,0x06,
		0x08,
		0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x00
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x5a,
		0x03,0x04,0x05,0x06,0x07,
		0x30,0x31,0x32,0x33,0x34,0x35,0x00
	};
	struct cerberus_protocol_get_pfm_supported_fw *req;
	struct cerberus_protocol_get_pfm_supported_fw_response *resp;

	TEST_START;

	req = (struct cerberus_protocol_get_pfm_supported_fw*) raw_buffer_req;
	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		cerberus_protocol_get_pfm_supported_fw_request_length_with_id (req));

	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
	CuAssertIntEquals (test, 0x02, req->region);
	CuAssertIntEquals (test, 0x06050403, req->offset);
	CuAssertIntEquals (test, 0x08, cerberus_protocol_get_pfm_supported_fw_id_length (req));
	CuAssertPtrEquals (test, &raw_buffer_req[12], cerberus_protocol_get_pfm_supported_fw_id (req));

	resp = (struct cerberus_protocol_get_pfm_supported_fw_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, resp->header.command);

	CuAssertIntEquals (test, 0x03, resp->valid);
	CuAssertIntEquals (test, 0x07060504, resp->version);
	CuAssertPtrEquals (test, &raw_buffer_resp[10], cerberus_protocol_pfm_supported_fw (resp));
}

static void cerberus_protocol_optional_commands_test_prepare_recovery_image_update_format (
	CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x72,
		0x01,0x02,0x03,0x04,0x05
	};
	struct cerberus_protocol_prepare_recovery_image_update *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_prepare_recovery_image_update));

	req = (struct cerberus_protocol_prepare_recovery_image_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
	CuAssertIntEquals (test, 0x05040302, req->size);
}

static void cerberus_protocol_optional_commands_test_recovery_image_update_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x73,
		0x01,
		0x02,0x03,0x04,0x05
	};
	struct cerberus_protocol_recovery_image_update *req;

	TEST_START;

	req = (struct cerberus_protocol_recovery_image_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
	CuAssertPtrEquals (test, &raw_buffer_req[6], &req->payload);
}

static void cerberus_protocol_optional_commands_test_complete_recovery_image_update_format (
	CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x74,
		0x01
	};
	struct cerberus_protocol_complete_recovery_image_update *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_complete_recovery_image_update));

	req = (struct cerberus_protocol_complete_recovery_image_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
}

static void cerberus_protocol_optional_commands_test_get_recovery_image_id_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x75,
		0x01,02
	};
	uint8_t raw_buffer_resp_version[] = {
		0x7e,0x14,0x13,0x03,0x75,
		0x30,0x31,0x32,0x33,0x34,0x35,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};
	uint8_t raw_buffer_resp_platform[] = {
		0x7e,0x14,0x13,0x03,0x75,
		0x36,0x37,0x38,0x39,0x00
	};
	struct cerberus_protocol_get_recovery_image_id *req;
	struct cerberus_protocol_get_recovery_image_id_version_response *resp1;
	struct cerberus_protocol_get_recovery_image_id_platform_response *resp2;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_recovery_image_id));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp_version),
		sizeof (struct cerberus_protocol_get_recovery_image_id_version_response));

	req = (struct cerberus_protocol_get_recovery_image_id*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION,
		req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);

	resp1 =
		(struct cerberus_protocol_get_recovery_image_id_version_response*) raw_buffer_resp_version;
	CuAssertIntEquals (test, 0, resp1->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp1->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp1->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp1->header.rq);
	CuAssertIntEquals (test, 0, resp1->header.reserved2);
	CuAssertIntEquals (test, 0, resp1->header.crypt);
	CuAssertIntEquals (test, 0x03, resp1->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION, resp1->header.command);

	CuAssertStrEquals (test, "012345", resp1->version);

	resp2 = (struct cerberus_protocol_get_recovery_image_id_platform_response*)
		raw_buffer_resp_platform;
	CuAssertIntEquals (test, 0, resp2->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp2->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp2->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp2->header.rq);
	CuAssertIntEquals (test, 0, resp2->header.reserved2);
	CuAssertIntEquals (test, 0, resp2->header.crypt);
	CuAssertIntEquals (test, 0x03, resp2->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION, resp2->header.command);

	CuAssertStrEquals (test, "6789", (char*) &resp2->platform);
}

static void cerberus_protocol_optional_commands_test_get_host_state_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x40,
		0x01
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x40,
		0x02
	};
	struct cerberus_protocol_get_host_state *req;
	struct cerberus_protocol_get_host_state_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_host_state));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct cerberus_protocol_get_host_state_response));

	req = (struct cerberus_protocol_get_host_state*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE,
		req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);

	resp = (struct cerberus_protocol_get_host_state_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, resp->header.command);

	CuAssertIntEquals (test, 0x02, resp->reset_status);
}

static void cerberus_protocol_optional_commands_test_pmr_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x80,
		0x01,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54,
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x80,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x20,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54,
		0x30,0x46,0x02,0x21,0x00,0x86,0x1d,0x0e,0x39,0x20,0xdc,0xae,0x77,0xcc,0xb0,0x33,
		0x38,0xb7,0xd8,0x47,0xb9,0x7a,0x6b,0x65,0x3b,0xe2,0x72,0x52,0x8f,0x77,0x82,0x00,
		0x82,0x8f,0x6f,0xc5,0x9e,0x02,0x21,0x00,0xf8,0xf9,0x96,0xaf,0xd5,0xc5,0x50,0x16,
		0xa9,0x31,0x2d,0xad,0x1e,0xec,0x61,0x3a,0x80,0xe5,0x7a,0x1f,0xa0,0xc3,0x0c,0x35,
		0x41,0x00,0x96,0xcf,0x71,0x24,0x08,0x43
	};
	struct cerberus_protocol_pmr *req;
	struct cerberus_protocol_pmr_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct cerberus_protocol_pmr));

	req = (struct cerberus_protocol_pmr*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PMR, req->header.command);

	CuAssertIntEquals (test, 0x01, req->measurement_number);
	CuAssertPtrEquals (test, &raw_buffer_req[6], req->nonce);

	resp = (struct cerberus_protocol_pmr_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PMR, resp->header.command);

	CuAssertPtrEquals (test, &raw_buffer_resp[5], resp->nonce);
	CuAssertIntEquals (test, 0x20, resp->pmr_length);
	CuAssertPtrEquals (test, &raw_buffer_resp[38], &resp->measurement);
	CuAssertPtrEquals (test, &raw_buffer_resp[70], cerberus_protocol_pmr_get_signature (resp));
}

static void cerberus_protocol_optional_commands_test_update_pmr_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x86,
		0x01,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54,
	};
	struct cerberus_protocol_update_pmr *req;

	TEST_START;

	req = (struct cerberus_protocol_update_pmr*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UPDATE_PMR, req->header.command);

	CuAssertIntEquals (test, 0x01, req->measurement_number);
	CuAssertPtrEquals (test, &raw_buffer_req[6], &req->measurement_ext);
}

static void cerberus_protocol_optional_commands_test_key_exchange_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x84,
		0x01,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54,
	};
	struct cerberus_protocol_key_exchange *req;

	TEST_START;

	req = (struct cerberus_protocol_key_exchange*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, req->header.command);

	CuAssertIntEquals (test, 0x01, req->key_type);
	CuAssertPtrEquals (test, &raw_buffer_req[6], cerberus_protocol_key_exchange_data (req));
}

static void cerberus_protocol_optional_commands_test_get_log_info_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x4f,
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x4f,
		0x01,0x02,0x03,0x04,
		0x05,0x06,0x07,0x08,
		0x09,0x0a,0x0b,0x0c
	};
	struct cerberus_protocol_get_log_info *req;
	struct cerberus_protocol_get_log_info_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_log_info));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct cerberus_protocol_get_log_info_response));

	req = (struct cerberus_protocol_get_log_info*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_LOG_INFO, req->header.command);

	resp = (struct cerberus_protocol_get_log_info_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_LOG_INFO, resp->header.command);

	CuAssertIntEquals (test, 0x04030201, resp->debug_log_length);
	CuAssertIntEquals (test, 0x08070605, resp->attestation_log_length);
	CuAssertIntEquals (test, 0x0c0b0a09, resp->tamper_log_length);
}

static void cerberus_protocol_optional_commands_test_get_log_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x50,
		0x01,0x02,0x03,0x04,0x05
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x50,
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c
	};
	struct cerberus_protocol_get_log *req;
	struct cerberus_protocol_get_log_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct cerberus_protocol_get_log));

	req = (struct cerberus_protocol_get_log*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, req->header.command);

	CuAssertIntEquals (test, 0x01, req->log_type);
	CuAssertIntEquals (test, 0x05040302, req->offset);

	resp = (struct cerberus_protocol_get_log_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG, resp->header.command);

	CuAssertPtrEquals (test, &raw_buffer_resp[5], cerberus_protocol_log_data (resp));
}

static void cerberus_protocol_optional_commands_test_clear_log_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x51,
		0x01
	};
	struct cerberus_protocol_clear_log *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct cerberus_protocol_clear_log));

	req = (struct cerberus_protocol_clear_log*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CLEAR_LOG, req->header.command);

	CuAssertIntEquals (test, 0x01, req->log_type);
}

static void cerberus_protocol_optional_commands_test_get_attestation_data_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x52,
		0x01,0x02,0x03,0x04,0x05,0x06
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x52,
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c
	};
	struct cerberus_protocol_get_attestation_data *req;
	struct cerberus_protocol_get_attestation_data_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_get_attestation_data));

	req = (struct cerberus_protocol_get_attestation_data*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_ATTESTATION_DATA, req->header.command);

	CuAssertIntEquals (test, 0x01, req->pmr);
	CuAssertIntEquals (test, 0x02, req->entry);
	CuAssertIntEquals (test, 0x06050403, req->offset);

	resp = (struct cerberus_protocol_get_attestation_data_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_ATTESTATION_DATA, resp->header.command);

	CuAssertPtrEquals (test, &raw_buffer_resp[5], cerberus_protocol_attestation_data (resp));
}

static void cerberus_protocol_optional_commands_test_prepare_fw_update_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x66,
		0x01,0x02,0x03,0x04
	};
	struct cerberus_protocol_prepare_fw_update *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_prepare_fw_update));

	req = (struct cerberus_protocol_prepare_fw_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_INIT_FW_UPDATE, req->header.command);

	CuAssertIntEquals (test, 0x04030201, req->total_size);
}

static void cerberus_protocol_optional_commands_test_fw_update_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x67,
		0x02,0x03,0x04,0x05
	};
	struct cerberus_protocol_fw_update *req;

	TEST_START;

	req = (struct cerberus_protocol_fw_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_FW_UPDATE, req->header.command);

	CuAssertPtrEquals (test, &raw_buffer_req[5], &req->payload);
}

static void cerberus_protocol_optional_commands_test_complete_fw_update_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x69,
	};
	struct cerberus_protocol_complete_fw_update *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_complete_fw_update));

	req = (struct cerberus_protocol_complete_fw_update*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE, req->header.command);
}

static void cerberus_protocol_optional_commands_test_reset_config_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x6a,
		0x01,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x30,0x46,0x02,0x21,0x00,0x86,0x1d,0x0e,0x39,0x20,0xdc,0xae,0x77,0xcc,0xb0,0x33,
		0x38,0xb7,0xd8,0x47,0xb9,0x7a,0x6b,0x65,0x3b,0xe2,0x72,0x52,0x8f,0x77,0x82,0x00,
		0x82,0x8f,0x6f,0xc5,0x9e,0x02,0x21,0x00,0xf8,0xf9,0x96,0xaf,0xd5,0xc5,0x50,0x16,
		0xa9,0x31,0x2d,0xad,0x1e,0xec,0x61,0x3a,0x80,0xe5,0x7a,0x1f,0xa0,0xc3,0x0c,0x35,
		0x41,0x00,0x96,0xcf,0x71,0x24,0x08,0x43
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x6a,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
	};
	struct cerberus_protocol_reset_config *req;
	struct cerberus_protocol_reset_config_response *resp;

	TEST_START;

	req = (struct cerberus_protocol_reset_config*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, req->header.command);

	CuAssertIntEquals (test, 0x01, req->type);
	CuAssertPtrEquals (test, &raw_buffer_req[6], cerberus_protocol_reset_authorization (req));

	resp = (struct cerberus_protocol_reset_config_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG, resp->header.command);

	CuAssertPtrEquals (test, &raw_buffer_resp[5], cerberus_protocol_reset_authorization (resp));
}

static void cerberus_protocol_optional_commands_test_recover_firmware_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x71,
		0x01,0x02
	};
	struct cerberus_protocol_recover_firmware *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_recover_firmware));

	req = (struct cerberus_protocol_recover_firmware*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_TRIGGER_FW_RECOVERY, req->header.command);

	CuAssertIntEquals (test, 0x01, req->port_id);
	CuAssertIntEquals (test, 0x02, req->recovery_img);
}

static void cerberus_protocol_optional_commands_test_message_unseal_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x89,
		0x01,0x02,
		0x48,0x00,
		0x30,0x46,0x02,0x21,0x00,0x86,0x1d,0x0e,0x39,0x20,0xdc,0xae,0x77,0xcc,0xb0,0x33,
		0x38,0xb7,0xd8,0x47,0xb9,0x7a,0x6b,0x65,0x3b,0xe2,0x72,0x52,0x8f,0x77,0x82,0x00,
		0x82,0x8f,0x6f,0xc5,0x9e,0x02,0x21,0x00,0xf8,0xf9,0x96,0xaf,0xd5,0xc5,0x50,0x16,
		0xa9,0x31,0x2d,0xad,0x1e,0xec,0x61,0x3a,0x80,0xe5,0x7a,0x1f,0xa0,0xc3,0x0c,0x35,
		0x41,0x00,0x96,0xcf,0x71,0x24,0x08,0x43,
		0x10,0x00,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x20,0x00,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};
	struct cerberus_protocol_message_unseal *req;
	const struct cerberus_protocol_unseal_pmrs *pmrs;

	TEST_START;

	req = (struct cerberus_protocol_message_unseal*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE, req->header.command);

	CuAssertIntEquals (test, 0x00, req->reserved);
	CuAssertIntEquals (test, 0x00, req->hmac_type);
	CuAssertIntEquals (test, 0x01, req->seed_type);
	CuAssertIntEquals (test, 0x00, req->seed_params.rsa.reserved);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA256,
		req->seed_params.rsa.padding);
	CuAssertIntEquals (test, 0x01, req->seed_params.ecdh.reserved);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_ECDH_RAW, req->seed_params.ecdh.processing);
	CuAssertIntEquals (test, 0x02, req->seed_params.raw);
	CuAssertIntEquals (test, 0x0048, req->seed_length);
	CuAssertPtrEquals (test, &raw_buffer_req[9], &req->seed);
	CuAssertIntEquals (test, 0x0010, cerberus_protocol_unseal_ciphertext_length (req));
	CuAssertPtrEquals (test, &raw_buffer_req[83], cerberus_protocol_unseal_ciphertext (req));
	CuAssertIntEquals (test, 0x0020, cerberus_protocol_unseal_hmac_length (req));
	CuAssertPtrEquals (test, &raw_buffer_req[101], cerberus_protocol_unseal_hmac (req));

	pmrs = cerberus_protocol_get_unseal_pmr_sealing (req);
	CuAssertPtrEquals (test, &raw_buffer_req[133], (uint8_t*) pmrs);
	CuAssertPtrEquals (test, &raw_buffer_req[133], (uint8_t*) pmrs->pmr[0]);
	CuAssertPtrEquals (test, &raw_buffer_req[197], (uint8_t*) pmrs->pmr[1]);
	CuAssertPtrEquals (test, &raw_buffer_req[261], (uint8_t*) pmrs->pmr[2]);
	CuAssertPtrEquals (test, &raw_buffer_req[325], (uint8_t*) pmrs->pmr[3]);
	CuAssertPtrEquals (test, &raw_buffer_req[389], (uint8_t*) pmrs->pmr[4]);

	raw_buffer_req[5] = 0x21;
	CuAssertIntEquals (test, 0x01, req->reserved);
	CuAssertIntEquals (test, 0x00, req->hmac_type);
	CuAssertIntEquals (test, 0x01, req->seed_type);

	raw_buffer_req[5] = 0x29;
	CuAssertIntEquals (test, 0x01, req->reserved);
	CuAssertIntEquals (test, 0x02, req->hmac_type);
	CuAssertIntEquals (test, 0x01, req->seed_type);

	raw_buffer_req[6] = 0x01;
	CuAssertIntEquals (test, 0x00, req->seed_params.rsa.reserved);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA1,
		req->seed_params.rsa.padding);
	CuAssertIntEquals (test, 0x00, req->seed_params.ecdh.reserved);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_ECDH_SHA256,
		req->seed_params.ecdh.processing);
	CuAssertIntEquals (test, 0x01, req->seed_params.raw);

	raw_buffer_req[6] = 0x11;
	CuAssertIntEquals (test, 0x02, req->seed_params.rsa.reserved);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA1,
		req->seed_params.rsa.padding);
	CuAssertIntEquals (test, 0x08, req->seed_params.ecdh.reserved);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_ECDH_SHA256,
		req->seed_params.ecdh.processing);
	CuAssertIntEquals (test, 0x11, req->seed_params.raw);

	raw_buffer_req[6] = 0x10;
	CuAssertIntEquals (test, 0x02, req->seed_params.rsa.reserved);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_RSA_PKCS15,
		req->seed_params.rsa.padding);
	CuAssertIntEquals (test, 0x08, req->seed_params.ecdh.reserved);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_ECDH_RAW, req->seed_params.ecdh.processing);
	CuAssertIntEquals (test, 0x10, req->seed_params.raw);
}

static void cerberus_protocol_optional_commands_test_message_unseal_result_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x8a
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0x8a,
		0x03,0x04,0x05,0x06,
		0x07,0x00,
		0x30,0x31,0x32,0x33,0x34,0x35,0x00
	};
	struct cerberus_protocol_message_unseal_result *req;
	struct cerberus_protocol_message_unseal_result_response *resp1;
	struct cerberus_protocol_message_unseal_result_completed_response *resp2;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_message_unseal_result));
	CuAssertIntEquals (test, 9, sizeof (struct cerberus_protocol_message_unseal_result_response));

	req = (struct cerberus_protocol_message_unseal_result*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT,
		req->header.command);

	resp1 = (struct cerberus_protocol_message_unseal_result_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp1->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp1->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp1->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp1->header.rq);
	CuAssertIntEquals (test, 0, resp1->header.reserved2);
	CuAssertIntEquals (test, 0, resp1->header.crypt);
	CuAssertIntEquals (test, 0x03, resp1->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT, resp1->header.command);

	CuAssertIntEquals (test, 0x06050403, resp1->unseal_status);

	resp2 = (struct cerberus_protocol_message_unseal_result_completed_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp2->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp2->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp2->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp2->header.rq);
	CuAssertIntEquals (test, 0, resp2->header.reserved2);
	CuAssertIntEquals (test, 0, resp2->header.crypt);
	CuAssertIntEquals (test, 0x03, resp2->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT, resp2->header.command);

	CuAssertIntEquals (test, 0x06050403, resp2->unseal_status);
	CuAssertIntEquals (test, 0x0007, resp2->key_length);
	CuAssertPtrEquals (test, &raw_buffer_resp[11], &resp2->key);
}

static void cerberus_protocol_optional_commands_test_key_exchange_type0_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x84,
		0x00,
		0x00,0x1,0x2,0x3
	};
	uint8_t raw_buffer_rsp[] = {
		0x7e,0x14,0x13,0x03,0x84,
		0x00,
		0x00,0x03,0x00,0x1,0x2,0x3,0x02,0x00,0xa,0xb,0x04,0x00,0xa1,0xb2,0xc3,0xd4
	};
	struct cerberus_protocol_key_exchange_type_0 *rq;
	struct cerberus_protocol_key_exchange_response_type_0 *rsp;

	TEST_START;

	rq = (struct cerberus_protocol_key_exchange_type_0*) raw_buffer_req;
	CuAssertIntEquals (test, 0, rq->common.header.integrity_check);
	CuAssertIntEquals (test, 0x7e, rq->common.header.msg_type);
	CuAssertIntEquals (test, 0x1314, rq->common.header.pci_vendor_id);
	CuAssertIntEquals (test, 0, rq->common.header.rq);
	CuAssertIntEquals (test, 0, rq->common.header.reserved2);
	CuAssertIntEquals (test, 0, rq->common.header.crypt);
	CuAssertIntEquals (test, 0x03, rq->common.header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, rq->common.header.command);

	CuAssertIntEquals (test, 0x00, rq->common.key_type);

	CuAssertIntEquals (test, 0x00, rq->hmac_type);

	CuAssertPtrEquals (test, &raw_buffer_req[7],
		cerberus_protocol_key_exchange_type_0_key_data (raw_buffer_req));

	rsp = (struct cerberus_protocol_key_exchange_response_type_0*) raw_buffer_rsp;
	CuAssertIntEquals (test, 0, rsp->common.header.integrity_check);
	CuAssertIntEquals (test, 0x7e, rsp->common.header.msg_type);
	CuAssertIntEquals (test, 0x1314, rsp->common.header.pci_vendor_id);
	CuAssertIntEquals (test, 0, rsp->common.header.rq);
	CuAssertIntEquals (test, 0, rsp->common.header.reserved2);
	CuAssertIntEquals (test, 0, rsp->common.header.crypt);
	CuAssertIntEquals (test, 0x03, rsp->common.header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, rsp->common.header.command);

	CuAssertIntEquals (test, 0x00, rsp->common.key_type);

	CuAssertIntEquals (test, 0x00, rsp->reserved);
	CuAssertIntEquals (test, 0x03, rsp->key_len);

	CuAssertPtrEquals (test, &raw_buffer_rsp[9],
		cerberus_protocol_key_exchange_type_0_response_key_data (rsp));

	CuAssertIntEquals (test, 0x02,
		cerberus_protocol_key_exchange_type_0_response_sig_len (rsp));

	CuAssertPtrEquals (test, &raw_buffer_rsp[14],
		cerberus_protocol_key_exchange_type_0_response_sig_data (rsp));

	CuAssertIntEquals (test, 0x04,
		cerberus_protocol_key_exchange_type_0_response_hmac_len (rsp));

	CuAssertPtrEquals (test, &raw_buffer_rsp[18],
		cerberus_protocol_key_exchange_type_0_response_hmac_data (rsp));
}

static void cerberus_protocol_optional_commands_test_key_exchange_type1_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x23,0x84,
		0x01,
		0xaa,0x00,0x1,0x2,0x3
	};
	uint8_t raw_buffer_rsp[] = {
		0x7e,0x14,0x13,0x23,0x84,
		0x01
	};
	struct cerberus_protocol_key_exchange_type_1 *rq;
	struct cerberus_protocol_key_exchange_response *rsp;

	TEST_START;

	rq = (struct cerberus_protocol_key_exchange_type_1*) raw_buffer_req;
	CuAssertIntEquals (test, 0, rq->common.header.integrity_check);
	CuAssertIntEquals (test, 0x7e, rq->common.header.msg_type);
	CuAssertIntEquals (test, 0x1314, rq->common.header.pci_vendor_id);
	CuAssertIntEquals (test, 0, rq->common.header.rq);
	CuAssertIntEquals (test, 0, rq->common.header.reserved2);
	CuAssertIntEquals (test, 1, rq->common.header.crypt);
	CuAssertIntEquals (test, 0x03, rq->common.header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, rq->common.header.command);

	CuAssertIntEquals (test, 0x01, rq->common.key_type);

	CuAssertIntEquals (test, 0xaa, rq->pairing_key_len);

	CuAssertPtrEquals (test, &raw_buffer_req[8],
		cerberus_protocol_key_exchange_type_1_hmac_data (rq));

	rsp = (struct cerberus_protocol_key_exchange_response*) raw_buffer_rsp;
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, rsp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, rsp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.reserved2);
	CuAssertIntEquals (test, 1, rsp->header.crypt);
	CuAssertIntEquals (test, 0x03, rsp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, rsp->header.command);

	CuAssertIntEquals (test, 0x01, rsp->key_type);
}

static void cerberus_protocol_optional_commands_test_key_exchange_type2_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x23,0x84,
		0x02,
		0x1,0x2,0x3
	};
	uint8_t raw_buffer_rsp[] = {
		0x7e,0x14,0x13,0x23,0x84,
		0x02
	};
	struct cerberus_protocol_key_exchange_type_2 *rq;
	struct cerberus_protocol_key_exchange_response *rsp;

	TEST_START;

	rq = (struct cerberus_protocol_key_exchange_type_2*) raw_buffer_req;
	CuAssertIntEquals (test, 0, rq->common.header.integrity_check);
	CuAssertIntEquals (test, 0x7e, rq->common.header.msg_type);
	CuAssertIntEquals (test, 0x1314, rq->common.header.pci_vendor_id);
	CuAssertIntEquals (test, 0, rq->common.header.rq);
	CuAssertIntEquals (test, 0, rq->common.header.reserved2);
	CuAssertIntEquals (test, 1, rq->common.header.crypt);
	CuAssertIntEquals (test, 0x03, rq->common.header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, rq->common.header.command);

	CuAssertIntEquals (test, 0x02, rq->common.key_type);

	CuAssertPtrEquals (test, &raw_buffer_req[6],
		cerberus_protocol_key_exchange_type_2_hmac_data (rq));

	rsp = (struct cerberus_protocol_key_exchange_response*) raw_buffer_rsp;
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, rsp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, rsp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.reserved2);
	CuAssertIntEquals (test, 1, rsp->header.crypt);
	CuAssertIntEquals (test, 0x03, rsp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXCHANGE_KEYS, rsp->header.command);

	CuAssertIntEquals (test, 0x02, rsp->key_type);
}

static void cerberus_protocol_optional_commands_test_session_sync_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0x85,
		0x00,0x1,0x2,0x3
	};
	uint8_t raw_buffer_rsp[] = {
		0x7e,0x14,0x13,0x03,0x85,
		0x00,0x03,0x00,0x1,0x2,0x3,0x02,0x00,0xa,0xb,0x04,0x00,0xa1,0xb2,0xc3,0xd4
	};
	struct cerberus_protocol_session_sync *rq;
	struct cerberus_protocol_session_sync_response *rsp;

	TEST_START;

	rq = (struct cerberus_protocol_session_sync*) raw_buffer_req;
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, rq->header.msg_type);
	CuAssertIntEquals (test, 0x1314, rq->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, rq->header.rq);
	CuAssertIntEquals (test, 0, rq->header.reserved2);
	CuAssertIntEquals (test, 0, rq->header.crypt);
	CuAssertIntEquals (test, 0x03, rq->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_SESSION_SYNC, rq->header.command);

	CuAssertIntEquals (test, 0x03020100, rq->rn_req);

	rsp = (struct cerberus_protocol_session_sync_response*) raw_buffer_rsp;
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, rsp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, rsp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.reserved2);
	CuAssertIntEquals (test, 0, rsp->header.crypt);
	CuAssertIntEquals (test, 0x03, rsp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_SESSION_SYNC, rsp->header.command);

	CuAssertPtrEquals (test, &raw_buffer_rsp[5], cerberus_protocol_session_sync_hmac_data (rsp));
}


TEST_SUITE_START (cerberus_protocol_optional_commands);

TEST (cerberus_protocol_optional_commands_test_prepare_pfm_update_format);
TEST (cerberus_protocol_optional_commands_test_pfm_update_format);
TEST (cerberus_protocol_optional_commands_test_complete_pfm_update_format);
TEST (cerberus_protocol_optional_commands_test_get_pfm_id_format);
TEST (cerberus_protocol_optional_commands_test_get_pfm_supported_fw_format);
TEST (cerberus_protocol_optional_commands_test_prepare_recovery_image_update_format);
TEST (cerberus_protocol_optional_commands_test_recovery_image_update_format);
TEST (cerberus_protocol_optional_commands_test_complete_recovery_image_update_format);
TEST (cerberus_protocol_optional_commands_test_get_recovery_image_id_format);
TEST (cerberus_protocol_optional_commands_test_get_host_state_format);
TEST (cerberus_protocol_optional_commands_test_pmr_format);
TEST (cerberus_protocol_optional_commands_test_update_pmr_format);
TEST (cerberus_protocol_optional_commands_test_key_exchange_format);
TEST (cerberus_protocol_optional_commands_test_get_log_info_format);
TEST (cerberus_protocol_optional_commands_test_get_log_format);
TEST (cerberus_protocol_optional_commands_test_clear_log_format);
TEST (cerberus_protocol_optional_commands_test_get_attestation_data_format);
TEST (cerberus_protocol_optional_commands_test_prepare_fw_update_format);
TEST (cerberus_protocol_optional_commands_test_fw_update_format);
TEST (cerberus_protocol_optional_commands_test_complete_fw_update_format);
TEST (cerberus_protocol_optional_commands_test_reset_config_format);
TEST (cerberus_protocol_optional_commands_test_recover_firmware_format);
TEST (cerberus_protocol_optional_commands_test_message_unseal_format);
TEST (cerberus_protocol_optional_commands_test_message_unseal_result_format);
TEST (cerberus_protocol_optional_commands_test_key_exchange_type0_format);
TEST (cerberus_protocol_optional_commands_test_key_exchange_type1_format);
TEST (cerberus_protocol_optional_commands_test_key_exchange_type2_format);
TEST (cerberus_protocol_optional_commands_test_session_sync_format);

TEST_SUITE_END;
