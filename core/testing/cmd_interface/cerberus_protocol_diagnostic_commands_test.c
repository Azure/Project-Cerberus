// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_diagnostic_commands.h"
#include "cmd_interface/cmd_device.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/cmd_interface/cerberus_protocol_diagnostic_commands_testing.h"


TEST_SUITE_LABEL ("cerberus_protocol_diagnostic_commands");


void cerberus_protocol_diagnostic_commands_testing_process_heap_stats (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_heap_stats *req = (struct cerberus_protocol_heap_stats*) data;
	struct cerberus_protocol_heap_stats_response *resp =
		(struct cerberus_protocol_heap_stats_response*) data;
	int status;
	struct cmd_device_heap_stats heap = {
		.total = 0x12345678,
		.free = 0x1122,
		.min_free = 0x33,
		.free_blocks = 0xabcd,
		.max_block = 0xef,
		.min_block = 0x44
	};

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_DIAG_HEAP_USAGE;

	request.length = sizeof (struct cerberus_protocol_heap_stats);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&device->mock, device->base.get_heap_stats, device, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&device->mock, 0, &heap, sizeof (heap), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_heap_stats_response), request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DIAG_HEAP_USAGE, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertIntEquals (test, heap.total, resp->heap.total);
	CuAssertIntEquals (test, heap.free, resp->heap.free);
	CuAssertIntEquals (test, heap.min_free, resp->heap.min_free);
	CuAssertIntEquals (test, heap.free_blocks, resp->heap.free_blocks);
	CuAssertIntEquals (test, heap.max_block, resp->heap.max_block);
	CuAssertIntEquals (test, heap.min_block, resp->heap.min_block);

	status = mock_validate (&device->mock);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_diagnostic_commands_testing_process_heap_stats_invalid_len (CuTest *test,
	struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_heap_stats *req = (struct cerberus_protocol_heap_stats*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_DIAG_HEAP_USAGE;

	request.length = sizeof (struct cerberus_protocol_heap_stats) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	/* Length - 1 is less than minimum message length. */
}

void cerberus_protocol_diagnostic_commands_testing_process_heap_stats_fail (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_heap_stats *req = (struct cerberus_protocol_heap_stats*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_DIAG_HEAP_USAGE;

	request.length = sizeof (struct cerberus_protocol_heap_stats);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&device->mock, device->base.get_heap_stats, device,
		CMD_DEVICE_HEAP_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_DEVICE_HEAP_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = mock_validate (&device->mock);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void cerberus_protocol_diagnostic_commands_test_heap_stats_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x14,0x13,0x03,0xd0
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x14,0x13,0x03,0xd0,
		0x01,0x02,0x03,0x04,
		0x05,0x06,0x07,0x08,
		0x09,0x0a,0x0b,0x0c,
		0x0d,0x0e,0x0f,0x10,
		0x11,0x12,0x13,0x14,
		0x15,0x16,0x17,0x18
	};
	struct cerberus_protocol_heap_stats *req;
	struct cerberus_protocol_heap_stats_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_heap_stats));

	req = (struct cerberus_protocol_heap_stats*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DIAG_HEAP_USAGE, req->header.command);

	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct cerberus_protocol_heap_stats_response));

	resp = (struct cerberus_protocol_heap_stats_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DIAG_HEAP_USAGE, resp->header.command);

	CuAssertIntEquals (test, 0x04030201, resp->heap.total);
	CuAssertIntEquals (test, 0x08070605, resp->heap.free);
	CuAssertIntEquals (test, 0x0c0b0a09, resp->heap.min_free);
	CuAssertIntEquals (test, 0x100f0e0d, resp->heap.free_blocks);
	CuAssertIntEquals (test, 0x14131211, resp->heap.max_block);
	CuAssertIntEquals (test, 0x18171615, resp->heap.min_block);
}


TEST_SUITE_START (cerberus_protocol_diagnostic_commands);

TEST (cerberus_protocol_diagnostic_commands_test_heap_stats_format);

TEST_SUITE_END;
