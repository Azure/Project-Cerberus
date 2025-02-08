// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_diagnostic_commands.h"
#include "cmd_interface/cmd_device.h"
#include "testing/cmd_interface/cerberus_protocol_diagnostic_commands_testing.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"


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

void cerberus_protocol_diagnostic_commands_testing_process_stack_stats (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_stack_stats *req = (struct cerberus_protocol_stack_stats*) data;
	struct cerberus_protocol_stack_stats_response *resp =
		(struct cerberus_protocol_stack_stats_response*) data;
	int status;
	uint32_t task_offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_stack_stats_response);
	char buffer[256] = {
		0x02, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00,
		0x06, 0x00, 0x00, 0x00,
		// task1
		0x74, 0x61, 0x73, 0x6b, 0x31, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x06, 0x00, 0x00, 0x00,
		// task2
		0x74, 0x61, 0x73, 0x6b, 0x32, 0x00
	};
	struct cmd_device_stack_stats *stack_stats = (struct cmd_device_stack_stats*) buffer;
	struct cmd_device_task_stack_stats *task_stack_stats;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_DIAG_STACK_USAGE;
	req->task_offset = 0;

	request.length = sizeof (struct cerberus_protocol_stack_stats);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&device->mock, device->base.get_stack_stats, device,
		sizeof (struct cmd_device_stack_stats) +
		2 * sizeof (struct cmd_device_task_stack_stats) + 12, MOCK_ARG (task_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (max));
	status |= mock_expect_output (&device->mock, 1, stack_stats, sizeof (buffer), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, cerberus_protocol_get_stack_stats_response_length (32),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DIAG_STACK_USAGE, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertIntEquals (test, 2, stack_stats->num_tasks);

	task_stack_stats = (struct cmd_device_task_stack_stats*) &stack_stats->task_stack_stats;

	CuAssertIntEquals (test, 0x200, task_stack_stats->min_free_stack);
	CuAssertIntEquals (test, 6, task_stack_stats->task_name_len);
	CuAssertStrEquals (test, "task1", (char*) task_stack_stats->task_name);

	task_stack_stats = (struct cmd_device_task_stack_stats*) ((uint8_t*) task_stack_stats +
		task_stack_stats->task_name_len);
	task_stack_stats++;

	CuAssertIntEquals (test, 0x100, task_stack_stats->min_free_stack);
	CuAssertIntEquals (test, 6, task_stack_stats->task_name_len);
	CuAssertStrEquals (test, "task2", task_stack_stats->task_name);

	status = mock_validate (&device->mock);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_diagnostic_commands_testing_process_stack_stats_non_zero_offset (
	CuTest *test, struct cmd_interface *cmd, struct cmd_device_mock *device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_stack_stats *req = (struct cerberus_protocol_stack_stats*) data;
	struct cerberus_protocol_stack_stats_response *resp =
		(struct cerberus_protocol_stack_stats_response*) data;
	int status;
	uint32_t task_offset = 1;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_stack_stats_response);
	char buffer[256] = {
		0x02, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00,
		0x06, 0x00, 0x00, 0x00,
		// task1
		0x74, 0x61, 0x73, 0x6b, 0x31, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x06, 0x00, 0x00, 0x00,
		// task2
		0x74, 0x61, 0x73, 0x6b, 0x32, 0x00
	};
	struct cmd_device_stack_stats *stack_stats = (struct cmd_device_stack_stats*) buffer;
	struct cmd_device_task_stack_stats *task_stack_stats;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_DIAG_STACK_USAGE;
	req->task_offset = 1;

	request.length = sizeof (struct cerberus_protocol_stack_stats);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&device->mock, device->base.get_stack_stats, device,
		sizeof (struct cmd_device_stack_stats) +
		sizeof (struct cmd_device_task_stack_stats) + 6, MOCK_ARG (task_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (max));
	status |= mock_expect_output (&device->mock, 1, stack_stats, sizeof (buffer), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, cerberus_protocol_get_stack_stats_response_length (18),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DIAG_STACK_USAGE, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	CuAssertIntEquals (test, 2, stack_stats->num_tasks);

	task_stack_stats = (struct cmd_device_task_stack_stats*) &stack_stats->task_stack_stats;

	CuAssertIntEquals (test, 0x200, task_stack_stats->min_free_stack);
	CuAssertIntEquals (test, 6, task_stack_stats->task_name_len);
	CuAssertStrEquals (test, "task1", (char*) task_stack_stats->task_name);

	task_stack_stats = (struct cmd_device_task_stack_stats*) ((uint8_t*) task_stack_stats +
		task_stack_stats->task_name_len);
	task_stack_stats++;

	CuAssertIntEquals (test, 0x100, task_stack_stats->min_free_stack);
	CuAssertIntEquals (test, 6, task_stack_stats->task_name_len);
	CuAssertStrEquals (test, "task2", task_stack_stats->task_name);

	status = mock_validate (&device->mock);
	CuAssertIntEquals (test, 0, status);
}

void cerberus_protocol_diagnostic_commands_testing_process_stack_stats_invalid_len (
	CuTest *test, struct cmd_interface *cmd)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_stack_stats *req = (struct cerberus_protocol_stack_stats*) data;
	int status;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_DIAG_STACK_USAGE;

	request.length = sizeof (struct cerberus_protocol_stack_stats) + 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	/* Length - 1 is less than minimum message length. */
}

void cerberus_protocol_diagnostic_commands_testing_process_stack_stats_fail (CuTest *test,
	struct cmd_interface *cmd, struct cmd_device_mock *device)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_stack_stats *req = (struct cerberus_protocol_stack_stats*) data;
	int status;
	uint32_t task_offset = 0;
	size_t max = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		sizeof (struct cerberus_protocol_stack_stats_response);

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_DIAG_STACK_USAGE;

	request.length = sizeof (struct cerberus_protocol_stack_stats);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&device->mock, device->base.get_stack_stats, device,
		CMD_DEVICE_STACK_FAILED, MOCK_ARG (task_offset), MOCK_ARG_NOT_NULL, MOCK_ARG (max));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd->process_request (cmd, &request);
	CuAssertIntEquals (test, CMD_DEVICE_STACK_FAILED, status);
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
		0x7e, 0x14, 0x13, 0x03, 0xd0
	};
	uint8_t raw_buffer_resp[] = {
		0x7e, 0x14, 0x13, 0x03, 0xd0,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c,
		0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18
	};
	struct cerberus_protocol_heap_stats *req;
	struct cerberus_protocol_heap_stats_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct cerberus_protocol_heap_stats));

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

static void cerberus_protocol_diagnostic_commands_test_stack_stats_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e, 0x14, 0x13, 0x03, 0xd1,
		0x02, 0x00, 0x00, 0x00
	};
	uint8_t raw_buffer_resp[] = {
		0x7e, 0x14, 0x13, 0x03, 0xd1,
		0x02, 0x00, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00,
		0x06, 0x00, 0x00, 0x00,
		// task1
		0x74, 0x61, 0x73, 0x6b, 0x31, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x07, 0x00, 0x00, 0x00,
		// task2
		0x74, 0x61, 0x73, 0x6b, 0x31, 0x31, 0x00
	};
	uint8_t raw_expected_task1_name[] = {0x74, 0x61, 0x73, 0x6b, 0x31, 0x00};
	uint8_t raw_expected_task2_name[] = {0x74, 0x61, 0x73, 0x6b, 0x31, 0x31, 0x00};

	struct cerberus_protocol_stack_stats *req;
	struct cerberus_protocol_stack_stats_response *resp;
	struct cmd_device_task_stack_stats *task_stack_stats;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct cerberus_protocol_stack_stats));

	req = (struct cerberus_protocol_stack_stats*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0x1314, req->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.reserved2);
	CuAssertIntEquals (test, 0, req->header.crypt);
	CuAssertIntEquals (test, 0x03, req->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DIAG_STACK_USAGE, req->header.command);

	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		cerberus_protocol_get_stack_stats_response_length (29));

	resp = (struct cerberus_protocol_stack_stats_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0x1314, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.crypt);
	CuAssertIntEquals (test, 0x03, resp->header.reserved1);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DIAG_STACK_USAGE, resp->header.command);

	CuAssertIntEquals (test, 2, resp->stack_stats.num_tasks);

	task_stack_stats = (struct cmd_device_task_stack_stats*) &resp->stack_stats.task_stack_stats;

	CuAssertIntEquals (test, 0x00000200, task_stack_stats->min_free_stack);
	CuAssertIntEquals (test, 0x00000006, task_stack_stats->task_name_len);
	testing_validate_array (raw_expected_task1_name, task_stack_stats->task_name,
		sizeof (raw_expected_task1_name));

	task_stack_stats = (struct cmd_device_task_stack_stats*) ((uint8_t*) task_stack_stats +
		task_stack_stats->task_name_len);
	task_stack_stats++;

	CuAssertIntEquals (test, 0x00000100, task_stack_stats->min_free_stack);
	CuAssertIntEquals (test, 0x00000007, task_stack_stats->task_name_len);
	testing_validate_array (raw_expected_task2_name, task_stack_stats->task_name,
		sizeof (raw_expected_task2_name));
}


// *INDENT-OFF*
TEST_SUITE_START (cerberus_protocol_diagnostic_commands);

TEST (cerberus_protocol_diagnostic_commands_test_heap_stats_format);
TEST (cerberus_protocol_diagnostic_commands_test_stack_stats_format);

TEST_SUITE_END;
// *INDENT-ON*
