// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_control_protocol_commands.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"


TEST_SUITE_LABEL ("mctp_control_protocol_commands");


/*******************
 * Test cases
 *******************/

static void mctp_control_protocol_commands_test_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x7e,0xf5,0xaa
	};
	struct mctp_control_protocol_header *header;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct mctp_control_protocol_header));

	header = (struct mctp_control_protocol_header*) raw_buffer;
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0x7e, header->msg_type);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 1, header->d_bit);
	CuAssertIntEquals (test, 1, header->rsvd);
	CuAssertIntEquals (test, 0x15, header->instance_id);
	CuAssertIntEquals (test, 0xaa, header->command_code);

	raw_buffer[0] = 0xfe;
	CuAssertIntEquals (test, 1, header->integrity_check);
	CuAssertIntEquals (test, 0x7e, header->msg_type);

	raw_buffer[1] = 0x75;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->d_bit);
	CuAssertIntEquals (test, 1, header->rsvd);
	CuAssertIntEquals (test, 0x15, header->instance_id);

	raw_buffer[1] = 0x35;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 1, header->rsvd);
	CuAssertIntEquals (test, 0x15, header->instance_id);

	raw_buffer[1] = 0x15;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0x15, header->instance_id);
}

static void mctp_control_protocol_commands_test_set_eid_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x03,0x01,
		0x12,0x34
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x03,0x01,
		0x11,0xe1,0x33,0x44
	};
	struct mctp_control_set_eid *req;
	struct mctp_control_set_eid_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct mctp_control_set_eid));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct mctp_control_set_eid_response));

	req = (struct mctp_control_set_eid*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.d_bit);
	CuAssertIntEquals (test, 0, req->header.rsvd);
	CuAssertIntEquals (test, 0x03, req->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SET_EID, req->header.command_code);

	CuAssertIntEquals (test, 0x04, req->reserved);
	CuAssertIntEquals (test, 0x02, req->operation);
	CuAssertIntEquals (test, 0x34, req->eid);

	resp = (struct mctp_control_set_eid_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.d_bit);
	CuAssertIntEquals (test, 0, resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SET_EID, resp->header.command_code);

	CuAssertIntEquals (test, 0x11, resp->completion_code);
	CuAssertIntEquals (test, 0x03, resp->reserved2);
	CuAssertIntEquals (test, 0x02, resp->eid_assignment_status);
	CuAssertIntEquals (test, 0x00, resp->reserved1);
	CuAssertIntEquals (test, 0x01, resp->eid_allocation_status);
	CuAssertIntEquals (test, 0x33, resp->eid_setting);
	CuAssertIntEquals (test, 0x44, resp->eid_pool_size);
}

static void mctp_control_protocol_commands_test_get_eid_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x03,0x02
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x03,0x02,
		0x11,0xBB,0x9C,0xCC
	};
	struct mctp_control_get_eid *req;
	struct mctp_control_get_eid_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct mctp_control_get_eid));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct mctp_control_get_eid_response));

	req = (struct mctp_control_get_eid*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.d_bit);
	CuAssertIntEquals (test, 0, req->header.rsvd);
	CuAssertIntEquals (test, 0x03, req->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_EID, req->header.command_code);

	resp = (struct mctp_control_get_eid_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.d_bit);
	CuAssertIntEquals (test, 0, resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_EID, resp->header.command_code);

	CuAssertIntEquals (test, 0x11, resp->completion_code);
	CuAssertIntEquals (test, 0xBB, resp->eid);
	CuAssertIntEquals (test, 0, resp->eid_type);
	CuAssertIntEquals (test, 3, resp->reserved);
	CuAssertIntEquals (test, 1, resp->endpoint_type);
	CuAssertIntEquals (test, 2, resp->reserved2);
	CuAssertIntEquals (test, 0xCC, resp->medium_specific_info);
}

static void mctp_control_protocol_commands_test_get_mctp_version_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x03,0x04,
		0x01
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x03,0x04,
		0x11,0x02,
		0xDD,0xCC,0xBB,0xAA,
		0xFF,0xEE,0x22,0x11
	};
	struct mctp_control_get_mctp_version *req;
	struct mctp_control_get_mctp_version_response *resp;
	struct mctp_control_mctp_version_number_entry* entry;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct mctp_control_get_mctp_version));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		mctp_control_get_mctp_version_response_length (2));

	req = (struct mctp_control_get_mctp_version*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.d_bit);
	CuAssertIntEquals (test, 0, req->header.rsvd);
	CuAssertIntEquals (test, 0x03, req->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION, req->header.command_code);

	CuAssertIntEquals (test, 0x01, req->message_type_num);

	resp = (struct mctp_control_get_mctp_version_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.d_bit);
	CuAssertIntEquals (test, 0, resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION, resp->header.command_code);

	CuAssertIntEquals (test, 0x11, resp->completion_code);
	CuAssertIntEquals (test, 0x02, resp->version_num_entry_count);

	entry = mctp_control_get_mctp_version_response_get_entries (resp);

	CuAssertIntEquals (test, 0xAA, entry->major);
	CuAssertIntEquals (test, 0xBB, entry->minor);
	CuAssertIntEquals (test, 0xCC, entry->update);
	CuAssertIntEquals (test, 0xDD, entry->alpha);

	++entry;

	CuAssertIntEquals (test, 0x11, entry->major);
	CuAssertIntEquals (test, 0x22, entry->minor);
	CuAssertIntEquals (test, 0xEE, entry->update);
	CuAssertIntEquals (test, 0xFF, entry->alpha);
}

static void mctp_control_protocol_commands_test_get_message_type_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x03,0x05
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x03,0x05,
		0x11,0x02,
		0xAA,0xBB
	};
	struct mctp_control_get_message_type *req;
	struct mctp_control_get_message_type_response *resp;
	uint8_t *entry;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct mctp_control_get_message_type));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		mctp_control_get_message_type_response_length (2));

	req = (struct mctp_control_get_message_type*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.d_bit);
	CuAssertIntEquals (test, 0, req->header.rsvd);
	CuAssertIntEquals (test, 0x03, req->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE, req->header.command_code);

	resp = (struct mctp_control_get_message_type_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.d_bit);
	CuAssertIntEquals (test, 0, resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE, resp->header.command_code);

	CuAssertIntEquals (test, 0x11, resp->completion_code);
	CuAssertIntEquals (test, 0x02, resp->message_type_count);

	entry = mctp_control_get_message_type_response_get_entries (resp);

	CuAssertIntEquals (test, 0xAA, entry[0]);
	CuAssertIntEquals (test, 0xBB, entry[1]);
}

static void mctp_control_protocol_commands_test_get_vendor_def_msg_support_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x03,0x06,
		0x12
	};
	uint8_t raw_buffer_pci_resp[] = {
		0x7e,0x03,0x06,
		0x11,0x22,0x00,0x44,0x55,0x66,0x77
	};
	uint8_t raw_buffer_iana_resp[] = {
		0x7e,0x03,0x06,
		0x11,0x22,0x01,0xAA,0xBB,0x44,0x55,0x66,0x77
	};
	struct mctp_control_get_vendor_def_msg_support *req;
	struct mctp_control_get_vendor_def_msg_support_pci_response *pci_resp;
	struct mctp_control_get_vendor_def_msg_support_iana_response *iana_resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct mctp_control_get_vendor_def_msg_support));
	CuAssertIntEquals (test, sizeof (raw_buffer_pci_resp),
		sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response));
	CuAssertIntEquals (test, sizeof (raw_buffer_iana_resp),
		sizeof (struct mctp_control_get_vendor_def_msg_support_iana_response));

	req = (struct mctp_control_get_vendor_def_msg_support*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.d_bit);
	CuAssertIntEquals (test, 0, req->header.rsvd);
	CuAssertIntEquals (test, 0x03, req->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT,
		req->header.command_code);

	CuAssertIntEquals (test, 0x12, req->vid_set_selector);

	pci_resp = (struct mctp_control_get_vendor_def_msg_support_pci_response*) raw_buffer_pci_resp;
	CuAssertIntEquals (test, 0, pci_resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, pci_resp->header.msg_type);
	CuAssertIntEquals (test, 0, pci_resp->header.rq);
	CuAssertIntEquals (test, 0, pci_resp->header.d_bit);
	CuAssertIntEquals (test, 0, pci_resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, pci_resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT,
		pci_resp->header.command_code);

	CuAssertIntEquals (test, 0x11, pci_resp->completion_code);
	CuAssertIntEquals (test, 0x22, pci_resp->vid_set_selector);
	CuAssertIntEquals (test, 0x00, pci_resp->vid_format);
	CuAssertIntEquals (test, 0x5544, pci_resp->vid);
	CuAssertIntEquals (test, 0x7766, pci_resp->protocol_version);

	iana_resp =
		(struct mctp_control_get_vendor_def_msg_support_iana_response*) raw_buffer_iana_resp;
	CuAssertIntEquals (test, 0, iana_resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, iana_resp->header.msg_type);
	CuAssertIntEquals (test, 0, iana_resp->header.rq);
	CuAssertIntEquals (test, 0, iana_resp->header.d_bit);
	CuAssertIntEquals (test, 0, iana_resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, iana_resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT,
		iana_resp->header.command_code);

	CuAssertIntEquals (test, 0x11, iana_resp->completion_code);
	CuAssertIntEquals (test, 0x22, iana_resp->vid_set_selector);
	CuAssertIntEquals (test, 0x01, iana_resp->vid_format);
	CuAssertIntEquals (test, 0x5544BBAA, iana_resp->vid);
	CuAssertIntEquals (test, 0x7766, iana_resp->protocol_version);
}

static void mctp_control_protocol_commands_test_get_routing_table_entries_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x03,0x0A,
		0x12
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x03,0x0A,
		0x11,0x22,2,
		0x02,0xAA,0xB5,0x55,0x66,0x77,0x88,
		0x03,0xFF,0xCA,0x11,0x22,0x33,0x44,
	};
	struct mctp_control_get_routing_table_entries *req;
	struct mctp_control_get_routing_table_entries_response *resp;
	struct mctp_control_routing_table_entry *entry;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct mctp_control_get_routing_table_entries));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		mctp_control_get_routing_table_entries_response_length (2));

	req = (struct mctp_control_get_routing_table_entries*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.d_bit);
	CuAssertIntEquals (test, 0, req->header.rsvd);
	CuAssertIntEquals (test, 0x03, req->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES,
		req->header.command_code);

	CuAssertIntEquals (test, 0x12, req->entry_handle);

	resp = (struct mctp_control_get_routing_table_entries_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.d_bit);
	CuAssertIntEquals (test, 0, resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES,
		resp->header.command_code);

	CuAssertIntEquals (test, 0x11, resp->completion_code);
	CuAssertIntEquals (test, 0x22, resp->next_entry_handle);
	CuAssertIntEquals (test, 0x02, resp->num_entries);

	entry = mctp_control_get_routing_table_entries_response_get_entries (resp);

	CuAssertIntEquals (test, 0x02, entry->eid_range_size);
	CuAssertIntEquals (test, 0xAA, entry->starting_eid);
	CuAssertIntEquals (test, 0x15, entry->port_number);
	CuAssertIntEquals (test, 0x01, entry->eid_assignment_type);
	CuAssertIntEquals (test, 0x02, entry->entry_type);
	CuAssertIntEquals (test, 0x55, entry->binding_type_id);
	CuAssertIntEquals (test, 0x66, entry->media_type_id);
	CuAssertIntEquals (test, 0x77, entry->address_size);
	CuAssertIntEquals (test, 0x88, entry->address);

	++entry;

	CuAssertIntEquals (test, 0x03, entry->eid_range_size);
	CuAssertIntEquals (test, 0xFF, entry->starting_eid);
	CuAssertIntEquals (test, 0x0A, entry->port_number);
	CuAssertIntEquals (test, 0x00, entry->eid_assignment_type);
	CuAssertIntEquals (test, 0x03, entry->entry_type);
	CuAssertIntEquals (test, 0x11, entry->binding_type_id);
	CuAssertIntEquals (test, 0x22, entry->media_type_id);
	CuAssertIntEquals (test, 0x33, entry->address_size);
	CuAssertIntEquals (test, 0x44, entry->address);
}

static void mctp_control_protocol_commands_test_process_set_eid (CuTest *test)
{
	struct device_manager device_manager;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->reserved = 0;
	rq->operation = MCTP_CONTROL_SET_EID_OPERATION_SET_ID;
	rq->eid = 0xBB;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = 0xAA;
	request.source_addr = 0x20;
	request.target_eid = MCTP_BASE_PROTOCOL_NULL_EID;

	status = device_manager_init (&device_manager, 2, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_BMC_EID, 0x10);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_set_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_set_eid_response), request.length);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 0, response->reserved1);
	CuAssertIntEquals (test, 0, response->eid_assignment_status);
	CuAssertIntEquals (test, 0, response->reserved2);
	CuAssertIntEquals (test, 0, response->eid_allocation_status);
	CuAssertIntEquals (test, 0xBB, response->eid_setting);
	CuAssertIntEquals (test, 0, response->eid_pool_size);
	CuAssertIntEquals (test, 0xBB, device_manager_get_device_eid (&device_manager,
		DEVICE_MANAGER_SELF_DEVICE_NUM));
	CuAssertIntEquals (test, 0xAA, device_manager_get_device_eid (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM));
	CuAssertIntEquals (test, 0x20, device_manager_get_device_addr (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM));

	device_manager_release (&device_manager);
}

static void mctp_control_protocol_commands_test_process_set_eid_force (CuTest *test)
{
	struct device_manager device_manager;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->reserved = 0;
	rq->operation = MCTP_CONTROL_SET_EID_OPERATION_FORCE_ID;
	rq->eid = 0xBB;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = 0xAA;
	request.source_addr = 0x20;
	request.target_eid = MCTP_BASE_PROTOCOL_NULL_EID;

	status = device_manager_init (&device_manager, 2, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_BMC_EID, 0x10);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_set_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_set_eid_response), request.length);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 0, response->reserved1);
	CuAssertIntEquals (test, 0, response->eid_assignment_status);
	CuAssertIntEquals (test, 0, response->reserved2);
	CuAssertIntEquals (test, 0, response->eid_allocation_status);
	CuAssertIntEquals (test, 0xBB, response->eid_setting);
	CuAssertIntEquals (test, 0, response->eid_pool_size);
	CuAssertIntEquals (test, 0xBB, device_manager_get_device_eid (&device_manager,
		DEVICE_MANAGER_SELF_DEVICE_NUM));
	CuAssertIntEquals (test, 0xAA, device_manager_get_device_eid (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM));
	CuAssertIntEquals (test, 0x20, device_manager_get_device_addr (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM));

	device_manager_release (&device_manager);
}

static void mctp_control_protocol_commands_test_process_set_eid_null (CuTest *test)
{
	struct device_manager device_manager;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->reserved = 0;
	rq->operation = MCTP_CONTROL_SET_EID_OPERATION_SET_ID;
	rq->eid = 0xBB;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_NULL_EID;

	status = device_manager_init (&device_manager, 2, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_BMC_EID, 0x10);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_set_eid (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	status = mctp_control_protocol_set_eid (&device_manager, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	device_manager_release (&device_manager);
}

static void mctp_control_protocol_commands_test_process_set_eid_invalid_len (CuTest *test)
{
	struct device_manager device_manager;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_set_eid) + 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init (&device_manager, 2, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_BMC_EID, 0x10);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_set_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	response->completion_code = 0;
	request.length = sizeof (struct mctp_control_set_eid) - 1;

	status = mctp_control_protocol_set_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	device_manager_release (&device_manager);
}

static void mctp_control_protocol_commands_test_process_set_eid_invalid_data (CuTest *test)
{
	struct device_manager device_manager;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = MCTP_BASE_PROTOCOL_NULL_EID;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init (&device_manager, 2, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_BMC_EID, 0x10);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_set_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	rq->header.rq = 1;
	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = MCTP_BASE_PROTOCOL_BROADCAST_EID;
	request.length = sizeof (struct mctp_control_set_eid);

	status = mctp_control_protocol_set_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	rq->header.rq = 1;
	rq->reserved = 0;
	rq->operation = 2;
	rq->eid = 0xAA;
	request.length = sizeof (struct mctp_control_set_eid);

	status = mctp_control_protocol_set_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	rq->header.rq = 1;
	rq->reserved = 1;
	rq->operation = 0;
	rq->eid = 0xAA;
	request.length = sizeof (struct mctp_control_set_eid);

	status = mctp_control_protocol_set_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	device_manager_release (&device_manager);
}

static void mctp_control_protocol_commands_test_process_get_eid (CuTest *test)
{
	struct device_manager device_manager;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_eid *rq = (struct mctp_control_get_eid*) data;
	struct mctp_control_get_eid_response *response = (struct mctp_control_get_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_eid);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init (&device_manager, 1, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_get_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_eid_response), request.length);
	CuAssertIntEquals (test, 2, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response->eid);
	CuAssertIntEquals (test, 1, response->eid_type);
	CuAssertIntEquals (test, 0, response->reserved);
	CuAssertIntEquals (test, 0, response->endpoint_type);
	CuAssertIntEquals (test, 0, response->reserved2);
	CuAssertIntEquals (test, 0, response->medium_specific_info);

	device_manager_release (&device_manager);
}

static void mctp_control_protocol_commands_test_process_get_eid_null (CuTest *test)
{
	struct device_manager device_manager;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_eid *rq = (struct mctp_control_get_eid*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_eid);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init (&device_manager, 1, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_get_eid (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	status = mctp_control_protocol_get_eid (&device_manager, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	device_manager_release (&device_manager);
}

static void mctp_control_protocol_commands_test_process_get_eid_invalid_len (CuTest *test)
{
	struct device_manager device_manager;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_eid *rq = (struct mctp_control_get_eid*) data;
	struct mctp_control_get_eid_response *response = (struct mctp_control_get_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_eid) + 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init (&device_manager, 2, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_get_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 2, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);

	request.length = sizeof (struct mctp_control_get_eid) - 1;
	response->completion_code = 0;

	status = mctp_control_protocol_get_eid (&device_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 2, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);

	device_manager_release (&device_manager);
}

static void mctp_control_protocol_commands_test_process_get_mctp_version_support_mctp_base_protocol (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_mctp_version *rq = (struct mctp_control_get_mctp_version*) data;
	struct mctp_control_get_mctp_version_response *response =
		(struct mctp_control_get_mctp_version_response*) data;
	struct mctp_control_mctp_version_number_entry *entry =
		mctp_control_get_mctp_version_response_get_entries (response);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->message_type_num = 0xFF;

	request.length = sizeof (struct mctp_control_get_mctp_version);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_mctp_version_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, mctp_control_get_mctp_version_response_length (1), request.length);
	CuAssertIntEquals (test, 4, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 1, response->version_num_entry_count);
	CuAssertIntEquals (test,
		MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | MCTP_BASE_PROTOCOL_MAJOR_VERSION,
		entry->major);
	CuAssertIntEquals (test,
		MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | MCTP_BASE_PROTOCOL_MINOR_VERSION,
		entry->minor);
	CuAssertIntEquals (test,
		MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | MCTP_BASE_PROTOCOL_UPDATE_VERSION,
		entry->update);
	CuAssertIntEquals (test, 0, entry->alpha);
}

static void mctp_control_protocol_commands_test_process_get_mctp_version_support_mctp_ctrl_protocol (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_mctp_version *rq = (struct mctp_control_get_mctp_version*) data;
	struct mctp_control_get_mctp_version_response *response =
		(struct mctp_control_get_mctp_version_response*) data;
	struct mctp_control_mctp_version_number_entry *entry =
		mctp_control_get_mctp_version_response_get_entries (response);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->message_type_num = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;

	request.length = sizeof (struct mctp_control_get_mctp_version);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_mctp_version_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, mctp_control_get_mctp_version_response_length (1), request.length);
	CuAssertIntEquals (test, 4, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 1, response->version_num_entry_count);
	CuAssertIntEquals (test,
		MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | MCTP_CONTROL_PROTOCOL_MAJOR_VERSION,
		entry->major);
	CuAssertIntEquals (test,
		MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | MCTP_CONTROL_PROTOCOL_MINOR_VERSION,
		entry->minor);
	CuAssertIntEquals (test,
		MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | MCTP_CONTROL_PROTOCOL_UPDATE_VERSION,
		entry->update);
	CuAssertIntEquals (test, 0, entry->alpha);
}

static void mctp_control_protocol_commands_test_process_get_mctp_version_support_vdm_protocol (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_mctp_version *rq = (struct mctp_control_get_mctp_version*) data;
	struct mctp_control_get_mctp_version_response *response =
		(struct mctp_control_get_mctp_version_response*) data;
	struct mctp_control_mctp_version_number_entry *entry =
		mctp_control_get_mctp_version_response_get_entries (response);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->message_type_num = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	request.length = sizeof (struct mctp_control_get_mctp_version);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_mctp_version_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, mctp_control_get_mctp_version_response_length (1), request.length);
	CuAssertIntEquals (test, 4, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 1, response->version_num_entry_count);
	CuAssertIntEquals (test,
		MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | CERBERUS_PROTOCOL_PROTOCOL_VERSION,
		entry->major);
	CuAssertIntEquals (test, MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | 0, entry->minor);
	CuAssertIntEquals (test, MCTP_CONTROL_GET_MCTP_VERSION_VERSION_IGNORE_UPDATE, entry->update);
	CuAssertIntEquals (test, 0, entry->alpha);
}

static void mctp_control_protocol_commands_test_process_get_mctp_version_support_null (CuTest *test)
{
	int status;

	TEST_START;

	status = mctp_control_protocol_get_mctp_version_support (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);
}

static void mctp_control_protocol_commands_test_process_get_mctp_version_support_invalid_len (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_mctp_version *rq = (struct mctp_control_get_mctp_version*) data;
	struct mctp_control_get_mctp_version_response *response =
		(struct mctp_control_get_mctp_version_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->message_type_num = 0xFF;

	request.length = sizeof (struct mctp_control_get_mctp_version) + 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_mctp_version_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 4, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);

	request.length = sizeof (struct mctp_control_get_mctp_version) - 1;
	response->completion_code = 0;

	status = mctp_control_protocol_get_mctp_version_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 4, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
}

static void mctp_control_protocol_commands_test_process_get_mctp_version_support_unsupported_msg_type (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_mctp_version *rq = (struct mctp_control_get_mctp_version*) data;
	struct mctp_control_get_mctp_version_response *response =
		(struct mctp_control_get_mctp_version_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_mctp_version);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rq->message_type_num = 0xAA;

	status = mctp_control_protocol_get_mctp_version_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 4, response->header.command_code);
	CuAssertIntEquals (test, 0x80, response->completion_code);
}

static void mctp_control_protocol_commands_test_process_get_message_type_support (CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_message_type *rq = (struct mctp_control_get_message_type*) data;
	struct mctp_control_get_message_type_response *response =
		(struct mctp_control_get_message_type_response*) data;
	uint8_t *entry = mctp_control_get_message_type_response_get_entries (response);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_message_type);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_message_type_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, mctp_control_get_message_type_response_length (2), request.length);
	CuAssertIntEquals (test, 5, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 2, response->message_type_count);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, entry[0]);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, entry[1]);
}

static void mctp_control_protocol_commands_test_process_get_message_type_support_invalid_len (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_message_type *rq = (struct mctp_control_get_message_type*) data;
	struct mctp_control_get_message_type_response *response =
		(struct mctp_control_get_message_type_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_message_type) + 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_message_type_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 5, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);

	request.length = sizeof (struct mctp_control_get_message_type) - 1;
	response->completion_code = 0;

	status = mctp_control_protocol_get_message_type_support (&request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 5, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
}

static void mctp_control_protocol_commands_test_generate_get_message_type_support_request (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct mctp_control_get_message_type *rq = (struct mctp_control_get_message_type*) data;
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_message_type_support_request (data, sizeof (data));
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_message_type), status);
	CuAssertIntEquals (test, 0, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 0, rq->header.instance_id);
	CuAssertIntEquals (test, 0, rq->header.rsvd);
	CuAssertIntEquals (test, 0, rq->header.d_bit);
	CuAssertIntEquals (test, 1, rq->header.rq);
	CuAssertIntEquals (test, 5, rq->header.command_code);
}

static void mctp_control_protocol_commands_test_generate_get_message_type_support_request_null (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_message_type_support_request (NULL, sizeof (data));
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);
}

static void mctp_control_protocol_commands_test_generate_get_message_type_support_request_buf_too_small (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_message_type_support_request (data,
		sizeof (struct mctp_control_get_message_type) - 1);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BUF_TOO_SMALL, status);
}

static void mctp_control_protocol_commands_test_process_get_message_type_support_response (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_message_type_response *rsp =
		(struct mctp_control_get_message_type_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_message_type_response_length (3);
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 0;
	rsp->message_type_count = 3;

	status = mctp_control_protocol_process_get_message_type_support_response (&response);
	CuAssertIntEquals (test, 0, status);
}

static void mctp_control_protocol_commands_test_process_get_message_type_support_response_null (
	CuTest *test)
{
	int status;

	TEST_START;

	status = mctp_control_protocol_process_get_message_type_support_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);
}

static void mctp_control_protocol_commands_test_process_get_message_type_support_response_bad_len (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_message_type_response *rsp =
		(struct mctp_control_get_message_type_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_message_type_response);
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 0;
	rsp->message_type_count = 3;

	status = mctp_control_protocol_process_get_message_type_support_response (&response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);

	response.length = mctp_control_get_message_type_response_length (3) + 1;

	status = mctp_control_protocol_process_get_message_type_support_response (&response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);
}

static void mctp_control_protocol_commands_test_process_get_message_type_support_response_cc_fail (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_message_type_response *rsp =
		(struct mctp_control_get_message_type_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_message_type_response_length (3);
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 1;
	rsp->message_type_count = 3;

	status = mctp_control_protocol_process_get_message_type_support_response (&response);
	CuAssertIntEquals (test, 0, status);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support (CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_pci_response *response =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->vid_set_selector = CERBERUS_VID_SET;
	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_vendor_def_msg_support (0x1414, 4, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response),
		request.length);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, CERBERUS_VID_SET_RESPONSE, response->vid_set_selector);
	CuAssertIntEquals (test, 0, response->vid_format);
	CuAssertIntEquals (test, 0x1414, response->vid);
	CuAssertIntEquals (test, 0x0400, response->protocol_version);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_vid_endian_test (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_pci_response *response =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->vid_set_selector = CERBERUS_VID_SET;
	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_vendor_def_msg_support (0xFF, 4, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response),
		request.length);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, CERBERUS_VID_SET_RESPONSE, response->vid_set_selector);
	CuAssertIntEquals (test, 0, response->vid_format);
	CuAssertIntEquals (test, 0xFF00, response->vid);
	CuAssertIntEquals (test, 0x0400, response->protocol_version);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_null (
	CuTest *test)
{
	int status;

	TEST_START;

	status = mctp_control_protocol_get_vendor_def_msg_support (0xFF, 4, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_invalid_len (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_pci_response *response =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support) + 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_vendor_def_msg_support (0xFF00, 4, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN, request.length);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);

	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support) - 1;
	rq->header.rq = 1;
	response->completion_code = 0;

	status = mctp_control_protocol_get_vendor_def_msg_support (0xFF00, 4, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN, request.length);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_invalid_vid_set (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_pci_response *response =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->vid_set_selector = 0xFF;
	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mctp_control_protocol_get_vendor_def_msg_support (0xFF00, 4, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN, request.length);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
}

static void mctp_control_protocol_commands_test_generate_get_vendor_def_msg_support_request (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_vendor_def_msg_support_request (1, data,
		sizeof (data));
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_vendor_def_msg_support), status);
	CuAssertIntEquals (test, 0, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 0, rq->header.instance_id);
	CuAssertIntEquals (test, 0, rq->header.rsvd);
	CuAssertIntEquals (test, 0, rq->header.d_bit);
	CuAssertIntEquals (test, 1, rq->header.rq);
	CuAssertIntEquals (test, 6, rq->header.command_code);
	CuAssertIntEquals (test, 1, rq->vid_set_selector);
}

static void mctp_control_protocol_commands_test_generate_get_vendor_def_msg_support_request_null (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_vendor_def_msg_support_request (0, NULL,
		sizeof (data));
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);
}

static void mctp_control_protocol_commands_test_generate_get_vendor_def_msg_support_request_buf_too_small (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_vendor_def_msg_support_request (0, data,
		sizeof (struct mctp_control_get_vendor_def_msg_support) - 1);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BUF_TOO_SMALL, status);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_pci (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_vendor_def_msg_support_pci_response *rsp =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response);
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 0;
	rsp->vid_set_selector = 0;
	rsp->vid_format = 0;

	status = mctp_control_protocol_process_get_vendor_def_msg_support_response (&response);
	CuAssertIntEquals (test, 0, status);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_iana (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_vendor_def_msg_support_iana_response *rsp =
		(struct mctp_control_get_vendor_def_msg_support_iana_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_iana_response);
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 0;
	rsp->vid_set_selector = 0;
	rsp->vid_format = 1;

	status = mctp_control_protocol_process_get_vendor_def_msg_support_response (&response);
	CuAssertIntEquals (test, 0, status);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_null (
	CuTest *test)
{
	int status;

	TEST_START;

	status = mctp_control_protocol_process_get_vendor_def_msg_support_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_bad_len (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_vendor_def_msg_support_pci_response *rsp =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response) - 1;
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 0;
	rsp->vid_set_selector = 0;
	rsp->vid_format = 0;

	status = mctp_control_protocol_process_get_vendor_def_msg_support_response (&response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);

	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response) + 1;

	status = mctp_control_protocol_process_get_vendor_def_msg_support_response (&response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);

	rsp->vid_format = 1;

	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_iana_response) + 1;

	status = mctp_control_protocol_process_get_vendor_def_msg_support_response (&response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);
}

static void mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_cc_fail (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_vendor_def_msg_support_pci_response *rsp =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response);
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 1;
	rsp->vid_set_selector = 0;
	rsp->vid_format = 0;

	status = mctp_control_protocol_process_get_vendor_def_msg_support_response (&response);
	CuAssertIntEquals (test, 0, status);
}

static void mctp_control_protocol_commands_test_generate_get_routing_table_entries_request (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct mctp_control_get_routing_table_entries *rq =
		(struct mctp_control_get_routing_table_entries*) data;
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_routing_table_entries_request (1, data,
		sizeof (data));
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_routing_table_entries), status);
	CuAssertIntEquals (test, 0, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 0, rq->header.instance_id);
	CuAssertIntEquals (test, 0, rq->header.rsvd);
	CuAssertIntEquals (test, 0, rq->header.d_bit);
	CuAssertIntEquals (test, 1, rq->header.rq);
	CuAssertIntEquals (test, 0x0a, rq->header.command_code);
	CuAssertIntEquals (test, 1, rq->entry_handle);
}

static void mctp_control_protocol_commands_test_generate_get_routing_table_entries_request_null (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_routing_table_entries_request (0, NULL,
		sizeof (data));
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);
}

static void mctp_control_protocol_commands_test_generate_get_routing_table_entries_request_buf_too_small (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	int status;

	TEST_START;

	memset (data, 0, sizeof (data));

	status = mctp_control_protocol_generate_get_routing_table_entries_request (0, data,
		sizeof (struct mctp_control_get_routing_table_entries) - 1);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BUF_TOO_SMALL, status);
}

static void mctp_control_protocol_commands_test_process_get_routing_table_entries_response (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_routing_table_entries_response *rsp =
		(struct mctp_control_get_routing_table_entries_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_routing_table_entries_response_length (2);
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 0;
	rsp->num_entries = 2;
	rsp->next_entry_handle = 1;

	status = mctp_control_protocol_process_get_routing_table_entries_response (&response);
	CuAssertIntEquals (test, 0, status);
}

static void mctp_control_protocol_commands_test_process_get_routing_table_entries_response_null (
	CuTest *test)
{
	int status;

	TEST_START;

	status = mctp_control_protocol_process_get_routing_table_entries_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);
}

static void mctp_control_protocol_commands_test_process_get_routing_table_entries_response_bad_len (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_routing_table_entries_response *rsp =
		(struct mctp_control_get_routing_table_entries_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_routing_table_entries_response) - 1;
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 0;
	rsp->num_entries = 2;
	rsp->next_entry_handle = 1;

	status = mctp_control_protocol_process_get_routing_table_entries_response (&response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);

	response.length = mctp_control_get_routing_table_entries_response_length (2) + 1;

	status = mctp_control_protocol_process_get_routing_table_entries_response (&response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);
}

static void mctp_control_protocol_commands_test_process_get_routing_table_entries_response_cc_fail (
	CuTest *test)
{
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg response;
	struct mctp_control_get_routing_table_entries_response *rsp =
		(struct mctp_control_get_routing_table_entries_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_routing_table_entries_response_length (2);
	response.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES;
	rsp->header.rq = 0;
	rsp->header.instance_id = 2;

	rsp->completion_code = 1;
	rsp->num_entries = 2;
	rsp->next_entry_handle = 1;

	status = mctp_control_protocol_process_get_routing_table_entries_response (&response);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START (mctp_control_protocol_commands);

TEST (mctp_control_protocol_commands_test_header_format);
TEST (mctp_control_protocol_commands_test_set_eid_format);
TEST (mctp_control_protocol_commands_test_get_eid_format);
TEST (mctp_control_protocol_commands_test_get_mctp_version_format);
TEST (mctp_control_protocol_commands_test_get_message_type_format);
TEST (mctp_control_protocol_commands_test_get_vendor_def_msg_support_format);
TEST (mctp_control_protocol_commands_test_get_routing_table_entries_format);
TEST (mctp_control_protocol_commands_test_process_set_eid);
TEST (mctp_control_protocol_commands_test_process_set_eid_force);
TEST (mctp_control_protocol_commands_test_process_set_eid_null);
TEST (mctp_control_protocol_commands_test_process_set_eid_invalid_len);
TEST (mctp_control_protocol_commands_test_process_set_eid_invalid_data);
TEST (mctp_control_protocol_commands_test_process_get_eid);
TEST (mctp_control_protocol_commands_test_process_get_eid_null);
TEST (mctp_control_protocol_commands_test_process_get_eid_invalid_len);
TEST (mctp_control_protocol_commands_test_process_get_mctp_version_support_mctp_base_protocol);
TEST (mctp_control_protocol_commands_test_process_get_mctp_version_support_mctp_ctrl_protocol);
TEST (mctp_control_protocol_commands_test_process_get_mctp_version_support_vdm_protocol);
TEST (mctp_control_protocol_commands_test_process_get_mctp_version_support_null);
TEST (mctp_control_protocol_commands_test_process_get_mctp_version_support_invalid_len);
TEST (mctp_control_protocol_commands_test_process_get_mctp_version_support_unsupported_msg_type);
TEST (mctp_control_protocol_commands_test_process_get_message_type_support);
TEST (mctp_control_protocol_commands_test_process_get_message_type_support_invalid_len);
TEST (mctp_control_protocol_commands_test_generate_get_message_type_support_request);
TEST (mctp_control_protocol_commands_test_generate_get_message_type_support_request_null);
TEST (mctp_control_protocol_commands_test_generate_get_message_type_support_request_buf_too_small);
TEST (mctp_control_protocol_commands_test_process_get_message_type_support_response);
TEST (mctp_control_protocol_commands_test_process_get_message_type_support_response_null);
TEST (mctp_control_protocol_commands_test_process_get_message_type_support_response_bad_len);
TEST (mctp_control_protocol_commands_test_process_get_message_type_support_response_cc_fail);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_vid_endian_test);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_null);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_invalid_len);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_invalid_vid_set);
TEST (mctp_control_protocol_commands_test_generate_get_vendor_def_msg_support_request);
TEST (mctp_control_protocol_commands_test_generate_get_vendor_def_msg_support_request_null);
TEST (mctp_control_protocol_commands_test_generate_get_vendor_def_msg_support_request_buf_too_small);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_pci);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_iana);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_null);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_bad_len);
TEST (mctp_control_protocol_commands_test_process_get_vendor_def_msg_support_response_cc_fail);
TEST (mctp_control_protocol_commands_test_generate_get_routing_table_entries_request);
TEST (mctp_control_protocol_commands_test_generate_get_routing_table_entries_request_null);
TEST (mctp_control_protocol_commands_test_generate_get_routing_table_entries_request_buf_too_small);
TEST (mctp_control_protocol_commands_test_process_get_routing_table_entries_response);
TEST (mctp_control_protocol_commands_test_process_get_routing_table_entries_response_null);
TEST (mctp_control_protocol_commands_test_process_get_routing_table_entries_response_bad_len);
TEST (mctp_control_protocol_commands_test_process_get_routing_table_entries_response_cc_fail);

TEST_SUITE_END;
