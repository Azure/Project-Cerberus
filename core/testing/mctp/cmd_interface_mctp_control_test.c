// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "mctp/mctp_base_protocol.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "mctp/mctp_control_protocol_commands.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/cmd_interface_mctp_control.h"
#include "testing/mock/mctp/mctp_control_protocol_observer_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"


TEST_SUITE_LABEL ("cmd_interface_mctp_control");


/**
 * Dependencies for testing the MCTP protocol command interface.
 */
struct cmd_interface_mctp_control_testing {
	struct cmd_interface_mctp_control handler;					/**< Command handler instance. */
	struct device_manager device_manager;						/**< Device manager. */
	struct mctp_control_protocol_observer_mock observer;		/**< MCTP protocol observer. */
};


/**
 * Helper function to setup the MCTP command interface.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 * @param register_response_observer Flag indicating whether to register observer to response
 * 	notifications.
 */
static void setup_cmd_interface_mctp_control_test (CuTest *test,
	struct cmd_interface_mctp_control_testing *cmd, bool register_response_observer)
{
	int status;

	status = device_manager_init (&cmd->device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager,
		DEVICE_MANAGER_SELF_DEVICE_NUM, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, MCTP_BASE_PROTOCOL_BMC_EID, 0x10);
	CuAssertIntEquals (test, 0, status);

	status = mctp_control_protocol_observer_mock_init (&cmd->observer);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mctp_control_init (&cmd->handler, &cmd->device_manager,
		0x1414, 0x04);
	CuAssertIntEquals (test, 0, status);

	if (register_response_observer) {
		status = cmd_interface_mctp_control_add_mctp_control_protocol_observer (&cmd->handler,
			&cmd->observer.base);
		CuAssertIntEquals (test, 0, status);
	}
}

/**
 * Helper function to release the MCTP command interface instance.
 *
 * @param test The test framework.
 * @param cmd The testing instance to release.
 */
 static void complete_cmd_interface_mctp_control_test (CuTest *test,
 	struct cmd_interface_mctp_control_testing *cmd)
{
	int status;

	status = mctp_control_protocol_observer_mock_validate_and_release (&cmd->observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&cmd->device_manager);

	cmd_interface_mctp_control_deinit (&cmd->handler);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_mctp_control_test_init (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	int status;

	TEST_START;

	status = mctp_control_protocol_observer_mock_init (&cmd.observer);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&cmd.device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mctp_control_init (&cmd.handler, &cmd.device_manager, 0x1414, 0x04);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, cmd.handler.base.process_request);
	CuAssertPtrNotNull (test, cmd.handler.base.process_response);
	CuAssertPtrNotNull (test, cmd.handler.base.generate_error_packet);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_init_null (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	int status;

	TEST_START;

	status = device_manager_init (&cmd.device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mctp_control_init (NULL, &cmd.device_manager, 0x1414, 0x04);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	status = cmd_interface_mctp_control_init (&cmd.handler, NULL, 0x1414, 0x04);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	device_manager_release (&cmd.device_manager);
}

static void cmd_interface_mctp_control_test_deinit_null (CuTest *test)
{
	TEST_START;

	cmd_interface_mctp_control_deinit (NULL);
}

static void cmd_interface_mctp_control_test_process_request_null (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_payload_too_short (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	request.length = MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN - 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_PAYLOAD_TOO_SHORT, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_unsupported_message (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_protocol_header *header = (struct mctp_control_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	header->msg_type = 1;
	header->rq = 1;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->rsvd = 0;
	header->command_code = 1;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG, status);

	header->msg_type = 0;
	header->d_bit = 1;

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG, status);

	header->d_bit = 0;
	header->integrity_check = 1;

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_rsvd_not_zero (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_protocol_header *header = (struct mctp_control_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	header->msg_type = 0;
	header->rq = 1;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->rsvd = 1;
	header->command_code = 1;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_RSVD_NOT_ZERO, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_unknown_command (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_protocol_header *header = (struct mctp_control_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	header->msg_type = 0;
	header->rq = 1;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->rsvd = 0;
	header->command_code = 0;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNKNOWN_REQUEST, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_set_eid (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *rsp = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x10;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rq->header.msg_type = 0;
	rq->header.rq = 1;
	rq->header.d_bit = 0;
	rq->header.integrity_check = 0;
	rq->header.rsvd = 0;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_SET_EID;
	request.crypto_timeout = true;

	rq->operation = 0;
	rq->eid = 0x11;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_set_eid_request, &cmd.observer,
		0);
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, !request.crypto_timeout);
	CuAssertIntEquals (test, sizeof (struct mctp_control_set_eid_response), request.length);
	CuAssertIntEquals (test, 0, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.d_bit);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.instance_id);
	CuAssertIntEquals (test, 0, rsp->header.rsvd);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SET_EID, rsp->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SUCCESS, rsp->completion_code);
	CuAssertIntEquals (test, 0x11, rsp->eid_setting);
	CuAssertIntEquals (test, MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED,
		rsp->eid_assignment_status);
	CuAssertIntEquals (test, 0, rsp->reserved1);
	CuAssertIntEquals (test, 0, rsp->reserved2);
	CuAssertIntEquals (test, MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL,
		rsp->eid_allocation_status);
	CuAssertIntEquals (test, 0, rsp->eid_pool_size);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_set_eid_no_observer (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *rsp = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x10;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rq->header.msg_type = 0;
	rq->header.rq = 1;
	rq->header.d_bit = 0;
	rq->header.integrity_check = 0;
	rq->header.rsvd = 0;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_SET_EID;
	request.crypto_timeout = true;

	rq->operation = 0;
	rq->eid = 0x11;

	setup_cmd_interface_mctp_control_test (test, &cmd, false);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, !request.crypto_timeout);
	CuAssertIntEquals (test, sizeof (struct mctp_control_set_eid_response), request.length);
	CuAssertIntEquals (test, 0, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.d_bit);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.instance_id);
	CuAssertIntEquals (test, 0, rsp->header.rsvd);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SET_EID, rsp->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SUCCESS, rsp->completion_code);
	CuAssertIntEquals (test, 0x11, rsp->eid_setting);
	CuAssertIntEquals (test, MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED,
		rsp->eid_assignment_status);
	CuAssertIntEquals (test, 0, rsp->reserved1);
	CuAssertIntEquals (test, 0, rsp->reserved2);
	CuAssertIntEquals (test, MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL,
		rsp->eid_allocation_status);
	CuAssertIntEquals (test, 0, rsp->eid_pool_size);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_get_eid (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_eid *rq = (struct mctp_control_get_eid*) data;
	struct mctp_control_get_eid_response *rsp = (struct mctp_control_get_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = sizeof (struct mctp_control_get_eid);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x10;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = true;

	rq->header.msg_type = 0;
	rq->header.rq = 1;
	rq->header.d_bit = 0;
	rq->header.integrity_check = 0;
	rq->header.rsvd = 0;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_EID;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, !request.crypto_timeout);
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_eid_response), request.length);
	CuAssertIntEquals (test, 0, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.d_bit);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.instance_id);
	CuAssertIntEquals (test, 0, rsp->header.rsvd);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_EID, rsp->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SUCCESS, rsp->completion_code);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, rsp->eid);
	CuAssertIntEquals (test, MCTP_CONTROL_GET_EID_EID_TYPE_STATIC_EID_SUPPORTED, rsp->eid_type);
	CuAssertIntEquals (test, 0, rsp->reserved);
	CuAssertIntEquals (test, MCTP_CONTROL_GET_EID_ENDPOINT_TYPE_SIMPLE_ENDPOINT,
		rsp->endpoint_type);
	CuAssertIntEquals (test, 0, rsp->reserved2);
	CuAssertIntEquals (test, 0, rsp->medium_specific_info);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_get_mctp_version (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_mctp_version *rq = (struct mctp_control_get_mctp_version*) data;
	struct mctp_control_get_mctp_version_response *rsp =
		(struct mctp_control_get_mctp_version_response*) data;
	struct mctp_control_mctp_version_number_entry *entry;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = sizeof (struct mctp_control_get_mctp_version);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x10;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = true;

	rq->header.msg_type = 0;
	rq->header.rq = 1;
	rq->header.d_bit = 0;
	rq->header.integrity_check = 0;
	rq->header.rsvd = 0;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION;

	rq->message_type_num = 0x00;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, !request.crypto_timeout);
	CuAssertIntEquals (test, mctp_control_get_mctp_version_response_length (1), request.length);
	CuAssertIntEquals (test, 0, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.d_bit);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.instance_id);
	CuAssertIntEquals (test, 0, rsp->header.rsvd);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION, rsp->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SUCCESS, rsp->completion_code);
	CuAssertIntEquals (test, 1, rsp->version_num_entry_count);

	entry = mctp_control_get_mctp_version_response_get_entries (rsp);
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

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_get_message_type_support (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_message_type *rq = (struct mctp_control_get_message_type*) data;
	struct mctp_control_get_message_type_response *rsp =
		(struct mctp_control_get_message_type_response*) data;
	uint8_t *entry;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = sizeof (struct mctp_control_get_message_type);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x10;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = true;

	rq->header.msg_type = 0;
	rq->header.rq = 1;
	rq->header.d_bit = 0;
	rq->header.integrity_check = 0;
	rq->header.rsvd = 0;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, !request.crypto_timeout);
	CuAssertIntEquals (test, mctp_control_get_message_type_response_length (2), request.length);
	CuAssertIntEquals (test, 0, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.d_bit);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.instance_id);
	CuAssertIntEquals (test, 0, rsp->header.rsvd);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE, rsp->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SUCCESS, rsp->completion_code);
	CuAssertIntEquals (test, 2, rsp->message_type_count);

	entry = mctp_control_get_message_type_response_get_entries (rsp);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, entry[0]);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, entry[1]);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_request_get_vendor_def_msg_support (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_pci_response *rsp =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x10;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = true;

	rq->header.msg_type = 0;
	rq->header.rq = 1;
	rq->header.d_bit = 0;
	rq->header.integrity_check = 0;
	rq->header.rsvd = 0;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;

	rq->vid_set_selector = CERBERUS_VID_SET;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, !request.crypto_timeout);
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response),
		request.length);
	CuAssertIntEquals (test, 0, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.d_bit);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.instance_id);
	CuAssertIntEquals (test, 0, rsp->header.rsvd);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT,
		rsp->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SUCCESS, rsp->completion_code);
	CuAssertIntEquals (test, CERBERUS_VID_SET_RESPONSE, rsp->vid_set_selector);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_VID_FORMAT_PCI, rsp->vid_format);
	CuAssertIntEquals (test, platform_htons (0x1414), rsp->vid);
	CuAssertIntEquals (test, platform_htons (0x04), rsp->protocol_version);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_null (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_payload_too_short (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.length = MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN - 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_PAYLOAD_TOO_SHORT, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_unsupported_message (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_protocol_header *header = (struct mctp_control_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	header->msg_type = 1;
	header->rq = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->rsvd = 0;
	header->command_code = 1;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG, status);

	header->msg_type = 0;
	header->d_bit = 1;

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG, status);

	header->d_bit = 0;
	header->integrity_check = 1;

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_rsvd_not_zero (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_protocol_header *header = (struct mctp_control_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	header->msg_type = 0;
	header->rq = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->rsvd = 1;
	header->command_code = 1;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_RSVD_NOT_ZERO, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_unknown_command (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_protocol_header *header = (struct mctp_control_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	header->msg_type = 0;
	header->rq = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->rsvd = 0;
	header->command_code = 0;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNKNOWN_RESPONSE, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_message_type (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_message_type_response *rsp =
		(struct mctp_control_get_message_type_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_message_type_response_length (2);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->message_type_count = 2;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_get_message_type_response,
		&cmd.observer, 0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response,
		sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_message_type_fail (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_message_type_response *rsp =
		(struct mctp_control_get_message_type_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_message_type_response_length (1);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->message_type_count = 2;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_message_type_no_observer (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_message_type_response *rsp =
		(struct mctp_control_get_message_type_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_message_type_response_length (2);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->message_type_count = 2;

	setup_cmd_interface_mctp_control_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_vendor_def_msg_support (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_vendor_def_msg_support_pci_response *rsp =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->vid_format = MCTP_CONTROL_PCI_VID_FORMAT;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_get_vendor_def_msg_response,
		&cmd.observer, 0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response,
		sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_vendor_def_msg_support_fail (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_vendor_def_msg_support_pci_response *rsp =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response) + 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->vid_format = MCTP_CONTROL_PCI_VID_FORMAT;

	setup_cmd_interface_mctp_control_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_vendor_def_msg_support_no_observer (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_vendor_def_msg_support_pci_response *rsp =
		(struct mctp_control_get_vendor_def_msg_support_pci_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->vid_format = MCTP_CONTROL_PCI_VID_FORMAT;

	setup_cmd_interface_mctp_control_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_routing_table_entries (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_routing_table_entries_response *rsp =
		(struct mctp_control_get_routing_table_entries_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_routing_table_entries_response_length (10);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->num_entries = 10;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock,
		cmd.observer.base.on_get_routing_table_entries_response, &cmd.observer, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response, sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_routing_table_entries_fail (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_routing_table_entries_response *rsp =
		(struct mctp_control_get_routing_table_entries_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_routing_table_entries_response_length (10) + 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->num_entries = 10;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_BAD_LENGTH, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_process_response_get_routing_table_entries_no_observer (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_get_routing_table_entries_response *rsp =
		(struct mctp_control_get_routing_table_entries_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = mctp_control_get_routing_table_entries_response_length (10);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rsp->header.msg_type = 0;
	rsp->header.rq = 0;
	rsp->header.d_bit = 0;
	rsp->header.integrity_check = 0;
	rsp->header.rsvd = 0;
	rsp->header.command_code = MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES;

	rsp->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
	rsp->num_entries = 10;

	setup_cmd_interface_mctp_control_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_generate_error_packet (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd.handler.base.generate_error_packet (&cmd.handler.base, &request, 0x0A, 0xAABBCCDD,
		1);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_OPERATION, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_add_mctp_control_protocol_observer_invalid_arg (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd_interface_mctp_control_add_mctp_control_protocol_observer (NULL,
		&cmd.observer.base);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	status = cmd_interface_mctp_control_add_mctp_control_protocol_observer (&cmd.handler, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_remove_mctp_control_protocol_observer (CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *rsp = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x10;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rq->header.msg_type = 0;
	rq->header.rq = 1;
	rq->header.d_bit = 0;
	rq->header.integrity_check = 0;
	rq->header.rsvd = 0;
	rq->header.command_code = MCTP_CONTROL_PROTOCOL_SET_EID;
	request.crypto_timeout = true;

	rq->operation = 0;
	rq->eid = 0x11;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd_interface_mctp_control_remove_mctp_control_protocol_observer (&cmd.handler,
		&cmd.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, !request.crypto_timeout);
	CuAssertIntEquals (test, sizeof (struct mctp_control_set_eid_response), request.length);
	CuAssertIntEquals (test, 0, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.rq);
	CuAssertIntEquals (test, 0, rsp->header.d_bit);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.instance_id);
	CuAssertIntEquals (test, 0, rsp->header.rsvd);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SET_EID, rsp->header.command_code);
	CuAssertIntEquals (test, MCTP_CONTROL_PROTOCOL_SUCCESS, rsp->completion_code);
	CuAssertIntEquals (test, 0x11, rsp->eid_setting);
	CuAssertIntEquals (test, MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED,
		rsp->eid_assignment_status);
	CuAssertIntEquals (test, 0, rsp->reserved1);
	CuAssertIntEquals (test, 0, rsp->reserved2);
	CuAssertIntEquals (test, MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL,
		rsp->eid_allocation_status);
	CuAssertIntEquals (test, 0, rsp->eid_pool_size);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}

static void cmd_interface_mctp_control_test_remove_mctp_control_protocol_observer_invalid_arg (
	CuTest *test)
{
	struct cmd_interface_mctp_control_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_mctp_control_test (test, &cmd, true);

	status = cmd_interface_mctp_control_remove_mctp_control_protocol_observer (NULL,
		&cmd.observer.base);
	CuAssertIntEquals (test, CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT, status);

	status = cmd_interface_mctp_control_remove_mctp_control_protocol_observer (&cmd.handler, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	complete_cmd_interface_mctp_control_test (test, &cmd);
}


TEST_SUITE_START (cmd_interface_mctp_control);

TEST (cmd_interface_mctp_control_test_init);
TEST (cmd_interface_mctp_control_test_init_null);
TEST (cmd_interface_mctp_control_test_deinit_null);
TEST (cmd_interface_mctp_control_test_process_request_null);
TEST (cmd_interface_mctp_control_test_process_request_payload_too_short);
TEST (cmd_interface_mctp_control_test_process_request_unsupported_message);
TEST (cmd_interface_mctp_control_test_process_request_rsvd_not_zero);
TEST (cmd_interface_mctp_control_test_process_request_unknown_command);
TEST (cmd_interface_mctp_control_test_process_request_set_eid);
TEST (cmd_interface_mctp_control_test_process_request_set_eid_no_observer);
TEST (cmd_interface_mctp_control_test_process_request_get_eid);
TEST (cmd_interface_mctp_control_test_process_request_get_mctp_version);
TEST (cmd_interface_mctp_control_test_process_request_get_message_type_support);
TEST (cmd_interface_mctp_control_test_process_request_get_vendor_def_msg_support);
TEST (cmd_interface_mctp_control_test_process_response_null);
TEST (cmd_interface_mctp_control_test_process_response_payload_too_short);
TEST (cmd_interface_mctp_control_test_process_response_unsupported_message);
TEST (cmd_interface_mctp_control_test_process_response_rsvd_not_zero);
TEST (cmd_interface_mctp_control_test_process_response_unknown_command);
TEST (cmd_interface_mctp_control_test_process_response_get_message_type);
TEST (cmd_interface_mctp_control_test_process_response_get_message_type_fail);
TEST (cmd_interface_mctp_control_test_process_response_get_message_type_no_observer);
TEST (cmd_interface_mctp_control_test_process_response_get_vendor_def_msg_support);
TEST (cmd_interface_mctp_control_test_process_response_get_vendor_def_msg_support_fail);
TEST (cmd_interface_mctp_control_test_process_response_get_vendor_def_msg_support_no_observer);
TEST (cmd_interface_mctp_control_test_process_response_get_routing_table_entries);
TEST (cmd_interface_mctp_control_test_process_response_get_routing_table_entries_fail);
TEST (cmd_interface_mctp_control_test_process_response_get_routing_table_entries_no_observer);
TEST (cmd_interface_mctp_control_test_generate_error_packet);
TEST (cmd_interface_mctp_control_test_add_mctp_control_protocol_observer_invalid_arg);
TEST (cmd_interface_mctp_control_test_remove_mctp_control_protocol_observer);
TEST (cmd_interface_mctp_control_test_remove_mctp_control_protocol_observer_invalid_arg);

TEST_SUITE_END;
