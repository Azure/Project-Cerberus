// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/attestation_cmd_interface.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_diagnostic_commands.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "cmd_interface/cerberus_protocol_optional_commands.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"
#include "common/array_size.h"
#include "logging/debug_log.h"
#include "recovery/cmd_interface_recovery.h"
#include "recovery/cmd_interface_recovery_static.h"
#include "recovery/recovery_image_header.h"
#include "testing/cmd_interface/cerberus_protocol_debug_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_diagnostic_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_master_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_optional_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_required_commands_testing.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/firmware/firmware_update_control_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/manifest_cmd_interface_mock.h"
#include "testing/mock/recovery/recovery_image_cmd_interface_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/recovery/recovery_image_mock.h"
#include "testing/recovery/recovery_image_header_testing.h"


TEST_SUITE_LABEL ("cmd_interface_recovery");

/**
*List of version count.
*/
#define FW_VERSION_COUNT 1

/**
 * Cerberus firmware version string.
 */
const char RECOVERY_FW_VERSION[CERBERUS_PROTOCOL_FW_VERSION_LEN] = "A1.B2.C3.01";

/**
 * List of FW version strings.
 */
const char *fw_version_list[FW_VERSION_COUNT];

/**
 * Dependencies for testing the recovery command interface.
 */
struct cmd_interface_recovery_testing {
	struct cmd_interface_recovery handler;		/**< Command handler instance. */
	struct firmware_update_control_mock update;	/**< The firmware update mock. */
	struct logging_mock debug;					/**< The debug logger mock. */
	struct device_manager device_manager;		/**< Device manager. */
	struct cmd_interface_fw_version fw_version;	/**< The firmware version data. */
};


/**
 * Helper function to initialize a subset of the recovery command interface parameters.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 */
static void setup_cmd_interface_recovery_mock_test_init (CuTest *test,
	struct cmd_interface_recovery_testing *cmd)
{
	int status;

	debug_log = NULL;

	status = device_manager_init (&cmd->device_manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&cmd->device_manager, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&cmd->device_manager, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0, 1);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_control_mock_init (&cmd->update);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&cmd->debug);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to initialize the firmware version strings.
 *
 * @param cmd The instance to use for testing.
 * @param fw_version The Cerberus firmware version to initialize.
 * @param count The number of firmware versions.
 */
static void setup_cmd_interface_recovery_mock_test_init_fw_version (
	struct cmd_interface_recovery_testing *cmd, const char *fw_version,	size_t count)
{
	fw_version_list[0] = fw_version;
	cmd->fw_version.count = count;
	cmd->fw_version.id = fw_version_list;
}

/**
 * Helper function to setup the recovery command interface.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 */
static void setup_cmd_interface_recovery_mock_test (CuTest *test,
	struct cmd_interface_recovery_testing *cmd)
{
	int status;

	setup_cmd_interface_recovery_mock_test_init (test, cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

	status = cmd_interface_recovery_init (&cmd->handler, &cmd->update.base, &cmd->device_manager,
		&cmd->fw_version);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release the recovery command interface instance.
 *
 * @param test The test framework.
 * @param cmd The testing instance to release.
 */
static void complete_cmd_interface_recovery_mock_test (CuTest *test,
	struct cmd_interface_recovery_testing *cmd)
{
	int status;

	debug_log = NULL;

	status = firmware_update_control_mock_validate_and_release (&cmd->update);
	status |= logging_mock_validate_and_release (&cmd->debug);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&cmd->device_manager);

	cmd_interface_recovery_deinit (&cmd->handler);
}

/**
 * Tear down the test suite.
 *
 * @param test The test framework.
 */
static void cmd_interface_recovery_testing_suite_tear_down (CuTest *test)
{
	debug_log = NULL;
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_recovery_test_init (CuTest *test)
{
	struct cmd_interface_recovery interface;
	struct firmware_update_control_mock update;
	struct logging_mock debug;
	struct device_manager device_manager;

	const char *id[FW_VERSION_COUNT] = {RECOVERY_FW_VERSION};
	struct cmd_interface_fw_version fw_version = {
		.count = FW_VERSION_COUNT,
		.id = id
	};
	int status;

	TEST_START;

	status = firmware_update_control_mock_init (&update);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&debug);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	debug_log = &debug.base;

	status = cmd_interface_recovery_init (&interface, &update.base, &device_manager, &fw_version);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, interface.base.process_request);
	CuAssertPtrNotNull (test, interface.base.process_response);

	status = firmware_update_control_mock_validate_and_release (&update);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&debug);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_manager);

	debug_log = NULL;

	cmd_interface_recovery_deinit (&interface);
}

static void cmd_interface_recovery_test_init_null (CuTest *test)
{
	struct cmd_interface_recovery interface;
	struct firmware_update_control_mock update;
	struct logging_mock debug;
	struct device_manager device_manager;

	const char *id[FW_VERSION_COUNT] = {RECOVERY_FW_VERSION};
	struct cmd_interface_fw_version fw_version = {
		.count = FW_VERSION_COUNT,
		.id = id
	};
	int status;

	TEST_START;

	status = firmware_update_control_mock_init (&update);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&debug);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	debug_log = &debug.base;

	status = cmd_interface_recovery_init (NULL, &update.base, &device_manager, &fw_version);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_recovery_init (&interface, NULL,	&device_manager, &fw_version);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_recovery_init (&interface, &update.base,	NULL, &fw_version);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_recovery_init (&interface, &update.base,	&device_manager, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = firmware_update_control_mock_validate_and_release (&update);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&debug);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_manager);

	debug_log = NULL;
}

static void cmd_interface_recovery_test_deinit_null (CuTest *test)
{
	TEST_START;

	cmd_interface_recovery_deinit (NULL);
}

static void cmd_interface_recovery_test_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	CuAssertPtrNotNull (test, cmd.handler.base.process_request);
	CuAssertPtrNotNull (test, cmd.handler.base.process_response);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_null (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cmd.handler.base.process_request (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_null_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cmd.handler.base.process_request (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_payload_too_short (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_unsupported_message (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;

	header->msg_type = 0x11;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 1;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->integrity_check = 0;
	header->pci_vendor_id = 0xAA;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_unknown_command (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = 0xFF;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_REQUEST, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_reserved_fields_not_zero (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 1;
	header->reserved2 = 0;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->reserved1 = 0;
	header->reserved2 = 1;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_fw_update_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_fw_update_init (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_fw_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_fw_update_init_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_fw_update_init_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_fw_update_init_fail (test,
		&cmd.handler.base, &cmd.update);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_fw_update (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_fw_update (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_fw_update_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_fw_update (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_fw_update_no_data (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_fw_update_no_data (test, &cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_fw_update_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_fw_update_fail (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_complete_fw_update (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_complete_fw_update (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_complete_fw_update_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_complete_fw_update (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_complete_fw_update_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_complete_fw_update_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_complete_fw_update_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_complete_fw_update_fail (test,
		&cmd.handler.base, &cmd.update);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_ext_update_status_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_master_commands_testing_process_get_ext_update_status_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_ext_update_status_invalid_type (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_master_commands_testing_process_get_ext_update_status_invalid_type (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_fw_version (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;
	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version (test, &cmd.handler.base,
		RECOVERY_FW_VERSION);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_fw_version_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};

	TEST_START;
	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version (test, &cmd.handler.base,
		RECOVERY_FW_VERSION);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_fw_version_unset_version (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, NULL,	FW_VERSION_COUNT);

	status = cmd_interface_recovery_init (&cmd.handler, &cmd.update.base, &cmd.device_manager,
		&cmd.fw_version);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_process_get_fw_version_unset_version (test,
		&cmd.handler.base);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_fw_version_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_fw_version_unsupported_area (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version_unsupported_area (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_fw_version_bad_count (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, NULL, 0);

	status = cmd_interface_recovery_init (&cmd.handler, &cmd.update.base, &cmd.device_manager,
		&cmd.fw_version);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_process_get_fw_version_bad_count (test,
		&cmd.handler.base);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_log_info (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_get_log_info (test, &cmd.handler.base,
		&cmd.debug, 0);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_log_info_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_get_log_info (test, &cmd.handler.base,
		&cmd.debug, 0);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_log_info_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_get_log_info_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_log_info_fail_debug (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_get_log_info_fail_debug (test,
		&cmd.handler.base, &cmd.debug, 0);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_log_read_debug (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_log_read_debug (test, &cmd.handler.base,
		&cmd.debug);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_log_read_debug_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_log_read_debug (test, &cmd.handler.base,
		&cmd.debug);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_log_read_debug_limited_response (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_log_read_debug_limited_response (test,
		&cmd.handler.base, &cmd.debug);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_log_read_debug_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_optional_commands_testing_process_log_read_debug_fail (test,
		&cmd.handler.base, &cmd.debug);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_capabilities (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_capabilities (test, &cmd.handler.base,
		&cmd.device_manager);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_capabilities_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_capabilities (test, &cmd.handler.base,
		&cmd.device_manager);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_capabilities_invalid_device (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_device (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_capabilities_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_response (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_response_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager,	&cmd.update.base,
			&cmd.fw_version)
	};
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	status = cmd.handler.base.process_response (NULL, &response);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_response_null (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	status = cmd.handler.base.process_response (NULL, &response);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}


TEST_SUITE_START (cmd_interface_recovery);

TEST (cmd_interface_recovery_test_init);
TEST (cmd_interface_recovery_test_init_null);
TEST (cmd_interface_recovery_test_static_init);
TEST (cmd_interface_recovery_test_deinit_null);
TEST (cmd_interface_recovery_test_process_null);
TEST (cmd_interface_recovery_test_process_null_static_init);
TEST (cmd_interface_recovery_test_process_payload_too_short);
TEST (cmd_interface_recovery_test_process_unsupported_message);
TEST (cmd_interface_recovery_test_process_unknown_command);
TEST (cmd_interface_recovery_test_process_reserved_fields_not_zero);
TEST (cmd_interface_recovery_test_process_fw_update_init);
TEST (cmd_interface_recovery_test_process_fw_update_init_invalid_len);
TEST (cmd_interface_recovery_test_process_fw_update_init_fail);
TEST (cmd_interface_recovery_test_process_fw_update);
TEST (cmd_interface_recovery_test_process_fw_update_static_init);
TEST (cmd_interface_recovery_test_process_fw_update_no_data);
TEST (cmd_interface_recovery_test_process_fw_update_fail);
TEST (cmd_interface_recovery_test_process_complete_fw_update);
TEST (cmd_interface_recovery_test_process_complete_fw_update_static_init);
TEST (cmd_interface_recovery_test_process_complete_fw_update_invalid_len);
TEST (cmd_interface_recovery_test_process_complete_fw_update_fail);
TEST (cmd_interface_recovery_test_process_get_ext_update_status_invalid_len);
TEST (cmd_interface_recovery_test_process_get_ext_update_status_invalid_type);
TEST (cmd_interface_recovery_test_process_get_fw_version);
TEST (cmd_interface_recovery_test_process_get_fw_version_static_init);
TEST (cmd_interface_recovery_test_process_get_fw_version_unset_version);
TEST (cmd_interface_recovery_test_process_get_fw_version_unsupported_area);
TEST (cmd_interface_recovery_test_process_get_fw_version_invalid_len);
TEST (cmd_interface_recovery_test_process_get_fw_version_bad_count);
TEST (cmd_interface_recovery_test_process_get_log_info);
TEST (cmd_interface_recovery_test_process_get_log_info_static_init);
TEST (cmd_interface_recovery_test_process_get_log_info_invalid_len);
TEST (cmd_interface_recovery_test_process_get_log_info_fail_debug);
TEST (cmd_interface_recovery_test_process_log_read_debug);
TEST (cmd_interface_recovery_test_process_log_read_debug_static_init);
TEST (cmd_interface_recovery_test_process_log_read_debug_limited_response);
TEST (cmd_interface_recovery_test_process_log_read_debug_fail);
TEST (cmd_interface_recovery_test_process_get_capabilities);
TEST (cmd_interface_recovery_test_process_get_capabilities_static_init);
TEST (cmd_interface_recovery_test_process_get_capabilities_invalid_device);
TEST (cmd_interface_recovery_test_process_get_capabilities_invalid_len);
TEST (cmd_interface_recovery_test_process_response);
TEST (cmd_interface_recovery_test_process_response_static_init);
TEST (cmd_interface_recovery_test_process_response_null);

/* Tear down after the tests in this suite have run. */
TEST (cmd_interface_recovery_testing_suite_tear_down);

TEST_SUITE_END;
