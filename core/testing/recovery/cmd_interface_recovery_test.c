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
#include "testing/asn1/x509_testing.h"
#include "testing/cmd_interface/cerberus_protocol_debug_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_diagnostic_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_master_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_optional_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_required_commands_testing.h"
#include "testing/cmd_interface/cmd_interface_system_testing.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/firmware/firmware_update_control_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/manifest_cmd_interface_mock.h"
#include "testing/mock/recovery/recovery_image_cmd_interface_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/recovery/recovery_image_mock.h"
#include "testing/recovery/recovery_image_header_testing.h"
#include "testing/riot/riot_core_testing.h"

TEST_SUITE_LABEL ("cmd_interface_recovery");

/**
 * Cerberus firmware version string.
 */
static const char RECOVERY_FW_VERSION[CERBERUS_PROTOCOL_FW_VERSION_LEN] = "A1.B2.C3.01";

/**
 * List of FW version strings.
 */
static const char *cmd_interface_recovery_testing_fw_version_list[FW_VERSION_COUNT];

/**
 * Device ID details.
 */
static const uint16_t cmd_interface_recovery_test_vendor_id = 0x1414;
static const uint16_t cmd_interface_recovery_test_device_id = 0x0002;
static const uint16_t cmd_interface_recovery_test_subsystem_vid = 0x1414;
static const uint16_t cmd_interface_recovery_test_subsystem_id = 0x0003;

/**
 * Dependencies for testing the recovery command interface.
 */
struct cmd_interface_recovery_testing {
	struct cmd_interface_recovery handler;			/**< Command handler instance. */
	struct firmware_update_control_mock update;		/**< The firmware update mock. */
	struct logging_mock debug;						/**< The debug logger mock. */
	struct device_manager device_manager;			/**< Device manager. */
	struct cmd_interface_fw_version fw_version;		/**< The firmware version data. */
	struct cmd_interface_device_id device_id;		/**< Device ID information */
	struct riot_key_manager riot;					/**< RIoT keys manager. */
	struct riot_key_manager_state riot_state;		/**< Context for RIoT key manager. */
	X509_TESTING_ENGINE (x509);						/**< X.509 engine for the RIoT keys. */
	struct keystore_mock keystore;					/**< Keystore mock */
	struct cmd_background_mock background;			/**< The background command interface mock. */
	struct attestation_responder_mock attestation;	/**< The attestation responder mock. */
	struct cmd_device_mock cmd_device;				/**< The device command handler mock instance. */
};


/**
 * RIoT keys for testing.
 */
static struct riot_keys keys = {
	.devid_cert = RIOT_CORE_DEVID_CERT,
	.devid_cert_length = 0,
	.devid_csr = RIOT_CORE_DEVID_CSR,
	.devid_csr_length = 0,
	.alias_key = RIOT_CORE_ALIAS_KEY,
	.alias_key_length = 0,
	.alias_cert = RIOT_CORE_ALIAS_CERT,
	.alias_cert_length = 0
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
	uint8_t *dev_id_der = NULL;

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

	status = cmd_device_mock_init (&cmd->cmd_device);
	CuAssertIntEquals (test, 0, status);

	status = attestation_responder_mock_init (&cmd->attestation);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_mock_init (&cmd->background);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd->keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->keystore.mock, cmd->keystore.base.load_key, &cmd->keystore,
		KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&cmd->keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&cmd->x509);
	CuAssertIntEquals (test, 0, status);

	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;
	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

	status = riot_key_manager_init_static_keys (&cmd->riot, &cmd->riot_state, &cmd->keystore.base,
		&keys, &cmd->x509.base, NULL, 0);
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
	struct cmd_interface_recovery_testing *cmd, const char *fw_version, size_t count)
{
	cmd_interface_recovery_testing_fw_version_list[0] = fw_version;
	cmd->fw_version.count = count;
	cmd->fw_version.id = cmd_interface_recovery_testing_fw_version_list;
}

/**
 * Helper function to initialize the device ids.
 *
 * @param cmd The instance to use for testing.
 */
static void setup_cmd_interface_recovery_mock_test_init_device_id (
	struct cmd_interface_recovery_testing *cmd)
{
	cmd->device_id.vendor_id = cmd_interface_recovery_test_vendor_id;
	cmd->device_id.device_id = cmd_interface_recovery_test_device_id;
	cmd->device_id.subsystem_vid = cmd_interface_recovery_test_subsystem_vid;
	cmd->device_id.subsystem_id = cmd_interface_recovery_test_subsystem_id;
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
	setup_cmd_interface_recovery_mock_test_init_device_id (cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

	status = cmd_interface_recovery_init (&cmd->handler, &cmd->attestation.base, &cmd->update.base,
		&cmd->device_manager, &cmd->background.base, &cmd->riot, &cmd->fw_version,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_device_id,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_subsystem_id,
		&cmd->cmd_device.base);

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
	status |= cmd_device_mock_validate_and_release (&cmd->cmd_device);
	status |= attestation_responder_mock_validate_and_release (&cmd->attestation);
	status |= cmd_background_mock_validate_and_release (&cmd->background);
	status |= keystore_mock_validate_and_release (&cmd->keystore);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&cmd->device_manager);

	cmd_interface_recovery_deinit (&cmd->handler);
	X509_TESTING_ENGINE_RELEASE (&cmd->x509);
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
	struct cmd_interface_recovery_testing cmd;
	const char *id[FW_VERSION_COUNT] = {RECOVERY_FW_VERSION};
	struct cmd_interface_fw_version fw_version = {
		.count = FW_VERSION_COUNT,
		.id = id
	};
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	status = cmd_interface_recovery_init (&cmd.handler, &cmd.attestation.base, &cmd.update.base,
		&cmd.device_manager, &cmd.background.base, &cmd.riot, &fw_version,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_device_id,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_subsystem_id,
		&cmd.cmd_device.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cmd.handler.base.process_request);
	CuAssertPtrNotNull (test, cmd.handler.base.process_response);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}


static void cmd_interface_recovery_test_init_null (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
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

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	debug_log = &debug.base;

	status = cmd_interface_recovery_init (NULL, &cmd.attestation.base, &cmd.update.base,
		&cmd.device_manager, &cmd.background.base, &cmd.riot, &fw_version,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_device_id,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_subsystem_id,
		&cmd.cmd_device.base);

	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_recovery_init (&cmd.handler, NULL, &cmd.update.base, &cmd.device_manager,
		&cmd.background.base, &cmd.riot, &fw_version, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_device_id, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_subsystem_id, &cmd.cmd_device.base);

	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_recovery_init (&cmd.handler, &cmd.attestation.base, NULL,
		&cmd.device_manager, &cmd.background.base, &cmd.riot, &fw_version,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_device_id,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_subsystem_id,
		&cmd.cmd_device.base);

	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_recovery_init (&cmd.handler, &cmd.attestation.base, &cmd.update.base,
		NULL, &cmd.background.base, &cmd.riot, &fw_version, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_device_id, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_subsystem_id, &cmd.cmd_device.base);

	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_recovery_init (&cmd.handler, &cmd.attestation.base, &cmd.update.base,
		&cmd.device_manager, NULL, &cmd.riot, &fw_version, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_device_id, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_subsystem_id, &cmd.cmd_device.base);

	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	status = cmd_interface_recovery_init (&cmd.handler, &cmd.attestation.base, &cmd.update.base,
		&cmd.device_manager, &cmd.background.base, NULL, &fw_version,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_device_id,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_subsystem_id,
		&cmd.cmd_device.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_recovery_init (&cmd.handler, &cmd.attestation.base, &cmd.update.base,
		&cmd.device_manager, &cmd.background.base, &cmd.riot, NULL, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_device_id, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_subsystem_id, &cmd.cmd_device.base);

	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = firmware_update_control_mock_validate_and_release (&update);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&debug);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_manager);
	complete_cmd_interface_recovery_mock_test (test, &cmd);

	debug_log = NULL;
}

static void cmd_interface_recovery_test_deinit_null (CuTest *test)
{
	TEST_START;

	cmd_interface_recovery_deinit (NULL);
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

static void cmd_interface_recovery_test_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

	CuAssertPtrNotNull (test, cmd.handler.base.process_request);
	CuAssertPtrNotNull (test, cmd.handler.base.process_response);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_null_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

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
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

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
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

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
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

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
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);
	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, NULL, FW_VERSION_COUNT);

	status = cmd_interface_recovery_init (&cmd.handler, &cmd.attestation.base, &cmd.update.base,
		&cmd.device_manager, &cmd.background.base, &cmd.riot, &cmd.fw_version,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_device_id,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_subsystem_id,
		&cmd.cmd_device.base);

	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_process_get_fw_version_unset_version (test,
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

static void cmd_interface_recovery_test_process_get_fw_version_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_fw_version_bad_count (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);
	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, NULL, 0);

	status = cmd_interface_recovery_init (&cmd.handler, &cmd.attestation.base, &cmd.update.base,
		&cmd.device_manager, &cmd.background.base, &cmd.riot, &cmd.fw_version,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_device_id,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, cmd_interface_recovery_test_subsystem_id,
		&cmd.cmd_device.base);

	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_process_get_fw_version_bad_count (test,
		&cmd.handler.base);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_no_key_exchange (
		test, &cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_aux_slot (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_aux_slot (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_limited_response (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_limited_response (
		test, &cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd = {
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

	cerberus_protocol_required_commands_testing_process_get_certificate_digest_aux_slot (test,
		&cmd.handler.base, &cmd.attestation);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_unsupported_slot (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_slot (
		test, &cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_unavailable_cert (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unavailable_cert (
		test, &cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_unsupported_algo (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_algo (
		test, &cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_invalid_slot (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_slot (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_digest_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_fail (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate (test, &cmd.handler.base,
		&cmd.attestation);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_length_0 (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_length_0 (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_aux_slot (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_aux_slot (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_limited_response (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_limited_response (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_invalid_offset (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_offset (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void
cmd_interface_recovery_test_process_get_certificate_valid_offset_and_length_beyond_cert_len (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_valid_offset_and_length_beyond_cert_len
		(test, &cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_length_too_big (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_length_too_big (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_unsupported_slot (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_slot (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_unsupported_cert (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_cert (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_unavailable_cert (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_unavailable_cert (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_invalid_slot_num (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_slot_num (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_certificate_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_fail (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_export_csr (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr (test, &cmd.handler.base,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_export_csr_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	struct cmd_interface_recovery test_static =
		cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base, &cmd.fw_version,
		0x1234, 20, 0x5678, 40, &cmd.attestation.base, &cmd.riot, &cmd.background.base,
		&cmd.cmd_device.base);

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

	cerberus_protocol_required_commands_testing_process_get_devid_csr (test, &test_static.base,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
	cmd_interface_recovery_deinit (&test_static);
}

static void cmd_interface_recovery_test_process_export_csr_invalid_buf_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_export_csr_unsupported_index (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_unsupported_index (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_export_csr_too_big (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big (test,
		&cmd.handler.base, &cmd.riot);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_export_csr_too_big_limited_response (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big_limited_response (
		test, &cmd.handler.base, RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}


static void cmd_interface_recovery_test_process_import_ca_signed_cert (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert (test,
		&cmd.handler.base, &cmd.keystore, &cmd.background);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_import_ca_signed_cert_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_import_ca_signed_cert_no_cert (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_no_cert (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_import_ca_signed_cert_bad_cert_length (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_bad_cert_length (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_import_ca_signed_cert_unsupported_index (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_unsupported_index (
		test, &cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_import_ca_signed_cert_authenticate_error (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_authenticate_error (
		test, &cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_signed_cert_state (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_signed_cert_state (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_signed_cert_state_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_signed_cert_state_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_device_info (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info (test, &cmd.handler.base,
		&cmd.cmd_device);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_device_info_limited_response (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info_limited_response (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_device_info_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_device_info_bad_info_index (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info_bad_info_index (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_device_info_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info_fail (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_reset_counter (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter (test, &cmd.handler.base,
		&cmd.cmd_device);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_reset_counter_port0 (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter_port0 (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_reset_counter_port1 (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter_port1 (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_reset_counter_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_reset_counter_invalid_counter (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter_invalid_counter (test,
		&cmd.handler.base, &cmd.cmd_device);
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
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

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
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

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

static void cmd_interface_recovery_test_process_get_challenge_response_no_session_mgr (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_no_session_mgr (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_challenge_response_key_exchange_not_requested (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_key_exchange_not_requested
		(test, &cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void
cmd_interface_recovery_test_process_get_challenge_response_limited_response_no_session_mgr (
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_no_session_mgr
		(test, &cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void
cmd_interface_recovery_test_process_get_challenge_response_limited_response_key_exchange_not_requested
(
	CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_key_exchange_not_requested
		(test, &cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_challenge_response_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_fail (test,
		&cmd.handler.base, &cmd.attestation);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_challenge_response_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_invalid_len (test,
		&cmd.handler.base);
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
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

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

static void cmd_interface_recovery_test_process_get_device_id (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_device_id *req = (struct cerberus_protocol_get_device_id*) data;
	struct cerberus_protocol_get_device_id_response *resp =
		(struct cerberus_protocol_get_device_id_response*) data;

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
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
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
	CuAssertIntEquals (test, cmd_interface_recovery_test_vendor_id, resp->vendor_id);
	CuAssertIntEquals (test, cmd_interface_recovery_test_device_id, resp->device_id);
	CuAssertIntEquals (test, cmd_interface_recovery_test_subsystem_vid, resp->subsystem_vid);
	CuAssertIntEquals (test, cmd_interface_recovery_test_subsystem_id, resp->subsystem_id);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_get_device_id_static_init (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;
	struct cmd_interface_recovery test_static =
		cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base, &cmd.fw_version,
		0x1234, 20, 0x5678, 40, &cmd.attestation.base, &cmd.riot, &cmd.background.base,
		&cmd.cmd_device.base);

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

	cerberus_protocol_required_commands_testing_process_get_device_id (test, &test_static.base,
		0x1234, 20, 0x5678, 40);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
	cmd_interface_recovery_deinit (&test_static);
}

static void cmd_interface_recovery_test_process_get_device_id_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_id_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

#ifdef CMD_ENABLE_STACK_STATS
static void cmd_interface_recovery_test_process_get_stack_stats (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	cerberus_protocol_diagnostic_commands_testing_process_stack_stats (test, &cmd.handler.base,
		&cmd.cmd_device);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_stack_stats_non_zero_offset (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	cerberus_protocol_diagnostic_commands_testing_process_stack_stats_non_zero_offset (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_stack_stats_invalid_len (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	cerberus_protocol_diagnostic_commands_testing_process_stack_stats_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_recovery_mock_test (test, &cmd);
}

static void cmd_interface_recovery_test_process_stack_stats_fail (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);

	cerberus_protocol_diagnostic_commands_testing_process_stack_stats_fail (test, &cmd.handler.base,
		&cmd.cmd_device);

	complete_cmd_interface_recovery_mock_test (test, &cmd);
}
#endif

static void cmd_interface_recovery_test_supports_all_required_commands (CuTest *test)
{
	struct cmd_interface_recovery_testing cmd;

	TEST_START;

	setup_cmd_interface_recovery_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_supports_all_required_commands (test,
		&cmd.handler.base, RECOVERY_FW_VERSION, &cmd.attestation, &cmd.device_manager,
		&cmd.background, &cmd.keystore, &cmd.cmd_device, RIOT_CORE_DEVID_CSR,
		RIOT_CORE_DEVID_CSR_LEN, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_device_id, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		cmd_interface_recovery_test_subsystem_id, NULL);
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
		.handler = cmd_interface_recovery_static_init (&cmd.device_manager, &cmd.update.base,
			&cmd.fw_version, cmd_interface_recovery_test_vendor_id,
			cmd_interface_recovery_test_device_id, cmd_interface_recovery_test_subsystem_vid,
			cmd_interface_recovery_test_subsystem_id, &cmd.attestation.base, &cmd.riot,
			&cmd.background.base, &cmd.cmd_device.base)
	};
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	setup_cmd_interface_recovery_mock_test_init (test, &cmd);
	setup_cmd_interface_recovery_mock_test_init_device_id (&cmd);

	setup_cmd_interface_recovery_mock_test_init_fw_version (&cmd, RECOVERY_FW_VERSION,
		FW_VERSION_COUNT);

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


// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_recovery);

TEST (cmd_interface_recovery_test_init);
TEST (cmd_interface_recovery_test_init_null);
TEST (cmd_interface_recovery_test_deinit_null);
TEST (cmd_interface_recovery_test_process_null);
TEST (cmd_interface_recovery_test_static_init);
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
TEST (cmd_interface_recovery_test_process_get_certificate_digest);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_aux_slot);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_unsupported_slot);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_unavailable_cert);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_limited_response);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_static_init);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_invalid_len);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_unsupported_algo);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_invalid_slot);
TEST (cmd_interface_recovery_test_process_get_certificate_digest_fail);
TEST (cmd_interface_recovery_test_process_get_certificate);
TEST (cmd_interface_recovery_test_process_get_certificate_length_0);
TEST (cmd_interface_recovery_test_process_get_certificate_aux_slot);
TEST (cmd_interface_recovery_test_process_get_certificate_limited_response);
TEST (cmd_interface_recovery_test_process_get_certificate_invalid_offset);
TEST (cmd_interface_recovery_test_process_get_certificate_valid_offset_and_length_beyond_cert_len);
TEST (cmd_interface_recovery_test_process_get_certificate_length_too_big);
TEST (cmd_interface_recovery_test_process_get_certificate_unsupported_slot);
TEST (cmd_interface_recovery_test_process_get_certificate_unsupported_cert);
TEST (cmd_interface_recovery_test_process_get_certificate_unavailable_cert);
TEST (cmd_interface_recovery_test_process_get_certificate_invalid_len);
TEST (cmd_interface_recovery_test_process_get_certificate_invalid_slot_num);
TEST (cmd_interface_recovery_test_process_get_certificate_fail);
TEST (cmd_interface_recovery_test_process_export_csr);
TEST (cmd_interface_recovery_test_process_export_csr_static_init);
TEST (cmd_interface_recovery_test_process_export_csr_invalid_buf_len);
TEST (cmd_interface_recovery_test_process_export_csr_unsupported_index);
TEST (cmd_interface_recovery_test_process_export_csr_too_big);
TEST (cmd_interface_recovery_test_process_export_csr_too_big_limited_response);
TEST (cmd_interface_recovery_test_process_import_ca_signed_cert);
TEST (cmd_interface_recovery_test_process_import_ca_signed_cert_invalid_len);
TEST (cmd_interface_recovery_test_process_import_ca_signed_cert_no_cert);
TEST (cmd_interface_recovery_test_process_import_ca_signed_cert_bad_cert_length);
TEST (cmd_interface_recovery_test_process_import_ca_signed_cert_unsupported_index);
TEST (cmd_interface_recovery_test_process_import_ca_signed_cert_authenticate_error);
TEST (cmd_interface_recovery_test_process_get_signed_cert_state);
TEST (cmd_interface_recovery_test_process_get_signed_cert_state_invalid_len);
TEST (cmd_interface_recovery_test_process_get_device_info);
TEST (cmd_interface_recovery_test_process_get_device_info_limited_response);
TEST (cmd_interface_recovery_test_process_get_device_info_invalid_len);
TEST (cmd_interface_recovery_test_process_get_device_info_bad_info_index);
TEST (cmd_interface_recovery_test_process_get_device_info_fail);
TEST (cmd_interface_recovery_test_process_reset_counter);
TEST (cmd_interface_recovery_test_process_reset_counter_port0);
TEST (cmd_interface_recovery_test_process_reset_counter_port1);
TEST (cmd_interface_recovery_test_process_reset_counter_invalid_len);
TEST (cmd_interface_recovery_test_process_reset_counter_invalid_counter);
TEST (cmd_interface_recovery_test_process_get_log_info);
TEST (cmd_interface_recovery_test_process_get_log_info_static_init);
TEST (cmd_interface_recovery_test_process_get_log_info_invalid_len);
TEST (cmd_interface_recovery_test_process_get_log_info_fail_debug);
TEST (cmd_interface_recovery_test_process_log_read_debug);
TEST (cmd_interface_recovery_test_process_log_read_debug_static_init);
TEST (cmd_interface_recovery_test_process_log_read_debug_limited_response);
TEST (cmd_interface_recovery_test_process_log_read_debug_fail);
TEST (cmd_interface_recovery_test_process_get_challenge_response_no_session_mgr);
TEST (cmd_interface_recovery_test_process_get_challenge_response_key_exchange_not_requested);
TEST (cmd_interface_recovery_test_process_get_challenge_response_limited_response_no_session_mgr);
TEST (cmd_interface_recovery_test_process_get_challenge_response_limited_response_key_exchange_not_requested);
TEST (cmd_interface_recovery_test_process_get_challenge_response_fail);
TEST (cmd_interface_recovery_test_process_get_challenge_response_invalid_len);
TEST (cmd_interface_recovery_test_process_get_capabilities);
TEST (cmd_interface_recovery_test_process_get_capabilities_static_init);
TEST (cmd_interface_recovery_test_process_get_capabilities_invalid_device);
TEST (cmd_interface_recovery_test_process_get_capabilities_invalid_len);
TEST (cmd_interface_recovery_test_process_get_device_id);
TEST (cmd_interface_recovery_test_process_get_device_id_static_init);
TEST (cmd_interface_recovery_test_process_get_device_id_invalid_len);
#ifdef CMD_ENABLE_STACK_STATS
TEST (cmd_interface_recovery_test_process_get_stack_stats);
TEST (cmd_interface_recovery_test_process_stack_stats_non_zero_offset);
TEST (cmd_interface_recovery_test_process_stack_stats_invalid_len);
TEST (cmd_interface_recovery_test_process_stack_stats_fail);
#endif
TEST (cmd_interface_recovery_test_supports_all_required_commands);
TEST (cmd_interface_recovery_test_process_response);
TEST (cmd_interface_recovery_test_process_response_static_init);
TEST (cmd_interface_recovery_test_process_response_null);

/* Tear down after the tests in this suite have run. */
TEST (cmd_interface_recovery_testing_suite_tear_down);

TEST_SUITE_END;
// *INDENT-ON*
