// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "x509_testing.h"
#include "mctp/mctp_protocol.h"
#include "cmd_interface/cmd_interface_slave.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "cmd_interface/attestation_cmd_interface.h"
#include "mock/attestation_slave_mock.h"
#include "mock/cmd_background_mock.h"
#include "mock/keystore_mock.h"
#include "mock/rng_mock.h"
#include "mock/ecc_mock.h"
#include "mock/rsa_mock.h"
#include "engines/x509_testing_engine.h"
#include "riot_core_testing.h"
#include "mock/signature_verification_mock.h"
#include "mock/x509_mock.h"
#include "mock/flash_mock.h"
#include "mock/cmd_device_mock.h"
#include "cmd_interface_system_testing.h"
#include "cerberus_protocol_required_commands_testing.h"


static const char *SUITE = "cmd_interface_slave";


/**
 * Dependencies for testing the system command interface.
 */
struct cmd_interface_slave_testing {
	struct cmd_interface_slave handler;						/**< Command handler instance. */
	struct attestation_slave_mock slave_attestation;		/**< The slave attestation manager mock. */
	struct keystore_mock keystore;							/**< RIoT keystore. */
	struct x509_engine_mock x509_mock;						/**< The X.509 engine mock for the RIoT keys. */
	X509_TESTING_ENGINE x509;								/**< X.509 engine for the RIoT keys. */
	struct signature_verification_mock verification;		/**< The signature verification mock. */
	struct cmd_background_mock background;					/**< The background command interface mock. */
	struct device_manager device_manager;					/**< Device manager. */
	struct riot_key_manager riot;							/**< RIoT keys manager. */
	struct cmd_interface_fw_version fw_version;				/**< The firmware version data. */
	struct cmd_device_mock cmd_device;						/**< The device command handler mock instance. */
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
 * Helper function to initialize a subset of the system command interface parameters.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 * @param direction The device direction to set for the device manager table entry.
 */
static void setup_cmd_interface_slave_mock_test_init (CuTest *test,
	struct cmd_interface_slave_testing *cmd, uint8_t direction)
{
	uint8_t *dev_id_der = NULL;
	int status;

	status = device_manager_init (&cmd->device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager, 0, DEVICE_MANAGER_SELF,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager, 1, direction,
		MCTP_PROTOCOL_BMC_EID, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_mock_init (&cmd->background);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_init (&cmd->slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&cmd->x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&cmd->keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd->keystore.mock, cmd->keystore.base.load_key, &cmd->keystore,
		KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&cmd->keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;
	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

	status = riot_key_manager_init_static (&cmd->riot, &cmd->keystore.base, &keys, &cmd->x509.base);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd->x509_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&cmd->verification);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&cmd->cmd_device);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to initialize the firmware version strings.
 *
 * @param cmd The instance to use for testing.
 * @param fw_version The Cerberus firmware version to initialize.
 * @param riot_core_version The RIoT core version to initialize.
 * @param count The number of firmware versions.
 */
static void setup_cmd_interface_slave_mock_test_init_fw_version (
	struct cmd_interface_slave_testing *cmd, const char *fw_version, const char *riot_core_version,
	size_t count)
{
	fw_version_list[0] = fw_version;
	fw_version_list[1] = riot_core_version;
	cmd->fw_version.count = count;
	cmd->fw_version.id = fw_version_list;
}

/**
 * Helper function to setup the system command interface.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 */
static void setup_cmd_interface_slave_mock_test (CuTest *test,
	struct cmd_interface_slave_testing *cmd)
{
	int status;

	setup_cmd_interface_slave_mock_test_init (test, cmd, DEVICE_MANAGER_UPSTREAM);

	setup_cmd_interface_slave_mock_test_init_fw_version (cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_slave_init (&cmd->handler, &cmd->slave_attestation.base,
		&cmd->device_manager, &cmd->background.base, &cmd->fw_version, &cmd->riot,
		&cmd->cmd_device.base, CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		4);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release the system command interface instance.
 *
 * @param test The test framework.
 * @param cmd The testing instance to release.
 */
 static void complete_cmd_interface_slave_mock_test (CuTest *test,
	struct cmd_interface_slave_testing *cmd)
{
	int status = cmd_background_mock_validate_and_release (&cmd->background);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_validate_and_release (&cmd->slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&cmd->keystore);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&cmd->x509_mock);
	CuAssertIntEquals (test, 0, status);

	signature_verification_mock_release (&cmd->verification);

	status = cmd_device_mock_validate_and_release (&cmd->cmd_device);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&cmd->device_manager);

	riot_key_manager_release (&cmd->riot);
	X509_TESTING_ENGINE_RELEASE (&cmd->x509);

	cmd_interface_slave_deinit (&cmd->handler);
}

/*******************
 * Test cases
 *******************/

static void cmd_interface_slave_test_init (CuTest *test)
{
	struct cmd_interface_slave interface;
	struct attestation_slave_mock slave_attestation;
	struct cmd_background_mock background;
	struct device_manager device_manager;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct cmd_device_mock cmd_device;
	X509_TESTING_ENGINE x509;
	uint8_t *dev_id_der = NULL;
	const char *id[FW_VERSION_COUNT] = {CERBERUS_FW_VERSION, RIOT_CORE_VERSION};
	struct cmd_interface_fw_version fw_version = {.count = FW_VERSION_COUNT, .id = id};
	int status;

	TEST_START;

	status = cmd_background_mock_init (&background);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
	MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);

	CuAssertIntEquals (test, 0, status);

	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;
	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_init (&slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		&background.base, &fw_version, &riot, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, interface.base.process_request);
	CuAssertPtrNotNull (test, interface.base.issue_request);

	status = cmd_background_mock_validate_and_release (&background);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_validate_and_release (&slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_validate_and_release (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_manager);

	riot_key_manager_release (&riot);
	X509_TESTING_ENGINE_RELEASE (&x509);

	cmd_interface_slave_deinit (&interface);
}

static void cmd_interface_slave_test_init_null (CuTest *test)
{
	struct cmd_interface_slave interface;
	struct attestation_slave_mock slave_attestation;
	struct cmd_background_mock background;
	struct device_manager device_manager;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct cmd_device_mock cmd_device;
	X509_TESTING_ENGINE x509;
	uint8_t *dev_id_der = NULL;
	const char *id[FW_VERSION_COUNT] = {CERBERUS_FW_VERSION, RIOT_CORE_VERSION};
	struct cmd_interface_fw_version fw_version = {.count = FW_VERSION_COUNT, .id = id};
	int status;

	TEST_START;

	status = cmd_background_mock_init (&background);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
	MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);

	CuAssertIntEquals (test, 0, status);

	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;
	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_init (&slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_slave_init (NULL, &slave_attestation.base, &device_manager,
		&background.base, &fw_version, &riot, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, NULL, &device_manager, &background.base,
		&fw_version, &riot, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, NULL,
		&background.base, &fw_version, &riot, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		NULL, &fw_version, &riot, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		&background.base, NULL, &riot, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		&background.base, &fw_version, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		&background.base, &fw_version, &riot, NULL, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_background_mock_validate_and_release (&background);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_validate_and_release (&slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_validate_and_release (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_manager);

	riot_key_manager_release (&riot);
	X509_TESTING_ENGINE_RELEASE (&x509);

	cmd_interface_slave_deinit (&interface);
}

static void cmd_interface_slave_test_deinit_null (CuTest *test)
{
	TEST_START;

	cmd_interface_slave_deinit (NULL);
}

static void cmd_interface_slave_test_process_null (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	struct cmd_interface_request request;
	int status;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cmd.handler.base.process_request (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_payload_too_short (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	struct cmd_interface_request request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_unsupported_message (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = 0x11;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = 0xAA;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.crypt = 1;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_unknown_command (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = 0xFF;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_unknown_device (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_DIGEST;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = 0xEE;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_error_packet (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	error->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	error->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	error->header.command = CERBERUS_PROTOCOL_ERROR;

	request.length = sizeof (struct cerberus_protocol_error);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_fw_version (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version (test, &cmd.handler.base,
		CERBERUS_FW_VERSION);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_fw_version_unset_version (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_slave_mock_test_init (test, &cmd, DEVICE_MANAGER_UPSTREAM);

	setup_cmd_interface_slave_mock_test_init_fw_version (&cmd, NULL,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_slave_init (&cmd.handler, &cmd.slave_attestation.base,
		&cmd.device_manager, &cmd.background.base, &cmd.fw_version, &cmd.riot, &cmd.cmd_device.base,
		0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_process_get_fw_version_unset_version (test,
		&cmd.handler.base);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_fw_version_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_fw_version_unsupported_area (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version_unsupported_area (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_fw_version_riot (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_fw_version_riot (test,
		&cmd.handler.base, RIOT_CORE_VERSION);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_fw_version_bad_count (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_slave_mock_test_init (test, &cmd, DEVICE_MANAGER_UPSTREAM);

	setup_cmd_interface_slave_mock_test_init_fw_version (&cmd, NULL, RIOT_CORE_VERSION, 0);

	status = cmd_interface_slave_init (&cmd.handler, &cmd.slave_attestation.base,
		&cmd.device_manager, &cmd.background.base, &cmd.fw_version, &cmd.riot, &cmd.cmd_device.base,
		0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_process_get_fw_version_bad_count (test,
		&cmd.handler.base);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_digest (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_digest_limited_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_limited_response (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_digest_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_digest_unsupported_algo (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_algo (
		test, &cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_digest_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_fail (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate (test, &cmd.handler.base,
		&cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_length_0 (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_length_0 (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_limited_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_limited_response (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_invalid_offset (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_offset (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_valid_offset_and_length_beyond_cert_len (
	CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_valid_offset_and_length_beyond_cert_len (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_length_too_big (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_length_too_big (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_unsupported_slot_num (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_slot_num (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_fail (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response_limited_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_fail (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_capabilities (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_capabilities (test, &cmd.handler.base,
		&cmd.device_manager);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_capabilities_invalid_device (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_device (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_capabilities_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_devid_csr (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr (test, &cmd.handler.base,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_devid_csr_invalid_buf_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_devid_csr_unsupported_index (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_unsupported_index (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_devid_csr_too_big (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big (test,
		&cmd.handler.base, &cmd.riot);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_devid_csr_too_big_limited_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big_limited_response (
		test, &cmd.handler.base, RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_signed_dev_id_cert (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert (test,
		&cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_root_ca_cert (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_root_ca_cert (test,
		&cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_intermediate_cert (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_intermediate_cert (test,
		&cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_signed_ca_cert_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_signed_ca_cert_no_cert (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_no_cert (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_signed_ca_cert_bad_cert_length (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_bad_cert_length (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_signed_ca_cert_unsupported_index (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_unsupported_index (
		test, &cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_signed_dev_id_cert_save_error (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert_save_error (test,
		&cmd.handler.base, &cmd.keystore);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_root_ca_cert_save_error (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_root_ca_cert_save_error (test,
		&cmd.handler.base, &cmd.keystore);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_intermediate_cert_save_error (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_intermediate_cert_save_error (test,
		&cmd.handler.base, &cmd.keystore);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_import_signed_ca_cert_authenticate_error (
	CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_authenticate_error (
		test, &cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_signed_cert_state (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_signed_cert_state (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_signed_cert_state_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_signed_cert_state_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_device_info (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info (test, &cmd.handler.base,
		&cmd.cmd_device);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_device_info_limited_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info_limited_response (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_device_info_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_device_info_bad_info_index (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info_bad_info_index (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_device_info_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_info_fail (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_device_id (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_id (test, &cmd.handler.base,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID, 4);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_device_id_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_device_id_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_reset_counter (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter (test, &cmd.handler.base,
		&cmd.cmd_device);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_reset_counter_port0 (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter_port0 (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_reset_counter_port1 (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter_port1 (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_reset_counter_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_reset_counter_invalid_counter (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_reset_counter_invalid_counter (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_supports_all_required_commands (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_supports_all_required_commands (test,
		&cmd.handler.base, CERBERUS_FW_VERSION, &cmd.slave_attestation, &cmd.device_manager,
		&cmd.background, &cmd.keystore, &cmd.cmd_device, RIOT_CORE_DEVID_CSR,
		RIOT_CORE_DEVID_CSR_LEN, CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		4);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_issue_request_unsupported (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}


CuSuite* get_cmd_interface_slave_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, cmd_interface_slave_test_init);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_init_null);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_deinit_null);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_null);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_payload_too_short);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_unsupported_message);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_unknown_command);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_unknown_device);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_error_packet);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_fw_version);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_fw_version_unset_version);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_fw_version_unsupported_area);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_fw_version_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_fw_version_riot);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_fw_version_bad_count);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_digest);
	SUITE_ADD_TEST (suite,
		cmd_interface_slave_test_process_get_certificate_digest_limited_response);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_digest_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_slave_test_process_get_certificate_digest_unsupported_algo);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_digest_fail);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_length_0);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_limited_response);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_invalid_offset);
	SUITE_ADD_TEST (suite,
		cmd_interface_slave_test_process_get_certificate_valid_offset_and_length_beyond_cert_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_length_too_big);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_unsupported_slot_num);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_certificate_fail);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_challenge_response);
	SUITE_ADD_TEST (suite,
		cmd_interface_slave_test_process_get_challenge_response_limited_response);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_challenge_response_fail);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_challenge_response_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_capabilities);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_capabilities_invalid_device);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_capabilities_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_devid_csr);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_devid_csr_invalid_buf_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_devid_csr_unsupported_index);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_devid_csr_too_big);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_devid_csr_too_big_limited_response);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_signed_dev_id_cert);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_root_ca_cert);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_intermediate_cert);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_signed_ca_cert_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_signed_ca_cert_no_cert);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_signed_ca_cert_bad_cert_length);
	SUITE_ADD_TEST (suite,
		cmd_interface_slave_test_process_import_signed_ca_cert_unsupported_index);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_signed_dev_id_cert_save_error);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_root_ca_cert_save_error);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_import_intermediate_cert_save_error);
	SUITE_ADD_TEST (suite,
		cmd_interface_slave_test_process_import_signed_ca_cert_authenticate_error);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_signed_cert_state);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_signed_cert_state_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_device_info);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_device_info_limited_response);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_device_info_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_device_info_bad_info_index);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_device_info_fail);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_device_id);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_get_device_id_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_reset_counter);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_reset_counter_port0);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_reset_counter_port1);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_reset_counter_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_process_reset_counter_invalid_counter);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_supports_all_required_commands);
	SUITE_ADD_TEST (suite, cmd_interface_slave_test_issue_request_unsupported);

	return suite;
}
