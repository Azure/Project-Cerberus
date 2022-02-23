// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "mctp/mctp_base_protocol.h"
#include "cmd_interface/cmd_interface_slave.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "cmd_interface/attestation_cmd_interface.h"
#include "testing/mock/attestation/attestation_slave_mock.h"
#include "testing/mock/cmd_interface/cmd_background_mock.h"
#include "testing/mock/cmd_interface/cmd_device_mock.h"
#include "testing/mock/cmd_interface/session_manager_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/cmd_interface/cmd_interface_system_testing.h"
#include "testing/cmd_interface/cerberus_protocol_required_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_optional_commands_testing.h"
#include "testing/crypto/x509_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("cmd_interface_slave");


/**
 * Dependencies for testing the slave command interface.
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
	struct session_manager_mock session;					/**< Session manager mock instance. */
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
 * Helper function to initialize a subset of the slave command interface parameters.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 * @param direction The device direction to set for the device manager table entry.
 */
static void setup_cmd_interface_slave_mock_test_init (CuTest *test,
	struct cmd_interface_slave_testing *cmd)
{
	uint8_t *dev_id_der = NULL;
	int status;

	status = device_manager_init (&cmd->device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager, 0, 
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager, 1, 
		MCTP_BASE_PROTOCOL_BMC_EID, 0);
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

	status = session_manager_mock_init (&cmd->session);
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
 * Helper function to setup the slave command interface.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 */
static void setup_cmd_interface_slave_mock_test (CuTest *test,
	struct cmd_interface_slave_testing *cmd)
{
	int status;

	setup_cmd_interface_slave_mock_test_init (test, cmd);

	setup_cmd_interface_slave_mock_test_init_fw_version (cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_slave_init (&cmd->handler, &cmd->slave_attestation.base,
		&cmd->device_manager, &cmd->background.base, &cmd->fw_version, &cmd->riot,
		&cmd->cmd_device.base, CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		4, &cmd->session.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to setup the slave command interface with a flag controlling inclusion of
 * session manager.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 * @param include_session Flag to include session manager.
 */
static void setup_cmd_interface_slave_mock_test_with_session_manager (CuTest *test,
	struct cmd_interface_slave_testing *cmd, bool include_session)
{
	struct session_manager *session_ptr = NULL;
	int status;

	setup_cmd_interface_slave_mock_test_init (test, cmd);

	setup_cmd_interface_slave_mock_test_init_fw_version (cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	if (include_session) {
		session_ptr = &cmd->session.base;
	}

	status = cmd_interface_slave_init (&cmd->handler, &cmd->slave_attestation.base,
		&cmd->device_manager, &cmd->background.base, &cmd->fw_version, &cmd->riot,
		&cmd->cmd_device.base, CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		4, session_ptr);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release the slave command interface instance.
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

	status = session_manager_mock_validate_and_release (&cmd->session);
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
		&background.base, &fw_version, &riot, &cmd_device.base, 0, 0, 0, 0, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, interface.base.process_request);
	CuAssertPtrNotNull (test, interface.base.process_response);
	CuAssertPtrNotNull (test, interface.base.generate_error_packet);

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
		&background.base, &fw_version, &riot, &cmd_device.base, 0, 0, 0, 0, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, NULL, &device_manager, &background.base,
		&fw_version, &riot, &cmd_device.base, 0, 0, 0, 0, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, NULL,
		&background.base, &fw_version, &riot, &cmd_device.base, 0, 0, 0, 0, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		NULL, &fw_version, &riot, &cmd_device.base, 0, 0, 0, 0, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		&background.base, NULL, &riot, &cmd_device.base, 0, 0, 0, 0, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		&background.base, &fw_version, NULL, &cmd_device.base, 0, 0, 0, 0, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_slave_init (&interface, &slave_attestation.base, &device_manager,
		&background.base, &fw_version, &riot, NULL, 0, 0, 0, 0, NULL);
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
	struct cmd_interface_msg request;
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
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

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
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	header->msg_type = 0x11;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = 0xAA;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_unknown_command (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = 0xFF;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_REQUEST, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_reserved_fields_not_zero (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 1;
	header->reserved2 = 0;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

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

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_encrypted_message (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	uint8_t encrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg encrypted_response;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	struct cerberus_protocol_reset_counter_response *resp =
		(struct cerberus_protocol_reset_counter_response*) data;
	struct cerberus_protocol_reset_counter *plaintext_rq =
		(struct cerberus_protocol_reset_counter*) decrypted_data;
	struct cerberus_protocol_reset_counter_response *plaintext_rsp =
		(struct cerberus_protocol_reset_counter_response*) response_data;
	struct cerberus_protocol_reset_counter_response *ciphertext_rsp =
		(struct cerberus_protocol_reset_counter_response*) encrypted_data;
	uint8_t encrypted_port = 0x33;
	uint8_t port = 0;
	uint8_t encrypted_type = 0xBB;
	uint8_t type = 0;
	uint16_t encrypted_counter = 0x1122;
	uint16_t counter = 4;
	int status;

	TEST_START;

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

	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	req->header.crypt = 1;

	req->type = encrypted_type;
	req->port = encrypted_port;
	request.length = sizeof (struct cerberus_protocol_reset_counter) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rq->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	plaintext_rq->header.crypt = 1;
	plaintext_rq->type = 0;

	decrypted_request.length = sizeof (struct cerberus_protocol_reset_counter);
	decrypted_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rsp->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	plaintext_rsp->header.crypt = 1;
	plaintext_rsp->counter = counter;

	response.length = sizeof (struct cerberus_protocol_reset_counter_response);
	response.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	ciphertext_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	ciphertext_rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	ciphertext_rsp->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	ciphertext_rsp->header.crypt = 1;
	ciphertext_rsp->counter = encrypted_counter;

	encrypted_response.length = sizeof (struct cerberus_protocol_reset_counter_response) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	encrypted_response.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	encrypted_response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted_response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, true);

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message, &cmd.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.session.mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cmd_device.mock, cmd.cmd_device.base.get_reset_counter,
		&cmd.cmd_device, 0,	MOCK_ARG (type), MOCK_ARG (port), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.cmd_device.mock, 2, &counter, sizeof (uint16_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.session.mock, cmd.session.base.encrypt_message,
		&cmd.session, 0, MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request,
			&response, sizeof (response), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request, cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.session.mock, 0, &encrypted_response,
		sizeof (encrypted_response), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_reset_counter_response) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 1, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_COUNTER, resp->header.command);
	CuAssertIntEquals (test, encrypted_counter, resp->counter);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_encrypted_message_decrypt_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	uint8_t encrypted_port = 0x33;
	uint8_t encrypted_type = 0xBB;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	req->header.crypt = 1;

	req->type = encrypted_type;
	req->port = encrypted_port;
	request.length = sizeof (struct cerberus_protocol_reset_counter) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, true);

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message,
		&cmd.session, SESSION_MANAGER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_encrypted_message_encrypt_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	struct cerberus_protocol_reset_counter *plaintext_rq =
		(struct cerberus_protocol_reset_counter*) decrypted_data;
	struct cerberus_protocol_reset_counter_response *plaintext_rsp =
		(struct cerberus_protocol_reset_counter_response*) response_data;
	uint8_t encrypted_port = 0x33;
	uint8_t port = 0;
	uint8_t encrypted_type = 0xBB;
	uint8_t type = 0;
	uint16_t counter = 4;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	req->header.crypt = 1;

	req->type = encrypted_type;
	req->port = encrypted_port;
	request.length = sizeof (struct cerberus_protocol_reset_counter) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rq->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	plaintext_rq->header.crypt = 1;
	plaintext_rq->type = 0;

	decrypted_request.length = sizeof (struct cerberus_protocol_reset_counter);
	decrypted_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rsp->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	plaintext_rsp->header.crypt = 1;
	plaintext_rsp->counter = counter;

	response.length = sizeof (struct cerberus_protocol_reset_counter_response);
	response.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, true);

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message, &cmd.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.session.mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cmd_device.mock, cmd.cmd_device.base.get_reset_counter,
		&cmd.cmd_device, 0,	MOCK_ARG (type), MOCK_ARG (port), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.cmd_device.mock, 2, &counter, sizeof (uint16_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.session.mock, cmd.session.base.encrypt_message,
		&cmd.session, SESSION_MANAGER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_encrypted_message_no_session_manager (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_reset_counter *req = (struct cerberus_protocol_reset_counter*) data;
	uint8_t encrypted_port = 0x33;
	uint8_t encrypted_type = 0xBB;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_RESET_COUNTER;
	req->header.crypt = 1;

	req->type = encrypted_type;
	req->port = encrypted_port;
	request.length = sizeof (struct cerberus_protocol_reset_counter);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, false);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_ENCRYPTION_UNSUPPORTED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_encrypted_message_no_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	struct cerberus_protocol_import_certificate *req =
		(struct cerberus_protocol_import_certificate*) data;
	struct cerberus_protocol_import_certificate *plaintext_rq =
		(struct cerberus_protocol_import_certificate*) decrypted_data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (decrypted_request));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;
	req->header.crypt = 1;

	req->index = 0xAA;
	req->cert_length = 0xBB;
	request.length = sizeof (struct cerberus_protocol_import_certificate) +
		X509_CERTSS_RSA_CA_NOPL_DER_LEN - 1 + CERBERUS_PROTOCOL_AES_GCM_TAG_LEN +
		CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	plaintext_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rq->header.command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;
	plaintext_rq->header.crypt = 1;

	plaintext_rq->index = 1;
	plaintext_rq->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&plaintext_rq->certificate, X509_CERTSS_RSA_CA_NOPL_DER,
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	decrypted_request.length = sizeof (struct cerberus_protocol_import_certificate) +
		X509_CERTSS_RSA_CA_NOPL_DER_LEN - 1;
	decrypted_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message, &cmd.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.session.mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.keystore.mock, cmd.keystore.base.save_key, &cmd.keystore, 0,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER,
		X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));
	status |= mock_expect (&cmd.background.mock, cmd.background.base.authenticate_riot_certs,
		&cmd.background, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

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

	setup_cmd_interface_slave_mock_test_init (test, &cmd);

	setup_cmd_interface_slave_mock_test_init_fw_version (&cmd, NULL,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_slave_init (&cmd.handler, &cmd.slave_attestation.base,
		&cmd.device_manager, &cmd.background.base, &cmd.fw_version, &cmd.riot, &cmd.cmd_device.base,
		0, 0, 0, 0, NULL);
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

	setup_cmd_interface_slave_mock_test_init (test, &cmd);

	setup_cmd_interface_slave_mock_test_init_fw_version (&cmd, NULL, RIOT_CORE_VERSION, 0);

	status = cmd_interface_slave_init (&cmd.handler, &cmd.slave_attestation.base,
		&cmd.device_manager, &cmd.background.base, &cmd.fw_version, &cmd.riot, &cmd.cmd_device.base,
		0, 0, 0, 0, NULL);
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
		&cmd.handler.base, &cmd.slave_attestation, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_digest_aux_slot (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_aux_slot (test,
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

static void cmd_interface_slave_test_process_get_certificate_digest_unsupported_slot (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_slot (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_digest_unavailable_cert (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unavailable_cert (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_digest_encryption_unsupported (
	CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, false);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_encryption_unsupported (
		test, &cmd.handler.base);
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

static void cmd_interface_slave_test_process_get_certificate_digest_invalid_slot (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_slot (
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

static void cmd_interface_slave_test_process_get_certificate_aux_slot (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_aux_slot (test,
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

static void cmd_interface_slave_test_process_get_certificate_unsupported_slot (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_slot (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_unsupported_cert (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_cert (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_certificate_unavailable_cert (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_unavailable_cert (test,
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

static void cmd_interface_slave_test_process_get_certificate_invalid_slot_num (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_slot_num (test,
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

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response (test,
		&cmd.handler.base, &cmd.slave_attestation, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response_no_session_mgr (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, false);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_no_session_mgr (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response_key_exchange_not_requested (
	CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_key_exchange_not_requested (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response_limited_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response (
		test, &cmd.handler.base, &cmd.slave_attestation, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response_limited_response_no_session_mgr (
	CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, false);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_no_session_mgr (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_get_challenge_response_limited_response_key_exchange_not_requested (
	CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_key_exchange_not_requested (
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

static void cmd_interface_slave_test_process_key_exchange_type_0 (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_0 (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_type_0_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_0_fail (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_type_1 (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1 (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_type_1_unencrypted (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1_unencrypted (
		test, &cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_type_1_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1_fail (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_type_2 (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2 (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_type_2_unencrypted (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2_unencrypted (
		test, &cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_type_2_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2_fail (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_unsupported (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test_with_session_manager (test, &cmd, false);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_unsupported (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_unsupported_index (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_unsupported_index (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_key_exchange_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_session_sync (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_session_sync (test,	&cmd.handler.base,
		&cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_session_sync_no_session_mgr (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_slave_mock_test_init (test, &cmd);

	setup_cmd_interface_slave_mock_test_init_fw_version (&cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_slave_init (&cmd.handler, &cmd.slave_attestation.base,
		&cmd.device_manager, &cmd.background.base, &cmd.fw_version, &cmd.riot,
		&cmd.cmd_device.base, CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		4, NULL);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_optional_commands_testing_process_session_sync_no_session_mgr (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_session_sync_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_session_sync_fail (test, &cmd.handler.base,
		&cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_session_sync_unencrypted (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_session_sync_unencrypted (test,
		&cmd.handler.base);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_session_sync_invalid_len (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_optional_commands_testing_process_session_sync_invalid_len (test,
		&cmd.handler.base, &cmd.session);
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
		4, &cmd.session);
	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_process_response (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_generate_error_packet (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_required_commands_testing_generate_error_packet (test, &cmd.handler.base);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_generate_error_packet_encrypted (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_required_commands_testing_generate_error_packet_encrypted (test,
		&cmd.handler.base, &cmd.session);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_generate_error_packet_encrypted_fail (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_required_commands_testing_generate_error_packet_encrypted_fail (test,
		&cmd.handler.base, &cmd.session);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}

static void cmd_interface_slave_test_generate_error_packet_invalid_arg (CuTest *test)
{
	struct cmd_interface_slave_testing cmd;

	TEST_START;

	setup_cmd_interface_slave_mock_test (test, &cmd);

	cerberus_protocol_required_commands_testing_generate_error_packet_invalid_arg (test,
		&cmd.handler.base);

	complete_cmd_interface_slave_mock_test (test, &cmd);
}


TEST_SUITE_START (cmd_interface_slave);

TEST (cmd_interface_slave_test_init);
TEST (cmd_interface_slave_test_init_null);
TEST (cmd_interface_slave_test_deinit_null);
TEST (cmd_interface_slave_test_process_null);
TEST (cmd_interface_slave_test_process_payload_too_short);
TEST (cmd_interface_slave_test_process_unsupported_message);
TEST (cmd_interface_slave_test_process_unknown_command);
TEST (cmd_interface_slave_test_process_reserved_fields_not_zero);
TEST (cmd_interface_slave_test_process_encrypted_message);
TEST (cmd_interface_slave_test_process_encrypted_message_decrypt_fail);
TEST (cmd_interface_slave_test_process_encrypted_message_encrypt_fail);
TEST (cmd_interface_slave_test_process_encrypted_message_no_session_manager);
TEST (cmd_interface_slave_test_process_encrypted_message_no_response);
TEST (cmd_interface_slave_test_process_get_fw_version);
TEST (cmd_interface_slave_test_process_get_fw_version_unset_version);
TEST (cmd_interface_slave_test_process_get_fw_version_unsupported_area);
TEST (cmd_interface_slave_test_process_get_fw_version_invalid_len);
TEST (cmd_interface_slave_test_process_get_fw_version_riot);
TEST (cmd_interface_slave_test_process_get_fw_version_bad_count);
TEST (cmd_interface_slave_test_process_get_certificate_digest);
TEST (cmd_interface_slave_test_process_get_certificate_digest_aux_slot);
TEST (cmd_interface_slave_test_process_get_certificate_digest_unsupported_slot);
TEST (cmd_interface_slave_test_process_get_certificate_digest_unavailable_cert);
TEST (cmd_interface_slave_test_process_get_certificate_digest_limited_response);
TEST (cmd_interface_slave_test_process_get_certificate_digest_invalid_len);
TEST (cmd_interface_slave_test_process_get_certificate_digest_unsupported_algo);
TEST (cmd_interface_slave_test_process_get_certificate_digest_encryption_unsupported);
TEST (cmd_interface_slave_test_process_get_certificate_digest_invalid_slot);
TEST (cmd_interface_slave_test_process_get_certificate_digest_fail);
TEST (cmd_interface_slave_test_process_get_certificate);
TEST (cmd_interface_slave_test_process_get_certificate_length_0);
TEST (cmd_interface_slave_test_process_get_certificate_aux_slot);
TEST (cmd_interface_slave_test_process_get_certificate_limited_response);
TEST (cmd_interface_slave_test_process_get_certificate_invalid_offset);
TEST (cmd_interface_slave_test_process_get_certificate_valid_offset_and_length_beyond_cert_len);
TEST (cmd_interface_slave_test_process_get_certificate_length_too_big);
TEST (cmd_interface_slave_test_process_get_certificate_unsupported_slot);
TEST (cmd_interface_slave_test_process_get_certificate_unsupported_cert);
TEST (cmd_interface_slave_test_process_get_certificate_unavailable_cert);
TEST (cmd_interface_slave_test_process_get_certificate_invalid_len);
TEST (cmd_interface_slave_test_process_get_certificate_invalid_slot_num);
TEST (cmd_interface_slave_test_process_get_certificate_fail);
TEST (cmd_interface_slave_test_process_get_challenge_response);
TEST (cmd_interface_slave_test_process_get_challenge_response_no_session_mgr);
TEST (cmd_interface_slave_test_process_get_challenge_response_key_exchange_not_requested);
TEST (cmd_interface_slave_test_process_get_challenge_response_limited_response);
TEST (cmd_interface_slave_test_process_get_challenge_response_limited_response_no_session_mgr);
TEST (cmd_interface_slave_test_process_get_challenge_response_limited_response_key_exchange_not_requested);
TEST (cmd_interface_slave_test_process_get_challenge_response_fail);
TEST (cmd_interface_slave_test_process_get_challenge_response_invalid_len);
TEST (cmd_interface_slave_test_process_get_capabilities);
TEST (cmd_interface_slave_test_process_get_capabilities_invalid_device);
TEST (cmd_interface_slave_test_process_get_capabilities_invalid_len);
TEST (cmd_interface_slave_test_process_get_devid_csr);
TEST (cmd_interface_slave_test_process_get_devid_csr_invalid_buf_len);
TEST (cmd_interface_slave_test_process_get_devid_csr_unsupported_index);
TEST (cmd_interface_slave_test_process_get_devid_csr_too_big);
TEST (cmd_interface_slave_test_process_get_devid_csr_too_big_limited_response);
TEST (cmd_interface_slave_test_process_import_signed_dev_id_cert);
TEST (cmd_interface_slave_test_process_import_root_ca_cert);
TEST (cmd_interface_slave_test_process_import_intermediate_cert);
TEST (cmd_interface_slave_test_process_import_signed_ca_cert_invalid_len);
TEST (cmd_interface_slave_test_process_import_signed_ca_cert_no_cert);
TEST (cmd_interface_slave_test_process_import_signed_ca_cert_bad_cert_length);
TEST (cmd_interface_slave_test_process_import_signed_ca_cert_unsupported_index);
TEST (cmd_interface_slave_test_process_import_signed_dev_id_cert_save_error);
TEST (cmd_interface_slave_test_process_import_root_ca_cert_save_error);
TEST (cmd_interface_slave_test_process_import_intermediate_cert_save_error);
TEST (cmd_interface_slave_test_process_import_signed_ca_cert_authenticate_error);
TEST (cmd_interface_slave_test_process_get_signed_cert_state);
TEST (cmd_interface_slave_test_process_get_signed_cert_state_invalid_len);
TEST (cmd_interface_slave_test_process_get_device_info);
TEST (cmd_interface_slave_test_process_get_device_info_limited_response);
TEST (cmd_interface_slave_test_process_get_device_info_invalid_len);
TEST (cmd_interface_slave_test_process_get_device_info_bad_info_index);
TEST (cmd_interface_slave_test_process_get_device_info_fail);
TEST (cmd_interface_slave_test_process_get_device_id);
TEST (cmd_interface_slave_test_process_get_device_id_invalid_len);
TEST (cmd_interface_slave_test_process_reset_counter);
TEST (cmd_interface_slave_test_process_reset_counter_port0);
TEST (cmd_interface_slave_test_process_reset_counter_port1);
TEST (cmd_interface_slave_test_process_reset_counter_invalid_len);
TEST (cmd_interface_slave_test_process_reset_counter_invalid_counter);
TEST (cmd_interface_slave_test_process_key_exchange_type_0);
TEST (cmd_interface_slave_test_process_key_exchange_type_0_fail);
TEST (cmd_interface_slave_test_process_key_exchange_type_1);
TEST (cmd_interface_slave_test_process_key_exchange_type_1_unencrypted);
TEST (cmd_interface_slave_test_process_key_exchange_type_1_fail);
TEST (cmd_interface_slave_test_process_key_exchange_type_2);
TEST (cmd_interface_slave_test_process_key_exchange_type_2_unencrypted);
TEST (cmd_interface_slave_test_process_key_exchange_type_2_fail);
TEST (cmd_interface_slave_test_process_key_exchange_unsupported);
TEST (cmd_interface_slave_test_process_key_exchange_unsupported_index);
TEST (cmd_interface_slave_test_process_key_exchange_invalid_len);
TEST (cmd_interface_slave_test_process_session_sync);
TEST (cmd_interface_slave_test_process_session_sync_no_session_mgr);
TEST (cmd_interface_slave_test_process_session_sync_fail);
TEST (cmd_interface_slave_test_process_session_sync_unencrypted);
TEST (cmd_interface_slave_test_process_session_sync_invalid_len);
TEST (cmd_interface_slave_test_supports_all_required_commands);
TEST (cmd_interface_slave_test_process_response);
TEST (cmd_interface_slave_test_generate_error_packet);
TEST (cmd_interface_slave_test_generate_error_packet_encrypted);
TEST (cmd_interface_slave_test_generate_error_packet_encrypted_fail);
TEST (cmd_interface_slave_test_generate_error_packet_invalid_arg);

TEST_SUITE_END;
