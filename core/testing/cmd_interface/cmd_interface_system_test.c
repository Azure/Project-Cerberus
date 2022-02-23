// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "mctp/mctp_base_protocol.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cmd_interface_system.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "cmd_interface/cerberus_protocol_optional_commands.h"
#include "cmd_interface/attestation_cmd_interface.h"
#include "logging/logging_flash.h"
#include "logging/debug_log.h"
#include "attestation/pcr_store.h"
#include "recovery/recovery_image_header.h"
#include "testing/mock/attestation/attestation_master_mock.h"
#include "testing/mock/attestation/attestation_slave_mock.h"
#include "testing/mock/cmd_interface/cmd_authorization_mock.h"
#include "testing/mock/cmd_interface/cmd_background_mock.h"
#include "testing/mock/cmd_interface/cmd_device_mock.h"
#include "testing/mock/cmd_interface/session_manager_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/cerberus_protocol_observer_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/mock/firmware/firmware_update_control_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/host_fw/host_processor_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/manifest_cmd_interface_mock.h"
#include "testing/mock/manifest/pfm_manager_mock.h"
#include "testing/mock/manifest/cfm_manager_mock.h"
#include "testing/mock/manifest/pcd_manager_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/manifest/cfm_mock.h"
#include "testing/mock/manifest/pcd_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/recovery/recovery_image_mock.h"
#include "testing/mock/recovery/recovery_image_cmd_interface_mock.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/cmd_interface/cmd_interface_system_testing.h"
#include "testing/cmd_interface/cerberus_protocol_required_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_master_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_optional_commands_testing.h"
#include "testing/cmd_interface/cerberus_protocol_debug_commands_testing.h"
#include "testing/crypto/x509_testing.h"
#include "testing/recovery/recovery_image_header_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("cmd_interface_system");


/**
 * Unique chip identifier.
 */
uint8_t CMD_DEVICE_UUID[] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
    0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38
};

/**
 * Length of unique chip identifier in bytes.
 */
const size_t CMD_DEVICE_UUID_LEN = sizeof (CMD_DEVICE_UUID);

/**
 * Cerberus firmware version string.
 */
const char CERBERUS_FW_VERSION[CERBERUS_PROTOCOL_FW_VERSION_LEN] = "AB.CD.EF.01";

/**
 * RIoT core version string.
 */
const char RIOT_CORE_VERSION[CERBERUS_PROTOCOL_FW_VERSION_LEN] = "1.0";

/**
 * List of FW version strings.
 */
const char *fw_version_list[FW_VERSION_COUNT];

/**
 * Dependencies for testing the system command interface.
 */
struct cmd_interface_system_testing {
	struct cmd_interface_system handler;						/**< Command handler instance. */
	struct firmware_update_control_mock update;					/**< The firmware update mock. */
	struct manifest_cmd_interface_mock pfm_0;					/**< The PFM update mock for port 0. */
	struct manifest_cmd_interface_mock pfm_1;					/**< The PFM update mock for port 1. */
	struct manifest_cmd_interface_mock cfm;						/**< The CFM update mock. */
	struct manifest_cmd_interface_mock pcd;						/**< The PCD update mock. */
	struct pfm_manager_mock pfm_manager_0;						/**< The PFM manager mock for port 0. */
	struct pfm_manager_mock pfm_manager_1;						/**< The PFM manager mock for port 1. */
	struct cfm_manager_mock cfm_manager;						/**< The CFM manager mock. */
	struct pcd_manager_mock pcd_manager;						/**< The PCD manager mock. */
	struct logging_mock debug;									/**< The debug logger mock. */
	struct attestation_master_mock master_attestation;			/**< The master attestation manager mock. */
	struct attestation_slave_mock slave_attestation;			/**< The slave attestation manager mock. */
	struct recovery_image_cmd_interface_mock recovery_0;		/**< The recovery image update mock for port 0. */
	struct recovery_image_cmd_interface_mock recovery_1;		/**< The recovery image update mock for port 1. */
	struct recovery_image_manager_mock recovery_manager_0;		/**< The recovery image manager mock for port 0. */
	struct recovery_image_manager_mock recovery_manager_1;		/**< The recovery image manager mock for port 1. */
	struct hash_engine_mock hash;								/**< Hashing engine mock. */
	struct host_processor_mock host_0;							/**< The host interface mock for port 0. */
	struct host_processor_mock host_1;							/**< The host interface mock for port 1. */
	struct keystore_mock keystore;								/**< RIoT keystore. */
	struct x509_engine_mock x509_mock;							/**< The X.509 engine mock for the RIoT keys. */
	X509_TESTING_ENGINE x509;									/**< X.509 engine for the RIoT keys. */
	struct flash_mock flash;									/**< The flash mock to set expectations on. */
	struct host_state_manager state;							/**< The state manager. */
	struct flash_mock flash_state;								/**< The mock for the flash state storage. */
	struct cmd_background_mock background;						/**< The background command interface mock. */
	struct pcr_store store;										/**< PCR storage. */
	struct device_manager device_manager;						/**< Device manager. */
	struct cmd_authorization_mock auth;							/**< The authorization handler. */
	struct riot_key_manager riot;								/**< RIoT keys manager. */
	struct host_control_mock host_ctrl_0;						/**< The host control mock interface for port 0. */
	struct host_control_mock host_ctrl_1;						/**< The host control mock interface for port 1. */
	struct cmd_interface_fw_version fw_version;					/**< The firmware version data. */
	struct cmd_device_mock cmd_device;							/**< The device command handler mock instance. */
	struct session_manager_mock session;						/**< Session manager mock. */
	struct cerberus_protocol_observer_mock observer;			/**< Cerberus protocol observer. */
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
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param state The host state instance to initialize.
 * @param flash The mock for the flash state storage.
 */
static void cmd_interface_system_testing_init_host_state (CuTest *test,
	struct host_state_manager *state, struct flash_mock *flash)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	status = flash_mock_init (flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash->mock, flash->base.get_sector_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash->mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&flash->mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&flash->mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (state, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to initialize a subset of the system command interface parameters.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 */
static void setup_cmd_interface_system_mock_test_init (CuTest *test,
	struct cmd_interface_system_testing *cmd)
{
	uint8_t num_pcr_measurements[2] = {6, 0};
	uint8_t *dev_id_der = NULL;
	int status;

	debug_log = NULL;

	status = device_manager_init (&cmd->device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager, 0, 
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager, 1, 
		MCTP_BASE_PROTOCOL_BMC_EID, 0);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_control_mock_init (&cmd->update);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&cmd->pfm_0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&cmd->pfm_1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&cmd->cfm);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&cmd->pcd);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_mock_init (&cmd->background);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&cmd->pfm_manager_0);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&cmd->pfm_manager_1);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&cmd->cfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&cmd->pcd_manager);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&cmd->host_0);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&cmd->host_1);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&cmd->debug);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_mock_init (&cmd->master_attestation);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_init (&cmd->slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&cmd->hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&cmd->store, num_pcr_measurements, sizeof (num_pcr_measurements));
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

	status = cmd_authorization_mock_init (&cmd->auth);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_init (&cmd->recovery_manager_0);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_init (&cmd->recovery_manager_1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_cmd_interface_mock_init (&cmd->recovery_0);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_cmd_interface_mock_init (&cmd->recovery_1);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd->x509_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&cmd->flash);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_system_testing_init_host_state (test, &cmd->state, &cmd->flash_state);

	status = host_control_mock_init (&cmd->host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&cmd->host_ctrl_1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&cmd->cmd_device);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_mock_init (&cmd->session);
	CuAssertIntEquals (test, 0, status);

	status = cerberus_protocol_observer_mock_init (&cmd->observer);
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
static void setup_cmd_interface_system_mock_test_init_fw_version (
	struct cmd_interface_system_testing *cmd, const char *fw_version, const char *riot_core_version,
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
 * @param pfm_0_enabled Initialize port 0 PFM management or not.
 * @param pfm_1_enabled Initialize port 1 PFM management or not.
 * @param cfm_enabled Initialize CFM management or not.
 * @param pcd_enabled Initialize PCD management or not.
 * @param recovery_0_enabled Initialize port 0 recovery image management or not.
 * @param recovery_1_enabled Initialize port 1 recovery image management or not.
 * @param host_ctrl_0_enabled Initialize port 0 host control or not.
 * @param host_ctrl_1_enabled Initialize port 1 host control or not.
 * @param session_mgr_enabled Initialize session manager or not.
 * @param register_response_observer Flag indicating whether to register observer to response
 * 	notifications.
 */
static void setup_cmd_interface_system_mock_test (CuTest *test,
	struct cmd_interface_system_testing *cmd, bool pfm_0_enabled, bool pfm_1_enabled,
	bool cfm_enabled, bool pcd_enabled, bool recovery_0_enabled, bool recovery_1_enabled,
	bool host_ctrl_0_enabled, bool host_ctrl_1_enabled, bool session_mgr_enabled,
	bool register_response_observer)
{
	struct manifest_cmd_interface *pfm_0_ptr = NULL;
	struct manifest_cmd_interface *pfm_1_ptr = NULL;
	struct manifest_cmd_interface *cfm_ptr = NULL;
	struct manifest_cmd_interface *pcd_ptr = NULL;
	struct pfm_manager *pfm_manager_0_ptr = NULL;
	struct pfm_manager *pfm_manager_1_ptr = NULL;
	struct cfm_manager *cfm_manager_ptr = NULL;
	struct pcd_manager *pcd_manager_ptr = NULL;
	struct host_processor *host_0_ptr = NULL;
	struct host_processor *host_1_ptr = NULL;
	struct recovery_image_cmd_interface *recovery_0_ptr = NULL;
	struct recovery_image_cmd_interface *recovery_1_ptr = NULL;
	struct recovery_image_manager *recovery_manager_0_ptr = NULL;
	struct recovery_image_manager *recovery_manager_1_ptr = NULL;
	struct host_control *host_ctrl_0_ptr = NULL;
	struct host_control *host_ctrl_1_ptr = NULL;
	struct session_manager *session_mgr_ptr = NULL;
	int status;

	setup_cmd_interface_system_mock_test_init (test, cmd);

	setup_cmd_interface_system_mock_test_init_fw_version (cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	if (pfm_0_enabled) {
		pfm_0_ptr = &cmd->pfm_0.base;
		pfm_manager_0_ptr = &cmd->pfm_manager_0.base;
		host_0_ptr = &cmd->host_0.base;
	}

	if (pfm_1_enabled) {
		pfm_1_ptr = &cmd->pfm_1.base;
		pfm_manager_1_ptr = &cmd->pfm_manager_1.base;
		host_1_ptr = &cmd->host_1.base;
	}

	if (cfm_enabled) {
		cfm_ptr = &cmd->cfm.base;
		cfm_manager_ptr = &cmd->cfm_manager.base;
	}

	if (pcd_enabled) {
		pcd_ptr = &cmd->pcd.base;
		pcd_manager_ptr = &cmd->pcd_manager.base;
	}

	if (recovery_0_enabled) {
		recovery_0_ptr = &cmd->recovery_0.base;
		recovery_manager_0_ptr = &cmd->recovery_manager_0.base;
	}

	if (recovery_1_enabled) {
		recovery_1_ptr = &cmd->recovery_1.base;
		recovery_manager_1_ptr = &cmd->recovery_manager_1.base;
	}

	if (host_ctrl_0_enabled) {
		host_ctrl_0_ptr = &cmd->host_ctrl_0.base;
	}

	if (host_ctrl_1_enabled) {
		host_ctrl_1_ptr = &cmd->host_ctrl_1.base;
	}

	if (session_mgr_enabled) {
		session_mgr_ptr = &cmd->session.base;
	}

	status = cmd_interface_system_init (&cmd->handler, &cmd->update.base, pfm_0_ptr, pfm_1_ptr,
		cfm_ptr, pcd_ptr, pfm_manager_0_ptr, pfm_manager_1_ptr, cfm_manager_ptr, pcd_manager_ptr,
		&cmd->master_attestation.base, &cmd->slave_attestation.base, &cmd->device_manager,
		&cmd->store, &cmd->hash.base, &cmd->background.base, host_0_ptr, host_1_ptr,
		&cmd->fw_version, &cmd->riot, &cmd->auth.base, host_ctrl_0_ptr, host_ctrl_1_ptr,
		recovery_0_ptr, recovery_1_ptr, recovery_manager_0_ptr, recovery_manager_1_ptr,
		&cmd->cmd_device.base, CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID, 4,
		session_mgr_ptr);
	CuAssertIntEquals (test, 0, status);

	if (register_response_observer) {
		status = cmd_interface_system_add_cerberus_protocol_observer (&cmd->handler,
			&cmd->observer.base);
		CuAssertIntEquals (test, 0, status);
	}
}

/**
 * Helper function to release the system command interface instance.
 *
 * @param test The test framework.
 * @param cmd The testing instance to release.
 */
 static void complete_cmd_interface_system_mock_test (CuTest *test,
	struct cmd_interface_system_testing *cmd)
{
	int status;

	debug_log = NULL;

	status = firmware_update_control_mock_validate_and_release (&cmd->update);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&cmd->pfm_0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&cmd->pfm_1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&cmd->cfm);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&cmd->pcd);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_mock_validate_and_release (&cmd->background);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&cmd->pfm_manager_0);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&cmd->pfm_manager_1);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&cmd->cfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&cmd->pcd_manager);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&cmd->host_0);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&cmd->host_1);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&cmd->debug);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_mock_validate_and_release (&cmd->master_attestation);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_validate_and_release (&cmd->slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&cmd->hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&cmd->keystore);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_mock_validate_and_release (&cmd->auth);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_cmd_interface_mock_validate_and_release (&cmd->recovery_0);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_cmd_interface_mock_validate_and_release (&cmd->recovery_1);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&cmd->x509_mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&cmd->recovery_manager_0);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&cmd->recovery_manager_1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&cmd->flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&cmd->flash_state);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&cmd->host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&cmd->host_ctrl_1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_validate_and_release (&cmd->cmd_device);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_mock_validate_and_release (&cmd->session);
	CuAssertIntEquals (test, 0, status);

	status = cerberus_protocol_observer_mock_validate_and_release (&cmd->observer);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&cmd->device_manager);

	riot_key_manager_release (&cmd->riot);
	X509_TESTING_ENGINE_RELEASE (&cmd->x509);

	pcr_store_release (&cmd->store);

	host_state_manager_release (&cmd->state);

	cmd_interface_system_deinit (&cmd->handler);
}

/**
 * Tear down the test suite.
 *
 * @param test The test framework.
 */
static void cmd_interface_system_testing_suite_tear_down (CuTest *test)
{
	debug_log = NULL;
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_system_test_init (CuTest *test)
{
	struct cmd_interface_system interface;
	struct firmware_update_control_mock update;
	struct manifest_cmd_interface_mock pfm_0;
	struct manifest_cmd_interface_mock pfm_1;
	struct manifest_cmd_interface_mock cfm;
	struct manifest_cmd_interface_mock pcd;
	struct pfm_manager_mock pfm_mgr_0;
	struct pfm_manager_mock pfm_mgr_1;
	struct cfm_manager_mock cfm_mgr;
	struct pcd_manager_mock pcd_mgr;
	struct host_processor_mock host_0;
	struct host_processor_mock host_1;
	struct logging_mock debug;
	struct attestation_master_mock master_attestation;
	struct attestation_slave_mock slave_attestation;
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct cmd_background_mock background;
	struct device_manager device_manager;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct cmd_authorization_mock auth;
	struct host_control_mock host_ctrl_0;
	struct host_control_mock host_ctrl_1;
	struct cmd_device_mock cmd_device;
	struct session_manager_mock session;
	X509_TESTING_ENGINE x509;
	uint8_t *dev_id_der = NULL;
	uint8_t num_pcr_measurements[2] = {6, 6};
	const char *id[FW_VERSION_COUNT] = {CERBERUS_FW_VERSION, RIOT_CORE_VERSION};
	struct cmd_interface_fw_version fw_version = {
		.count = FW_VERSION_COUNT,
		.id = id
	};
	int status;

	TEST_START;

	status = firmware_update_control_mock_init (&update);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&pfm_0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&pfm_1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_mock_init (&background);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr_0);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr_1);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&cfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&pcd_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host_0);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host_1);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&debug);
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

	status = attestation_master_mock_init (&master_attestation);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_init (&slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_mock_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host_ctrl_1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_mock_init (&session);
	CuAssertIntEquals (test, 0, status);

	debug_log = &debug.base;

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base,
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, interface.base.process_request);
	CuAssertPtrNotNull (test, interface.base.process_response);
	CuAssertPtrNotNull (test, interface.base.generate_error_packet);

	status = firmware_update_control_mock_validate_and_release (&update);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&pfm_0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&pfm_1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_mock_validate_and_release (&background);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr_0);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr_1);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&cfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&pcd_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host_0);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host_1);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&debug);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_mock_validate_and_release (&master_attestation);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_validate_and_release (&slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_mock_validate_and_release (&auth);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&host_ctrl_1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_validate_and_release (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_manager);

	riot_key_manager_release (&riot);
	X509_TESTING_ENGINE_RELEASE (&x509);

	debug_log = NULL;

	pcr_store_release (&store);

	cmd_interface_system_deinit (&interface);
}

static void cmd_interface_system_test_init_null (CuTest *test)
{
	struct cmd_interface_system interface;
	struct firmware_update_control_mock update;
	struct manifest_cmd_interface_mock pfm_0;
	struct manifest_cmd_interface_mock pfm_1;
	struct manifest_cmd_interface_mock cfm;
	struct manifest_cmd_interface_mock pcd;
	struct pfm_manager_mock pfm_mgr_0;
	struct pfm_manager_mock pfm_mgr_1;
	struct cfm_manager_mock cfm_mgr;
	struct pcd_manager_mock pcd_mgr;
	struct host_processor_mock host_0;
	struct host_processor_mock host_1;
	struct logging_mock debug;
	struct attestation_master_mock master_attestation;
	struct attestation_slave_mock slave_attestation;
	struct pcr_store store;
	struct hash_engine_mock hash;
	struct cmd_background_mock background;
	struct device_manager device_manager;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct cmd_authorization_mock auth;
	struct host_control_mock host_ctrl_0;
	struct host_control_mock host_ctrl_1;
	struct cmd_device_mock cmd_device;
	struct session_manager_mock session;
	X509_TESTING_ENGINE x509;
	uint8_t *dev_id_der = NULL;
	uint8_t num_pcr_measurements[2] = {6, 6};
	const char *id[FW_VERSION_COUNT] = {CERBERUS_FW_VERSION, RIOT_CORE_VERSION};
	struct cmd_interface_fw_version fw_version = {
		.count = FW_VERSION_COUNT,
		.id = id
	};
	int status;

	TEST_START;

	status = firmware_update_control_mock_init (&update);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&pfm_0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&pfm_1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_init (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_mock_init (&background);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr_0);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr_1);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_init (&cfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_init (&pcd_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host_0);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&host_1);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&debug);
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

	status = attestation_master_mock_init (&master_attestation);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_init (&slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_manager, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_mock_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host_ctrl_1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_mock_init (&session);
	CuAssertIntEquals (test, 0, status);

	debug_log = &debug.base;

	status = cmd_interface_system_init (NULL, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base,
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, NULL, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base,
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base, NULL,
		&slave_attestation.base, &device_manager, &store, &hash.base, &background.base,
		&host_0.base, &host_1.base, &fw_version, &riot, &auth.base, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, NULL, &device_manager, &store, &hash.base, &background.base,
		&host_0.base, &host_1.base, &fw_version, &riot, &auth.base, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, NULL, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base,
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, NULL, &hash.base,
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base,
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, NULL,
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base,
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		NULL, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, NULL, &riot, &auth.base, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, &fw_version, NULL, &auth.base,
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, NULL, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base,
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0,
		&session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = firmware_update_control_mock_validate_and_release (&update);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&pfm_0);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&pfm_1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&cfm);
	CuAssertIntEquals (test, 0, status);

	status = manifest_cmd_interface_mock_validate_and_release (&pcd);
	CuAssertIntEquals (test, 0, status);

	status = cmd_background_mock_validate_and_release (&background);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr_0);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr_1);
	CuAssertIntEquals (test, 0, status);

	status = cfm_manager_mock_validate_and_release (&cfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_mock_validate_and_release (&pcd_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host_0);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_validate_and_release (&host_1);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&debug);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_mock_validate_and_release (&master_attestation);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_mock_validate_and_release (&slave_attestation);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_mock_validate_and_release (&auth);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&host_ctrl_1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_validate_and_release (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	status = session_manager_mock_validate_and_release (&session);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_manager);

	riot_key_manager_release (&riot);
	X509_TESTING_ENGINE_RELEASE (&x509);

	debug_log = NULL;

	pcr_store_release (&store);
}

static void cmd_interface_system_test_deinit_null (CuTest *test)
{
	TEST_START;

	cmd_interface_system_deinit (NULL);
}

static void cmd_interface_system_test_process_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cmd.handler.base.process_request (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_payload_too_short (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_unsupported_message (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
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

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

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

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_unknown_command (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
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

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_REQUEST, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reserved_fields_not_zero (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
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

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

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

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_encrypted_message (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	uint8_t encrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg encrypted_response;
	struct cerberus_protocol_update_status *req = (struct cerberus_protocol_update_status*) data;
	struct cerberus_protocol_update_status_response *resp =
		(struct cerberus_protocol_update_status_response*) data;
	struct cerberus_protocol_update_status *plaintext_rq =
		(struct cerberus_protocol_update_status*) decrypted_data;
	struct cerberus_protocol_update_status_response *plaintext_rsp =
		(struct cerberus_protocol_update_status_response*) response_data;
	struct cerberus_protocol_update_status_response *ciphertext_rsp =
		(struct cerberus_protocol_update_status_response*) encrypted_data;
	int update_status = 0x00BB11AA;
	int encrypted_update_status = 0x11223344;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (struct cmd_interface_msg));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	memset (&encrypted_response, 0, sizeof (struct cmd_interface_msg));
	memset (encrypted_data, 0, sizeof (encrypted_data));
	encrypted_response.data = encrypted_data;

	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	req->header.crypt = 1;

	req->update_type = 0xAA;
	req->port_id = 0xBB;
	request.length = sizeof (struct cerberus_protocol_update_status) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rq->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	plaintext_rq->header.crypt = 1;
	plaintext_rq->update_type = 0;
	plaintext_rq->port_id = 1;

	decrypted_request.length = sizeof (struct cerberus_protocol_update_status);
	decrypted_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rsp->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	plaintext_rsp->header.crypt = 1;
	plaintext_rsp->update_status = update_status;

	response.length = sizeof (struct cerberus_protocol_update_status_response);
	response.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	ciphertext_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	ciphertext_rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	ciphertext_rsp->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	ciphertext_rsp->header.crypt = 1;
	ciphertext_rsp->update_status = encrypted_update_status;

	encrypted_response.length = sizeof (struct cerberus_protocol_update_status_response) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	encrypted_response.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	encrypted_response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted_response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message, &cmd.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.session.mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.update.mock, cmd.update.base.get_status, &cmd.update, update_status);
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
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_update_status_response) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 1, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS, resp->header.command);
	CuAssertIntEquals (test, encrypted_update_status, resp->update_status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_encrypted_message_decrypt_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	struct cerberus_protocol_update_status *req = (struct cerberus_protocol_update_status*) data;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	req->header.crypt = 1;

	req->update_type = 0xAA;
	req->port_id = 0xBB;
	request.length = sizeof (struct cerberus_protocol_update_status) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message,
		&cmd.session, SESSION_MANAGER_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS_TMP (&request, sizeof (request)));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_encrypted_message_encrypt_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_update_status *req = (struct cerberus_protocol_update_status*) data;
	struct cerberus_protocol_update_status *plaintext_rq =
		(struct cerberus_protocol_update_status*) decrypted_data;
	struct cerberus_protocol_update_status_response *plaintext_rsp =
		(struct cerberus_protocol_update_status_response*) response_data;
	int update_status = 0x00BB11AA;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (struct cmd_interface_msg));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	req->header.crypt = 1;

	req->update_type = 0xAA;
	req->port_id = 0xBB;
	request.length = sizeof (struct cerberus_protocol_update_status) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rq->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	plaintext_rq->header.crypt = 1;
	plaintext_rq->update_type = 0;
	plaintext_rq->port_id = 1;

	decrypted_request.length = sizeof (struct cerberus_protocol_update_status);
	decrypted_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rsp->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	plaintext_rsp->header.crypt = 1;
	plaintext_rsp->update_status = update_status;

	response.length = sizeof (struct cerberus_protocol_update_status_response);
	response.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message, &cmd.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.session.mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.update.mock, cmd.update.base.get_status, &cmd.update, update_status);
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

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_encrypted_message_no_session_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	struct cerberus_protocol_update_status *req = (struct cerberus_protocol_update_status*) data;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	req->header.crypt = 1;

	req->update_type = 0xAA;
	req->port_id = 0xBB;
	request.length = sizeof (struct cerberus_protocol_update_status);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_ENCRYPTION_UNSUPPORTED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_encrypted_message_no_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	struct cerberus_protocol_clear_log *req = (struct cerberus_protocol_clear_log*) data;
	struct cerberus_protocol_clear_log *plaintext_rq =
		(struct cerberus_protocol_clear_log*) decrypted_data;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (struct cmd_interface_msg));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_CLEAR_LOG;
	req->header.crypt = 1;

	req->log_type = 0xAA;
	request.length = sizeof (struct cerberus_protocol_clear_log) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rq->header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;
	plaintext_rq->header.crypt = 1;
	plaintext_rq->log_type = CERBERUS_PROTOCOL_DEBUG_LOG;

	decrypted_request.length = sizeof (struct cerberus_protocol_clear_log);
	decrypted_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message,
		&cmd.session, 0, MOCK_ARG_PTR_CONTAINS_TMP (&request, sizeof (request)));
	status |= mock_expect_output (&cmd.session.mock, 0, &decrypted_request,
		sizeof (decrypted_request), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.background.mock, cmd.background.base.debug_log_clear,
		&cmd.background, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_encrypted_message_only_header (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_get_attestation_data *req =
		(struct cerberus_protocol_get_attestation_data*) data;
	struct cerberus_protocol_get_attestation_data *plaintext_rq =
		(struct cerberus_protocol_get_attestation_data*) decrypted_data;
	struct cerberus_protocol_get_attestation_data_response *resp =
		(struct cerberus_protocol_get_attestation_data_response*) data;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	memset (&request, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	request.data = data;

	memset (&decrypted_request, 0, sizeof (struct cmd_interface_msg));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_request.data = decrypted_data;

	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_ATTESTATION_DATA;
	req->header.crypt = 1;

	req->pmr = 0xAA;
	req->entry = 0xBB;
	req->offset = 0xCC;

	request.length = sizeof (struct cerberus_protocol_get_attestation_data) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	plaintext_rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rq->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rq->header.command = CERBERUS_PROTOCOL_GET_ATTESTATION_DATA;
	plaintext_rq->header.crypt = 1;

	plaintext_rq->pmr = 0;
	plaintext_rq->entry = 0;
	plaintext_rq->offset = 0;

	decrypted_request.length = sizeof (struct cerberus_protocol_get_attestation_data);
	decrypted_request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	decrypted_request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	memcpy (&response, &decrypted_request, sizeof (response));
	memcpy (&response_data, decrypted_data, sizeof (response_data));
	response.data = response_data;
	response.length = sizeof (struct cerberus_protocol_header);

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message, &cmd.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.session.mock, 0, &decrypted_request,
		sizeof (decrypted_request), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.session.mock, cmd.session.base.encrypt_message,
		&cmd.session, 0, MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request,
			&response, sizeof (response), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request, cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		sizeof (struct cerberus_protocol_get_attestation_data_response),
		request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, resp->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, resp->header.pci_vendor_id);
	CuAssertIntEquals (test, 1, resp->header.crypt);
	CuAssertIntEquals (test, 0, resp->header.reserved2);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.reserved1);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_ATTESTATION_DATA, resp->header.command);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_init (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_fw_update_init (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_fw_update_init_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_init_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_fw_update_init_fail (test,
		&cmd.handler.base, &cmd.update);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_fw_update (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_fw_update_no_data (test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_fw_update_fail (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_complete_fw_update (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_complete_fw_update (test, &cmd.handler.base,
		&cmd.update);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_complete_fw_update_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_complete_fw_update_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_complete_fw_update_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_complete_fw_update_fail (test,
		&cmd.handler.base, &cmd.update);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_fw_update_status (test,
		&cmd.handler.base, &cmd.update);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pfm_update_status_port0 (test,
		&cmd.handler.base, &cmd.pfm_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pfm_update_status_port1 (test,
		&cmd.handler.base, &cmd.pfm_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pfm_update_status_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pfm_update_status_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pfm_update_status_invalid_port (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_update_status (test,
		&cmd.handler.base, &cmd.cfm);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_update_status_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_update_status_no_cfm_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_update_status (test,
		&cmd.handler.base, &cmd.pcd);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_update_status_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_update_status_no_pcd_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_port0 (
		test, &cmd.handler.base, &cmd.host_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_port1 (
		test, &cmd.handler.base, &cmd.host_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_port0_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_port1_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_invalid_port (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_invalid_port (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_fail (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_status_fail (
		test, &cmd.handler.base, &cmd.host_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_port0 (
		test, &cmd.handler.base, &cmd.recovery_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_port1 (
		test, &cmd.handler.base, &cmd.recovery_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_port0_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_port1_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_update_status_bad_port_index (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_reset_config_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_reset_config_status (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_update_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_update_status_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_update_status_invalid_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_update_status_invalid_type (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_ext_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_fw_ext_update_status (test,
		&cmd.handler.base, &cmd.update);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_ext_update_status_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pfm_ext_update_status_port0 (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_ext_update_status_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pfm_ext_update_status_port1 (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_ext_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_ext_update_status (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_ext_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_ext_update_status (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_ext_status_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_ext_status_port0 (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_ext_status_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_host_fw_reset_verification_ext_status_port1 (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_ext_update_status_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port0 (
		test, &cmd.handler.base, &cmd.recovery_0, &cmd.recovery_manager_0, &cmd.flash);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_ext_update_status_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port1 (
		test, &cmd.handler.base, &cmd.recovery_1, &cmd.recovery_manager_1, &cmd.flash);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_ext_update_status_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port0_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_ext_update_status_port0_cmd_intf_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test_init (test, &cmd);

	setup_cmd_interface_system_mock_test_init_fw_version (&cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_system_init (&cmd.handler, &cmd.update.base, &cmd.pfm_0.base,
		&cmd.pfm_1.base, &cmd.cfm.base, &cmd.pcd.base, &cmd.pfm_manager_0.base,
		&cmd.pfm_manager_1.base, &cmd.cfm_manager.base, &cmd.pcd_manager.base,
		&cmd.master_attestation.base, &cmd.slave_attestation.base, &cmd.device_manager, &cmd.store,
		&cmd.hash.base, &cmd.background.base, &cmd.host_0.base, &cmd.host_1.base, &cmd.fw_version,
		&cmd.riot, &cmd.auth.base, &cmd.host_ctrl_0.base, &cmd.host_ctrl_1.base, NULL,
		&cmd.recovery_1.base, &cmd.recovery_manager_0.base, &cmd.recovery_manager_1.base,
		&cmd.cmd_device.base, 0, 0, 0, 0, &cmd.session.base);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port0_cmd_intf_null (
		test, &cmd.handler.base);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_ext_update_status_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port1_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_ext_update_status_port1_cmd_intf_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test_init (test, &cmd);

	setup_cmd_interface_system_mock_test_init_fw_version (&cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_system_init (&cmd.handler, &cmd.update.base, &cmd.pfm_0.base,
		&cmd.pfm_1.base, &cmd.cfm.base, &cmd.pcd.base, &cmd.pfm_manager_0.base,
		&cmd.pfm_manager_1.base, &cmd.cfm_manager.base, &cmd.pcd_manager.base,
		&cmd.master_attestation.base, &cmd.slave_attestation.base, &cmd.device_manager, &cmd.store,
		&cmd.hash.base, &cmd.background.base, &cmd.host_0.base, &cmd.host_1.base, &cmd.fw_version,
		&cmd.riot, &cmd.auth.base, &cmd.host_ctrl_0.base, &cmd.host_ctrl_1.base,
		&cmd.recovery_0.base, NULL, &cmd.recovery_manager_0.base, &cmd.recovery_manager_1.base,
		&cmd.cmd_device.base, 0, 0, 0, 0, &cmd.session.base);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_port1_cmd_intf_null (
		test, &cmd.handler.base);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_ext_update_status_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_recovery_image_ext_update_status_bad_port_index (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_reset_config_ext_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_reset_config_ext_update_status (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_update_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_ext_update_status_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_update_status_invalid_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_ext_update_status_invalid_type (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_fw_version (test, &cmd.handler.base,
		CERBERUS_FW_VERSION);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_unset_version (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test_init (test, &cmd);
	setup_cmd_interface_system_mock_test_init_fw_version (&cmd, NULL, RIOT_CORE_VERSION,
		FW_VERSION_COUNT);

	status = cmd_interface_system_init (&cmd.handler, &cmd.update.base, &cmd.pfm_0.base,
		&cmd.pfm_1.base, &cmd.cfm.base, &cmd.pcd.base, &cmd.pfm_manager_0.base,
		&cmd.pfm_manager_1.base, &cmd.cfm_manager.base, &cmd.pcd_manager.base,
		&cmd.master_attestation.base, &cmd.slave_attestation.base, &cmd.device_manager, &cmd.store,
		&cmd.hash.base, &cmd.background.base, &cmd.host_0.base, &cmd.host_1.base, &cmd.fw_version,
		&cmd.riot, &cmd.auth.base, &cmd.host_ctrl_0.base, &cmd.host_ctrl_1.base,
		&cmd.recovery_0.base, &cmd.recovery_1.base, &cmd.recovery_manager_0.base,
		&cmd.recovery_manager_1.base, &cmd.cmd_device.base, 0, 0, 0, 0, &cmd.session.base);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_process_get_fw_version_unset_version (test,
		&cmd.handler.base);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_fw_version_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_unsupported_area (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_fw_version_unsupported_area (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_riot (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_fw_version_riot (test,
		&cmd.handler.base, RIOT_CORE_VERSION);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_bad_count (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test_init (test, &cmd);
	setup_cmd_interface_system_mock_test_init_fw_version (&cmd, NULL, RIOT_CORE_VERSION, 0);

	status = cmd_interface_system_init (&cmd.handler, &cmd.update.base, &cmd.pfm_0.base,
		&cmd.pfm_1.base, &cmd.cfm.base, &cmd.pcd.base, &cmd.pfm_manager_0.base,
		&cmd.pfm_manager_1.base, &cmd.cfm_manager.base, &cmd.pcd_manager.base,
		&cmd.master_attestation.base, &cmd.slave_attestation.base, &cmd.device_manager, &cmd.store,
		&cmd.hash.base, &cmd.background.base, &cmd.host_0.base, &cmd.host_1.base, &cmd.fw_version,
		&cmd.riot, &cmd.auth.base, &cmd.host_ctrl_0.base, &cmd.host_ctrl_1.base,
		&cmd.recovery_0.base, &cmd.recovery_1.base, &cmd.recovery_manager_0.base,
		&cmd.recovery_manager_1.base, &cmd.cmd_device.base, 0, 0, 0, 0, &cmd.session.base);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_process_get_fw_version_bad_count (test,
		&cmd.handler.base);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_init_port0 (test,
		&cmd.handler.base, &cmd.pfm_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_init_port1 (test,
		&cmd.handler.base, &cmd.pfm_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_init_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_init_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_init_invalid_port (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_init_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_fail_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_init_fail_port0 (test,
		&cmd.handler.base, &cmd.pfm_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_fail_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_init_fail_port1 (test,
		&cmd.handler.base, &cmd.pfm_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_port0 (test,
		&cmd.handler.base, &cmd.pfm_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_port1 (test,
		&cmd.handler.base, &cmd.pfm_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_no_data (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_invalid_port (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_fail_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_fail_port0 (test,
		&cmd.handler.base, &cmd.pfm_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_fail_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_fail_port1 (test,
		&cmd.handler.base, &cmd.pfm_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port0 (test,
		&cmd.handler.base, &cmd.pfm_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port1 (test,
		&cmd.handler.base, &cmd.pfm_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port0_immediate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port0_immediate (test,
		&cmd.handler.base, &cmd.pfm_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port1_immediate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port1_immediate (test,
		&cmd.handler.base, &cmd.pfm_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_invalid_port (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_fail_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_fail_port0 (test,
		&cmd.handler.base, &cmd.pfm_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_fail_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_pfm_update_complete_fail_port1 (test,
		&cmd.handler.base, &cmd.pfm_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port0_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_port0_region0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port0_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_port0_region1 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port1_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_port1_region0 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port1_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_port1_region1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_no_id_type_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_id_type_port0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_no_id_type_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_id_type_port1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port0_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_port0_region0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port0_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_port0_region1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port1_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_port1_region0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port1_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_port1_region1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_no_active_pfm_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_active_pfm_port0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_no_active_pfm_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_active_pfm_port1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_no_pending_pfm_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_pending_pfm_port0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_no_pending_pfm_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_no_pending_pfm_port1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_fail_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_fail_port0 (test, 
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_fail_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_fail_port1 (test, 
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_invalid_port (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_invalid_region (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_invalid_region (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_invalid_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_invalid_id (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_port0_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port0_region0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_port0_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port0_region1 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_port1_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port1_region0 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_port1_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port1_region1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_port0_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port0_region0_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_port0_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port0_region1_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_port1_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port1_region0_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_port1_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_port1_region1_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_no_active_pfm_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_no_active_pfm_port0 (
		test, &cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_no_active_pfm_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_no_active_pfm_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_no_pending_pfm_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_no_pending_pfm_port0 (
		test, &cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_no_pending_pfm_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_no_pending_pfm_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_fail_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_fail_port0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_platform_id_fail_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_id_platform_fail_port1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port0_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port0_region0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port0_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port0_region1 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port1_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port1_region0 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port1_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port1_region1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_with_firmware_id_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_with_firmware_id_port0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_with_firmware_id_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_with_firmware_id_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_zero_length_firmware_id_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_zero_length_firmware_id_port0 (
		test, &cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_zero_length_firmware_id_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_zero_length_firmware_id_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_nonzero_offset_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_limited_response_port0 (
		test, &cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_nonzero_offset_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_nonzero_offset_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_limited_response_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_limited_response_port0 (
		test, &cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_limited_response_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_limited_response_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_empty_list_port0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_empty_list_port1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_nonzero_offset_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_empty_list_nonzero_offset_port0 (
		test, &cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_nonzero_offset_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_empty_list_nonzero_offset_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port0_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port0_region0_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port0_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port0_region1_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port1_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port1_region0_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port1_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_port1_region1_null (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_no_active_pfm_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_no_active_pfm_port0 (
		test, &cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_no_active_pfm_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_no_active_pfm_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_no_pending_pfm_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_no_pending_pfm_port0 (
		test, &cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_no_pending_pfm_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_no_pending_pfm_port1 (
		test, &cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_fail_id_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_fail_id_port0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_fail_id_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_fail_id_port1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_fail_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_fail_port0 (test,
		&cmd.handler.base, &cmd.pfm_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_fail_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_fail_port1 (test,
		&cmd.handler.base, &cmd.pfm_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_invalid_region (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_invalid_region (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_pfm_supported_fw_invalid_port (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_init (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_init (test, &cmd.handler.base,
		&cmd.cfm);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_init_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_init_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_init_no_cfm_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_init_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_init_fail (test, &cmd.handler.base,
		&cmd.cfm);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update (test, &cmd.handler.base,
		&cmd.cfm);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_no_data (test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_no_cfm_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_fail (test, &cmd.handler.base,
		&cmd.cfm);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_complete (test, &cmd.handler.base,
		&cmd.cfm);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete_immediate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_complete_immediate (test,
		&cmd.handler.base, &cmd.cfm);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_complete_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_complete_no_cfm_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_cfm_update_complete_fail (test,
		&cmd.handler.base, &cmd.cfm);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_region0 (test, &cmd.handler.base,
		&cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_region1 (test, &cmd.handler.base,
		&cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_no_id_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_no_id_type (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_invalid_region (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_invalid_region (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_fail (test, &cmd.handler.base,
		&cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_no_cfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_no_cfm (test, &cmd.handler.base,
		&cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_no_cfm_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_invalid_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_invalid_id (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_platform_id_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_region0 (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_platform_id_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_region1 (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_platform_id_no_cfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_no_cfm (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_platform_id_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_no_cfm_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_platform_id_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_id_platform_fail (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_region0 (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_region1 (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_nonzero_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_nonzero_offset (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_limited_response (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_no_cfm_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_no_active_cfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_no_active_cfm (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_no_pending_cfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_no_pending_cfm (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_fail_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_fail_id (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_fail (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_invalid_region (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_invalid_region (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_invalid_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_cfm_component_ids_invalid_offset (test,
		&cmd.handler.base, &cmd.cfm_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_clear_debug (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_clear_debug (test, &cmd.handler.base,
		&cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_clear_attestation (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_clear_attestation (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_clear_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_clear_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_clear_invalid_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_clear_invalid_type (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_clear_debug_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_clear_debug_fail (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_debug_fill_log (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_debug_commands_testing_process_debug_fill_log (test, &cmd.handler.base,
		&cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_log_info (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_log_info (test, &cmd.handler.base,
		&cmd.debug, 6);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_log_info_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_log_info_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_log_info_fail_debug (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_log_info_fail_debug (test,
		&cmd.handler.base, &cmd.debug, 6);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_debug (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_debug (test, &cmd.handler.base,
		&cmd.debug);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_debug_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_debug_limited_response (test,
		&cmd.handler.base, &cmd.debug);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_attestation (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_attestation (test,
		&cmd.handler.base, &cmd.hash, &cmd.store);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_tcg (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_tcg (test, &cmd.handler.base,
		&cmd.store);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_tcg_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_tcg_fail (test, &cmd.handler.base,
		&cmd.store);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_attestation_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_attestation_limited_response (test,
		&cmd.handler.base, &cmd.hash, &cmd.store);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_debug_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_debug_fail (test,
		&cmd.handler.base, &cmd.debug);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_attestation_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_attestation_fail (test,
		&cmd.handler.base, &cmd.hash, &cmd.store);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_invalid_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_invalid_offset (test,
		&cmd.handler.base, &cmd.debug);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_invalid_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_invalid_type (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_log_read_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest (test,
		&cmd.handler.base, &cmd.slave_attestation, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_aux_slot (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_aux_slot (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_limited_response (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_unsupported_slot (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_slot (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_unavailable_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unavailable_cert (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_encryption_unsupported (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_encryption_unsupported (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_unsupported_algo (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_unsupported_algo (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_invalid_slot (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_invalid_slot (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_digest_fail (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate (test, &cmd.handler.base,
		&cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_length_0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_length_0 (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_aux_slot (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_aux_slot (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_limited_response (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_invalid_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_offset (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_valid_offset_and_length_beyond_cert_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_valid_offset_and_length_beyond_cert_len (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_length_too_big (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_length_too_big (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_unsupported_slot (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_slot (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_unsupported_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_unsupported_cert (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_unavailable_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_unavailable_cert (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_invalid_slot_num (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_invalid_slot_num (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_certificate_fail (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response (test,
		&cmd.handler.base, &cmd.slave_attestation, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_no_session_mgr (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_no_session_mgr (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_key_exchange_not_requested (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_key_exchange_not_requested (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response (
		test, &cmd.handler.base, &cmd.slave_attestation, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_limited_response_no_session_mgr (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_no_session_mgr (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_limited_response_key_exchange_not_requested (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_limited_response_key_exchange_not_requested (
		test, &cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_fail (test,
		&cmd.handler.base, &cmd.slave_attestation);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_challenge_response_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_capabilities (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_capabilities (test, &cmd.handler.base,
		&cmd.device_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_capabilities_invalid_device (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_device (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_capabilities_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_rsa (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_rsa (test, &cmd.handler.base,
		&cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_ecc (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_rsa (test, &cmd.handler.base,
		&cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_fail (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_invalid_hmac (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_invalid_hmac (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_invalid_seed (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_invalid_seed (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_rsa_invalid_padding (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_rsa_invalid_padding (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_no_seed (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_no_seed (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_incomplete_seed (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_incomplete_seed (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_no_ciphertext (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_no_ciphertext (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_incomplete_ciphertext (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_incomplete_ciphertext (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_no_hmac (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_no_hmac (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_bad_hmac_length (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_bad_hmac_length (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_incomplete_hmac (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_incomplete_hmac (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_result (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_result_limited_response (
		test, &cmd.handler.base, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result_busy (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_result_busy (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_result_fail (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_request_unseal_result_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port0_out_of_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port0_out_of_reset (
		test, &cmd.handler.base, &cmd.host_ctrl_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port0_held_in_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port0_held_in_reset (
		test, &cmd.handler.base, &cmd.host_ctrl_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port0_not_held_in_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port0_not_held_in_reset (
		test, &cmd.handler.base, &cmd.host_ctrl_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, false,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port1_out_of_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port1_out_of_reset (
		test, &cmd.handler.base, &cmd.host_ctrl_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port1_held_in_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port1_held_in_reset (
		test, &cmd.handler.base, &cmd.host_ctrl_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port1_not_held_in_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port1_not_held_in_reset (
		test, &cmd.handler.base, &cmd.host_ctrl_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		false, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_invalid_port (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_reset_check_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_check_error (test,
		&cmd.handler.base, &cmd.host_ctrl_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_hold_check_error (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_host_reset_status_hold_check_error (
		test, &cmd.handler.base, &cmd.host_ctrl_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id (test, &cmd.handler.base,
		&cmd.pcd_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_no_id_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_no_id_type (test,
		&cmd.handler.base, &cmd.pcd_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_no_pcd (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_no_pcd (test, &cmd.handler.base,
		&cmd.pcd_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_no_pcd_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_fail (test, &cmd.handler.base,
		&cmd.pcd_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_invalid_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_invalid_id (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_platform_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_platform (test, &cmd.handler.base,
		&cmd.pcd_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_platform_id_no_pcd (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_platform_no_pcd (test,
		&cmd.handler.base, &cmd.pcd_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_platform_id_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_platform_no_pcd_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_platform_id_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_get_pcd_id_platform_fail (test,
		&cmd.handler.base, &cmd.pcd_manager);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_init (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_init (test, &cmd.handler.base,
		&cmd.pcd);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_init_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_init_no_pcd_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_init_invalid_len (test, \
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_init_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_init_fail (test, &cmd.handler.base,
		&cmd.pcd);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update (test, &cmd.handler.base,
		&cmd.pcd);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_no_data (test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_no_pcd_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_fail (test, &cmd.handler.base,
		&cmd.pcd);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_complete (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_complete (test, &cmd.handler.base,
		&cmd.pcd);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_complete_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_complete_no_pcd_manager (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_complete_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_complete_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_complete_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_pcd_update_complete_fail (test,
		&cmd.handler.base, &cmd.pcd);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_devid_csr (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_devid_csr (test, &cmd.handler.base,
		RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_devid_csr_invalid_buf_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_devid_csr_unsupported_index (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_unsupported_index (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_devid_csr_too_big (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big (test,
		&cmd.handler.base, &cmd.riot);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_devid_csr_too_big_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_devid_csr_too_big_limited_response (
		test, &cmd.handler.base, RIOT_CORE_DEVID_CSR, RIOT_CORE_DEVID_CSR_LEN);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_dev_id_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert (test,
		&cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_root_ca_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_root_ca_cert (test,
		&cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_intermediate_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_intermediate_cert (test,
		&cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_no_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_no_cert (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_bad_cert_length (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_bad_cert_length (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_unsupported_index (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_unsupported_index (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_dev_id_cert_save_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_signed_dev_id_cert_save_error (test,
		&cmd.handler.base, &cmd.keystore);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_root_ca_cert_save_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_root_ca_cert_save_error (test,
		&cmd.handler.base, &cmd.keystore);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_intermediate_cert_save_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_intermediate_cert_save_error (test,
		&cmd.handler.base, &cmd.keystore);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_authenticate_error (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_import_signed_ca_cert_authenticate_error (
		test, &cmd.handler.base, &cmd.keystore, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_signed_cert_state (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_signed_cert_state (test,
		&cmd.handler.base, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_signed_cert_state_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_signed_cert_state_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_authorized (test,
		&cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_challenge (test,
		&cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_max_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_max_challenge (test,
		&cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_not_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_not_authorized (test,
		&cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_with_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_with_nonce_authorized (test,
		&cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_with_nonce_not_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_with_nonce_not_authorized (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_invalid_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_invalid_challenge (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_invalid_challenge_limited_response (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_no_nonce_invalid_challenge_limited_response (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_bypass_error (test, &cmd.handler.base,
		&cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_authorized (test,
		&cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_challenge (test,
		&cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_max_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_max_challenge (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_not_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_not_authorized (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_with_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_with_nonce_authorized (
		test, &cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_with_nonce_not_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_with_nonce_not_authorized (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_invalid_challenge (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_invalid_challenge (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_invalid_challenge_limited_response (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_no_nonce_invalid_challenge_limited_response (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_restore_defaults_error (test,
		&cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_no_nonce_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_authorized (
		test, &cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_no_nonce_challenge (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_challenge (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_no_nonce_max_challenge (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_max_challenge (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_no_nonce_not_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_not_authorized (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_with_nonce_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_with_nonce_authorized (
		test, &cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_with_nonce_not_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_with_nonce_not_authorized (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_no_nonce_invalid_challenge (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_invalid_challenge (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_no_nonce_invalid_challenge_limited_response (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_no_nonce_invalid_challenge_limited_response (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_clear_platform_config_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_clear_platform_config_error (test,
		&cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_no_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_authorized (test,
		&cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_no_nonce_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_challenge (test,
		&cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_no_nonce_max_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_max_challenge (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_no_nonce_not_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_not_authorized (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_with_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_with_nonce_authorized (test,
		&cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_with_nonce_not_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_with_nonce_not_authorized (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_no_nonce_invalid_challenge (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_invalid_challenge (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_no_nonce_invalid_challenge_limited_response (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_no_nonce_invalid_challenge_limited_response (
		test, &cmd.handler.base, &cmd.auth);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_intrusion_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_intrusion_error (test,
		&cmd.handler.base, &cmd.auth, &cmd.background);
	complete_cmd_interface_system_mock_test (test, &cmd);
}


static void cmd_interface_system_test_process_reset_config_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_config_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_config_invalid_request_subtype (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_reset_config_invalid_request_subtype (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_port0 (test,
		&cmd.handler.base, &cmd.recovery_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_port1 (test,
		&cmd.handler.base, &cmd.recovery_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_fail (test,
		&cmd.handler.base, &cmd.recovery_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_prepare_recovery_image_bad_port_index (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_update_recovery_image_port0 (test,
		&cmd.handler.base, &cmd.recovery_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_update_recovery_image_port1 (test,
		&cmd.handler.base, &cmd.recovery_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_update_recovery_image_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;
	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_update_recovery_image_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_update_recovery_image_no_data (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_update_recovery_image_bad_port_index (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_update_recovery_image_fail (test,
		&cmd.handler.base, &cmd.recovery_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_activate_recovery_image_port0 (test,
		&cmd.handler.base, &cmd.recovery_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_activate_recovery_image_port1 (test,
		&cmd.handler.base, &cmd.recovery_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_activate_recovery_image_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_activate_recovery_image_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_invalid_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_activate_recovery_image_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_bad_port_index (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_activate_recovery_image_bad_port_index (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_activate_recovery_image_fail (test,
		&cmd.handler.base, &cmd.recovery_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_port0 (test,
		&cmd.handler.base, &cmd.recovery_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_port1 (test,
		&cmd.handler.base, &cmd.recovery_manager_1);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_no_id_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_no_id_type (test,
		&cmd.handler.base, &cmd.recovery_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_port0_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_port1_null (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_no_image (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_no_image (test,
		&cmd.handler.base, &cmd.recovery_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_fail (test,
		&cmd.handler.base, &cmd.recovery_manager_0);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_invalid_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_invalid_len (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_recovery_image_version_bad_port_index (
		test,&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_attestation_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_attestation_data (test,
		&cmd.handler.base, &cmd.store);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_attestation_data_with_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t num_pcr_measurements[2] = {6, 6};
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	pcr_store_release (&cmd.store);

	status = pcr_store_init (&cmd.store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_optional_commands_testing_process_get_attestation_data_with_offset (test,
		&cmd.handler.base, &cmd.store);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_attestation_data_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_attestation_data_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_attestation_data_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_attestation_data_fail (test,
		&cmd.handler.base, &cmd.store, &cmd.flash);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_attestation_data_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_optional_commands_testing_process_get_attestation_data_no_data (test,
		&cmd.handler.base, &cmd.store);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_device_info (test, &cmd.handler.base,
		&cmd.cmd_device);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info_limited_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_device_info_limited_response (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_device_info_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info_bad_info_index (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_device_info_bad_info_index (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_device_info_fail (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_device_id (test, &cmd.handler.base,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID, 4);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_id_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_get_device_id_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_counter (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_reset_counter (test, &cmd.handler.base,
		&cmd.cmd_device);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_counter_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_reset_counter_port0 (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_counter_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_reset_counter_port1 (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_counter_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_reset_counter_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_counter_invalid_counter (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_process_reset_counter_invalid_counter (test,
		&cmd.handler.base, &cmd.cmd_device);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_type_0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_0 (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_type_0_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_0_fail (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_type_1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1 (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_type_1_unencrypted (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1_unencrypted (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_type_1_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_1_fail (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_type_2 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2 (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_type_2_unencrypted (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2_unencrypted (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_type_2_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_type_2_fail (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_unsupported (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_unsupported (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_unsupported_index (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_unsupported_index (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_key_exchange_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_get_key_exchange_invalid_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_session_sync (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_session_sync (test,	&cmd.handler.base,
		&cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_session_sync_no_session_mgr (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);

	cerberus_protocol_optional_commands_testing_process_session_sync_no_session_mgr (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_session_sync_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_session_sync_fail (test, &cmd.handler.base,
		&cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_session_sync_unencrypted (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_session_sync_unencrypted (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_session_sync_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_optional_commands_testing_process_session_sync_invalid_len (test,
		&cmd.handler.base, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_supports_all_required_commands (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_required_commands_testing_supports_all_required_commands (test,
		&cmd.handler.base, CERBERUS_FW_VERSION, &cmd.slave_attestation, &cmd.device_manager,
		&cmd.background, &cmd.keystore, &cmd.cmd_device, RIOT_CORE_DEVID_CSR,
		RIOT_CORE_DEVID_CSR_LEN, CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		4, &cmd.session);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (NULL, &response);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	status = cmd.handler.base.process_response (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_payload_too_short (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_unsupported_message (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;

	header->msg_type = 0x11;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;

	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = 0xAA;

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_unknown_command (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = 0xFF;

	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_RESPONSE, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_error_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg response;

	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_master_commands_testing_process_error_response (test, &cmd.handler.base,
		&response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_error_response_bad_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg response;

	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_master_commands_testing_process_error_response_invalid_len (test,
		&cmd.handler.base, &response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_reserved_fields_not_zero (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 1;
	header->reserved2 = 0;

	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	header->reserved1 = 0;
	header->reserved2 = 1;

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_encrypted_message (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg response;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg decrypted_response;
	struct cmd_interface_msg decrypted_response2;
	struct cerberus_protocol_get_certificate_digest_response *rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	struct cerberus_protocol_get_certificate_digest_response *plaintext_rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) decrypted_data;
	size_t offset = sizeof (struct cerberus_protocol_get_certificate_digest_response);
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;

	memset (&decrypted_response, 0, sizeof (struct cmd_interface_msg));
	memset (decrypted_data, 0, sizeof (decrypted_data));
	decrypted_response.data = decrypted_data;

	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rsp->header.command = CERBERUS_PROTOCOL_GET_DIGEST;
	rsp->header.crypt = 1;
	rsp->num_digests = 0xAA;

	data[offset] = 0xBB;
	data[offset + SHA256_HASH_LENGTH - 1] = 0xCC;

	response.length =
		cerberus_protocol_get_certificate_digest_response_length (SHA256_HASH_LENGTH) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.max_response = SESSION_MANAGER_TRAILER_LEN;

	plaintext_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	plaintext_rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	plaintext_rsp->header.command = CERBERUS_PROTOCOL_GET_DIGEST;
	plaintext_rsp->num_digests = 1;

	decrypted_data[offset] = 0xDD;
	decrypted_data[offset + SHA256_HASH_LENGTH - 1] = 0xEE;

	decrypted_response.length =
		cerberus_protocol_get_certificate_digest_response_length (SHA256_HASH_LENGTH);
	decrypted_response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted_response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	decrypted_response.max_response = SESSION_MANAGER_TRAILER_LEN;

	memcpy (&decrypted_response2, &decrypted_response, sizeof (struct cmd_interface_msg));

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message, &cmd.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.session.mock, 0, &decrypted_response,
		sizeof (decrypted_response), cmd_interface_mock_copy_request);
	CuAssertIntEquals (test, 0, status);

	decrypted_response2.max_response = 0;

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_get_digest_response,
		&cmd.observer, 0, MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request,
			&decrypted_response2, sizeof (decrypted_response2), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request, cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_encrypted_message_decrypt_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg response;
	struct cerberus_protocol_get_certificate_digest_response *rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rsp->header.command = CERBERUS_PROTOCOL_GET_DIGEST;
	rsp->header.crypt = 1;
	rsp->num_digests = 0xAA;

	response.length =
		cerberus_protocol_get_certificate_digest_response_length (SHA256_HASH_LENGTH) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = mock_expect (&cmd.session.mock, cmd.session.base.decrypt_message,
		&cmd.session, SESSION_MANAGER_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS_TMP (&response, sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, SESSION_MANAGER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_encrypted_message_no_session_manager (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg response;
	struct cerberus_protocol_get_certificate_digest_response *rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) data;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, false, true);

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rsp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	rsp->header.command = CERBERUS_PROTOCOL_GET_DIGEST;
	rsp->header.crypt = 1;
	rsp->num_digests = 0xAA;

	response.length =
		cerberus_protocol_get_certificate_digest_response_length (SHA256_HASH_LENGTH) +
		CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	response.crypto_timeout = true;
	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ENCRYPTION_UNSUPPORTED, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_get_certificate_digest (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_get_digest_response,
		&cmd.observer, 0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response,
		sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_master_commands_testing_process_response_get_certificate_digest (test,
		&cmd.handler.base, &response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_get_certificate_digest_no_observer (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, false);

	cerberus_protocol_master_commands_testing_process_response_get_certificate_digest (test,
		&cmd.handler.base, &response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_get_certificate_digest_invalid_buf_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_response_get_certificate_digest_invalid_buf_len (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_get_certificate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_get_certificate_response,
		&cmd.observer, 0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response,
		sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_master_commands_testing_process_response_get_certificate (test,
		&cmd.handler.base, &response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_get_certificate_no_observer (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, false);

	cerberus_protocol_master_commands_testing_process_response_get_certificate (test,
		&cmd.handler.base, &response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_get_certificate_invalid_buf_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_response_get_certificate_invalid_buf_len (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_get_certificate_unsupported_slot (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_response_get_certificate_unsupported_slot (
		test, &cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_challenge_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_challenge_response,
		&cmd.observer, 0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response,
		sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_master_commands_testing_process_response_challenge_response (test,
		&cmd.handler.base, &response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_challenge_response_no_observer (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, false);

	cerberus_protocol_master_commands_testing_process_response_challenge_response (test,
		&cmd.handler.base, &response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_challenge_response_invalid_buf_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_response_challenge_invalid_buf_len (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_challenge_response_unsupported_slot (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_response_challenge_unsupported_slot (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_response_challenge_response_rsvd_not_fail (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);
	cerberus_protocol_master_commands_testing_process_response_challenge_rsvd_not_zero (test,
		&cmd.handler.base);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_generate_error_packet (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_required_commands_testing_generate_error_packet (test, &cmd.handler.base);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_generate_error_packet_encrypted (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_required_commands_testing_generate_error_packet_encrypted (test,
		&cmd.handler.base, &cmd.session);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_generate_error_packet_encrypted_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_required_commands_testing_generate_error_packet_encrypted_fail (test,
		&cmd.handler.base, &cmd.session);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_generate_error_packet_invalid_arg (CuTest *test)
{
	struct cmd_interface_system_testing cmd;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	cerberus_protocol_required_commands_testing_generate_error_packet_invalid_arg (test,
		&cmd.handler.base);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_add_cerberus_protocol_observer_invalid_arg (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	status = cmd_interface_system_add_cerberus_protocol_observer (NULL, &cmd.observer.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_add_cerberus_protocol_observer (&cmd.handler, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_remove_cerberus_protocol_observer (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	response.data = data;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	status = cmd_interface_system_remove_cerberus_protocol_observer (&cmd.handler,
		&cmd.observer.base);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_master_commands_testing_process_response_challenge_response (test,
		&cmd.handler.base, &response);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_remove_cerberus_protocol_observer_invalid_arg (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, true, true);

	status = cmd_interface_system_remove_cerberus_protocol_observer (NULL, &cmd.observer.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_remove_cerberus_protocol_observer (&cmd.handler, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}


TEST_SUITE_START (cmd_interface_system);

TEST (cmd_interface_system_test_init);
TEST (cmd_interface_system_test_init_null);
TEST (cmd_interface_system_test_deinit_null);
TEST (cmd_interface_system_test_process_null);
TEST (cmd_interface_system_test_process_payload_too_short);
TEST (cmd_interface_system_test_process_unsupported_message);
TEST (cmd_interface_system_test_process_unknown_command);
TEST (cmd_interface_system_test_process_reserved_fields_not_zero);
TEST (cmd_interface_system_test_process_encrypted_message);
TEST (cmd_interface_system_test_process_encrypted_message_decrypt_fail);
TEST (cmd_interface_system_test_process_encrypted_message_encrypt_fail);
TEST (cmd_interface_system_test_process_encrypted_message_no_session_manager);
TEST (cmd_interface_system_test_process_encrypted_message_no_response);
TEST (cmd_interface_system_test_process_encrypted_message_only_header);
TEST (cmd_interface_system_test_process_fw_update_init);
TEST (cmd_interface_system_test_process_fw_update_init_invalid_len);
TEST (cmd_interface_system_test_process_fw_update_init_fail);
TEST (cmd_interface_system_test_process_fw_update);
TEST (cmd_interface_system_test_process_fw_update_no_data);
TEST (cmd_interface_system_test_process_fw_update_fail);
TEST (cmd_interface_system_test_process_complete_fw_update);
TEST (cmd_interface_system_test_process_complete_fw_update_invalid_len);
TEST (cmd_interface_system_test_process_complete_fw_update_fail);
TEST (cmd_interface_system_test_process_get_fw_update_status);
TEST (cmd_interface_system_test_process_get_pfm_update_status_port0);
TEST (cmd_interface_system_test_process_get_pfm_update_status_port1);
TEST (cmd_interface_system_test_process_get_pfm_update_status_port0_null);
TEST (cmd_interface_system_test_process_get_pfm_update_status_port1_null);
TEST (cmd_interface_system_test_process_get_pfm_update_status_invalid_port);
TEST (cmd_interface_system_test_process_get_cfm_update_status);
TEST (cmd_interface_system_test_process_get_cfm_update_status_no_cfm_manager);
TEST (cmd_interface_system_test_process_get_pcd_update_status);
TEST (cmd_interface_system_test_process_get_pcd_update_status_no_pcd_manager);
TEST (cmd_interface_system_test_process_get_host_fw_reset_verification_status_port0);
TEST (cmd_interface_system_test_process_get_host_fw_reset_verification_status_port1);
TEST (cmd_interface_system_test_process_get_host_fw_reset_verification_status_port0_null);
TEST (cmd_interface_system_test_process_get_host_fw_reset_verification_status_port1_null);
TEST (cmd_interface_system_test_process_get_host_fw_reset_verification_status_invalid_port);
TEST (cmd_interface_system_test_process_get_host_fw_reset_verification_status_fail);
TEST (cmd_interface_system_test_process_get_recovery_image_update_status_port0);
TEST (cmd_interface_system_test_process_get_recovery_image_update_status_port1);
TEST (cmd_interface_system_test_process_get_recovery_image_update_status_port0_null);
TEST (cmd_interface_system_test_process_get_recovery_image_update_status_port1_null);
TEST (cmd_interface_system_test_process_get_recovery_image_update_status_bad_port_index);
TEST (cmd_interface_system_test_process_get_reset_config_status);
TEST (cmd_interface_system_test_process_get_update_status_invalid_len);
TEST (cmd_interface_system_test_process_get_update_status_invalid_type);
TEST (cmd_interface_system_test_process_get_fw_ext_update_status);
TEST (cmd_interface_system_test_process_get_pfm_ext_update_status_port0);
TEST (cmd_interface_system_test_process_get_pfm_ext_update_status_port1);
TEST (cmd_interface_system_test_process_get_cfm_ext_update_status);
TEST (cmd_interface_system_test_process_get_pcd_ext_update_status);
TEST (cmd_interface_system_test_process_get_host_fw_reset_verification_ext_status_port0);
TEST (cmd_interface_system_test_process_get_host_fw_reset_verification_ext_status_port1);
TEST (cmd_interface_system_test_process_get_recovery_image_ext_update_status_port0);
TEST (cmd_interface_system_test_process_get_recovery_image_ext_update_status_port1);
TEST (cmd_interface_system_test_process_get_recovery_image_ext_update_status_port0_null);
TEST (cmd_interface_system_test_process_get_recovery_image_ext_update_status_port0_cmd_intf_null);
TEST (cmd_interface_system_test_process_get_recovery_image_ext_update_status_port1_null);
TEST (cmd_interface_system_test_process_get_recovery_image_ext_update_status_port1_cmd_intf_null);
TEST (cmd_interface_system_test_process_get_recovery_image_ext_update_status_bad_port_index);
TEST (cmd_interface_system_test_process_get_reset_config_ext_update_status);
TEST (cmd_interface_system_test_process_get_ext_update_status_invalid_len);
TEST (cmd_interface_system_test_process_get_ext_update_status_invalid_type);
TEST (cmd_interface_system_test_process_get_fw_version);
TEST (cmd_interface_system_test_process_get_fw_version_unset_version);
TEST (cmd_interface_system_test_process_get_fw_version_unsupported_area);
TEST (cmd_interface_system_test_process_get_fw_version_invalid_len);
TEST (cmd_interface_system_test_process_get_fw_version_riot);
TEST (cmd_interface_system_test_process_get_fw_version_bad_count);
TEST (cmd_interface_system_test_process_pfm_update_init_port0);
TEST (cmd_interface_system_test_process_pfm_update_init_port1);
TEST (cmd_interface_system_test_process_pfm_update_init_port0_null);
TEST (cmd_interface_system_test_process_pfm_update_init_port1_null);
TEST (cmd_interface_system_test_process_pfm_update_init_invalid_port);
TEST (cmd_interface_system_test_process_pfm_update_init_invalid_len);
TEST (cmd_interface_system_test_process_pfm_update_init_fail_port0);
TEST (cmd_interface_system_test_process_pfm_update_init_fail_port1);
TEST (cmd_interface_system_test_process_pfm_update_port0);
TEST (cmd_interface_system_test_process_pfm_update_port1);
TEST (cmd_interface_system_test_process_pfm_update_port0_null);
TEST (cmd_interface_system_test_process_pfm_update_port1_null);
TEST (cmd_interface_system_test_process_pfm_update_no_data);
TEST (cmd_interface_system_test_process_pfm_update_invalid_port);
TEST (cmd_interface_system_test_process_pfm_update_fail_port0);
TEST (cmd_interface_system_test_process_pfm_update_fail_port1);
TEST (cmd_interface_system_test_process_pfm_update_complete_port0);
TEST (cmd_interface_system_test_process_pfm_update_complete_port1);
TEST (cmd_interface_system_test_process_pfm_update_complete_port0_immediate);
TEST (cmd_interface_system_test_process_pfm_update_complete_port1_immediate);
TEST (cmd_interface_system_test_process_pfm_update_complete_port0_null);
TEST (cmd_interface_system_test_process_pfm_update_complete_port1_null);
TEST (cmd_interface_system_test_process_pfm_update_complete_invalid_len);
TEST (cmd_interface_system_test_process_pfm_update_complete_invalid_port);
TEST (cmd_interface_system_test_process_pfm_update_complete_fail_port0);
TEST (cmd_interface_system_test_process_pfm_update_complete_fail_port1);
TEST (cmd_interface_system_test_process_get_pfm_id_port0_region0);
TEST (cmd_interface_system_test_process_get_pfm_id_port0_region1);
TEST (cmd_interface_system_test_process_get_pfm_id_port1_region0);
TEST (cmd_interface_system_test_process_get_pfm_id_port1_region1);
TEST (cmd_interface_system_test_process_get_pfm_id_no_id_type_port0);
TEST (cmd_interface_system_test_process_get_pfm_id_no_id_type_port1);
TEST (cmd_interface_system_test_process_get_pfm_id_port0_region0_null);
TEST (cmd_interface_system_test_process_get_pfm_id_port0_region1_null);
TEST (cmd_interface_system_test_process_get_pfm_id_port1_region0_null);
TEST (cmd_interface_system_test_process_get_pfm_id_port1_region1_null);
TEST (cmd_interface_system_test_process_get_pfm_id_no_active_pfm_port0);
TEST (cmd_interface_system_test_process_get_pfm_id_no_active_pfm_port1);
TEST (cmd_interface_system_test_process_get_pfm_id_no_pending_pfm_port0);
TEST (cmd_interface_system_test_process_get_pfm_id_no_pending_pfm_port1);
TEST (cmd_interface_system_test_process_get_pfm_id_fail_port0);
TEST (cmd_interface_system_test_process_get_pfm_id_fail_port1);
TEST (cmd_interface_system_test_process_get_pfm_id_invalid_len);
TEST (cmd_interface_system_test_process_get_pfm_id_invalid_port);
TEST (cmd_interface_system_test_process_get_pfm_id_invalid_region);
TEST (cmd_interface_system_test_process_get_pfm_id_invalid_id);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_port0_region0);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_port0_region1);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_port1_region0);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_port1_region1);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_port0_region0_null);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_port0_region1_null);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_port1_region0_null);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_port1_region1_null);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_no_active_pfm_port0);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_no_active_pfm_port1);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_no_pending_pfm_port0);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_no_pending_pfm_port1);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_fail_port0);
TEST (cmd_interface_system_test_process_get_pfm_platform_id_fail_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_port0_region0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_port0_region1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_port1_region0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_port1_region1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_with_firmware_id_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_with_firmware_id_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_zero_length_firmware_id_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_zero_length_firmware_id_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_nonzero_offset_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_nonzero_offset_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_limited_response_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_limited_response_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_nonzero_offset_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_nonzero_offset_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_port0_region0_null);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_port0_region1_null);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_port1_region0_null);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_port1_region1_null);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_no_active_pfm_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_no_active_pfm_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_no_pending_pfm_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_no_pending_pfm_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_fail_id_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_fail_id_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_fail_port0);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_fail_port1);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_invalid_len);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_invalid_region);
TEST (cmd_interface_system_test_process_get_pfm_supported_fw_invalid_port);
TEST (cmd_interface_system_test_process_cfm_update_init);
TEST (cmd_interface_system_test_process_cfm_update_init_invalid_len);
TEST (cmd_interface_system_test_process_cfm_update_init_no_cfm_manager);
TEST (cmd_interface_system_test_process_cfm_update_init_fail);
TEST (cmd_interface_system_test_process_cfm_update);
TEST (cmd_interface_system_test_process_cfm_update_no_data);
TEST (cmd_interface_system_test_process_cfm_update_no_cfm_manager);
TEST (cmd_interface_system_test_process_cfm_update_fail);
TEST (cmd_interface_system_test_process_cfm_update_complete);
TEST (cmd_interface_system_test_process_cfm_update_complete_immediate);
TEST (cmd_interface_system_test_process_cfm_update_complete_invalid_len);
TEST (cmd_interface_system_test_process_cfm_update_complete_no_cfm_manager);
TEST (cmd_interface_system_test_process_cfm_update_complete_fail);
TEST (cmd_interface_system_test_process_get_cfm_id_region0);
TEST (cmd_interface_system_test_process_get_cfm_id_region1);
TEST (cmd_interface_system_test_process_get_cfm_id_no_id_type);
TEST (cmd_interface_system_test_process_get_cfm_id_invalid_len);
TEST (cmd_interface_system_test_process_get_cfm_id_invalid_region);
TEST (cmd_interface_system_test_process_get_cfm_id_no_cfm_manager);
TEST (cmd_interface_system_test_process_get_cfm_id_no_cfm);
TEST (cmd_interface_system_test_process_get_cfm_id_fail);
TEST (cmd_interface_system_test_process_get_cfm_id_invalid_id);
TEST (cmd_interface_system_test_process_get_cfm_platform_id_region0);
TEST (cmd_interface_system_test_process_get_cfm_platform_id_region1);
TEST (cmd_interface_system_test_process_get_cfm_platform_id_no_cfm);
TEST (cmd_interface_system_test_process_get_cfm_platform_id_no_cfm_manager);
TEST (cmd_interface_system_test_process_get_cfm_platform_id_fail);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_region0);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_region1);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_nonzero_offset);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_limited_response);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_no_cfm_manager);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_no_active_cfm);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_no_pending_cfm);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_fail_id);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_fail);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_invalid_len);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_invalid_region);
TEST (cmd_interface_system_test_process_get_cfm_component_ids_invalid_offset);
TEST (cmd_interface_system_test_process_log_clear_debug);
TEST (cmd_interface_system_test_process_log_clear_attestation);
TEST (cmd_interface_system_test_process_log_clear_invalid_len);
TEST (cmd_interface_system_test_process_log_clear_invalid_type);
TEST (cmd_interface_system_test_process_log_clear_debug_fail);
TEST (cmd_interface_system_test_process_debug_fill_log);
TEST (cmd_interface_system_test_process_get_log_info);
TEST (cmd_interface_system_test_process_get_log_info_invalid_len);
TEST (cmd_interface_system_test_process_get_log_info_fail_debug);
TEST (cmd_interface_system_test_process_log_read_debug);
TEST (cmd_interface_system_test_process_log_read_debug_limited_response);
TEST (cmd_interface_system_test_process_log_read_attestation);
TEST (cmd_interface_system_test_process_log_read_tcg);
TEST (cmd_interface_system_test_process_log_read_tcg_fail);
TEST (cmd_interface_system_test_process_log_read_attestation_limited_response);
TEST (cmd_interface_system_test_process_log_read_debug_fail);
TEST (cmd_interface_system_test_process_log_read_attestation_fail);
TEST (cmd_interface_system_test_process_log_read_invalid_type);
TEST (cmd_interface_system_test_process_log_read_invalid_offset);
TEST (cmd_interface_system_test_process_log_read_invalid_len);
TEST (cmd_interface_system_test_process_get_certificate_digest);
TEST (cmd_interface_system_test_process_get_certificate_digest_aux_slot);
TEST (cmd_interface_system_test_process_get_certificate_digest_limited_response);
TEST (cmd_interface_system_test_process_get_certificate_digest_unsupported_slot);
TEST (cmd_interface_system_test_process_get_certificate_digest_unavailable_cert);
TEST (cmd_interface_system_test_process_get_certificate_digest_encryption_unsupported);
TEST (cmd_interface_system_test_process_get_certificate_digest_invalid_len);
TEST (cmd_interface_system_test_process_get_certificate_digest_unsupported_algo);
TEST (cmd_interface_system_test_process_get_certificate_digest_invalid_slot);
TEST (cmd_interface_system_test_process_get_certificate_digest_fail);
TEST (cmd_interface_system_test_process_get_certificate);
TEST (cmd_interface_system_test_process_get_certificate_length_0);
TEST (cmd_interface_system_test_process_get_certificate_aux_slot);
TEST (cmd_interface_system_test_process_get_certificate_limited_response);
TEST (cmd_interface_system_test_process_get_certificate_invalid_offset);
TEST (cmd_interface_system_test_process_get_certificate_valid_offset_and_length_beyond_cert_len);
TEST (cmd_interface_system_test_process_get_certificate_length_too_big);
TEST (cmd_interface_system_test_process_get_certificate_unsupported_slot);
TEST (cmd_interface_system_test_process_get_certificate_unsupported_cert);
TEST (cmd_interface_system_test_process_get_certificate_unavailable_cert);
TEST (cmd_interface_system_test_process_get_certificate_invalid_len);
TEST (cmd_interface_system_test_process_get_certificate_invalid_slot_num);
TEST (cmd_interface_system_test_process_get_certificate_fail);
TEST (cmd_interface_system_test_process_get_challenge_response);
TEST (cmd_interface_system_test_process_get_challenge_response_no_session_mgr);
TEST (cmd_interface_system_test_process_get_challenge_response_key_exchange_not_requested);
TEST (cmd_interface_system_test_process_get_challenge_response_limited_response);
TEST (cmd_interface_system_test_process_get_challenge_response_limited_response_no_session_mgr);
TEST (cmd_interface_system_test_process_get_challenge_response_limited_response_key_exchange_not_requested);
TEST (cmd_interface_system_test_process_get_challenge_response_fail);
TEST (cmd_interface_system_test_process_get_challenge_response_invalid_len);
TEST (cmd_interface_system_test_process_get_capabilities);
TEST (cmd_interface_system_test_process_get_capabilities_invalid_device);
TEST (cmd_interface_system_test_process_get_capabilities_invalid_len);
TEST (cmd_interface_system_test_process_request_unseal_rsa);
TEST (cmd_interface_system_test_process_request_unseal_ecc);
TEST (cmd_interface_system_test_process_request_unseal_fail);
TEST (cmd_interface_system_test_process_request_unseal_invalid_hmac);
TEST (cmd_interface_system_test_process_request_unseal_invalid_seed);
TEST (cmd_interface_system_test_process_request_unseal_rsa_invalid_padding);
TEST (cmd_interface_system_test_process_request_unseal_no_seed);
TEST (cmd_interface_system_test_process_request_unseal_incomplete_seed);
TEST (cmd_interface_system_test_process_request_unseal_no_ciphertext);
TEST (cmd_interface_system_test_process_request_unseal_incomplete_ciphertext);
TEST (cmd_interface_system_test_process_request_unseal_no_hmac);
TEST (cmd_interface_system_test_process_request_unseal_bad_hmac_length);
TEST (cmd_interface_system_test_process_request_unseal_incomplete_hmac);
TEST (cmd_interface_system_test_process_request_unseal_invalid_len);
TEST (cmd_interface_system_test_process_request_unseal_result);
TEST (cmd_interface_system_test_process_request_unseal_result_limited_response);
TEST (cmd_interface_system_test_process_request_unseal_result_busy);
TEST (cmd_interface_system_test_process_request_unseal_result_fail);
TEST (cmd_interface_system_test_process_request_unseal_result_invalid_len);
TEST (cmd_interface_system_test_process_get_host_reset_status_port0_out_of_reset);
TEST (cmd_interface_system_test_process_get_host_reset_status_port0_held_in_reset);
TEST (cmd_interface_system_test_process_get_host_reset_status_port0_not_held_in_reset);
TEST (cmd_interface_system_test_process_get_host_reset_status_port0_null);
TEST (cmd_interface_system_test_process_get_host_reset_status_port1_out_of_reset);
TEST (cmd_interface_system_test_process_get_host_reset_status_port1_held_in_reset);
TEST (cmd_interface_system_test_process_get_host_reset_status_port1_not_held_in_reset);
TEST (cmd_interface_system_test_process_get_host_reset_status_port1_null);
TEST (cmd_interface_system_test_process_get_host_reset_status_invalid_len);
TEST (cmd_interface_system_test_process_get_host_reset_status_invalid_port);
TEST (cmd_interface_system_test_process_get_host_reset_status_reset_check_error);
TEST (cmd_interface_system_test_process_get_host_reset_status_hold_check_error);
TEST (cmd_interface_system_test_process_get_pcd_id);
TEST (cmd_interface_system_test_process_get_pcd_id_no_id_type);
TEST (cmd_interface_system_test_process_get_pcd_id_no_pcd);
TEST (cmd_interface_system_test_process_get_pcd_id_no_pcd_manager);
TEST (cmd_interface_system_test_process_get_pcd_id_invalid_len);
TEST (cmd_interface_system_test_process_get_pcd_id_fail);
TEST (cmd_interface_system_test_process_get_pcd_id_invalid_id);
TEST (cmd_interface_system_test_process_get_pcd_platform_id);
TEST (cmd_interface_system_test_process_get_pcd_platform_id_no_pcd);
TEST (cmd_interface_system_test_process_get_pcd_platform_id_no_pcd_manager);
TEST (cmd_interface_system_test_process_get_pcd_platform_id_fail);
TEST (cmd_interface_system_test_process_pcd_update_init);
TEST (cmd_interface_system_test_process_pcd_update_init_no_pcd_manager);
TEST (cmd_interface_system_test_process_pcd_update_init_invalid_len);
TEST (cmd_interface_system_test_process_pcd_update_init_fail);
TEST (cmd_interface_system_test_process_pcd_update);
TEST (cmd_interface_system_test_process_pcd_update_no_data);
TEST (cmd_interface_system_test_process_pcd_update_no_pcd_manager);
TEST (cmd_interface_system_test_process_pcd_update_fail);
TEST (cmd_interface_system_test_process_pcd_update_complete);
TEST (cmd_interface_system_test_process_pcd_update_complete_no_pcd_manager);
TEST (cmd_interface_system_test_process_pcd_update_complete_invalid_len);
TEST (cmd_interface_system_test_process_pcd_update_complete_fail);
TEST (cmd_interface_system_test_process_get_devid_csr);
TEST (cmd_interface_system_test_process_get_devid_csr_invalid_buf_len);
TEST (cmd_interface_system_test_process_get_devid_csr_unsupported_index);
TEST (cmd_interface_system_test_process_get_devid_csr_too_big);
TEST (cmd_interface_system_test_process_get_devid_csr_too_big_limited_response);
TEST (cmd_interface_system_test_process_import_signed_dev_id_cert);
TEST (cmd_interface_system_test_process_import_root_ca_cert);
TEST (cmd_interface_system_test_process_import_intermediate_cert);
TEST (cmd_interface_system_test_process_import_signed_ca_cert_invalid_len);
TEST (cmd_interface_system_test_process_import_signed_ca_cert_no_cert);
TEST (cmd_interface_system_test_process_import_signed_ca_cert_bad_cert_length);
TEST (cmd_interface_system_test_process_import_signed_ca_cert_unsupported_index);
TEST (cmd_interface_system_test_process_import_signed_dev_id_cert_save_error);
TEST (cmd_interface_system_test_process_import_root_ca_cert_save_error);
TEST (cmd_interface_system_test_process_import_intermediate_cert_save_error);
TEST (cmd_interface_system_test_process_import_signed_ca_cert_authenticate_error);
TEST (cmd_interface_system_test_process_get_signed_cert_state);
TEST (cmd_interface_system_test_process_get_signed_cert_state_invalid_len);
TEST (cmd_interface_system_test_process_reset_bypass_no_nonce_authorized);
TEST (cmd_interface_system_test_process_reset_bypass_no_nonce_challenge);
TEST (cmd_interface_system_test_process_reset_bypass_no_nonce_max_challenge);
TEST (cmd_interface_system_test_process_reset_bypass_no_nonce_not_authorized);
TEST (cmd_interface_system_test_process_reset_bypass_with_nonce_authorized);
TEST (cmd_interface_system_test_process_reset_bypass_with_nonce_not_authorized);
TEST (cmd_interface_system_test_process_reset_bypass_no_nonce_invalid_challenge);
TEST (cmd_interface_system_test_process_reset_bypass_no_nonce_invalid_challenge_limited_response);
TEST (cmd_interface_system_test_process_reset_bypass_error);
TEST (cmd_interface_system_test_process_restore_defaults_no_nonce_authorized);
TEST (cmd_interface_system_test_process_restore_defaults_no_nonce_challenge);
TEST (cmd_interface_system_test_process_restore_defaults_no_nonce_max_challenge);
TEST (cmd_interface_system_test_process_restore_defaults_no_nonce_not_authorized);
TEST (cmd_interface_system_test_process_restore_defaults_with_nonce_authorized);
TEST (cmd_interface_system_test_process_restore_defaults_with_nonce_not_authorized);
TEST (cmd_interface_system_test_process_restore_defaults_no_nonce_invalid_challenge);
TEST (cmd_interface_system_test_process_restore_defaults_no_nonce_invalid_challenge_limited_response);
TEST (cmd_interface_system_test_process_restore_defaults_error);
TEST (cmd_interface_system_test_process_clear_platform_config_no_nonce_authorized);
TEST (cmd_interface_system_test_process_clear_platform_config_no_nonce_challenge);
TEST (cmd_interface_system_test_process_clear_platform_config_no_nonce_max_challenge);
TEST (cmd_interface_system_test_process_clear_platform_config_no_nonce_not_authorized);
TEST (cmd_interface_system_test_process_clear_platform_config_with_nonce_authorized);
TEST (cmd_interface_system_test_process_clear_platform_config_with_nonce_not_authorized);
TEST (cmd_interface_system_test_process_clear_platform_config_no_nonce_invalid_challenge);
TEST (cmd_interface_system_test_process_clear_platform_config_no_nonce_invalid_challenge_limited_response);
TEST (cmd_interface_system_test_process_clear_platform_config_error);
TEST (cmd_interface_system_test_process_reset_intrusion_no_nonce_authorized);
TEST (cmd_interface_system_test_process_reset_intrusion_no_nonce_challenge);
TEST (cmd_interface_system_test_process_reset_intrusion_no_nonce_max_challenge);
TEST (cmd_interface_system_test_process_reset_intrusion_no_nonce_not_authorized);
TEST (cmd_interface_system_test_process_reset_intrusion_with_nonce_authorized);
TEST (cmd_interface_system_test_process_reset_intrusion_with_nonce_not_authorized);
TEST (cmd_interface_system_test_process_reset_intrusion_no_nonce_invalid_challenge);
TEST (cmd_interface_system_test_process_reset_intrusion_no_nonce_invalid_challenge_limited_response);
TEST (cmd_interface_system_test_process_reset_intrusion_error);
TEST (cmd_interface_system_test_process_reset_config_invalid_len);
TEST (cmd_interface_system_test_process_reset_config_invalid_request_subtype);
TEST (cmd_interface_system_test_process_prepare_recovery_image_port0);
TEST (cmd_interface_system_test_process_prepare_recovery_image_port1);
TEST (cmd_interface_system_test_process_prepare_recovery_image_port0_null);
TEST (cmd_interface_system_test_process_prepare_recovery_image_port1_null);
TEST (cmd_interface_system_test_process_prepare_recovery_image_invalid_len);
TEST (cmd_interface_system_test_process_prepare_recovery_image_fail);
TEST (cmd_interface_system_test_process_prepare_recovery_image_bad_port_index);
TEST (cmd_interface_system_test_process_update_recovery_image_port0);
TEST (cmd_interface_system_test_process_update_recovery_image_port1);
TEST (cmd_interface_system_test_process_update_recovery_image_port0_null);
TEST (cmd_interface_system_test_process_update_recovery_image_port1_null);
TEST (cmd_interface_system_test_process_update_recovery_image_no_data);
TEST (cmd_interface_system_test_process_update_recovery_image_bad_port_index);
TEST (cmd_interface_system_test_process_update_recovery_image_fail);
TEST (cmd_interface_system_test_process_activate_recovery_image_port0);
TEST (cmd_interface_system_test_process_activate_recovery_image_port1);
TEST (cmd_interface_system_test_process_activate_recovery_image_port0_null);
TEST (cmd_interface_system_test_process_activate_recovery_image_port1_null);
TEST (cmd_interface_system_test_process_activate_recovery_image_invalid_len);
TEST (cmd_interface_system_test_process_activate_recovery_image_bad_port_index);
TEST (cmd_interface_system_test_process_activate_recovery_image_fail);
TEST (cmd_interface_system_test_process_get_recovery_image_version_port0);
TEST (cmd_interface_system_test_process_get_recovery_image_version_port1);
TEST (cmd_interface_system_test_process_get_recovery_image_version_no_id_type);
TEST (cmd_interface_system_test_process_get_recovery_image_version_port0_null);
TEST (cmd_interface_system_test_process_get_recovery_image_version_port1_null);
TEST (cmd_interface_system_test_process_get_recovery_image_version_no_image);
TEST (cmd_interface_system_test_process_get_recovery_image_version_fail);
TEST (cmd_interface_system_test_process_get_recovery_image_version_invalid_len);
TEST (cmd_interface_system_test_process_get_recovery_image_version_bad_port_index);
TEST (cmd_interface_system_test_process_get_device_info);
TEST (cmd_interface_system_test_process_get_device_info_limited_response);
TEST (cmd_interface_system_test_process_get_device_info_invalid_len);
TEST (cmd_interface_system_test_process_get_device_info_bad_info_index);
TEST (cmd_interface_system_test_process_get_device_info_fail);
TEST (cmd_interface_system_test_process_get_device_id);
TEST (cmd_interface_system_test_process_get_device_id_invalid_len);
TEST (cmd_interface_system_test_process_reset_counter);
TEST (cmd_interface_system_test_process_reset_counter_port0);
TEST (cmd_interface_system_test_process_reset_counter_port1);
TEST (cmd_interface_system_test_process_reset_counter_invalid_len);
TEST (cmd_interface_system_test_process_reset_counter_invalid_counter);
TEST (cmd_interface_system_test_process_get_attestation_data);
TEST (cmd_interface_system_test_process_get_attestation_data_with_offset);
TEST (cmd_interface_system_test_process_get_attestation_data_invalid_len);
TEST (cmd_interface_system_test_process_get_attestation_data_fail);
TEST (cmd_interface_system_test_process_get_attestation_data_no_data);
TEST (cmd_interface_system_test_process_key_exchange_type_0);
TEST (cmd_interface_system_test_process_key_exchange_type_0_fail);
TEST (cmd_interface_system_test_process_key_exchange_type_1);
TEST (cmd_interface_system_test_process_key_exchange_type_1_unencrypted);
TEST (cmd_interface_system_test_process_key_exchange_type_1_fail);
TEST (cmd_interface_system_test_process_key_exchange_type_2);
TEST (cmd_interface_system_test_process_key_exchange_type_2_unencrypted);
TEST (cmd_interface_system_test_process_key_exchange_type_2_fail);
TEST (cmd_interface_system_test_process_key_exchange_unsupported);
TEST (cmd_interface_system_test_process_key_exchange_unsupported_index);
TEST (cmd_interface_system_test_process_key_exchange_invalid_len);
TEST (cmd_interface_system_test_process_session_sync);
TEST (cmd_interface_system_test_process_session_sync_no_session_mgr);
TEST (cmd_interface_system_test_process_session_sync_fail);
TEST (cmd_interface_system_test_process_session_sync_unencrypted);
TEST (cmd_interface_system_test_process_session_sync_invalid_len);
TEST (cmd_interface_system_test_supports_all_required_commands);
TEST (cmd_interface_system_test_process_response_null);
TEST (cmd_interface_system_test_process_response_payload_too_short);
TEST (cmd_interface_system_test_process_response_unsupported_message);
TEST (cmd_interface_system_test_process_response_unknown_command);
TEST (cmd_interface_system_test_process_error_response);
TEST (cmd_interface_system_test_process_error_response_bad_len);
TEST (cmd_interface_system_test_process_response_reserved_fields_not_zero);
TEST (cmd_interface_system_test_process_response_encrypted_message);
TEST (cmd_interface_system_test_process_response_encrypted_message_decrypt_fail);
TEST (cmd_interface_system_test_process_response_encrypted_message_no_session_manager);
TEST (cmd_interface_system_test_process_response_get_certificate_digest);
TEST (cmd_interface_system_test_process_response_get_certificate_digest_no_observer);
TEST (cmd_interface_system_test_process_response_get_certificate_digest_invalid_buf_len);
TEST (cmd_interface_system_test_process_response_get_certificate);
TEST (cmd_interface_system_test_process_response_get_certificate_no_observer);
TEST (cmd_interface_system_test_process_response_get_certificate_invalid_buf_len);
TEST (cmd_interface_system_test_process_response_get_certificate_unsupported_slot);
TEST (cmd_interface_system_test_process_response_challenge_response);
TEST (cmd_interface_system_test_process_response_challenge_response_no_observer);
TEST (cmd_interface_system_test_process_response_challenge_response_invalid_buf_len);
TEST (cmd_interface_system_test_process_response_challenge_response_unsupported_slot);
TEST (cmd_interface_system_test_process_response_challenge_response_rsvd_not_fail);
TEST (cmd_interface_system_test_generate_error_packet);
TEST (cmd_interface_system_test_generate_error_packet_encrypted);
TEST (cmd_interface_system_test_generate_error_packet_encrypted_fail);
TEST (cmd_interface_system_test_generate_error_packet_invalid_arg);
TEST (cmd_interface_system_test_add_cerberus_protocol_observer_invalid_arg);
TEST (cmd_interface_system_test_remove_cerberus_protocol_observer);
TEST (cmd_interface_system_test_remove_cerberus_protocol_observer_invalid_arg);

/* Tear down after the tests in this suite have run. */
TEST (cmd_interface_system_testing_suite_tear_down);

TEST_SUITE_END;
