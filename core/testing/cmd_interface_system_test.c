// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "x509_testing.h"
#include "mctp/mctp_protocol.h"
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
#include "mock/firmware_update_control_mock.h"
#include "mock/manifest_cmd_interface_mock.h"
#include "mock/pfm_manager_mock.h"
#include "mock/cfm_manager_mock.h"
#include "mock/pcd_manager_mock.h"
#include "mock/pfm_mock.h"
#include "mock/cfm_mock.h"
#include "mock/pcd_mock.h"
#include "mock/attestation_master_mock.h"
#include "mock/attestation_slave_mock.h"
#include "mock/hash_mock.h"
#include "mock/logging_mock.h"
#include "mock/cmd_background_mock.h"
#include "mock/host_processor_mock.h"
#include "mock/keystore_mock.h"
#include "mock/cmd_authorization_mock.h"
#include "mock/rng_mock.h"
#include "mock/ecc_mock.h"
#include "mock/rsa_mock.h"
#include "mock/host_control_mock.h"
#include "engines/x509_testing_engine.h"
#include "riot_core_testing.h"
#include "mock/recovery_image_manager_mock.h"
#include "mock/recovery_image_mock.h"
#include "mock/recovery_image_cmd_interface_mock.h"
#include "mock/signature_verification_mock.h"
#include "mock/x509_mock.h"
#include "mock/flash_mock.h"
#include "recovery_image_header_testing.h"
#include "recovery/recovery_image_header.h"
#include "cmd_interface_system_testing.h"
#include "mock/cmd_device_mock.h"


static const char *SUITE = "cmd_interface_system";

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
	struct recovery_image_mock image_0;							/**< The recovery image mock for port 0. */
	struct recovery_image_mock image_1;							/**< The recovery image mock for port 1. */
	struct hash_engine_mock hash;								/**< Hashing engine mock. */
	struct host_processor_mock host_0;							/**< The host interface mock for port 0. */
	struct host_processor_mock host_1;							/**< The host interface mock for port 1. */
	struct keystore_mock keystore;								/**< RIoT keystore. */
	struct x509_engine_mock x509_mock;							/**< The X.509 engine mock for the RIoT keys. */
	X509_TESTING_ENGINE x509;									/**< X.509 engine for the RIoT keys. */
	struct signature_verification_mock verification;			/**< The signature verification mock. */
	struct flash_mock flash;									/**< The flash mock to set expectations on. */
	struct state_manager state;									/**< The state manager. */
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
	struct state_manager *state, struct flash_mock *flash)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	status = flash_mock_init (flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash->mock, flash->base.get_sector_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash->mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash->mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
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
 * @param direction The device direction to set for the device manager table entry.
 */
static void setup_cmd_interface_system_mock_test_init (CuTest *test,
	struct cmd_interface_system_testing *cmd, uint8_t direction)
{
	uint8_t num_pcr_measurements[2] = {6, 0};
	uint8_t *dev_id_der = NULL;
	int status;

	status = device_manager_init (&cmd->device_manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager, 0, DEVICE_MANAGER_SELF,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&cmd->device_manager, 1, direction,
		MCTP_PROTOCOL_BMC_EID, 0);
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

	status = mock_expect (&cmd->keystore.mock, cmd->keystore.base.load_key, &cmd->keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
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

	status = recovery_image_mock_init (&cmd->image_0);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&cmd->image_1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_cmd_interface_mock_init (&cmd->recovery_0);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_cmd_interface_mock_init (&cmd->recovery_1);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&cmd->x509_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&cmd->verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&cmd->flash);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_system_testing_init_host_state (test, &cmd->state, &cmd->flash_state);

	debug_log = &cmd->debug.base;

	status = host_control_mock_init (&cmd->host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&cmd->host_ctrl_1);
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
 * @param direction The device direction to set for the device manager table entry.
 */
static void setup_cmd_interface_system_mock_test (CuTest *test,
	struct cmd_interface_system_testing *cmd, bool pfm_0_enabled, bool pfm_1_enabled,
	bool cfm_enabled, bool pcd_enabled, bool recovery_0_enabled, bool recovery_1_enabled,
	bool host_ctrl_0_enabled, bool host_ctrl_1_enabled, uint8_t direction)
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
	int status;

	setup_cmd_interface_system_mock_test_init (test, cmd, direction);

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

	status = cmd_interface_system_init (&cmd->handler, &cmd->update.base, pfm_0_ptr, pfm_1_ptr,
		cfm_ptr, pcd_ptr, pfm_manager_0_ptr, pfm_manager_1_ptr, cfm_manager_ptr, pcd_manager_ptr,
		&cmd->master_attestation.base, &cmd->slave_attestation.base, &cmd->device_manager, &cmd->store, 
		&cmd->hash.base, &cmd->background.base, host_0_ptr, host_1_ptr, &cmd->fw_version, 
		&cmd->riot, &cmd->auth.base, host_ctrl_0_ptr, host_ctrl_1_ptr, recovery_0_ptr, 
		recovery_1_ptr, recovery_manager_0_ptr, recovery_manager_1_ptr, &cmd->cmd_device.base, 
		CERBERUS_PROTOCOL_MSFT_PCI_VID, 2, CERBERUS_PROTOCOL_MSFT_PCI_VID, 4);
	CuAssertIntEquals (test, 0, status);
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
	int status = firmware_update_control_mock_validate_and_release (&cmd->update);
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

	status = recovery_image_mock_validate_and_release (&cmd->image_0);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&cmd->image_1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&cmd->recovery_manager_0);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&cmd->recovery_manager_1);
	CuAssertIntEquals (test, 0, status);

	signature_verification_mock_release (&cmd->verification);

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

	device_manager_release (&cmd->device_manager);

	riot_key_manager_release (&cmd->riot);
	X509_TESTING_ENGINE_RELEASE (&cmd->x509);

	debug_log = NULL;

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
	X509_TESTING_ENGINE x509;
	uint8_t *dev_id_der = NULL;
	uint8_t num_pcr_measurements[2] = {6, 6};
	const char *id[FW_VERSION_COUNT] = {CERBERUS_FW_VERSION, RIOT_CORE_VERSION};
	struct cmd_interface_fw_version fw_version = {.count = FW_VERSION_COUNT, .id = id};
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

	status = device_manager_init (&device_manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_mock_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host_ctrl_1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	debug_log = &debug.base;

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base, 
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base, 
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 
		0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, interface.base.process_request);
	CuAssertPtrNotNull (test, interface.base.issue_request);

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
	X509_TESTING_ENGINE x509;
	uint8_t *dev_id_der = NULL;
	uint8_t num_pcr_measurements[2] = {6, 6};
	const char *id[FW_VERSION_COUNT] = {CERBERUS_FW_VERSION, RIOT_CORE_VERSION};
	struct cmd_interface_fw_version fw_version = {.count = FW_VERSION_COUNT, .id = id};
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

	status = device_manager_init (&device_manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_mock_init (&auth);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host_ctrl_0);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host_ctrl_1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_device_mock_init (&cmd_device);
	CuAssertIntEquals (test, 0, status);

	debug_log = &debug.base;

	status = cmd_interface_system_init (NULL, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base, 
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base, 
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 
		0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, NULL, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base, 
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base, 
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 
		0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base, NULL,
		&slave_attestation.base, &device_manager, &store, &hash.base, &background.base, &host_0.base, 
		&host_1.base, &fw_version, &riot, &auth.base, &host_ctrl_0.base, &host_ctrl_1.base, NULL, 
		NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base, 
		&master_attestation.base, NULL, &device_manager, &store, &hash.base, &background.base, 
		&host_0.base, &host_1.base, &fw_version, &riot, &auth.base, &host_ctrl_0.base, 
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, NULL, &store, &hash.base, &background.base, 
		&host_0.base, &host_1.base, &fw_version, &riot, &auth.base, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, NULL, &hash.base, 
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base, 
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, NULL, &background.base, 
		&host_0.base, &host_1.base, &fw_version, &riot, &auth.base, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base, NULL, 
		&host_0.base, &host_1.base, &fw_version, &riot, &auth.base, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base,
		&background.base, &host_0.base, &host_1.base, NULL, &riot, &auth.base, &host_ctrl_0.base,
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base, 
		&background.base, &host_0.base, &host_1.base, &fw_version, NULL, &auth.base, 
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base, 
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, NULL, &host_ctrl_0.base, 
		&host_ctrl_1.base, NULL, NULL, NULL, NULL, &cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_system_init (&interface, &update.base, &pfm_0.base, &pfm_1.base,
		&cfm.base, &pcd.base, &pfm_mgr_0.base, &pfm_mgr_1.base, &cfm_mgr.base, &pcd_mgr.base,
		&master_attestation.base, &slave_attestation.base, &device_manager, &store, &hash.base, 
		&background.base, &host_0.base, &host_1.base, &fw_version, &riot, &auth.base, 
		&host_ctrl_0.base, &host_ctrl_1.base, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0);
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

	device_manager_release (&device_manager);

	riot_key_manager_release (&riot);
	X509_TESTING_ENGINE_RELEASE (&x509);

	debug_log = NULL;

	pcr_store_release (&store);

	cmd_interface_system_deinit (&interface);
}

static void cmd_interface_system_test_deinit_null (CuTest *test)
{
	TEST_START;

	cmd_interface_system_deinit (NULL);
}

static void cmd_interface_system_test_process_payload_too_short (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_unsupported_message (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
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

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

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

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_error_packet (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_ERROR;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_ERROR_MESSAGE_ESCAPE_SEQ, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_invalid_device (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + 3 * SHA256_HASH_LENGTH;
	request.source_eid = 0xEE;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}


static void cmd_interface_system_test_process_fw_update_init (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size = 0x31EEAABB;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_FW_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.update.mock, cmd.update.base.prepare_staging, &cmd.update, 0,
		MOCK_ARG (size));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_FW_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_FW;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.update.mock, cmd.update.base.write_staging, &cmd.update, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_FW;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_start (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.update.mock, cmd.update.base.start_update, &cmd.update, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_fw_update_start_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_update_status_response_packet*,
		&request);
	int update_status = 0x00BB11AA;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_FW_UPDATE;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.update.mock, cmd.update.base.get_status, &cmd.update, update_status);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS, header->command);
	CuAssertIntEquals (test, update_status, rsp->update_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_update_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_fw_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_ext_update_status_response_packet*,
		&request);
	int update_status = 0x00BB11AA;
	int remaining_len = 0xAABBCCAA;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_FW_UPDATE;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.update.mock, cmd.update.base.get_status, &cmd.update, update_status);
	status |= mock_expect (&cmd.update.mock, cmd.update.base.get_remaining_len, &cmd.update,
		remaining_len);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS, header->command);
	CuAssertIntEquals (test, update_status, rsp->update_status);
	CuAssertIntEquals (test, remaining_len, rsp->remaining_len);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_fw_update_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_fw_update_status_unsupported_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_PFM_UPDATE;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 32, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_FW_VERSION,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertStrEquals (test, CERBERUS_FW_VERSION,
		(char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_unset_version (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_fw_version_request_packet*, &request);
	uint8_t zero[32] = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	rq->area = 0;

	setup_cmd_interface_system_mock_test_init (test, &cmd, DEVICE_MANAGER_UPSTREAM);

	setup_cmd_interface_system_mock_test_init_fw_version (&cmd, NULL,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_system_init (&cmd.handler, &cmd.update.base, &cmd.pfm_0.base,
		&cmd.pfm_1.base, &cmd.cfm.base, &cmd.pcd.base, &cmd.pfm_manager_0.base,
		&cmd.pfm_manager_1.base, &cmd.cfm_manager.base, &cmd.pcd_manager.base, 
		&cmd.master_attestation.base, &cmd.slave_attestation.base, &cmd.device_manager, &cmd.store, 
		&cmd.hash.base, &cmd.background.base, &cmd.host_0.base, &cmd.host_1.base, &cmd.fw_version, 
		&cmd.riot, &cmd.auth.base, &cmd.host_ctrl_0.base, &cmd.host_ctrl_1.base, 
		&cmd.recovery_0.base, &cmd.recovery_1.base, &cmd.recovery_manager_0.base, 
		&cmd.recovery_manager_1.base, &cmd.cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 32, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_FW_VERSION,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (zero, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_unsupported_area (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_fw_version_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	rq->area = 2;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_riot (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_fw_version_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	rq->area = 1;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 32, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_FW_VERSION,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertStrEquals (test, RIOT_CORE_VERSION,
		(char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_fw_version_bad_count (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_fw_version_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	rq->area = 0;

	setup_cmd_interface_system_mock_test_init (test, &cmd, DEVICE_MANAGER_UPSTREAM);

	setup_cmd_interface_system_mock_test_init_fw_version (&cmd, NULL, RIOT_CORE_VERSION, 0);

	status = cmd_interface_system_init (&cmd.handler, &cmd.update.base, &cmd.pfm_0.base,
		&cmd.pfm_1.base, &cmd.cfm.base, &cmd.pcd.base, &cmd.pfm_manager_0.base,
		&cmd.pfm_manager_1.base, &cmd.cfm_manager.base, &cmd.pcd_manager.base, 
		&cmd.master_attestation.base, &cmd.slave_attestation.base, &cmd.device_manager, &cmd.store, 
		&cmd.hash.base, &cmd.background.base, &cmd.host_0.base, &cmd.host_1.base, &cmd.fw_version, 
		&cmd.riot, &cmd.auth.base, &cmd.host_ctrl_0.base, &cmd.host_ctrl_1.base, 
		&cmd.recovery_0.base, &cmd.recovery_1.base, &cmd.recovery_manager_0.base, 
		&cmd.recovery_manager_1.base, &cmd.cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_prepare_pfm_update_request_packet*,
		&request);
	uint32_t length = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	rq->port_id = 0;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_0.mock, cmd.pfm_0.base.prepare_manifest, &cmd.pfm_0, 0,
		MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_prepare_pfm_update_request_packet*,
		&request);
	uint32_t length = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	rq->port_id = 1;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_1.mock, cmd.pfm_1.base.prepare_manifest, &cmd.pfm_1, 0,
		MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_prepare_pfm_update_request_packet*,
		&request);
	uint32_t length = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	rq->port_id = 0;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_prepare_pfm_update_request_packet*,
		&request);
	uint32_t length = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	rq->port_id = 1;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_prepare_pfm_update_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	rq->port_id = 2;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_init_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_prepare_pfm_update_request_packet*,
		&request);
	uint32_t length = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_INIT_PFM_UPDATE;

	rq->port_id = 0;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_0.mock, cmd.pfm_0.base.prepare_manifest, &cmd.pfm_0,
		PFM_INVALID_ARGUMENT, MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header, struct cerberus_protocol_pfm_update_header_packet*,
		&request);
	uint8_t *update_data = &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_pfm_update_header_packet);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_UPDATE_PFM;

	update_header->port_id = 0;
	update_data[0] = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_pfm_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_0.mock, cmd.pfm_0.base.store_manifest, &cmd.pfm_0, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], 1),
		MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header, struct cerberus_protocol_pfm_update_header_packet*,
		&request);
	uint8_t *update_data = &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_pfm_update_header_packet);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_UPDATE_PFM;

	update_header->port_id = 1;
	update_data[0] = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_pfm_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_1.mock, cmd.pfm_1.base.store_manifest, &cmd.pfm_1, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], 1),
		MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header, struct cerberus_protocol_pfm_update_header_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_UPDATE_PFM;

	update_header->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_pfm_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header, struct cerberus_protocol_pfm_update_header_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_UPDATE_PFM;

	update_header->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_pfm_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header, struct cerberus_protocol_pfm_update_header_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_UPDATE_PFM;

	update_header->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_pfm_update_header_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header, struct cerberus_protocol_pfm_update_header_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_UPDATE_PFM;

	update_header->port_id = 2;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_pfm_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_complete_pfm_update_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	rq->port_id = 0;
	rq->activation_setting = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_0.mock, cmd.pfm_0.base.finish_manifest, &cmd.pfm_0, 0,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_complete_pfm_update_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	rq->port_id = 1;
	rq->activation_setting = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_1.mock, cmd.pfm_1.base.finish_manifest, &cmd.pfm_1, 0,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port0_immediate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_complete_pfm_update_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	rq->port_id = 0;
	rq->activation_setting = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_0.mock, cmd.pfm_0.base.finish_manifest, &cmd.pfm_0, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port1_immediate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_complete_pfm_update_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	rq->port_id = 1;
	rq->activation_setting = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_1.mock, cmd.pfm_1.base.finish_manifest, &cmd.pfm_1, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_complete_pfm_update_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_complete_pfm_update_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pfm_update_complete_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_complete_pfm_update_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE;

	rq->port_id = 2;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_update_status_response_packet*,
		&request);
	int update_status = 0x00BB11AA;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_PFM_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_0.mock, cmd.pfm_0.base.get_status, &cmd.pfm_0, update_status);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS, header->command);
	CuAssertIntEquals (test, update_status, rsp->update_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_update_status_response_packet*,
		&request);
	int update_status = 0x00BB11AA;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_PFM_UPDATE;
	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_1.mock, cmd.pfm_1.base.get_status, &cmd.pfm_1, update_status);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
			struct cerberus_protocol_get_update_status_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS, header->command);
	CuAssertIntEquals (test, update_status, rsp->update_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_PFM_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_PFM_UPDATE;
	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_update_status_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->port_id = 2;
	rq->update_type = CERBERUS_PROTOCOL_PFM_UPDATE;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port0_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_pfm_id_response_packet*, &request);
	uint32_t pfm_id = 0xABCD;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 0;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (rsp->id), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, header->command);
	CuAssertIntEquals (test, 1, rsp->valid);
	CuAssertIntEquals (test, pfm_id, rsp->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port0_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_pfm_id_response_packet*, &request);
	uint32_t pfm_id = 0xABCD;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 0;
	rq->region = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_pending_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));
	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, 4, -1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, header->command);
	CuAssertIntEquals (test, 1, rsp->valid);
	CuAssertIntEquals (test, pfm_id, rsp->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port1_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_pfm_id_response_packet*, &request);
	uint32_t pfm_id = 0xABCD;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 1;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_1.mock, cmd.pfm_manager_1.base.get_active_pfm,
		&cmd.pfm_manager_1, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_1.mock, cmd.pfm_manager_1.base.free_pfm,
		&cmd.pfm_manager_1, 0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, 4, -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, header->command);
	CuAssertIntEquals (test, 1, rsp->valid);
	CuAssertIntEquals (test, pfm_id, rsp->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port1_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_pfm_id_response_packet*, &request);
	uint32_t pfm_id = 0xABCD;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 1;
	rq->region = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_1.mock, cmd.pfm_manager_1.base.get_pending_pfm,
		&cmd.pfm_manager_1, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_1.mock, cmd.pfm_manager_1.base.free_pfm,
		&cmd.pfm_manager_1, 0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, 4, -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, header->command);
	CuAssertIntEquals (test, 1, rsp->valid);
	CuAssertIntEquals (test, pfm_id, rsp->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port0_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 0;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port0_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 0;
	rq->region = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port1_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 1;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_port1_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 1;
	rq->region = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_no_pfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_pfm_id_response_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 0;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) NULL);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_ID, header->command);
	CuAssertIntEquals (test, 0, rsp->valid);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 0;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));
	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, PFM_NO_MEMORY, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_id_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_ID;

	rq->port_id = 2;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_id_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port0_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp_header, struct cerberus_protocol_get_pfm_supported_fw_header*,
		&request);
	char *supported_fw = (char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_header);
	struct pfm_mock pfm;
	struct pfm_firmware_version versions[2];
	struct pfm_firmware_versions versions_list;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	int version_len;
	int status;

	TEST_START;

	versions[0].fw_version_id =
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1";
	versions[1].fw_version_id =
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2";

	versions_list.versions = versions;
	versions_list.count = 2;

	version_len = strlen (versions[0].fw_version_id) + 1;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &versions_list, sizeof (versions_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_header) + 436, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, header->command);
	CuAssertIntEquals (test, 1, rsp_header->valid);
	CuAssertIntEquals (test, pfm_id, rsp_header->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertStrEquals (test, versions[0].fw_version_id, supported_fw);
	CuAssertStrEquals (test, versions[1].fw_version_id, &supported_fw[version_len]);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port0_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp_header, struct cerberus_protocol_get_pfm_supported_fw_header*,
		&request);
	char *supported_fw = (char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_header);
	struct pfm_mock pfm;
	struct pfm_firmware_version versions[2];
	struct pfm_firmware_versions versions_list;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	int version_len;
	int status;

	TEST_START;

	versions[0].fw_version_id =
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1";
	versions[1].fw_version_id =
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2";

	versions_list.versions = versions;
	versions_list.count = 2;

	version_len = strlen (versions[0].fw_version_id) + 1;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_pending_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &versions_list, sizeof (versions_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_header) + 436, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, header->command);
	CuAssertIntEquals (test, 1, rsp_header->valid);
	CuAssertIntEquals (test, pfm_id, rsp_header->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertStrEquals (test, versions[0].fw_version_id, supported_fw);
	CuAssertStrEquals (test, versions[1].fw_version_id, &supported_fw[version_len]);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port1_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp_header, struct cerberus_protocol_get_pfm_supported_fw_header*,
		&request);
	char *supported_fw = (char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_header);
	struct pfm_mock pfm;
	struct pfm_firmware_version versions[2];
	struct pfm_firmware_versions versions_list;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	int version_len;
	int status;

	TEST_START;

	versions[0].fw_version_id =
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1";
	versions[1].fw_version_id =
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2";

	versions_list.versions = versions;
	versions_list.count = 2;

	version_len = strlen (versions[0].fw_version_id) + 1;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 1;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_1.mock, cmd.pfm_manager_1.base.get_active_pfm,
		&cmd.pfm_manager_1, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_1.mock, cmd.pfm_manager_1.base.free_pfm,
		&cmd.pfm_manager_1, 0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &versions_list, sizeof (versions_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_header) + 436, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, header->command);
	CuAssertIntEquals (test, 1, rsp_header->valid);
	CuAssertIntEquals (test, pfm_id, rsp_header->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertStrEquals (test, versions[0].fw_version_id, supported_fw);
	CuAssertStrEquals (test, versions[1].fw_version_id, &supported_fw[version_len]);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port1_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp_header, struct cerberus_protocol_get_pfm_supported_fw_header*,
		&request);
	char *supported_fw = (char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_header);
	struct pfm_mock pfm;
	struct pfm_firmware_version versions[2];
	struct pfm_firmware_versions versions_list;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	int version_len;
	int status;

	TEST_START;

	versions[0].fw_version_id =
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1";
	versions[1].fw_version_id =
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2";

	versions_list.versions = versions;
	versions_list.count = 2;

	version_len = strlen (versions[0].fw_version_id) + 1;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 1;
	rq->offset = offset;
	rq->region = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_1.mock, cmd.pfm_manager_1.base.get_pending_pfm,
		&cmd.pfm_manager_1, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_1.mock, cmd.pfm_manager_1.base.free_pfm,
		&cmd.pfm_manager_1, 0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &versions_list, sizeof (versions_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t) + 436,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, header->command);
	CuAssertIntEquals (test, 1, rsp_header->valid);
	CuAssertIntEquals (test, pfm_id, rsp_header->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertStrEquals (test, versions[0].fw_version_id, supported_fw);
	CuAssertStrEquals (test, versions[1].fw_version_id, &supported_fw[version_len]);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_nonzero_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp_header, struct cerberus_protocol_get_pfm_supported_fw_header*,
		&request);
	char *supported_fw = (char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_get_pfm_supported_fw_header);
	struct pfm_mock pfm;
	struct pfm_firmware_version versions[2];
	struct pfm_firmware_versions versions_list;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 218;
	int status;

	TEST_START;

	versions[0].fw_version_id =
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1";
	versions[1].fw_version_id =
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2";

	versions_list.versions = versions;
	versions_list.count = 2;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &versions_list, sizeof (versions_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_header) + 218, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, header->command);
	CuAssertIntEquals (test, 1, rsp_header->valid);
	CuAssertIntEquals (test, pfm_id, rsp_header->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertStrEquals (test, versions[1].fw_version_id, supported_fw);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_empty_list (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp_header, struct cerberus_protocol_get_pfm_supported_fw_header*,
		&request);
	struct pfm_mock pfm;
	struct pfm_firmware_versions versions_list;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	int status;

	TEST_START;

	versions_list.versions = NULL;
	versions_list.count = 0;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &versions_list, sizeof (versions_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_pfm_supported_fw_header),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW, header->command);
	CuAssertIntEquals (test, 1, rsp_header->valid);
	CuAssertIntEquals (test, pfm_id, rsp_header->id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_nonzero_offset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	struct pfm_mock pfm;
	struct pfm_firmware_versions versions_list;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 1;
	int status;

	TEST_START;

	versions_list.versions = NULL;
	versions_list.count = 0;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, sizeof (pfm_id), -1);

	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &versions_list, sizeof (versions_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port0_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port0_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port1_region0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 1;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_port1_region1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 1;
	rq->offset = offset;
	rq->region = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_no_pfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) NULL);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_fail_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));
	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, PFM_NO_MEMORY, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	struct pfm_mock pfm;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));
	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, 4, -1);
	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, PFM_NO_MEMORY,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, PFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_invalid_region (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pfm_mock pfm;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 2;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_invalid_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	struct pfm_mock pfm;
	struct pfm_firmware_version versions[2];
	struct pfm_firmware_versions versions_list;
	uint32_t pfm_id = 0xAABBCCDD;
	uint32_t offset = 500;
	int status;

	TEST_START;

	versions[0].fw_version_id =
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1."
		"1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1";
	versions[1].fw_version_id =
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2."
		"2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2";

	versions_list.versions = versions;
	versions_list.count = 2;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 0;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.get_active_pfm,
		&cmd.pfm_manager_0, (intptr_t) &pfm.base);
	status |= mock_expect (&cmd.pfm_manager_0.mock, cmd.pfm_manager_0.base.free_pfm,
		&cmd.pfm_manager_0, 0, MOCK_ARG (&pfm.base));

	status |= mock_expect (&pfm.mock, pfm.base.base.get_id, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &pfm_id, 4, -1);

	status |= mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &versions_list, sizeof(versions_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pfm_supported_fw_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		&request);
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW;

	rq->port_id = 2;
	rq->offset = offset;
	rq->region = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_init (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm.mock, cmd.cfm.base.prepare_manifest, &cmd.cfm, 0, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.crypto_timeout = true;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t) - 1;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_init_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_init_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm.mock, cmd.cfm.base.prepare_manifest, &cmd.cfm,
		MANIFEST_NO_MEMORY, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, MANIFEST_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_CFM;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm.mock, cmd.cfm.base.store_manifest, &cmd.cfm, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_CFM;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_CFM;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_CFM;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm.mock, cmd.cfm.base.store_manifest, &cmd.cfm, CFM_NO_MEMORY,
		MOCK_ARG (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm.mock, cmd.cfm.base.finish_manifest, &cmd.cfm, 0,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete_immediate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm.mock, cmd.cfm.base.finish_manifest, &cmd.cfm, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_cfm_update_complete_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm.mock, cmd.cfm.base.finish_manifest, &cmd.cfm, MANIFEST_NO_MEMORY,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, MANIFEST_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_CFM_UPDATE;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm.mock, cmd.cfm.base.get_status, &cmd.cfm, 0x11223344);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0x11223344,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_update_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_CFM_UPDATE;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_update_status_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_CFM_UPDATE;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t cfm_id = 0xABCD;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &cfm_id, sizeof (cfm_id), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t ),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_ID,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, cfm_id,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t cfm_id = 0xEFAB;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_ID;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_pending_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &cfm_id, sizeof (cfm_id), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_ID,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, cfm_id,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));
	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, CFM_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_no_cfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) NULL);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_ID,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_id_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_region0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cfm_component_ids ids_list= {0};
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t ids[100];
	uint32_t test_ids[100];
	uint32_t cfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	uint8_t *test_ptr = (uint8_t*)test_ids;
	int status;
	int i;

	TEST_START;

	for (i = 0; i < 100; ++i) {
		ids[i] = i;
	}

	ids_list.ids = ids;
	ids_list.count = 100;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &cfm_id, 4, -1);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.get_supported_component_ids, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &ids_list, sizeof(ids_list), -1);
	status |= mock_expect_save_arg (&cfm_mock.mock, 0, 0);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.free_component_ids, &cfm_mock, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (cfm_id) +
		100 * sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0xAABBCCDD,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	memcpy (test_ptr, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (cfm_id)], 400);
	status = testing_validate_array ((uint8_t*) ids, (uint8_t*) test_ids, 400);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_region1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cfm_component_ids ids_list= {0};
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t ids[100];
	uint32_t test_ids[100];
	uint32_t cfm_id = 0xAABBCCDD;
	uint32_t offset = 0;
	uint8_t *test_ptr = (uint8_t*)test_ids;
	int status;
	int i;

	TEST_START;

	for (i = 0; i < 100; ++i) {
		ids[i] = i;
	}

	ids_list.ids = ids;
	ids_list.count = 100;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_pending_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &cfm_id, 4, -1);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.get_supported_component_ids, &cfm_mock,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &ids_list, sizeof(ids_list), -1);
	status |= mock_expect_save_arg (&cfm_mock.mock, 0, 0);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.free_component_ids, &cfm_mock, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t) + 400,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0xAABBCCDD,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	memcpy (test_ptr, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (cfm_id)], 400);
	status = testing_validate_array ((uint8_t*) ids, (uint8_t*) test_ids, 400);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_nonzero_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cfm_component_ids ids_list= {0};
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t ids[100];
	uint32_t test_ids[50];
	uint32_t cfm_id = 0xAABBCCDD;
	uint32_t offset = 200;
	uint8_t *test_ptr = (uint8_t*)test_ids;
	int status;
	int i;

	TEST_START;

	for (i = 0; i < 100; ++i) {
		ids[i] = i;
	}

	ids_list.ids = ids;
	ids_list.count = 100;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &cfm_id, 4, -1);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.get_supported_component_ids, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &ids_list, sizeof(ids_list), -1);
	status |= mock_expect_save_arg (&cfm_mock.mock, 0, 0);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.free_component_ids, &cfm_mock, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (cfm_id) +
		50 * sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0xAABBCCDD,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	memcpy (test_ptr, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (cfm_id)], 200);
	status = testing_validate_array ((uint8_t*) &ids[50], (uint8_t*) test_ids, 200);
	CuAssertIntEquals (test, 0, status);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_no_cfm_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, false, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_no_active_cfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) NULL);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_no_pending_cfm (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_pending_cfm,
		&cmd.cfm_manager, (intptr_t) NULL);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_fail_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));
	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, CFM_NO_MEMORY,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t cfm_id = 0xAABBCCDD;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &cfm_id, 4, -1);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.get_supported_component_ids, &cfm_mock,
		CFM_NO_MEMORY, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CFM_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + sizeof (uint32_t);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t);
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_invalid_region (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 2;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_cfm_component_ids_invalid_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cfm_mock cfm_mock;
	struct cfm_component_ids ids_list;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t offset = 400;
	uint32_t ids[100];
	uint32_t cfm_id = 0xAABBCCDD;
	int status;

	TEST_START;

	ids_list.ids = ids;
	ids_list.count = 100;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cfm_mock_init (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.get_active_cfm,
		&cmd.cfm_manager, (intptr_t) &cfm_mock.base);
	status |= mock_expect (&cmd.cfm_manager.mock, cmd.cfm_manager.base.free_cfm, &cmd.cfm_manager,
		0, MOCK_ARG (&cfm_mock.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm_mock.mock, cfm_mock.base.base.get_id, &cfm_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &cfm_id, sizeof (cfm_id), -1);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.get_supported_component_ids, &cfm_mock,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cfm_mock.mock, 0, &ids_list, sizeof(ids_list), -1);
	status |= mock_expect_save_arg (&cfm_mock.mock, 0, 0);

	status |= mock_expect (&cfm_mock.mock, cfm_mock.base.free_component_ids, &cfm_mock, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cfm_mock_validate_and_release (&cfm_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_clear_debug (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_DEBUG_LOG;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

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

static void cmd_interface_system_test_process_log_clear_tcg (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_TCG_LOG;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_clear_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_DEBUG_LOG;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_clear_invalid_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_CLEAR_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_TAMPER_LOG;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_debug_fill_log (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_FILL_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.background.mock, cmd.background.base.debug_log_fill, &cmd.background,
 		0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_log_info (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t debug_size = 15;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_LOG_INFO;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.debug.mock, cmd.debug.base.get_size, &cmd.debug, debug_size);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 * sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_LOG_INFO,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, debug_size,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]));
	CuAssertIntEquals (test, 6 * sizeof (struct pcr_store_tcg_log_entry),
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t)]));
	CuAssertIntEquals (test, 0,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 * sizeof (uint32_t)]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_log_info_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_LOG_INFO;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_log_info_fail_debug (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t debug_size = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_LOG_INFO;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.debug.mock, cmd.debug.base.get_size, &cmd.debug,
		LOGGING_GET_SIZE_FAILED);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 * sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_LOG_INFO,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, debug_size,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]));
	CuAssertIntEquals (test, 6 * sizeof (struct pcr_store_tcg_log_entry),
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t)]));
	CuAssertIntEquals (test, 0,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 * sizeof (uint32_t)]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_debug (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t entry[5120];
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t offset = 0;
	uint8_t log_entries[5120];
	int status;
	int i_entry;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_READ_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_DEBUG_LOG;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

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
	}

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.debug.mock, cmd.debug.base.read_contents, &cmd.debug, 4083,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (4083));
	status |= mock_expect_output (&cmd.debug.mock, 1, entry, sizeof (entry), 2);

	status |= mock_expect (&cmd.debug.mock, cmd.debug.base.read_contents, &cmd.debug, 1037,
		MOCK_ARG (4083), MOCK_ARG_NOT_NULL, MOCK_ARG (4083));
	status |= mock_expect_output (&cmd.debug.mock, 1, &entry[4083], 1037, 2);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 4083, request.length);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	memcpy (log_entries, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], 4083);

	offset = 4083;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_DEBUG_LOG;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1037, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	memcpy (&log_entries[offset], &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], 1037);

	status = testing_validate_array ((uint8_t*) entry, log_entries, sizeof (log_entries));
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_tcg (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pcr_store_tcg_log_entry exp_buf[6];
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
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i_measurement;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_READ_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_TCG_LOG;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	memset (exp_buf, 0, sizeof (exp_buf));
	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		exp_buf[i_measurement].header.log_magic = 0xCB;
		exp_buf[i_measurement].header.length = sizeof (struct pcr_store_tcg_log_entry);
		exp_buf[i_measurement].header.entry_id = i_measurement;
		exp_buf[i_measurement].entry.digest_algorithm_id = 0x0B;
		exp_buf[i_measurement].entry.digest_count = 1;
		exp_buf[i_measurement].entry.measurement_size = 32;
		exp_buf[i_measurement].entry.measurement_index = i_measurement;
		exp_buf[i_measurement].entry.measurement_type = PCR_MEASUREMENT (0, i_measurement);

		memcpy (exp_buf[i_measurement].entry.digest, digests[i_measurement],
			sizeof (exp_buf[i_measurement].entry.digest));
		memcpy (exp_buf[i_measurement].entry.measurement, digests[5 - i_measurement],
			sizeof (exp_buf[i_measurement].entry.measurement));
	}

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[0], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digests[5], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digests[4], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digests[3], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[3], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digests[2], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[2], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[4], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digests[1], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash, 0);
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[1], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.update, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (digests[5], PCR_DIGEST_LENGTH), MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect (&cmd.hash.mock, cmd.hash.base.finish, &cmd.hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 0, digests[0], PCR_DIGEST_LENGTH, -1);

	CuAssertIntEquals (test, 0, status);

	for (i_measurement = 0; i_measurement < 6; ++i_measurement) {
		pcr_store_update_digest (&cmd.store, PCR_MEASUREMENT (0, i_measurement),
			digests[i_measurement], PCR_DIGEST_LENGTH);
	}

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN +
		6 * sizeof (struct pcr_store_tcg_log_entry), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) exp_buf,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		request.length - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_debug_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_READ_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_DEBUG_LOG;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.debug.mock, cmd.debug.base.read_contents, &cmd.debug,
		LOGGING_READ_CONTENTS_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (4083));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, LOGGING_READ_CONTENTS_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_tcg_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t offset = 0;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_READ_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_TCG_LOG;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.start_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	pcr_store_update_digest (&cmd.store, PCR_MEASUREMENT (0, 0), buffer0, PCR_DIGEST_LENGTH);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_invalid_offset (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t offset = 500;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_READ_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_DEBUG_LOG;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], &offset, sizeof (offset));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (offset);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.debug.mock, cmd.debug.base.read_contents, &cmd.debug, 0,
		MOCK_ARG (500), MOCK_ARG_NOT_NULL, MOCK_ARG (4083));
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_READ_LOG,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_invalid_type (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_READ_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = NUM_CERBERUS_PROTOCOL_LOG_TYPES;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_log_read_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_READ_LOG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_DEBUG_LOG;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + sizeof (uint32_t);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t);
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint8_t cert_buf[64] = {0};
	uint8_t num_cert = 2;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	cert_buf[0] = 0xAA;
	cert_buf[1] = 0xBB;
	cert_buf[62] = 0xCC;
	cert_buf[63] = 0xDD;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.get_digests, 
		&cmd.slave_attestation, 64, MOCK_ARG (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]), 
		MOCK_ARG (4081), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.slave_attestation.mock, 0, cert_buf, sizeof(cert_buf), -1);
	status |= mock_expect_output (&cmd.slave_attestation.mock, 2, &num_cert, sizeof(num_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 71, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 2, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, 0xAA, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 3]);
	CuAssertIntEquals (test, 0xCC, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 64]);
	CuAssertIntEquals (test, 0xDD, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 65]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_unsupported_algo (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_digest_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.get_digests, 
		&cmd.slave_attestation, ATTESTATION_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL, MOCK_ARG (4081), 
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate_digest (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct attestation_challenge challenge = {0};
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + 3 * SHA256_HASH_LENGTH;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.compare_digests, 
		&cmd.master_attestation, 0, MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.issue_challenge, 
		&cmd.master_attestation, sizeof (struct attestation_challenge), 
		MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG (0), 
		MOCK_ARG (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]), MOCK_ARG (4083));
	status |= mock_expect_output (&cmd.master_attestation.mock, 2, &challenge,
		sizeof (struct attestation_challenge), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = false;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN +
		sizeof (struct attestation_challenge), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, true, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) &challenge,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], sizeof (struct attestation_challenge));
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate_digest_int_mismatch (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + 3 * SHA256_HASH_LENGTH;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.compare_digests, 
		&cmd.master_attestation, 1, MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.new_request = false;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + 2 * sizeof (uint16_t),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, 0, *((uint16_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]));
	CuAssertIntEquals (test, 0,
		*((uint16_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + sizeof (uint16_t)]));
	CuAssertIntEquals (test, true, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate_digest_leaf_mismatch (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + SHA256_HASH_LENGTH;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.compare_digests, 
		&cmd.master_attestation, 1, MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.new_request = false;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + 2 * sizeof (uint16_t),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, 0, *((uint16_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]));
	CuAssertIntEquals (test, 0,
		*((uint16_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + sizeof (uint16_t)]));
	CuAssertIntEquals (test, true, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate_digest_compare_digests_fail (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + 3 * SHA256_HASH_LENGTH;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.compare_digests, 
		&cmd.master_attestation, ATTESTATION_NO_MEMORY, MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate_digest_issue_challenge_fail (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + 3 * SHA256_HASH_LENGTH;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.compare_digests, 
		&cmd.master_attestation, 0, MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG_NOT_NULL);
	status |= mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.issue_challenge, 
		&cmd.master_attestation, ATTESTATION_NO_MEMORY, MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG (0),
		MOCK_ARG (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]), MOCK_ARG (4083));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate_digest_invalid_buf_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 + 3 * SHA256_HASH_LENGTH;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + 3 * SHA256_HASH_LENGTH;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	struct cerberus_protocol_get_certificate_request_packet *rq =
		(struct cerberus_protocol_get_certificate_request_packet*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	struct cerberus_protocol_get_certificate_response_header *hdr =
		(struct cerberus_protocol_get_certificate_response_header*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	rq->slot_num = 0;
	rq->cert_num = 0;
	rq->offset = 0;
	rq->length = 10;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.get_certificate, 
		&cmd.slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.slave_attestation.mock, 2, &cert, sizeof (struct der_cert), -1);

	status |= mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.get_certificate, 
		&cmd.slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.slave_attestation.mock, 2, &cert, sizeof (struct der_cert), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_response_header) + 10, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, header->command);
	CuAssertIntEquals (test, 0, hdr->slot_num);
	CuAssertIntEquals (test, 0, hdr->cert_num);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, request.data +
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_certificate_response_header), 10);
	CuAssertIntEquals (test, 0, status);

	rq->slot_num = 0;
	rq->cert_num = 0;
	rq->offset = 10;
	rq->length = 10;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_response_header) + 10, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, header->command);
	CuAssertIntEquals (test, 0, hdr->slot_num);
	CuAssertIntEquals (test, 0, hdr->cert_num);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (&X509_CERTCA_ECC_CA_NOPL_DER[10], request.data +
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_certificate_response_header), 10);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_length_0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	struct cerberus_protocol_get_certificate_request_packet *rq =
		(struct cerberus_protocol_get_certificate_request_packet*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	struct cerberus_protocol_get_certificate_response_header *hdr =
		(struct cerberus_protocol_get_certificate_response_header*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	rq->slot_num = 0;
	rq->cert_num = 0;
	rq->offset = 0;
	rq->length = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.get_certificate, 
		&cmd.slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.slave_attestation.mock, 2, &cert, sizeof (struct der_cert), -1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_response_header) + X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, header->command);
	CuAssertIntEquals (test, 0, hdr->slot_num);
	CuAssertIntEquals (test, 0, hdr->cert_num);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, request.data +
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_certificate_response_header),
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_length_too_big (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	struct cerberus_protocol_get_certificate_request_packet *rq =
		(struct cerberus_protocol_get_certificate_request_packet*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	struct cerberus_protocol_get_certificate_response_header *hdr =
		(struct cerberus_protocol_get_certificate_response_header*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	struct der_cert cert = {
		.cert = X509_CERTCA_ECC_CA_NOPL_DER,
		.length = X509_CERTCA_ECC_CA_NOPL_DER_LEN
	};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	rq->slot_num = 0;
	rq->cert_num = 0;
	rq->offset = 0;
	rq->length = 6000;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.get_certificate, 
		&cmd.slave_attestation, 0, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.slave_attestation.mock, 2, &cert, sizeof (struct der_cert), -1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_response_header) + X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE, header->command);
	CuAssertIntEquals (test, 0, hdr->slot_num);
	CuAssertIntEquals (test, 0, hdr->cert_num);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, request.data +
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_certificate_response_header),
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	struct cerberus_protocol_get_certificate_request_packet *rq =
		(struct cerberus_protocol_get_certificate_request_packet*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	rq->slot_num = 0;
	rq->cert_num = 0;
	rq->offset = 0;
	rq->length = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_unsupported_slot_num (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	struct cerberus_protocol_get_certificate_request_packet *rq =
		(struct cerberus_protocol_get_certificate_request_packet*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	rq->slot_num = 2;
	rq->cert_num = 0;
	rq->offset = 0;
	rq->length = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_certificate_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	struct cerberus_protocol_get_certificate_request_packet *rq =
		(struct cerberus_protocol_get_certificate_request_packet*)
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	rq->slot_num = 0;
	rq->cert_num = 0;
	rq->offset = 0;
	rq->length = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.get_certificate, 
		&cmd.slave_attestation, ATTESTATION_NO_MEMORY, MOCK_ARG (0), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	memcpy (request.data, &header, sizeof (header));
	memset (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2], 0x55, 32);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 34;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.store_certificate, 
		&cmd.master_attestation, 0, MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG (0), MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2], 32),
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	cmd.handler.master_attestation->encryption_algorithm = ATTESTATION_ECDHE_KEY_EXCHANGE;

	request.new_request = false;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 2, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, ATTESTATION_ECDHE_KEY_EXCHANGE,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, true, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_certificate_store_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_CERTIFICATE;

	memcpy (request.data, &header, sizeof (header));
	memset (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2], 0x55, 32);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 34;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.store_certificate, 
		&cmd.master_attestation, ATTESTATION_NO_MEMORY, MOCK_ARG (MCTP_PROTOCOL_BMC_EID), MOCK_ARG (0), 
		MOCK_ARG (0), 
		MOCK_ARG_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2], 32),
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct attestation_response *response;
	struct cerberus_protocol_header header = {0};
	uint8_t response_buf[136] = {0};
	int status;

	TEST_START;

	response = (struct attestation_response*) response_buf;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (struct attestation_response)] = 0xCC;
	response_buf[sizeof (struct attestation_response) + 31] = 0xDD;
	response_buf[sizeof (struct attestation_response) + 32] = 0xEE;
	response_buf[sizeof (struct attestation_response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	memset (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2], 0x55, 32);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 34;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.challenge_response, 
		&cmd.slave_attestation, sizeof (response_buf), MOCK_ARG_NOT_NULL, MOCK_ARG (4083));
	status |= mock_expect_output (&cmd.slave_attestation.mock, 0, &response_buf, sizeof (response_buf), 
		-1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (response_buf, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (response_buf));
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	memset (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2], 0x55, 32);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 34;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.slave_attestation.mock, cmd.slave_attestation.base.challenge_response, 
		&cmd.slave_attestation, ATTESTATION_NO_MEMORY, MOCK_ARG_NOT_NULL, MOCK_ARG (4083));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_challenge_response_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	memset (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2], 0x55, 32);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 35;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 33;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_challenge_response (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	struct attestation_response *response;
	uint8_t response_buf[136] = {0};
	int status;

	TEST_START;

	response = (struct attestation_response*) response_buf;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (struct attestation_response)] = 0xCC;
	response_buf[sizeof (struct attestation_response) + 31] = 0xDD;
	response_buf[sizeof (struct attestation_response) + 32] = 0xEE;
	response_buf[sizeof (struct attestation_response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], response_buf, sizeof (response_buf));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, 
		cmd.master_attestation.base.process_challenge_response, &cmd.master_attestation, 0, 
		MOCK_ARG_PTR_CONTAINS (response_buf, sizeof (response_buf)),
		MOCK_ARG (sizeof (response_buf)), MOCK_ARG (MCTP_PROTOCOL_BMC_EID));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_process_challenge_response_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	struct attestation_response *response;
	uint8_t response_buf[136] = {0};
	int status;

	TEST_START;

	response = (struct attestation_response*) response_buf;

	response->slot_num = 0;
	response->slot_mask = 1;
	response->min_protocol_version = 1;
	response->max_protocol_version = 1;
	response->nonce[0] = 0xAA;
	response->nonce[31] = 0xBB;
	response->num_digests = 2;
	response->digests_size = SHA256_HASH_LENGTH;

	response_buf[sizeof (struct attestation_response)] = 0xCC;
	response_buf[sizeof (struct attestation_response) + 31] = 0xDD;
	response_buf[sizeof (struct attestation_response) + 32] = 0xEE;
	response_buf[sizeof (struct attestation_response) + 95] = 0xFF;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], response_buf, sizeof (response_buf));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (response_buf);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, 
		cmd.master_attestation.base.process_challenge_response, &cmd.master_attestation, ATTESTATION_NO_MEMORY, 
		MOCK_ARG_PTR_CONTAINS (response_buf, sizeof (response_buf)), 
		MOCK_ARG (sizeof (response_buf)), MOCK_ARG (MCTP_PROTOCOL_BMC_EID));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cmd.handler.base.process_request (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_ctrl_eid_unknown_command (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = 0xFF;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_get_capabilities (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cerberus_protocol_device_capabilities capabilities = {{0}};
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	capabilities.capabilities.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	capabilities.capabilities.bus_role = DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE;
	capabilities.capabilities.max_payload_size = 4224;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], (uint8_t*) &capabilities,
		sizeof (struct cerberus_protocol_device_capabilities));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN +
		sizeof (struct cerberus_protocol_device_capabilities);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN +
		sizeof (struct cerberus_protocol_device_capabilities_response), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) &capabilities,
		(uint8_t*) &cmd.handler.device_manager->entries[1].info.capabilities,
		sizeof (struct cerberus_protocol_device_capabilities));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (
		(uint8_t*) &cmd.handler.device_manager->entries[0].info.capabilities,
			&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		sizeof (struct cerberus_protocol_device_capabilities));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN +
		sizeof (struct cerberus_protocol_device_capabilities)],
		(MCTP_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10));
	CuAssertIntEquals (test,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN +
		sizeof (struct cerberus_protocol_device_capabilities) + 1],
		(MCTP_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100));

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_get_capabilities_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN +
		sizeof (struct cerberus_protocol_device_capabilities) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN +
		sizeof (struct cerberus_protocol_device_capabilities) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint16_t seed_len = 2;
	uint16_t cipher_len = 2;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &seed_len, sizeof (seed_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)] = 0xAA;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 1] = 0xBB;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2], &cipher_len,
		sizeof (cipher_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len)] =
		0xCC;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 3 + sizeof (cipher_len)] =
		0xDD;
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len)],
		0x55, SHA256_HASH_LENGTH);
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len) +
		SHA256_HASH_LENGTH], 0xAA, 64);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 104;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.background.mock, cmd.background.base.unseal_start, &cmd.background,
		0, MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)], seed_len),
		MOCK_ARG (seed_len), MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len)],
		SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len)],
		cipher_len), MOCK_ARG (cipher_len), MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len) +
		SHA256_HASH_LENGTH], 64), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint16_t seed_len = 2;
	uint16_t cipher_len = 2;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &seed_len, sizeof (seed_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)] = 0xAA;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 1] = 0xBB;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2], &cipher_len,
		sizeof (cipher_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len)] =
		0xCC;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 3 + sizeof (cipher_len)] =
		0xDD;
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len)],
		0x55, SHA256_HASH_LENGTH);
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len) +
		SHA256_HASH_LENGTH], 0xAA, 64);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 104;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.background.mock, cmd.background.base.unseal_start, &cmd.background,
		CMD_BACKGROUND_UNSEAL_FAILED, MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)], seed_len),
		MOCK_ARG (seed_len), MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len)],
		SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len)],
		cipher_len), MOCK_ARG (cipher_len), MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len) +
		SHA256_HASH_LENGTH], 64), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSEAL_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_downstream_device (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint16_t seed_len = 2;
	uint16_t cipher_len = 2;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &seed_len, sizeof (seed_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)] = 0xAA;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 1] = 0xBB;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2], &cipher_len,
		sizeof (cipher_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len)] =
		0xCC;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 3 + sizeof (cipher_len)] =
		0xDD;
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len)],
		0x55, SHA256_HASH_LENGTH);
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len) +
		SHA256_HASH_LENGTH], 0xAA, 64);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 104;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_DEVICE_MODE, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_no_seed_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint16_t seed_len = 0;
	uint16_t cipher_len = 2;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &seed_len, sizeof (seed_len));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)], &cipher_len,
		sizeof (cipher_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + sizeof (cipher_len)] =
		0xCC;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 1 + sizeof (cipher_len)] =
		0xDD;
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len)],
		0x55, SHA256_HASH_LENGTH);
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len) +
		SHA256_HASH_LENGTH], 0xAA, 64);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 102;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_no_cipher_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint16_t seed_len = 2;
	uint16_t cipher_len = 0;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &seed_len, sizeof (seed_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)] = 0xAA;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 1] = 0xBB;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2], &cipher_len,
		sizeof (cipher_len));
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len)],
		0x55, SHA256_HASH_LENGTH);
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len) +
		SHA256_HASH_LENGTH], 0xAA, 64);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 102;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_incomplete_payload (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint16_t seed_len = 2;
	uint16_t cipher_len = 2;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &seed_len, sizeof (seed_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)] = 0xAA;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 1] = 0xBB;
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2], &cipher_len,
		sizeof (cipher_len));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 2 + sizeof (cipher_len)] =
		0xCC;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 3 + sizeof (cipher_len)] =
		0xDD;
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len)],
		0x55, SHA256_HASH_LENGTH);
	memset (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + 4 + sizeof (cipher_len) +
		SHA256_HASH_LENGTH], 0xAA, 64);
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	size_t max_buf_len = 4077;
	uint32_t attestation_status = 0;
	uint8_t key[] = {
		0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,
		0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0xEE,0xDD
	};
	uint16_t key_len = sizeof (key);
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.background.mock, cmd.background.base.unseal_result, &cmd.background,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (&max_buf_len, sizeof (max_buf_len)),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.background.mock, 0, key, sizeof (key), -1);
	status |= mock_expect_output (&cmd.background.mock, 1, &key_len, sizeof (key_len), -1);
	status |= mock_expect_output (&cmd.background.mock, 2, &attestation_status,
		sizeof (attestation_status), -1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 43, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) &attestation_status,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], sizeof (attestation_status));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &key_len,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 4], sizeof (key_len));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (key, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 6],
		sizeof (key));
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result_busy (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	size_t max_buf_len = 4077;
	uint32_t attestation_status = ATTESTATION_CMD_STATUS_RUNNING;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.background.mock, cmd.background.base.unseal_result, &cmd.background,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (&max_buf_len, sizeof (max_buf_len)),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.background.mock, 2, &attestation_status,
		sizeof (attestation_status), -1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (attestation_status),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array ((uint8_t*) &attestation_status,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], sizeof (attestation_status));
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	size_t max_buf_len = 4077;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.background.mock, cmd.background.base.unseal_result, &cmd.background,
		CMD_BACKGROUND_UNSEAL_RESULT_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&max_buf_len, sizeof (max_buf_len)), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_UNSEAL_RESULT_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result_downstream_device (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_DOWNSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_DEVICE_MODE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_request_unseal_result_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_0.mock, cmd.host_0.base.get_next_reset_verification_actions,
		&cmd.host_0, HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_1.mock, cmd.host_1.base.get_next_reset_verification_actions,
		&cmd.host_1, HOST_PROCESSOR_ACTION_ACTIVATE_PFM_AND_UPDATE);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_ACTIVATE_PFM_AND_UPDATE,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, false, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, false, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_invalid_port (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_fw_reset_verification_status_invalid_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port0_out_of_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_host_state_response_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_ctrl_0.mock, cmd.host_ctrl_0.base.is_processor_in_reset,
		&cmd.host_ctrl_0, 0);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_host_state_response_packet),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, header->command);
	CuAssertIntEquals (test, 0, rsp->reset_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port0_held_in_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_host_state_response_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_ctrl_0.mock, cmd.host_ctrl_0.base.is_processor_in_reset,
		&cmd.host_ctrl_0, 1);
	status |= mock_expect (&cmd.host_ctrl_0.mock, cmd.host_ctrl_0.base.is_processor_held_in_reset,
		&cmd.host_ctrl_0, 1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_host_state_response_packet),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, header->command);
	CuAssertIntEquals (test, 1, rsp->reset_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port0_not_held_in_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_host_state_response_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_ctrl_0.mock, cmd.host_ctrl_0.base.is_processor_in_reset,
		&cmd.host_ctrl_0, 1);
	status |= mock_expect (&cmd.host_ctrl_0.mock, cmd.host_ctrl_0.base.is_processor_held_in_reset,
		&cmd.host_ctrl_0, 0);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_host_state_response_packet),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, header->command);
	CuAssertIntEquals (test, 2, rsp->reset_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port0_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, false,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port1_out_of_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_host_state_response_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_ctrl_1.mock, cmd.host_ctrl_1.base.is_processor_in_reset,
		&cmd.host_ctrl_1, 0);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_host_state_response_packet),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, header->command);
	CuAssertIntEquals (test, 0, rsp->reset_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port1_held_in_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_host_state_response_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_ctrl_1.mock, cmd.host_ctrl_1.base.is_processor_in_reset,
		&cmd.host_ctrl_1, 1);
	status |= mock_expect (&cmd.host_ctrl_1.mock, cmd.host_ctrl_1.base.is_processor_held_in_reset,
		&cmd.host_ctrl_1, 1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_host_state_response_packet),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, header->command);
	CuAssertIntEquals (test, 1, rsp->reset_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port1_not_held_in_reset (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_host_state_response_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_ctrl_1.mock, cmd.host_ctrl_1.base.is_processor_in_reset,
		&cmd.host_ctrl_1, 1);
	status |= mock_expect (&cmd.host_ctrl_1.mock, cmd.host_ctrl_1.base.is_processor_held_in_reset,
		&cmd.host_ctrl_1, 0);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_host_state_response_packet),
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_HOST_STATE, header->command);
	CuAssertIntEquals (test, 2, rsp->reset_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_port1_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		false, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_invalid_port (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 2;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_reset_check_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_ctrl_1.mock, cmd.host_ctrl_1.base.is_processor_in_reset,
		&cmd.host_ctrl_1, HOST_CONTROL_RESET_CHECK_FAILED);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, HOST_CONTROL_RESET_CHECK_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_host_reset_status_hold_check_error (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_HOST_STATE;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.host_ctrl_0.mock, cmd.host_ctrl_0.base.is_processor_in_reset,
		&cmd.host_ctrl_0, HOST_CONTROL_HOLD_CHECK_FAILED);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, HOST_CONTROL_HOLD_CHECK_FAILED, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_request_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (NULL,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, NULL, NULL, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, NULL, buf, CERBERUS_PROTOCOL_MIN_MSG_LEN - 1);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_request_invalid_request (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (&cmd.handler.base, 0xFF, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_COMMAND, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_get_device_capabilities (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, buf[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &buf[1]));
	CuAssertIntEquals (test, 0, buf[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN +
		sizeof (struct cerberus_protocol_device_capabilities), status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES,
		buf[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);

	status = testing_validate_array (
		(uint8_t*) &cmd.handler.device_manager->entries[0].info.capabilities,
		&buf[CERBERUS_PROTOCOL_MIN_MSG_LEN], sizeof (struct cerberus_protocol_device_capabilities));
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_get_device_capabilities_buf_too_small (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_get_certificate_digest (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	cmd.handler.master_attestation->encryption_algorithm = ATTESTATION_ECDHE_KEY_EXCHANGE;

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_DIGEST, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 2, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, buf[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &buf[1]));
	CuAssertIntEquals (test, 0, buf[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DIGEST, buf[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, buf[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, ATTESTATION_ECDHE_KEY_EXCHANGE,
		buf[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_get_certificate_digest_buf_too_small (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_DIGEST, NULL, buf, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_get_certificate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cerberus_protocol_cert_req_params params = {0};
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	params.slot_num = 1;
	params.cert_num = 2;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_CERTIFICATE, &params, buf, sizeof (buf));
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + 2 * sizeof (uint16_t), status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, buf[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &buf[1]));
	CuAssertIntEquals (test, 0, buf[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_CERTIFICATE,
		buf[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, buf[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 2, buf[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, 0, *((uint16_t*)&buf[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]));
	CuAssertIntEquals (test, 0,
		*((uint16_t*)&buf[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + sizeof (uint16_t)]));

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_get_certificate_buf_too_small (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cerberus_protocol_cert_req_params params = {0};
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_CERTIFICATE, &params, buf, CERBERUS_PROTOCOL_MIN_MSG_LEN + 5);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_get_certificate_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_GET_CERTIFICATE, NULL, buf, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cerberus_protocol_challenge_req_params params = {0};
	struct attestation_challenge challenge = {0};
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	params.eid = 2;
	params.slot_num = 3;

	challenge.slot_num = 3;
	challenge.reserved = 0;
	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.issue_challenge, 
		&cmd.master_attestation, sizeof (struct attestation_challenge), MOCK_ARG (2), MOCK_ARG (3),
		MOCK_ARG (&buf[CERBERUS_PROTOCOL_MIN_MSG_LEN]),
		MOCK_ARG (sizeof (buf) - CERBERUS_PROTOCOL_MIN_MSG_LEN));
	status |= mock_expect_output (&cmd.master_attestation.mock, 2, &challenge,
		sizeof (struct attestation_challenge), -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, &params, buf, sizeof (buf));
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 + ATTESTATION_NONCE_LEN, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, buf[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &buf[1]));
	CuAssertIntEquals (test, 0, buf[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE,
		buf[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 3, buf[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0, buf[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);

	status = testing_validate_array (challenge.nonce, &buf[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2],
		ATTESTATION_NONCE_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_challenge_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cerberus_protocol_challenge_req_params params = {0};
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	params.eid = 2;
	params.slot_num = 3;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.master_attestation.mock, cmd.master_attestation.base.issue_challenge, 
		&cmd.master_attestation, ATTESTATION_NO_MEMORY, MOCK_ARG (2), MOCK_ARG (3), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (buf) - CERBERUS_PROTOCOL_MIN_MSG_LEN));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, &params, buf, sizeof(buf));
	CuAssertIntEquals (test, ATTESTATION_NO_MEMORY, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_issue_challenge_null (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = cmd.handler.base.issue_request (&cmd.handler.base,
		CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE, NULL, buf, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_PCD_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_no_pcd (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_PCD_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pcd_manager.mock, cmd.pcd_manager.base.get_active_pcd,
		&cmd.pcd_manager, (intptr_t) NULL);
	status |= mock_expect (&cmd.pcd_manager.mock, cmd.pcd_manager.base.free_pcd, &cmd.pcd_manager,
		0, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PCD_ID,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pcd_mock pcd_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_PCD_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pcd_mock_init (&pcd_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pcd_manager.mock, cmd.pcd_manager.base.get_active_pcd,
		&cmd.pcd_manager, (intptr_t) &pcd_mock.base);
	status |= mock_expect (&cmd.pcd_manager.mock, cmd.pcd_manager.base.free_pcd, &cmd.pcd_manager,
		0, MOCK_ARG (&pcd_mock.base));
	status |= mock_expect (&pcd_mock.mock, pcd_mock.base.base.get_id, &pcd_mock, PCD_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, PCD_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pcd_mock_validate_and_release (&pcd_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct pcd_mock pcd_mock;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t pcd_id = 0xABCD;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_PCD_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = pcd_mock_init (&pcd_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.pcd_manager.mock, cmd.pcd_manager.base.get_active_pcd, &cmd.pcd_manager,
		(intptr_t) &pcd_mock.base);
	status |= mock_expect (&cmd.pcd_manager.mock, cmd.pcd_manager.base.free_pcd, &cmd.pcd_manager, 0,
		MOCK_ARG (&pcd_mock.base));
	status |= mock_expect (&pcd_mock.mock, pcd_mock.base.base.get_id, &pcd_mock, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pcd_mock.mock, 0, &pcd_id, sizeof (pcd_id), -1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_PCD_ID,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, pcd_id,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = pcd_mock_validate_and_release (&pcd_mock);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_id_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_PCD_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_init (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_PCD_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pcd.mock, cmd.pcd.base.prepare_manifest, &cmd.pcd, 0, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_init_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_PCD_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_init_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_PCD_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_init_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	uint32_t size = 1;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_INIT_PCD_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	memcpy (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &size, sizeof (size));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (size);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pcd.mock, cmd.pcd.base.prepare_manifest, &cmd.pcd, MANIFEST_NO_MEMORY,
		MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, MANIFEST_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_PCD;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pcd.mock, cmd.pcd.base.store_manifest, &cmd.pcd, 0,
		MOCK_ARG (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_PCD;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_PCD;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_UPDATE_PCD;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pcd.mock, cmd.pcd.base.store_manifest, &cmd.pcd, PCD_NO_MEMORY,
		MOCK_ARG (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, PCD_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_complete (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pcd.mock, cmd.pcd.base.finish_manifest, &cmd.pcd, 0, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_complete_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_complete_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	request.crypto_timeout = false;

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_pcd_update_complete_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pcd.mock, cmd.pcd.base.finish_manifest, &cmd.pcd, MANIFEST_NO_MEMORY,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, MANIFEST_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_update_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_PCD_UPDATE;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.pcd.mock, cmd.pcd.base.get_status, &cmd.pcd, 0x11223344);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0x11223344,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_update_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_PCD_UPDATE;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_pcd_update_status_no_pcd_manager (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_PCD_UPDATE;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, false, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_devid_csr (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + RIOT_CORE_DEVID_CSR_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_EXPORT_CSR,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (RIOT_CORE_DEVID_CSR,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		request.length - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_devid_csr_invalid_buf_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_devid_csr_unsupported_index (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_EXPORT_CSR;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_dev_id_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 0;
	rq->cert_length = RIOT_CORE_DEVID_SIGNED_CERT_LEN;
	memcpy (&rq->certificate, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		RIOT_CORE_DEVID_SIGNED_CERT_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.keystore.mock, cmd.keystore.base.save_key, &cmd.keystore, 0,
		MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN));

	status |= mock_expect (&cmd.background.mock, cmd.background.base.authenticate_riot_certs,
		&cmd.background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_root_ca_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 1;
	rq->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&rq->certificate, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		X509_CERTSS_RSA_CA_NOPL_DER_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.keystore.mock, cmd.keystore.base.save_key, &cmd.keystore, 0,
		MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));

	status |= mock_expect (&cmd.background.mock, cmd.background.base.authenticate_riot_certs,
		&cmd.background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_intermediate_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 2;
	rq->cert_length = X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&rq->certificate, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		X509_CERTCA_ECC_CA_NOPL_DER_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.keystore.mock, cmd.keystore.base.save_key, &cmd.keystore, 0,
		MOCK_ARG (2),
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));

	status |= mock_expect (&cmd.background.mock, cmd.background.base.authenticate_riot_certs,
		&cmd.background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 1;
	rq->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&rq->certificate, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) - 2;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_no_cert (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 1;
	rq->cert_length = 0;
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_bad_cert_length (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 1;
	rq->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&rq->certificate, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		X509_CERTSS_RSA_CA_NOPL_DER_LEN - 2;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_unsupported_index (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 3;
	rq->cert_length = RIOT_CORE_DEVID_SIGNED_CERT_LEN;
	memcpy (&rq->certificate, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		RIOT_CORE_DEVID_SIGNED_CERT_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_dev_id_cert_save_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 0;
	rq->cert_length = RIOT_CORE_DEVID_SIGNED_CERT_LEN;
	memcpy (&rq->certificate, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		RIOT_CORE_DEVID_SIGNED_CERT_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.keystore.mock, cmd.keystore.base.save_key, &cmd.keystore,
		KEYSTORE_SAVE_FAILED, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_root_ca_cert_save_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 1;
	rq->cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&rq->certificate, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		X509_CERTSS_RSA_CA_NOPL_DER_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.keystore.mock, cmd.keystore.base.save_key, &cmd.keystore,
		KEYSTORE_SAVE_FAILED, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_intermediate_cert_save_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 2;
	rq->cert_length = X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&rq->certificate, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		X509_CERTCA_ECC_CA_NOPL_DER_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.keystore.mock, cmd.keystore.base.save_key, &cmd.keystore,
		KEYSTORE_SAVE_FAILED, MOCK_ARG (2),
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_import_signed_ca_cert_authenticate_error (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_import_certificate_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT;

	rq->index = 0;
	rq->cert_length = RIOT_CORE_DEVID_SIGNED_CERT_LEN;
	memcpy (&rq->certificate, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	request.length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_import_certificate_request_packet) +
		RIOT_CORE_DEVID_SIGNED_CERT_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.keystore.mock, cmd.keystore.base.save_key, &cmd.keystore, 0,
		MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN));

	status |= mock_expect (&cmd.background.mock, cmd.background.base.authenticate_riot_certs,
		&cmd.background, CMD_BACKGROUND_TASK_BUSY);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_TASK_BUSY, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_signed_cert_state (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_certificate_state_response_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.background.mock, cmd.background.base.get_riot_cert_chain_state,
		&cmd.background, RIOT_CERT_STATE_CHAIN_INVALID);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_certificate_state_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE, header->command);
	CuAssertIntEquals (test, RIOT_CERT_STATE_CHAIN_INVALID, rsp->cert_state);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_signed_cert_state_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_revert_bypass, &cmd.auth, 0,
		MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)), MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect (&cmd.background.mock, cmd.background.base.reset_bypass, &cmd.background,
		0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[32];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < sizeof (nonce); i++) {
		nonce[i] = i;
	}

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_revert_bypass, &cmd.auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect_output (&cmd.auth.mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&cmd.auth.mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + length, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], length);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_max_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < sizeof (nonce); i++) {
		nonce[i] = i;
	}

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_revert_bypass, &cmd.auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect_output (&cmd.auth.mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&cmd.auth.mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + length, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], length);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_not_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_revert_bypass, &cmd.auth,
		AUTHORIZATION_NOT_AUTHORIZED, MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_with_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	size_t length = 253;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));

	for (i = (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1); i < (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + length);
		i++) {
		request.data[i] = i;
	}

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + length;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_revert_bypass, &cmd.auth, 0,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], length),
		MOCK_ARG_PTR_CONTAINS (&length, sizeof (length)));
	status |= mock_expect (&cmd.background.mock, cmd.background.base.reset_bypass, &cmd.background,
		0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_with_nonce_not_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	size_t length = 253;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));

	for (i = (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1); i < (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + length);
		i++) {
		request.data[i] = i;
	}

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + length;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_revert_bypass, &cmd.auth,
		AUTHORIZATION_NOT_AUTHORIZED,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], length),
		MOCK_ARG_PTR_CONTAINS (&length, sizeof (length)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_no_nonce_invalid_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < sizeof (nonce); i++) {
		nonce[i] = i;
	}

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_revert_bypass, &cmd.auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect_output (&cmd.auth.mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&cmd.auth.mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_bypass_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_revert_bypass, &cmd.auth, 0,
		MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)), MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect (&cmd.background.mock, cmd.background.base.reset_bypass, &cmd.background,
		CMD_BACKGROUND_BYPASS_FAILED);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_BYPASS_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_reset_defaults, &cmd.auth, 0,
		MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)), MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect (&cmd.background.mock, cmd.background.base.restore_defaults,
		&cmd.background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[32];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < sizeof (nonce); i++) {
		nonce[i] = i;
	}

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_reset_defaults, &cmd.auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect_output (&cmd.auth.mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&cmd.auth.mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + length, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], length);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_max_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < sizeof (nonce); i++) {
		nonce[i] = i;
	}

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_reset_defaults, &cmd.auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect_output (&cmd.auth.mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&cmd.auth.mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + length, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_RESET_CONFIG,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	status = testing_validate_array (nonce, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN], length);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_not_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_reset_defaults, &cmd.auth,
		AUTHORIZATION_NOT_AUTHORIZED, MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_with_nonce_authorized (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	size_t length = 253;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;

	for (i = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1; i < (length + CERBERUS_PROTOCOL_MIN_MSG_LEN + 1);
		i++) {
		request.data[i] = i;
	}

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + length;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_reset_defaults, &cmd.auth, 0,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], length),
		MOCK_ARG_PTR_CONTAINS (&length, sizeof (length)));
	status |= mock_expect (&cmd.background.mock, cmd.background.base.restore_defaults,
		&cmd.background, 0);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_with_nonce_not_authorized (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	size_t length = 253;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;

	for (i = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1; i < (length + CERBERUS_PROTOCOL_MIN_MSG_LEN + 1);
		i++) {
		request.data[i] = i;
	}

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + length;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_reset_defaults, &cmd.auth,
		AUTHORIZATION_NOT_AUTHORIZED,
		MOCK_ARG_PTR_PTR_CONTAINS_TMP (&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], length),
		MOCK_ARG_PTR_CONTAINS (&length, sizeof (length)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_no_nonce_invalid_challenge (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	int i;
	uint8_t *null = NULL;
	size_t zero = 0;
	uint8_t nonce[MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	uint8_t *challenge = nonce;
	size_t length = sizeof (nonce);

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	for (i = 0; i < sizeof (nonce); i++) {
		nonce[i] = i;
	}

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_reset_defaults, &cmd.auth,
		AUTHORIZATION_CHALLENGE, MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)),
		MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect_output (&cmd.auth.mock, 0, &challenge, sizeof (challenge), -1);
	status |= mock_expect_output (&cmd.auth.mock, 1, &length, sizeof (length), -1);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_restore_defaults_error (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;
	uint8_t *null = NULL;
	size_t zero = 0;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.auth.mock, cmd.auth.base.authorize_reset_defaults, &cmd.auth, 0,
		MOCK_ARG_PTR_CONTAINS (&null, sizeof (null)), MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect (&cmd.background.mock, cmd.background.base.restore_defaults,
		&cmd.background, CMD_BACKGROUND_DEFAULT_FAILED);

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_BACKGROUND_DEFAULT_FAILED, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_config_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_reset_config_invalid_request_subtype (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_RESET_CONFIG;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = false;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, true, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_reset_config_status (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_CONFIG_RESET_UPDATE;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.background.mock, cmd.background.base.get_config_reset_status,
		&cmd.background, 0x00BB11AA);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 0x00BB11AA,
		*((uint32_t*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]));
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_reset_config_status_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = CERBERUS_PROTOCOL_CONFIG_RESET_UPDATE;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_certificate (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = device_manager_init_cert_chain (&cmd.device_manager, 1, 3);
	status |= device_manager_update_cert (&cmd.device_manager, 1, 2, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 + X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, 2, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 3], X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_certificate_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 4;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_certificate_invalid_cert_num (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = device_manager_init_cert_chain (&cmd.device_manager, 1, 3);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_CERT_NUM, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_certificate_get_chain_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 3;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_cert_digest (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.calculate_sha256, &cmd.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 2, X509_CERTCA_ECC_CA2_NOPL_DER,
		SHA256_HASH_LENGTH, 3);

	status |= device_manager_init_cert_chain (&cmd.device_manager, 1, 3);
	status |= device_manager_update_cert (&cmd.device_manager, 1, 2, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 3 + SHA256_HASH_LENGTH,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, 0, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]);
	CuAssertIntEquals (test, 2, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA2_NOPL_DER,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 3], SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_cert_digest_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 4;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_cert_digest_invalid_cert_num (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = device_manager_init_cert_chain (&cmd.device_manager, 1, 3);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_CERT_NUM, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_cert_digest_get_chain_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 3;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 3;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_cert_digest_hash_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CERT_DIGEST;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2] = 2;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.hash.mock, cmd.hash.base.calculate_sha256, &cmd.hash,
		HASH_ENGINE_NO_MEMORY, MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&cmd.hash.mock, 2, X509_CERTCA_ECC_CA2_NOPL_DER,
		SHA256_HASH_LENGTH, 3);

	status |= device_manager_init_cert_chain (&cmd.device_manager, 1, 3);
	status |= device_manager_update_cert (&cmd.device_manager, 1, 2, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_challenge (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct rng_engine_mock rng;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (&cmd.master_attestation.base, &cmd.riot, 
		&cmd.hash.base, &ecc.base, &rsa.base, &cmd.x509.base, &rng.base, &cmd.device_manager, 0);
	CuAssertIntEquals (test, 0, status);

	memcpy (cmd.master_attestation.base.challenge[1].nonce, X509_CERTCA_ECC_CA_NOPL_DER,
		ATTESTATION_NONCE_LEN);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1 + ATTESTATION_NONCE_LEN,
		request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CHALLENGE,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, 1, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER,
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], ATTESTATION_NONCE_LEN);
	CuAssertIntEquals (test, 0, status);

	attestation_master_release (&cmd.master_attestation.base);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_challenge_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_DEBUG_GET_DEVICE_MANAGER_CHALLENGE;

	memcpy (request.data, &header, sizeof (header));
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 1;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint32_t length = 1;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_prepare_recovery_image_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 0;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_0.mock, cmd.recovery_0.base.prepare_recovery_image,
		&cmd.recovery_0, 0, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);

}

static void cmd_interface_system_test_process_prepare_recovery_image_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint32_t length = 1;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_prepare_recovery_image_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 1;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_1.mock, cmd.recovery_1.base.prepare_recovery_image,
		&cmd.recovery_1, 0, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint32_t length = 1;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_prepare_recovery_image_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 0;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint32_t length = 1;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_prepare_recovery_image_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 1;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_invalid_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	uint32_t length = 1;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_prepare_recovery_image_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 0;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_recovery_image_update_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = 5;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint32_t length = 1;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_prepare_recovery_image_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 0;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_0.mock, cmd.recovery_0.base.prepare_recovery_image,
		&cmd.recovery_0, RECOVERY_IMAGE_INVALID_ARGUMENT, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_prepare_recovery_image_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	uint32_t length = 1;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_prepare_recovery_image_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 2;
	rq->size = length;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header,
		struct cerberus_protocol_recovery_image_update_header_packet*, &request);
	uint8_t *update_data = &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_recovery_image_update_header_packet);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	update_header->port_id = 0;
	update_data[0] = 0xAA;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_recovery_image_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_0.mock, cmd.recovery_0.base.update_recovery_image,
		&cmd.recovery_0, 0, MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header,
		struct cerberus_protocol_recovery_image_update_header_packet*, &request);
	uint8_t *update_data = &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_recovery_image_update_header_packet);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	update_header->port_id = 1;
	update_data[0] = 0xAA;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_recovery_image_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_1.mock, cmd.recovery_1.base.update_recovery_image,
		&cmd.recovery_1, 0, MOCK_ARG_PTR_CONTAINS_TMP (
		&request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1], 1), MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header,
		struct cerberus_protocol_recovery_image_update_header_packet*, &request);
	uint8_t *update_data = &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_recovery_image_update_header_packet);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	update_header->port_id = 0;
	update_data[0] = 0xAA;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_recovery_image_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header,
		struct cerberus_protocol_recovery_image_update_header_packet*, &request);
	uint8_t *update_data = &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_recovery_image_update_header_packet);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	update_header->port_id = 1;
	update_data[0] = 0xAA;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_recovery_image_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_no_data (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header,
		struct cerberus_protocol_recovery_image_update_header_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	update_header->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_recovery_image_update_header_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_update_recovery_image_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (update_header,
		struct cerberus_protocol_recovery_image_update_header_packet*, &request);
	uint8_t *update_data = &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] +
		sizeof (struct cerberus_protocol_recovery_image_update_header_packet);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	update_header->port_id = 2;
	update_data[0] = 0xAA;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_recovery_image_update_header_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_port0 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_activate_recovery_image_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_activate_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_0.mock, cmd.recovery_0.base.activate_recovery_image,
		&cmd.recovery_0, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_port1 (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_activate_recovery_image_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_activate_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_1.mock, cmd.recovery_1.base.activate_recovery_image,
		&cmd.recovery_1, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_activate_recovery_image_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_activate_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_activate_recovery_image_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_activate_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_invalid_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_activate_recovery_image_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_activate_recovery_image_update_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_activate_recovery_image_update_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_activate_recovery_image_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_activate_recovery_image_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));

	header->command = CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	rq->port_id = 2;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_activate_recovery_image_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_update_status_response_packet*,
		&request);
	int update_status = 0x00BB11AA;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_0.mock, cmd.recovery_0.base.get_status,
		&cmd.recovery_0, update_status);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS, header->command);
	CuAssertIntEquals (test, update_status, rsp->update_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_recovery_image_update_status_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_ext_update_status_response_packet*,
		&request);
	int update_status = 0x00BB11AA;
	int remaining_len;
	struct flash_updater updater;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = flash_updater_init (&updater, &cmd.flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.recovery_0.mock, cmd.recovery_0.base.get_status,
		&cmd.recovery_0, update_status);
	status |= mock_expect (&cmd.recovery_manager_0.mock, cmd.recovery_manager_0.base.get_flash_update_manager,
		&cmd.recovery_manager_0, (intptr_t) &updater);
	CuAssertIntEquals (test, 0, status);

	remaining_len = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, remaining_len);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS, header->command);
	CuAssertIntEquals (test, update_status, rsp->update_status);
	CuAssertIntEquals (test, remaining_len, rsp->remaining_len);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	flash_updater_release (&updater);
	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_update_status_response_packet*,
		&request);
	int update_status = 0x00BB11AA;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_1.mock, cmd.recovery_1.base.get_status,
		&cmd.recovery_1, update_status);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (uint32_t), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_UPDATE_STATUS, header->command);
	CuAssertIntEquals (test, update_status, rsp->update_status);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_recovery_image_update_status_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_ext_update_status_response_packet*,
		&request);
	int update_status = 0x00BB11AA;
	int remaining_len;
	struct flash_updater updater;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = flash_updater_init (&updater, &cmd.flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cmd.recovery_1.mock, cmd.recovery_1.base.get_status,
		&cmd.recovery_1, update_status);
	status |= mock_expect (&cmd.recovery_manager_1.mock, cmd.recovery_manager_1.base.get_flash_update_manager,
		&cmd.recovery_manager_1, (intptr_t) &updater);
	CuAssertIntEquals (test, 0, status);

	remaining_len = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, remaining_len);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_response_packet), request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS, header->command);
	CuAssertIntEquals (test, update_status, rsp->update_status);
	CuAssertIntEquals (test, remaining_len, rsp->remaining_len);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_recovery_image_update_status_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_recovery_image_update_status_port0_cmd_intf_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test_init (test, &cmd, DEVICE_MANAGER_UPSTREAM);

	setup_cmd_interface_system_mock_test_init_fw_version (&cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_system_init (&cmd.handler, &cmd.update.base, &cmd.pfm_0.base,
		&cmd.pfm_1.base, &cmd.cfm.base, &cmd.pcd.base, &cmd.pfm_manager_0.base,
		&cmd.pfm_manager_1.base, &cmd.cfm_manager.base, &cmd.pcd_manager.base,
		&cmd.master_attestation.base, &cmd.slave_attestation.base, &cmd.device_manager, &cmd.store, 
		&cmd.hash.base, &cmd.background.base, &cmd.host_0.base, &cmd.host_1.base, &cmd.fw_version, 
		&cmd.riot, &cmd.auth.base, &cmd.host_ctrl_0.base, &cmd.host_ctrl_1.base, NULL, 
		&cmd.recovery_1.base, &cmd.recovery_manager_0.base, &cmd.recovery_manager_1.base, 
		&cmd.cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_recovery_image_update_status_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	int status;

	TEST_START;
	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_recovery_image_update_status_port1_cmd_intf_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	int status;

	TEST_START;
	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test_init (test, &cmd, DEVICE_MANAGER_UPSTREAM);

	setup_cmd_interface_system_mock_test_init_fw_version (&cmd, CERBERUS_FW_VERSION,
		RIOT_CORE_VERSION, FW_VERSION_COUNT);

	status = cmd_interface_system_init (&cmd.handler, &cmd.update.base, &cmd.pfm_0.base,
		&cmd.pfm_1.base, &cmd.cfm.base, &cmd.pcd.base, &cmd.pfm_manager_0.base,
		&cmd.pfm_manager_1.base, &cmd.cfm_manager.base, &cmd.pcd_manager.base,
		&cmd.master_attestation.base, &cmd.slave_attestation.base, &cmd.device_manager, &cmd.store, 
		&cmd.hash.base, &cmd.background.base, &cmd.host_0.base, &cmd.host_1.base, &cmd.fw_version, 
		&cmd.riot, &cmd.auth.base, &cmd.host_ctrl_0.base, &cmd.host_ctrl_1.base, 
		&cmd.recovery_0.base, NULL, &cmd.recovery_manager_0.base, &cmd.recovery_manager_1.base, 
		&cmd.cmd_device.base, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_invalid_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_recovery_image_update_status_invalid_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_update_status_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 3;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	request.target_eid = MCTP_PROTOCOL_BMC_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_ext_recovery_image_update_status_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS;

	rq->update_type = CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE;
	rq->port_id = 3;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_port0 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	memcpy (request.data, &header, sizeof (header));
	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_recovery_image_version_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_manager_0.mock,
		cmd.recovery_manager_0.base.get_active_recovery_image, &cmd.recovery_manager_0,
		(intptr_t) &cmd.image_0.base);
	status |= mock_expect (&cmd.image_0.mock, cmd.image_0.base.get_version, &cmd.image_0, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_FW_VERSION_LEN));
	status |= mock_expect_output (&cmd.image_0.mock, 0, RECOVERY_IMAGE_HEADER_VERSION_ID,
		RECOVERY_IMAGE_HEADER_VERSION_ID_LEN, 1);
	status |= mock_expect (&cmd.recovery_manager_0.mock,
		cmd.recovery_manager_0.base.free_recovery_image, &cmd.recovery_manager_0, 0,
		MOCK_ARG (&cmd.image_0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_MIN_MSG_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertStrEquals (test, RECOVERY_IMAGE_HEADER_VERSION_ID,
		(char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_port1 (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_recovery_image_version_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_manager_1.mock,
		cmd.recovery_manager_1.base.get_active_recovery_image, &cmd.recovery_manager_1,
		(intptr_t) &cmd.image_0.base);
	status |= mock_expect (&cmd.image_0.mock, cmd.image_0.base.get_version, &cmd.image_0, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_FW_VERSION_LEN));
	status |= mock_expect_output (&cmd.image_0.mock, 0, RECOVERY_IMAGE_HEADER_VERSION_ID,
		RECOVERY_IMAGE_HEADER_VERSION_ID_LEN, 1);
	status |= mock_expect (&cmd.recovery_manager_1.mock,
		cmd.recovery_manager_1.base.free_recovery_image, &cmd.recovery_manager_1, 0, MOCK_ARG (
		&cmd.image_0));

	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_MIN_MSG_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertStrEquals (test, RECOVERY_IMAGE_HEADER_VERSION_ID,
		(char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_port0_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_recovery_image_version_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_port1_null (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*,	&request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	rq->port_id = 1;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_recovery_image_version_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_no_image (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*, &request);
	char empty_string[CERBERUS_PROTOCOL_FW_VERSION_LEN] = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_recovery_image_version_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_manager_0.mock,
		cmd.recovery_manager_0.base.get_active_recovery_image, &cmd.recovery_manager_0,
		(intptr_t) NULL);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		CERBERUS_PROTOCOL_MIN_MSG_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertStrEquals (test, empty_string,
		(char*) &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_recovery_image_version_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.recovery_manager_0.mock,
		cmd.recovery_manager_0.base.get_active_recovery_image, &cmd.recovery_manager_0,
		(intptr_t) &cmd.image_0.base);
	status |= mock_expect (&cmd.image_0.mock, cmd.image_0.base.get_version, &cmd.image_0,
		RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_FW_VERSION_LEN));
	status |= mock_expect (&cmd.recovery_manager_0.mock,
		cmd.recovery_manager_0.base.free_recovery_image, &cmd.recovery_manager_0, 0,
		MOCK_ARG (&cmd.image_0));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_invalid_len (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	rq->port_id = 0;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_recovery_image_version_update_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_recovery_image_version_bad_port_index (
	CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*, &request);
	int status;

	TEST_START;
	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION;

	rq->port_id = 3;
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_recovery_image_version_update_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, true, true, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cmd_device.mock, cmd.cmd_device.base.get_uuid, &cmd.cmd_device,
		CMD_DEVICE_UUID_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG));

	status |= mock_expect_output (&cmd.cmd_device.mock, 0, CMD_DEVICE_UUID,
		CMD_DEVICE_UUID_LEN, 1);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + CMD_DEVICE_UUID_LEN, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, request.data[0]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, *((uint16_t*) &request.data[1]));
	CuAssertIntEquals (test, 0, request.data[3]);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_GET_DEVICE_INFO,
		request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN - 1]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

    status = testing_validate_array (CMD_DEVICE_UUID, &request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		CMD_DEVICE_UUID_LEN);
    CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_CMD_LEN (
        struct cerberus_protocol_get_device_info_request_packet) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = CERBERUS_PROTOCOL_CMD_LEN (
        struct cerberus_protocol_get_device_info_request_packet) - 1;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info_bad_info_index (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_device_info_request_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	rq->info = 1;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_INDEX, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_info_fail (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DEVICE_INFO;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	status = mock_expect (&cmd.cmd_device.mock, cmd.cmd_device.base.get_uuid, &cmd.cmd_device,
		CMD_DEVICE_UUID_BUFFER_TOO_SMALL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG));
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_DEVICE_UUID_BUFFER_TOO_SMALL, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_id (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_device_id_response_packet*, &request);
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DEVICE_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_device_id_response_packet), request.length);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, rsp->vendor_id);
	CuAssertIntEquals (test, 2, rsp->device_id);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, rsp->subsystem_vid);
	CuAssertIntEquals (test, 4, rsp->subsystem_id);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

static void cmd_interface_system_test_process_get_device_id_invalid_len (CuTest *test)
{
	struct cmd_interface_system_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header header = {0};
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header.msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header.command = CERBERUS_PROTOCOL_GET_DEVICE_ID;

	memcpy (request.data, &header, sizeof (header));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_cmd_interface_system_mock_test (test, &cmd, true, true, true, true, false, false, true,
		true, DEVICE_MANAGER_UPSTREAM);

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BAD_LENGTH, status);

	complete_cmd_interface_system_mock_test (test, &cmd);
}

CuSuite* get_cmd_interface_system_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, cmd_interface_system_test_init);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_init_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_deinit_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_payload_too_short);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_unsupported_message);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_error_packet);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_invalid_device);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_fw_update_init);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_fw_update_init_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_fw_update);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_fw_update_no_data);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_fw_update_start);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_fw_update_start_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_fw_update_status);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_fw_update_status_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_ext_fw_update_status);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_ext_fw_update_status_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_fw_update_status_unsupported_index);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_fw_version);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_fw_version_unset_version);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_fw_version_unsupported_area);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_fw_version_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_fw_version_riot);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_fw_version_bad_count);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_init_port0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_init_port1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_init_port0_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_init_port1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_init_invalid_port);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_init_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_init_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_port0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_port1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_port0_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_port1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_no_data);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_invalid_port);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_complete_port0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_complete_port1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_complete_port0_immediate);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_complete_port1_immediate);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_complete_port0_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_complete_port1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_complete_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pfm_update_complete_invalid_port);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_update_status_port0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_update_status_port1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_update_status_port0_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_update_status_port1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_update_status_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_update_status_invalid_port);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_port0_region0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_port0_region1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_port1_region0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_port1_region1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_port0_region0_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_port0_region1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_port1_region0_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_port1_region1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_no_pfm);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_id_invalid_port);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_port0_region0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_port0_region1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_port1_region0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_port1_region1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_nonzero_offset);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_empty_list);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_pfm_supported_fw_empty_list_nonzero_offset);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_pfm_supported_fw_port0_region0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_pfm_supported_fw_port0_region1_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_pfm_supported_fw_port1_region0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_pfm_supported_fw_port1_region1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_no_pfm);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_fail_id);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_invalid_region);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_invalid_offset);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pfm_supported_fw_invalid_port);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_init);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_init_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_init_no_cfm_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_init_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_no_data);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_no_cfm_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_complete);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_complete_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_complete_no_cfm_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_complete_immediate);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_cfm_update_complete_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_update_status);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_update_status_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_update_status_no_cfm_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_id_region0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_id_region1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_id_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_id_no_cfm_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_id_no_cfm);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_id_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_region0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_region1);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_nonzero_offset);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_no_cfm_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_no_active_cfm);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_no_pending_cfm);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_fail_id);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_invalid_region);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_cfm_component_ids_invalid_offset);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_clear_debug);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_clear_tcg);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_clear_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_clear_invalid_type);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_debug_fill_log);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_log_info);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_log_info_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_log_info_fail_debug);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_read_debug);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_read_tcg);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_read_debug_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_read_tcg_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_read_invalid_type);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_read_invalid_offset);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_log_read_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate_digest);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate_digest_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_certificate_digest_unsupported_algo);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate_digest_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_process_certificate_digest);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_process_certificate_digest_compare_digests_fail);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_process_certificate_digest_issue_challenge_fail);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_process_certificate_digest_int_mismatch);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_process_certificate_digest_leaf_mismatch);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_process_certificate_digest_invalid_buf_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate_length_0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate_length_too_big);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate_unsupported_slot_num);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_certificate_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_process_certificate);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_process_certificate_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_process_certificate_store_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_challenge_response);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_challenge_response_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_challenge_response_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_process_challenge_response);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_process_challenge_response_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_ctrl_eid_unknown_command);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_get_capabilities);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_get_capabilities_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_downstream_device);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_no_seed_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_no_cipher_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_incomplete_payload);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_result);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_result_busy);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_result_fail);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_request_unseal_result_downstream_device);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_request_unseal_result_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_fw_reset_verification_status_port0);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_fw_reset_verification_status_port1);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_fw_reset_verification_status_port0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_fw_reset_verification_status_port1_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_fw_reset_verification_status_invalid_port);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_fw_reset_verification_status_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_reset_status_port0_out_of_reset);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_reset_status_port0_held_in_reset);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_reset_status_port0_not_held_in_reset);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_host_reset_status_port0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_reset_status_port1_out_of_reset);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_reset_status_port1_held_in_reset);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_reset_status_port1_not_held_in_reset);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_host_reset_status_port1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_host_reset_status_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_host_reset_status_invalid_port);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_reset_status_reset_check_error);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_host_reset_status_hold_check_error);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_request_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_request_invalid_request);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_get_device_capabilities);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_get_device_capabilities_buf_too_small);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_get_certificate_digest);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_get_certificate_digest_buf_too_small);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_get_certificate);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_get_certificate_buf_too_small);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_get_certificate_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_challenge);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_challenge_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_issue_challenge_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pcd_id_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pcd_id_no_pcd);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pcd_id_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pcd_id);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pcd_id_no_pcd_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_init);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_init_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_init_no_pcd_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_init_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_no_data);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_no_pcd_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_complete);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_complete_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_complete_no_pcd_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_pcd_update_complete_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pcd_update_status);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pcd_update_status_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_pcd_update_status_no_pcd_manager);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_devid_csr);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_devid_csr_invalid_buf_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_devid_csr_unsupported_index);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_signed_dev_id_cert);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_root_ca_cert);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_intermediate_cert);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_signed_ca_cert_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_signed_ca_cert_no_cert);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_signed_ca_cert_bad_cert_length);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_import_signed_ca_cert_unsupported_index);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_signed_dev_id_cert_save_error);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_root_ca_cert_save_error);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_import_intermediate_cert_save_error);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_import_signed_ca_cert_authenticate_error);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_signed_cert_state);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_signed_cert_state_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_reset_bypass_no_nonce_authorized);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_reset_bypass_no_nonce_challenge);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_reset_bypass_no_nonce_max_challenge);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_reset_bypass_no_nonce_not_authorized);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_reset_bypass_with_nonce_authorized);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_reset_bypass_with_nonce_not_authorized);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_reset_bypass_no_nonce_invalid_challenge);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_reset_bypass_error);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_restore_defaults_no_nonce_authorized);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_restore_defaults_no_nonce_challenge);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_restore_defaults_no_nonce_max_challenge);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_restore_defaults_no_nonce_not_authorized);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_restore_defaults_with_nonce_authorized);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_restore_defaults_with_nonce_not_authorized);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_restore_defaults_no_nonce_invalid_challenge);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_restore_defaults_error);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_reset_config_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_reset_config_invalid_request_subtype);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_reset_config_status);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_reset_config_status_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_certificate);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_certificate_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_certificate_get_chain_fail);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_device_certificate_invalid_cert_num);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_cert_digest);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_cert_digest_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_cert_digest_get_chain_fail);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_device_cert_digest_invalid_cert_num);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_device_cert_digest_hash_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_challenge);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_challenge_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_prepare_recovery_image_port0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_prepare_recovery_image_port1);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_prepare_recovery_image_port0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_prepare_recovery_image_port1_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_prepare_recovery_image_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_prepare_recovery_image_fail);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_prepare_recovery_image_bad_port_index);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_update_recovery_image_port0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_update_recovery_image_port1);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_update_recovery_image_port0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_update_recovery_image_port1_null);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_update_recovery_image_no_data);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_update_recovery_image_bad_port_index);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_activate_recovery_image_port0);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_activate_recovery_image_port1);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_activate_recovery_image_port0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_activate_recovery_image_port1_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_activate_recovery_image_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_activate_recovery_image_bad_port_index);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_update_status_port0);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_recovery_image_update_status_port0);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_update_status_port1);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_recovery_image_update_status_port1);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_update_status_port0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_recovery_image_update_status_port0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_recovery_image_update_status_port0_cmd_intf_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_update_status_port1_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_recovery_image_update_status_port1_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_recovery_image_update_status_port1_cmd_intf_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_update_status_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_recovery_image_update_status_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_update_status_bad_port_index);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_ext_recovery_image_update_status_bad_port_index);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_version_port0);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_version_port1);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_version_port0_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_version_port1_null);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_version_no_image);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_version_fail);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_version_invalid_len);
	SUITE_ADD_TEST (suite,
		cmd_interface_system_test_process_get_recovery_image_version_bad_port_index);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_info);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_info_invalid_len);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_info_bad_info_index);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_info_fail);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_id);
	SUITE_ADD_TEST (suite, cmd_interface_system_test_process_get_device_id_invalid_len);

	/* Tear down after the tests in this suite have run. */
	SUITE_ADD_TEST (suite, cmd_interface_system_testing_suite_tear_down);
	return suite;
}

