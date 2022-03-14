// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pcd/pcd_manager_flash.h"
#include "manifest/pcd/pcd_format.h"
#include "manifest/manifest_logging.h"
#include "crypto/ecc.h"
#include "flash/flash_common.h"
#include "flash/spi_flash.h"
#include "system/system_state_manager.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/pcd_observer_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/manifest/manifest_flash_v2_testing.h"
#include "testing/manifest/pcd_testing.h"


TEST_SUITE_LABEL ("pcd_manager_flash");


/**
 * Dependencies for testing the PCD manager.
 */
struct pcd_manager_flash_testing {
	HASH_TESTING_ENGINE hash;							/**< Hashing engine for validation. */
	struct signature_verification_mock verification;	/**< PCD signature verification. */
	struct flash_master_mock flash_mock;				/**< Flash master for PCD flash. */
	struct flash_master_mock flash_mock_state;			/**< Flash master for host state flash. */
	struct spi_flash_state flash_context;				/**< PCD flash context. */
	struct spi_flash flash;								/**< Flash containing the PCD data. */
	struct spi_flash_state flash_state_context;			/**< Host state flash context. */
	struct spi_flash flash_state;						/**< Flash containing the host state. */
	struct state_manager state_mgr;						/**< Manager for host state. */
	struct pcd_flash pcd1;								/**< The first PCD. */
	uint8_t signature1[256];							/**< Buffer for the first manifest signature. */
	uint8_t platform_id1[256];							/**< Cache for the first platform ID. */
	uint32_t pcd1_addr;									/**< Base address of the first PCD. */
	struct pcd_flash pcd2;								/**< The second PCD. */
	uint8_t signature2[256];							/**< Buffer for the second manifest signature. */
	uint8_t platform_id2[256];							/**< Cache for the second platform ID. */
	uint32_t pcd2_addr;									/**< Base address of the second PCD. */
	struct pcd_observer_mock observer;					/**< Observer of manager events. */
	struct logging_mock log;							/**< Mock for debug logging. */
	struct pcd_manager_flash test;						/**< Manager instance under test. */
};


/**
 * Initialize the system state manager for testing.
 *
 * @param test The testing framework.
 * @param manager The testing components being initialized.
 */
static void pcd_manager_flash_testing_init_system_state (CuTest *test,
	struct pcd_manager_flash_testing *manager)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_master_mock_init (&manager->flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&manager->flash_state, &manager->flash_state_context,
		&manager->flash_mock_state.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&manager->flash_state, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, (uint8_t*) end,
		sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 8));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, (uint8_t*) end,
		sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, 8));

	status |= flash_master_mock_expect_erase_flash_sector_verify (&manager->flash_mock_state,
		0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = system_state_manager_init (&manager->state_mgr, &manager->flash_state.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize common PCD manager testing dependencies.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 * @param addr1 Base address of the first PCD.
 * @param addr2 Base address of the second PCD.
 */
static void pcd_manager_flash_testing_init_dependencies (CuTest *test,
	struct pcd_manager_flash_testing *manager, uint32_t addr1, uint32_t addr2)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&manager->hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&manager->verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&manager->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&manager->flash, &manager->flash_context, &manager->flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&manager->flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_flash_testing_init_system_state (test, manager);

	status = pcd_flash_init (&manager->pcd1, &manager->flash.base, &manager->hash.base, addr1,
		manager->signature1, sizeof (manager->signature1), manager->platform_id1,
		sizeof (manager->platform_id1));
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&manager->pcd2, &manager->flash.base, &manager->hash.base, addr2,
		manager->signature2, sizeof (manager->signature2), manager->platform_id2,
		sizeof (manager->platform_id2));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&manager->observer);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&manager->log);
	CuAssertIntEquals (test, 0, status);

	manager->pcd1_addr = addr1;
	manager->pcd2_addr = addr2;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param pcd The testing components to release.
 */
void pcd_manager_flash_testing_validate_and_release_dependencies (CuTest *test,
	struct pcd_manager_flash_testing *manager)
{
	int status;

	debug_log = NULL;

	status = flash_master_mock_validate_and_release (&manager->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&manager->flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&manager->verification);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&manager->observer);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&manager->log);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager->state_mgr);
	pcd_flash_release (&manager->pcd1);
	pcd_flash_release (&manager->pcd2);
	spi_flash_release (&manager->flash);
	spi_flash_release (&manager->flash_state);
	HASH_TESTING_ENGINE_RELEASE (&manager->hash);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 */
static void pcd_manager_flash_testing_validate_and_release (CuTest *test,
	struct pcd_manager_flash_testing *manager)
{
	pcd_manager_flash_release (&manager->test);

	pcd_manager_flash_testing_validate_and_release_dependencies (test, manager);
}

/**
 * Set up expectations for verifying a PCD on flash.
 *
 * @param manager The testing components.
 * @param address The base address of the PCD.
 * @param testing_data Container with testing data.
 * @param sig_verification_result Result of the signature verification call.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_a_pcd (struct pcd_manager_flash_testing *manager,
	uint32_t address, const struct pcd_testing_data *testing_data, int sig_verification_result)
{
	uint32_t vvalidate_toc_start = MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE;
	uint32_t validate_start = testing_data->manifest.plat_id_offset +
		MANIFEST_V2_PLATFORM_HEADER_SIZE;
	int status;

	status = flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, testing_data->manifest.raw,
		MANIFEST_V2_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, address, 0, -1, MANIFEST_V2_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		testing_data->manifest.signature, testing_data->manifest.sig_len,
		FLASH_EXP_READ_CMD (0x03, address + testing_data->manifest.sig_offset, 0, -1,
			testing_data->manifest.sig_len));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		testing_data->manifest.raw + MANIFEST_V2_TOC_HDR_OFFSET, MANIFEST_V2_TOC_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, address + MANIFEST_V2_TOC_HDR_OFFSET, 0, -1,
			MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		testing_data->manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE,
		FLASH_EXP_READ_CMD (0x03, address + MANIFEST_V2_TOC_ENTRY_OFFSET, 0, -1,
			MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_master_mock_expect_verify_flash (&manager->flash_mock,
		address + vvalidate_toc_start, testing_data->manifest.raw + vvalidate_toc_start,
		testing_data->manifest.toc_hash_offset - vvalidate_toc_start);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		testing_data->manifest.raw + testing_data->manifest.toc_hash_offset,
		testing_data->manifest.toc_hash_len,
		FLASH_EXP_READ_CMD (0x03, address + testing_data->manifest.toc_hash_offset, 0, -1,
			testing_data->manifest.toc_hash_len));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		testing_data->manifest.raw + testing_data->manifest.plat_id_offset,
		MANIFEST_V2_PLATFORM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, address + testing_data->manifest.plat_id_offset, 0, -1,
			MANIFEST_V2_PLATFORM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		testing_data->manifest.raw + validate_start, testing_data->manifest.plat_id_str_len,
		FLASH_EXP_READ_CMD (0x03, address + validate_start, 0, -1,
			testing_data->manifest.plat_id_str_len));

	validate_start += testing_data->manifest.plat_id_str_len;

	status |= flash_master_mock_expect_verify_flash (&manager->flash_mock, address + validate_start,
		testing_data->manifest.raw + validate_start,
		testing_data->manifest.length - validate_start - testing_data->manifest.sig_len);

	status |= mock_expect (&manager->verification.mock,
		manager->verification.base.verify_signature, &manager->verification,
		sig_verification_result, MOCK_ARG_PTR_CONTAINS (testing_data->manifest.hash,
		PCD_TESTING.manifest.hash_len), MOCK_ARG (testing_data->manifest.hash_len),
		MOCK_ARG_PTR_CONTAINS (testing_data->manifest.signature, testing_data->manifest.sig_len),
		MOCK_ARG (testing_data->manifest.sig_len));

	return status;
}

/**
 * Set up expectations for verifying a PCD on flash.
 *
 * @param manager The testing components.
 * @param address The base address of the PCD.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_pcd (struct pcd_manager_flash_testing *manager,
	uint32_t address)
{
	return pcd_manager_flash_testing_verify_a_pcd (manager, address, &PCD_TESTING, 0);
}

/**
 * Set up expectations for verifying a PCD on flash.
 *
 * @param manager The testing components.
 * @param address The base address of the PCD.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_pcd2 (struct pcd_manager_flash_testing *manager,
	uint32_t address)
{
	return pcd_manager_flash_testing_verify_a_pcd (manager, address, &PCD_NO_PORTS_TESTING, 0);
}

/**
 * Set up expectations for verifying an empty PCD on flash.
 *
 * @param manager The testing components.
 * @param address The base address of the PCD.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_pcd_empty (struct pcd_manager_flash_testing *manager,
	uint32_t address)
{
	return pcd_manager_flash_testing_verify_a_pcd (manager, address, &PCD_EMPTY_TESTING, 0);
}

/**
 * Set up expectations for verifying a SKU-specific PCD on flash.
 *
 * @param manager The testing components.
 * @param address The base address of the PCD.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_sku_specific_pcd (
	struct pcd_manager_flash_testing *manager, uint32_t address)
{
	return pcd_manager_flash_testing_verify_a_pcd (manager, address, &PCD_SKU_SPECIFIC_TESTING, 0);
}

/**
 * Set up expectations for verifying the PCDs during initialization.
 *
 * @param manager The testing components.
 * @param pcd1 The PCD verification function for region 1.
 * @param pcd2 The PCD verification function for region 2.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_initial_pcd_validation (
	struct pcd_manager_flash_testing *manager,
	int (*pcd1) (struct pcd_manager_flash_testing*, uint32_t),
	int (*pcd2) (struct pcd_manager_flash_testing*, uint32_t))
{
	int status;

	/* Base PCD verification.  Use blank check to simulate empty PCD regions. */
	if (pcd1) {
		status = pcd1 (manager, manager->pcd1_addr);
	}
	else {
		status = flash_master_mock_expect_blank_check (&manager->flash_mock, manager->pcd1_addr,
			MANIFEST_V2_HEADER_SIZE);
	}
	if (pcd2) {
		status |= pcd2 (manager, manager->pcd2_addr);
	}
	else {
		status |= flash_master_mock_expect_blank_check (&manager->flash_mock, manager->pcd2_addr,
			MANIFEST_V2_HEADER_SIZE);
	}

	return status;
}

/**
 * Initialize PCD manager for testing.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 * @param addr1 The base address for the first PCD.
 * @param addr2 The base address for the second PCD.
 * @param pcd1 The PCD verification function for region 1.
 * @param pcd2 The PCD verification function for region 2.
 * @param pcd1_active Flag indicating if region 1 is active.
 */
static void pcd_manager_flash_testing_init (CuTest *test, struct pcd_manager_flash_testing *manager,
	uint32_t addr1, uint32_t addr2, int (*pcd1) (struct pcd_manager_flash_testing*, uint32_t),
	int (*pcd2) (struct pcd_manager_flash_testing*, uint32_t), bool pcd1_active)
{
	int status;

	pcd_manager_flash_testing_init_dependencies (test, manager, addr1, addr2);

	if (!pcd1_active) {
		status = manager->state_mgr.save_active_manifest (&manager->state_mgr,
			SYSTEM_STATE_MANIFEST_PCD, MANIFEST_REGION_2);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcd_manager_flash_testing_initial_pcd_validation (manager, pcd1, pcd2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager->test, &manager->pcd1, &manager->pcd2,
		&manager->state_mgr, &manager->hash.base, &manager->verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->verification.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Write complete PCD data to the manager to enable pending PCD verification.
 *
 * @param test The test framework.
 * @param manager The testing components.
 * @param addr The expected address of PCD writes.
 *
 * @return The number of PCD bytes written.
 */
static int pcd_manager_flash_testing_write_new_pcd (CuTest *test,
	struct pcd_manager_flash_testing *manager, uint32_t addr)
{
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	status = flash_master_mock_expect_erase_flash_verify (&manager->flash_mock, addr, 0x10000);
	status |= flash_master_mock_expect_write_ext (&manager->flash_mock, addr, data, sizeof (data),
		true, 0);

	CuAssertIntEquals (test, 0, status);

	status = manager->test.base.base.clear_pending_region (&manager->test.base.base, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager->test.base.base.write_pending_data (&manager->test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	return sizeof (data);
}

/*******************
 * Test cases
 *******************/

static void pcd_manager_flash_test_init (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	/* Use blank check to simulate empty PCD regions. */
	status = pcd_manager_flash_testing_initial_pcd_validation (&manager, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.test.base.get_active_pcd);
	CuAssertPtrNotNull (test, manager.test.base.free_pcd);

	CuAssertPtrNotNull (test, manager.test.base.base.activate_pending_manifest);
	CuAssertPtrNotNull (test, manager.test.base.base.clear_pending_region);
	CuAssertPtrNotNull (test, manager.test.base.base.write_pending_data);
	CuAssertPtrNotNull (test, manager.test.base.base.verify_pending_manifest);
	CuAssertPtrNotNull (test, manager.test.base.base.clear_all_manifests);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		pcd_manager_flash_testing_verify_pcd, NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = manager.state_mgr.save_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager, NULL,
		pcd_manager_flash_testing_verify_pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_activate_pending (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_only_pending_region2_empty_manifest (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_EMPTY_PCD,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		NULL, pcd_manager_flash_testing_verify_pcd_empty);
	CuAssertIntEquals (test, 0, status);

	/* Erase manifest regions. */
	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	status |= mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_only_pending_region1_empty_manifest (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_EMPTY_PCD,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = manager.state_mgr.save_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		pcd_manager_flash_testing_verify_pcd_empty, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Erase manifest regions. */
	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	status |= mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_active_and_pending_empty_manifest (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_EMPTY_PCD,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd_empty);
	CuAssertIntEquals (test, 0, status);

	/* Erase manifest regions. */
	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	status |= mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_init (NULL, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, NULL, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, NULL,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		NULL, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, NULL, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	pcd_manager_flash_testing_validate_and_release_dependencies (test, &manager);
}

static void pcd_manager_flash_test_init_region1_flash_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	pcd_manager_flash_testing_validate_and_release_dependencies (test, &manager);
}

static void pcd_manager_flash_test_init_region2_flash_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	/* Use blank check to simulate empty PCD regions. */
	status = flash_master_mock_expect_blank_check (&manager.flash_mock, 0x10000,
		MANIFEST_V2_HEADER_SIZE);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	pcd_manager_flash_testing_validate_and_release_dependencies (test, &manager);
}

static void pcd_manager_flash_test_init_pcd_bad_signature (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x10000, &PCD_TESTING,
		RSA_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	/* Use blank check to simulate empty PCD regions. */
	status = flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000,
		MANIFEST_V2_HEADER_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_pcd_bad_signature_ecc (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x10000, &PCD_TESTING,
		ECC_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000,
		MANIFEST_V2_HEADER_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_bad_length (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t pcd_bad_data[PCD_TESTING.manifest.sig_offset];

	TEST_START;

	memcpy (pcd_bad_data, PCD_TESTING.manifest.raw, sizeof (pcd_bad_data));
	pcd_bad_data[9] = 0xff;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1,
		MANIFEST_V2_HEADER_SIZE));

	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000,
		MANIFEST_V2_HEADER_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_bad_magic_number (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t pcd_bad_data[PCD_TESTING.manifest.sig_offset];

	TEST_START;

	memcpy (pcd_bad_data, PCD_TESTING.manifest.raw, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1,
		MANIFEST_V2_HEADER_SIZE));
	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000,
		MANIFEST_V2_HEADER_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region2_pending_lower_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region2_pending_same_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region2_pending_different_platform_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, &PCD_NO_COMPONENTS_TESTING,
		0);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region1_pending_lower_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = manager.state_mgr.save_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_pcd2 (&manager, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region1_pending_same_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = manager.state_mgr.save_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_empty_manifest_pending_erase_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_EMPTY_PCD,
		.arg1 = 0,
		.arg2 = FLASH_MASTER_XFER_FAILED
	};

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		NULL, pcd_manager_flash_testing_verify_pcd_empty);
	CuAssertIntEquals (test, 0, status);

	/* Erase manifest regions. */
	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_empty_manifest_active_erase_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_EMPTY_PCD,
		.arg1 = 0,
		.arg2 = FLASH_MASTER_XFER_FAILED
	};

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		NULL, pcd_manager_flash_testing_verify_pcd_empty);
	CuAssertIntEquals (test, 0, status);

	/* Erase manifest regions. */
	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.log.mock, manager.log.base.create_entry, &manager.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &manager.log.base;

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_get_active_pcd_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (NULL));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_region2_after_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	enum manifest_region active;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	active = manager.state_mgr.get_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_region1_after_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	enum manifest_region active;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, false);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	active = manager.state_mgr.get_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_region2_after_write_notify_observers (
	CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	enum manifest_region active;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_activated,
		&manager.observer, 0, MOCK_ARG (&manager.pcd2));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	active = manager.state_mgr.get_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_region1_after_write_notify_observers (
	CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	enum manifest_region active;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, false);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_activated,
		&manager.observer, 0, MOCK_ARG (&manager.pcd1));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	active = manager.state_mgr.get_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_no_pending_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_no_pending_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, false);

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_no_pending_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = manager.test.base.base.activate_pending_manifest (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_invalidate_pending_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_invalidate_pending_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd2, pcd_manager_flash_testing_verify_pcd, false);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = manager.test.base.base.clear_pending_region (NULL, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_manifest_too_large (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base,
		FLASH_BLOCK_SIZE + 1);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_erase_error_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd2, pcd_manager_flash_testing_verify_pcd, true);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_erase_error_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_no_pending_in_use_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_no_pending_in_use_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, false);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_multiple (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20004, data2, 5);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20009, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data1,
		sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data2,
		sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data3,
		sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_block_end (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_BLOCK_SIZE - sizeof (data)] = {0};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, fill, sizeof (fill));
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x2fffc, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Fill with data to write at the end of the flash block. */
	status = manager.test.base.base.write_pending_data (&manager.test.base.base, fill,
		sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (NULL, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, NULL,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_write_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_write_after_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20004, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data1,
		sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data2,
		sizeof (data2));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data3,
		sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_partial_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, fill, sizeof (fill));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x200ff, 0, data, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Partially fill the page to force a write across pages. */
	status = manager.test.base.base.write_pending_data (&manager.test.base.base, fill,
		sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_write_after_partial_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, fill, sizeof (fill));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x200ff, 0, data1, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20100, data2, 5);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Partially fill the page to force a write across pages. */
	status = manager.test.base.base.write_pending_data (&manager.test.base.base, fill,
		sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data1,
		sizeof (data1));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data2,
		sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_without_clear (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_restart_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20004, data2, 5);

	status |= flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data1,
		sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data2,
		sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data3,
		sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_too_long (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_BLOCK_SIZE - sizeof (data) + 1] = {0};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, fill, sizeof (fill));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Fill with data to write at the end of the flash block. */
	status = manager.test.base.base.write_pending_data (&manager.test.base.base, fill,
		sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_region2_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_verified,
		&manager.observer, 0, MOCK_ARG (&manager.pcd2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_region1_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_verified,
		&manager.observer, 0, MOCK_ARG (&manager.pcd1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_with_active (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_lower_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd2, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_same_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_different_platform_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, &PCD_NO_COMPONENTS_TESTING,
		0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_upgrade_platform_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, &PCD_SKU_SPECIFIC_TESTING,
		0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_downgrade_platform_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_sku_specific_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, &PCD_TESTING, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_no_clear_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_no_clear_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_extra_data_written (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int offset;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	offset = pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = flash_master_mock_expect_write (&manager.flash_mock, 0x20000 + offset, data,
		sizeof (data));

	status |= pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = manager.test.base.base.verify_pending_manifest (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_error_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_error_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_error_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_fail_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, &PCD_TESTING,
		RSA_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_fail_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x10000, &PCD_TESTING,
		RSA_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, &PCD_TESTING,
		ECC_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x10000, &PCD_TESTING,
		ECC_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_fail (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, &PCD_TESTING,
		RSA_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_write_after_verify (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_write_after_verify_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_incomplete_pcd (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INCOMPLETE_UPDATE, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_write_after_incomplete_pcd (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INCOMPLETE_UPDATE, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd, false);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_region1_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd, false);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_clear_active,
		&manager.observer, 0);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_region2_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd, true);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_clear_active,
		&manager.observer, 0);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_only_active (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd2, NULL, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_only_pending (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_no_pcds (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_active_in_use (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	struct pcd *active;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	active = manager.test.base.get_active_pcd (&manager.test.base);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_ACTIVE_IN_USE, status);

	manager.test.base.free_pcd (&manager.test.base, active);

	active = manager.test.base.get_active_pcd (&manager.test.base);
	CuAssertPtrEquals (test, &manager.pcd2, active);
	manager.test.base.free_pcd (&manager.test.base, active);

	status = mock_validate (&manager.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_active_in_use_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	struct pcd *active;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_pcd (&manager.test.base);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_ACTIVE_IN_USE, status);

	manager.test.base.free_pcd (&manager.test.base, active);

	active = manager.test.base.get_active_pcd (&manager.test.base);
	CuAssertPtrEquals (test, &manager.pcd2, active);
	manager.test.base.free_pcd (&manager.test.base, active);

	status = mock_validate (&manager.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_clear_active,
		&manager.observer, 0);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_during_update (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = manager.test.base.base.clear_all_manifests (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_erase_pending_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_erase_active_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_erase_active_error_notify_observers (
	CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}


TEST_SUITE_START (pcd_manager_flash);

TEST (pcd_manager_flash_test_init);
TEST (pcd_manager_flash_test_init_region1);
TEST (pcd_manager_flash_test_init_region2);
TEST (pcd_manager_flash_test_init_activate_pending);
TEST (pcd_manager_flash_test_init_only_pending_region2_empty_manifest);
TEST (pcd_manager_flash_test_init_only_pending_region1_empty_manifest);
TEST (pcd_manager_flash_test_init_active_and_pending_empty_manifest);
TEST (pcd_manager_flash_test_init_null);
TEST (pcd_manager_flash_test_init_region1_flash_error);
TEST (pcd_manager_flash_test_init_region2_flash_error);
TEST (pcd_manager_flash_test_init_pcd_bad_signature);
TEST (pcd_manager_flash_test_init_pcd_bad_signature_ecc);
TEST (pcd_manager_flash_test_init_bad_length);
TEST (pcd_manager_flash_test_init_bad_magic_number);
TEST (pcd_manager_flash_test_init_region1_pending_same_id);
TEST (pcd_manager_flash_test_init_region1_pending_lower_id);
TEST (pcd_manager_flash_test_init_region2_pending_same_id);
TEST (pcd_manager_flash_test_init_region2_pending_different_platform_id);
TEST (pcd_manager_flash_test_init_region2_pending_lower_id);
TEST (pcd_manager_flash_test_init_empty_manifest_pending_erase_error);
TEST (pcd_manager_flash_test_init_empty_manifest_active_erase_error);
TEST (pcd_manager_flash_test_get_active_pcd_null);
TEST (pcd_manager_flash_test_activate_pending_pcd_region2_after_write);
TEST (pcd_manager_flash_test_activate_pending_pcd_region1_after_write);
TEST (pcd_manager_flash_test_activate_pending_pcd_region2_after_write_notify_observers);
TEST (pcd_manager_flash_test_activate_pending_pcd_region1_after_write_notify_observers);
TEST (pcd_manager_flash_test_activate_pending_pcd_no_pending_region2);
TEST (pcd_manager_flash_test_activate_pending_pcd_no_pending_region1);
TEST (pcd_manager_flash_test_activate_pending_pcd_no_pending_notify_observers);
TEST (pcd_manager_flash_test_activate_pending_pcd_null);
TEST (pcd_manager_flash_test_clear_pending_region_region2);
TEST (pcd_manager_flash_test_clear_pending_region_region1);
TEST (pcd_manager_flash_test_clear_pending_region_invalidate_pending_region2);
TEST (pcd_manager_flash_test_clear_pending_region_invalidate_pending_region1);
TEST (pcd_manager_flash_test_clear_pending_region_null);
TEST (pcd_manager_flash_test_clear_pending_region_manifest_too_large);
TEST (pcd_manager_flash_test_clear_pending_region_erase_error_region2);
TEST (pcd_manager_flash_test_clear_pending_region_erase_error_region1);
TEST (pcd_manager_flash_test_clear_pending_no_pending_in_use_region2);
TEST (pcd_manager_flash_test_clear_pending_no_pending_in_use_region1);
TEST (pcd_manager_flash_test_write_pending_data_region2);
TEST (pcd_manager_flash_test_write_pending_data_region1);
TEST (pcd_manager_flash_test_write_pending_data_multiple);
TEST (pcd_manager_flash_test_write_pending_data_block_end);
TEST (pcd_manager_flash_test_write_pending_data_null);
TEST (pcd_manager_flash_test_write_pending_data_write_error);
TEST (pcd_manager_flash_test_write_pending_data_write_after_error);
TEST (pcd_manager_flash_test_write_pending_data_partial_write);
TEST (pcd_manager_flash_test_write_pending_data_write_after_partial_write);
TEST (pcd_manager_flash_test_write_pending_data_without_clear);
TEST (pcd_manager_flash_test_write_pending_data_restart_write);
TEST (pcd_manager_flash_test_write_pending_data_too_long);
TEST (pcd_manager_flash_test_verify_pending_pcd_region2);
TEST (pcd_manager_flash_test_verify_pending_pcd_region1);
TEST (pcd_manager_flash_test_verify_pending_pcd_region2_notify_observers);
TEST (pcd_manager_flash_test_verify_pending_pcd_region1_notify_observers);
TEST (pcd_manager_flash_test_verify_pending_pcd_with_active);
TEST (pcd_manager_flash_test_verify_pending_pcd_lower_id);
TEST (pcd_manager_flash_test_verify_pending_pcd_same_id);
TEST (pcd_manager_flash_test_verify_pending_pcd_different_platform_id);
TEST (pcd_manager_flash_test_verify_pending_pcd_upgrade_platform_id);
TEST (pcd_manager_flash_test_verify_pending_pcd_downgrade_platform_id);
TEST (pcd_manager_flash_test_verify_pending_pcd_no_clear_region2);
TEST (pcd_manager_flash_test_verify_pending_pcd_no_clear_region1);
TEST (pcd_manager_flash_test_verify_pending_pcd_extra_data_written);
TEST (pcd_manager_flash_test_verify_pending_pcd_null);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_error_region2);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_error_region1);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_error_notify_observers);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_fail_region2);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_fail_region1);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region2);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region1);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_error);
TEST (pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_fail);
TEST (pcd_manager_flash_test_verify_pending_pcd_write_after_verify);
TEST (pcd_manager_flash_test_verify_pending_pcd_write_after_verify_error);
TEST (pcd_manager_flash_test_verify_pending_pcd_incomplete_pcd);
TEST (pcd_manager_flash_test_verify_pending_pcd_write_after_incomplete_pcd);
TEST (pcd_manager_flash_test_clear_all_manifests_region1);
TEST (pcd_manager_flash_test_clear_all_manifests_region2);
TEST (pcd_manager_flash_test_clear_all_manifests_region1_notify_observers);
TEST (pcd_manager_flash_test_clear_all_manifests_region2_notify_observers);
TEST (pcd_manager_flash_test_clear_all_manifests_only_active);
TEST (pcd_manager_flash_test_clear_all_manifests_only_pending);
TEST (pcd_manager_flash_test_clear_all_manifests_no_pcds);
TEST (pcd_manager_flash_test_clear_all_manifests_active_in_use);
TEST (pcd_manager_flash_test_clear_all_manifests_active_in_use_notify_observers);
TEST (pcd_manager_flash_test_clear_all_manifests_during_update);
TEST (pcd_manager_flash_test_clear_all_manifests_null);
TEST (pcd_manager_flash_test_clear_all_manifests_erase_pending_error);
TEST (pcd_manager_flash_test_clear_all_manifests_erase_active_error);
TEST (pcd_manager_flash_test_clear_all_manifests_erase_active_error_notify_observers);

TEST_SUITE_END;
