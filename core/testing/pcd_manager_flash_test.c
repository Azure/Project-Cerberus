// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pcd/pcd_manager_flash.h"
#include "manifest/pcd/pcd_format.h"
#include "flash/spi_flash.h"
#include "state_manager/system_state_manager.h"
#include "mock/flash_master_mock.h"
#include "mock/pcd_observer_mock.h"
#include "mock/signature_verification_mock.h"
#include "engines/hash_testing_engine.h"
#include "flash/flash_common.h"
#include "crypto/ecc.h"
#include "pcd_testing.h"


static const char *SUITE = "pcd_manager_flash";


/**
 * PCD with ID 1 for testing.
 */
const uint8_t PCD_DATA[] = {
	0x81,0x01,0xbc,0x8e,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x75,0x00,0x08,0x00,
	0x00,0x00,0x00,0x00,0x28,0x00,0x10,0x00,0x00,0x02,0x41,0x10,0x09,0x01,0x01,0x01,
	0x01,0x00,0x00,0x00,0x0c,0x00,0x0c,0x00,0x00,0x01,0x00,0x00,0x00,0x48,0xe8,0x01,
	0x0c,0x00,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x6c,0xdc,0x02,0x38,0x00,0x08,0x00,
	0x00,0x02,0x00,0x00,0x10,0x00,0x10,0x00,0x00,0x00,0x10,0x03,0x00,0x0c,0x0a,0x0b,
	0x01,0x00,0x00,0x00,0x20,0x00,0x10,0x00,0x00,0x02,0x15,0x03,0x01,0x0d,0x08,0x09,
	0x02,0x00,0x00,0x00,0x08,0x00,0x08,0x00,0x00,0xe2,0x03,0x01,0x08,0x00,0x08,0x00,
	0x00,0xe0,0x02,0x00,0x0d,0x00,0x08,0x00,0x00,0x05,0x00,0x00,0x43,0x32,0x30,0x33,
	0x30,0x13,0xd7,0x9d,0x3a,0x9d,0xde,0x08,0x35,0x06,0x01,0xf1,0xa9,0xff,0xd0,0x98,
	0xcd,0x60,0x00,0x76,0xd4,0x90,0x8a,0x60,0x36,0x69,0xaa,0xac,0xfc,0x42,0x90,0x26,
	0xa5,0xee,0x1f,0x59,0xfd,0x95,0xa2,0xc6,0xcd,0x07,0xee,0x1b,0xca,0x00,0xa2,0x62,
	0xb6,0xd4,0x45,0x7c,0xb1,0x2b,0x34,0x8e,0xa2,0xd8,0xe5,0x6a,0x89,0xa9,0x34,0x2f,
	0x01,0x1a,0xe6,0xd9,0x99,0xa2,0xe5,0x9b,0xd7,0x8b,0xc3,0x57,0x1b,0x30,0x82,0xb6,
	0xe6,0x08,0x81,0x9a,0x03,0xc3,0xb0,0x88,0x24,0x43,0x34,0x75,0x65,0x30,0xb7,0x04,
	0xf0,0x30,0xfb,0x89,0x67,0x1b,0x37,0xe5,0xed,0x69,0xdf,0xae,0xa0,0x48,0xd8,0xa2,
	0xe3,0x57,0xca,0x75,0x8e,0x18,0xf6,0x60,0x44,0xca,0xd1,0x8d,0x9d,0x82,0xd5,0x00,
	0x9d,0xba,0x56,0x49,0x7f,0x86,0xc0,0x5d,0x3a,0x10,0x5c,0xfe,0x9f,0x0f,0xd8,0x09,
	0xb3,0x90,0xee,0x71,0xa3,0x9c,0x80,0x34,0xc1,0x01,0x0a,0x1f,0x55,0x53,0x1f,0xe8,
	0x54,0xfb,0xce,0x93,0x56,0x99,0x27,0x4a,0xde,0xb5,0x7a,0x1d,0x3b,0x7c,0xe1,0x82,
	0x9d,0x91,0xde,0xf7,0x70,0x91,0x48,0x43,0x06,0xd8,0x7d,0xb4,0x41,0x03,0xee,0x92,
	0x82,0x65,0x8b,0x7c,0x3d,0x04,0x45,0x48,0x4e,0xa4,0xcf,0xac,0x79,0xf7,0x72,0xd6,
	0x0d,0xa8,0x4f,0x4a,0x72,0xc9,0xfa,0x4b,0x4a,0x2b,0xda,0xc5,0x0f,0xdd,0xce,0xc4,
	0x5a,0xb4,0xe5,0x20,0xeb,0xdb,0x6c,0xbb,0x7e,0x27,0xc5,0x7b,0x11,0x67,0xd8,0x96,
	0xdb,0x05,0x41,0x01,0x98,0x80,0x68,0xc5,0x12,0x29,0xa9,0x82,0x56,0xbc,0xd4,0xbe,
	0x59
};

/**
 * PCD with ID 2 for testing.
 */
const uint8_t PCD2_DATA[] = {
	0x39,0x01,0xbc,0x8e,0x02,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x2d,0x00,0x08,0x00,
	0x00,0x00,0x00,0x00,0x10,0x00,0x10,0x00,0x00,0x00,0x41,0x10,0x09,0x01,0x01,0x01,
	0x01,0x00,0x00,0x00,0x08,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x0d,0x00,0x08,0x00,
	0x00,0x05,0x00,0x00,0x43,0x32,0x30,0x33,0x30,0x1e,0x0c,0xef,0xe8,0x2c,0x57,0xf6,
	0x7a,0x45,0x7f,0x6c,0x8d,0x86,0x07,0xd7,0x9d,0x18,0xb6,0x4b,0x0b,0x67,0x82,0x69,
	0x34,0x9c,0x59,0x87,0xeb,0xb3,0x87,0x2a,0x9e,0xf2,0x84,0x24,0xe0,0xdd,0x27,0x07,
	0x0e,0x38,0x06,0xff,0x7e,0x0f,0xef,0x37,0xa7,0x0b,0xf3,0x12,0x90,0xbb,0x03,0xa3,
	0xc8,0xf3,0xc9,0xc8,0xc6,0xb6,0x0b,0x6f,0x83,0x5c,0x63,0x28,0xaf,0x28,0x8d,0xac,
	0x54,0x32,0x43,0xf2,0x8c,0x84,0xd1,0x50,0x36,0xe6,0x0f,0x24,0x56,0x84,0xf4,0xad,
	0xbe,0x8c,0x22,0x80,0x35,0x70,0x81,0xdb,0xa4,0xc6,0x8b,0x5d,0x5e,0xed,0x79,0x05,
	0x53,0xf2,0xed,0xa9,0xf1,0xfd,0x97,0x0b,0x9e,0x9a,0x20,0xfd,0xb2,0xe2,0x05,0x1c,
	0x43,0x95,0xa5,0x1d,0x29,0x3a,0x68,0xb3,0x6a,0x5e,0x86,0xe7,0x91,0x6d,0x5b,0x3f,
	0x41,0xc4,0x77,0xd2,0x26,0xbb,0xdc,0x4a,0xb1,0x76,0x7f,0xe7,0xa1,0x4e,0x06,0xdb,
	0xa3,0x2c,0xfb,0x97,0x27,0x60,0xfb,0x69,0x0e,0x72,0x10,0x83,0xc6,0xd5,0xc8,0x4c,
	0x1f,0x43,0x02,0xa8,0x05,0xe7,0xd1,0xe6,0x97,0x18,0x0e,0x08,0xb6,0xc1,0x12,0x45,
	0xb9,0xb9,0x67,0x8f,0x74,0xdf,0xb0,0xfa,0x83,0xb9,0x37,0x58,0x29,0x52,0x34,0xd2,
	0xb3,0x26,0x52,0x03,0xb2,0x74,0x1f,0xbf,0xb5,0x84,0x48,0x45,0x32,0xe8,0xe6,0x91,
	0x0b,0xef,0xba,0x54,0xa0,0x50,0xac,0x71,0x68,0x28,0x99,0x7e,0xb4,0xb0,0xcc,0x43,
	0x5b,0x94,0x5a,0xee,0x8a,0x29,0xb9,0xb4,0xd5,0xf3,0x8a,0x70,0x6e,0x9e,0x3b,0x18,
	0x91,0xb8,0xd7,0x24,0x12,0x45,0x10,0x6e,0x68
};

/**
 * Length of the testing PCD.
 */
const uint32_t PCD_DATA_LEN = sizeof (PCD_DATA);

/**
 * Length of the second testing PCD.
 */
const uint32_t PCD2_DATA_LEN = sizeof (PCD2_DATA);

/**
 * The offset from the base for the PCD header.
 */
const uint32_t PCD_HEADER_OFFSET = sizeof (struct manifest_header);

/**
 * The offset from the base for the PCD RoT section.
 */
const uint32_t PCD_ROT_OFFSET = sizeof (struct manifest_header) + sizeof (struct pcd_header);

/**
 * The offset from the base for the PCD components section.
 */
const uint32_t PCD_COMPONENTS_OFFSET = sizeof (struct manifest_header) +
	sizeof (struct pcd_header) + 40;

/**
 * The offset from the base for the PCD components section.
 */
const uint32_t PCD2_COMPONENTS_OFFSET = sizeof (struct manifest_header) +
	sizeof (struct pcd_header) + 16;

/**
 * The offset from the base for the PCD platform ID header section.
 */
const uint32_t PCD_PLATFORM_ID_HDR_OFFSET = sizeof (struct manifest_header) +
	sizeof (struct pcd_header) + 96;

/**
 * The offset from the base for the PCD platform ID section.
 */
const uint32_t PCD_PLATFORM_ID_OFFSET = sizeof (struct manifest_header) +
	sizeof (struct pcd_header) + 96 + sizeof (struct pcd_platform_header);

/**
 * The offset from the base for the PCD platform ID header section.
 */
const uint32_t PCD2_PLATFORM_ID_HDR_OFFSET = sizeof (struct manifest_header) +
	sizeof (struct pcd_header) + 24;

/**
 * The offset from the base for the PCD platform ID section.
 */
const uint32_t PCD2_PLATFORM_ID_OFFSET = sizeof (struct manifest_header) +
	sizeof (struct pcd_header) + 24 + sizeof (struct pcd_platform_header);

/**
 * The platform ID for the PCD.
 */
const char PCD_PLATFORM_ID[] = "C2030";

/**
 * The length of the PCD platform ID.
 */
const size_t PCD_PLATFORM_ID_LEN = sizeof (PCD_PLATFORM_ID) - 1;

/**
 * The offset from the base for the PCD signature.
 */
const uint32_t PCD_SIGNATURE_OFFSET = (sizeof (PCD_DATA) - 256);

/**
 * The offset from the base for the second PCD signature.
 */
const uint32_t PCD2_SIGNATURE_OFFSET = (sizeof (PCD2_DATA) - 256);

/**
 * The signature for the PCD.
 */
const uint8_t *PCD_SIGNATURE = PCD_DATA + (sizeof (PCD_DATA) - 256);

/**
 * The signature for the second PCD.
 */
const uint8_t *PCD2_SIGNATURE = PCD2_DATA + (sizeof (PCD2_DATA) - 256);

/**
 * The length of the PCD signature.
 */
const size_t PCD_SIGNATURE_LEN = 256;

/**
 * PCD_DATA hash for testing.
 */
const uint8_t PCD_HASH[] = {
	0xdb,0x84,0x36,0xef,0xd0,0xe1,0xcc,0xfc,0x8f,0x2b,0x56,0x98,0x33,0x35,0xfb,0xbf,
	0xe5,0x09,0xe0,0x89,0x3a,0x35,0x4c,0xa2,0x67,0x2c,0x17,0x09,0xc9,0xf7,0xfe,0x02
};

/**
 * PCD_DATA hash digest for testing.
 */
const uint8_t PCD_HASH_DIGEST[] = {
	0x28,0x7e,0x97,0x09,0x8f,0xc6,0x6f,0xd3,0xd6,0x3f,0x42,0xfb,0x71,0xff,0x96,0xb7,
	0xf3,0x15,0xff,0xcc,0xd8,0xf4,0xb6,0x90,0x0b,0xe0,0x03,0xc0,0xb0,0x93,0x8e,0x4b
};

/**
 * PCD2_DATA hash for testing.
 */
const uint8_t PCD2_HASH[] = {
	0xb2,0x07,0xe6,0xba,0xba,0xaa,0xee,0xe0,0x93,0xc0,0xfc,0x13,0x3a,0xaf,0x59,0xdd,
	0xd0,0x69,0xa9,0xcb,0xe6,0x31,0x0c,0x77,0x36,0xa1,0x69,0x55,0x44,0xbb,0x66,0x84
};

/**
 * Length of the test PCD hash.
 */
const uint32_t PCD_HASH_LEN = sizeof (PCD_HASH);


/**
 * Dependencies for testing the PCD manager.
 */
struct pcd_manager_flash_testing {
	HASH_TESTING_ENGINE hash;							/**< Hashing engine for validation. */
	struct signature_verification_mock verification;	/**< PCD signature verification. */
	struct flash_master_mock flash_mock;				/**< Flash master for PCD flash. */
	struct flash_master_mock flash_mock_state;			/**< Flash master for host state flash. */
	struct spi_flash flash;								/**< Flash containing the PCD data. */
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

	status = spi_flash_init (&manager->flash_state, &manager->flash_mock_state.base);
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

	status = spi_flash_init (&manager->flash, &manager->flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&manager->flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_flash_testing_init_system_state (test, manager);

	status = pcd_flash_init (&manager->pcd1, &manager->flash.base, addr1, manager->signature1,
		sizeof (manager->signature1), manager->platform_id1, sizeof (manager->platform_id1));
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&manager->pcd2, &manager->flash.base, addr2, manager->signature2,
		sizeof (manager->signature2), manager->platform_id2, sizeof (manager->platform_id2));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&manager->observer);
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

	status = flash_master_mock_validate_and_release (&manager->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&manager->flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&manager->verification);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&manager->observer);
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
 * @param managure The testing components.
 * @param address The base address of the PCD.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_pcd (struct pcd_manager_flash_testing *manager,
	uint32_t address)
{
	uint32_t pcd_offset;
	int status;

	status = flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, address, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, address + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager->flash_mock, address, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager->verification.mock, manager->verification.base.verify_signature,
		&manager->verification, 0, MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_platform_header)));

	pcd_offset += sizeof (struct pcd_platform_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD_DATA + pcd_offset,
		PCD_DATA_LEN - pcd_offset,
		FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1, PCD_PLATFORM_ID_LEN));

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
static int pcd_manager_flash_testing_verify_pcd2 (struct pcd_manager_flash_testing *manager,
	uint32_t address)
{
	uint32_t pcd_offset;
	int status;

	status = flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD2_DATA,
		PCD2_DATA_LEN, FLASH_EXP_READ_CMD (0x03, address, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD2_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, address + PCD2_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager->flash_mock, address, PCD2_DATA,
		PCD2_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager->verification.mock, manager->verification.base.verify_signature,
		&manager->verification, 0, MOCK_ARG_PTR_CONTAINS (PCD2_HASH, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (PCD2_SIGNATURE, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD2_DATA + pcd_offset,
		PCD2_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD2_DATA + pcd_offset,
		PCD2_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD2_DATA + pcd_offset,
		PCD2_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD2_DATA + pcd_offset,
		PCD2_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1,
		sizeof (struct pcd_platform_header)));

	pcd_offset += sizeof (struct pcd_platform_header);

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, PCD2_DATA + pcd_offset,
		PCD2_DATA_LEN - pcd_offset,
		FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1, PCD_PLATFORM_ID_LEN));

	return status;
}

/**
 * Set up expectations for verifying the PCDs during initialization.
 *
 * @param manager The testing components.
 * @param pcd1 The PCD verification function for region 1.
 * @param pcd2 The PCD verification function for region 2.
 * @param pcd1_active Flag indicating if region 1 is active.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_initial_pcd_validation (
	struct pcd_manager_flash_testing *manager,
	int (*pcd1) (struct pcd_manager_flash_testing*, uint32_t),
	int (*pcd2) (struct pcd_manager_flash_testing*, uint32_t), bool pcd1_active)
{
	int status;

	/* Base PCD verification.  Use blank check to simulate empty PCD regions. */
	if (pcd1) {
		status = pcd1 (manager, manager->pcd1_addr);
	}
	else {
		status = flash_master_mock_expect_blank_check (&manager->flash_mock, manager->pcd1_addr,
			PCD_HEADER_SIZE);
	}
	if (pcd2) {
		status |= pcd2 (manager, manager->pcd2_addr);
	}
	else {
		status |= flash_master_mock_expect_blank_check (&manager->flash_mock, manager->pcd2_addr,
			PCD_HEADER_SIZE);
	}

	return status;
}

/**
 * Initialize PCD manager for testing.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 * @param addr1 The base address for the first PFM.
 * @param addr2 The base address for the second PFM.
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

	status = pcd_manager_flash_testing_initial_pcd_validation (manager, pcd1, pcd2, pcd1_active);
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
	status = pcd_manager_flash_testing_initial_pcd_validation (&manager, NULL, NULL, true);
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
		pcd_manager_flash_testing_verify_pcd, NULL, true);
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
		pcd_manager_flash_testing_verify_pcd, false);
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
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, false);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

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
	status = flash_master_mock_expect_blank_check (&manager.flash_mock, 0x10000, PCD_HEADER_SIZE);
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

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager.verification.mock, manager.verification.base.verify_signature,
		&manager.verification, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_SIGNATURE_LEN));

	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000, PCD_HEADER_SIZE);
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

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager.verification.mock, manager.verification.base.verify_signature,
		&manager.verification, ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_SIGNATURE_LEN));

	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000, PCD_HEADER_SIZE);
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
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[9] = 0xff;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000, PCD_HEADER_SIZE);

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
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));
	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000, PCD_HEADER_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

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

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_activated,
		&manager.observer, 0, MOCK_ARG (&manager.pcd2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
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

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_activated,
		&manager.observer, 0, MOCK_ARG (&manager.pcd1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
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

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

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

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

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

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_activated,
		&manager.observer, 0, MOCK_ARG (&manager.pcd2));
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

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

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_activated,
		&manager.observer, 0, MOCK_ARG (&manager.pcd1));
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

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

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

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

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

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

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager.flash_mock, 0x20000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager.verification.mock, manager.verification.base.verify_signature,
		&manager.verification, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_SIGNATURE_LEN));

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

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager.verification.mock, manager.verification.base.verify_signature,
		&manager.verification, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_SIGNATURE_LEN));

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

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager.flash_mock, 0x20000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager.verification.mock, manager.verification.base.verify_signature,
		&manager.verification, ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_SIGNATURE_LEN));

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

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager.flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager.verification.mock, manager.verification.base.verify_signature,
		&manager.verification, ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_SIGNATURE_LEN));

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

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, PCD_SIGNATURE,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&manager.flash_mock, 0x20000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager.verification.mock, manager.verification.base.verify_signature,
		&manager.verification, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_SIGNATURE_LEN));

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

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

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


CuSuite* get_pcd_manager_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	/* TODO: No test coverage for
	 * - ID checks when activating during init
	 * - Platform ID checks when activating during init
	 * - Platfirm ID checks when validating a new PCD
	 */

	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_activate_pending);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region1_flash_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region2_flash_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_pcd_bad_signature);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_pcd_bad_signature_ecc);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_bad_length);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_bad_magic_number);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_get_active_pcd_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_region2_after_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_region1_after_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_region2_after_write_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_region1_after_write_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_no_pending_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_no_pending_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_no_pending_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_invalidate_pending_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_invalidate_pending_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_manifest_too_large);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_erase_error_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_erase_error_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_no_pending_in_use_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_no_pending_in_use_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_multiple);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_block_end);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_write_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_write_after_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_partial_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_write_after_partial_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_without_clear);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_restart_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_too_long);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_region2_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_region1_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_with_active);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_lower_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_same_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_no_clear_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_no_clear_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_extra_data_written);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_error_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_error_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_error_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_fail_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_fail_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_fail);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_write_after_verify);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_write_after_verify_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_incomplete_pcd);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_write_after_incomplete_pcd);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_only_active);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_only_pending);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_no_pcds);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_active_in_use);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_during_update);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_erase_pending_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_erase_active_error);

	return suite;
}
