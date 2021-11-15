// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "recovery/recovery_image_manager.h"
#include "recovery/recovery_image_header.h"
#include "recovery/recovery_image_section_header.h"
#include "recovery/recovery_image.h"
#include "crypto/ecc.h"
#include "host_fw/host_state_manager.h"
#include "flash/flash_common.h"
#include "common/image_header.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/manifest/pfm_manager_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/recovery/recovery_image_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/recovery/recovery_image_observer_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/common/image_header_testing.h"
#include "testing/recovery/recovery_image_testing.h"
#include "testing/recovery/recovery_image_header_testing.h"
#include "testing/recovery/recovery_image_section_header_testing.h"


TEST_SUITE_LABEL ("recovery_image_manager");


#define RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN	(FLASH_BLOCK_SIZE)


/**
 * Write complete recovery image data to the manager to enable recovery image verification.
 *
 * @param test The test framework.
 * @param manager The manager to use for writing recovery image data.
 * @param flash The mock for recovery image flash storage.
 * @param addr The expected address of recovery image writes.
 * @param data Recovery image data to write to flash.
 * @param data_size The size of recovery image data to write to flash.
 */
static void recovery_image_manager_testing_write_new_image (CuTest *test,
	struct recovery_image_manager *manager, struct flash_mock *flash, uint32_t addr, uint8_t *data,
	size_t data_size)
{
	int status;

	status = flash_mock_expect_erase_flash_verify (flash, addr, data_size);

	status |= mock_expect (&flash->mock, flash->base.write, flash, data_size, MOCK_ARG (addr),
		MOCK_ARG_PTR_CONTAINS (data, data_size), MOCK_ARG (data_size));

	CuAssertIntEquals (test, 0, status);

	status = manager->clear_recovery_image_region (manager, data_size);
	CuAssertIntEquals (test, 0, status);

	status = manager->write_recovery_image_data (manager, data, data_size);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash->mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param state The host state instance to initialize.
 * @param flash The mock for the flash state storage.
 */
static void recovery_image_manager_testing_init_host_state (CuTest *test,
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


/*******************
 * Test cases
 *******************/

static void recovery_image_manager_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	CuAssertPtrNotNull (test, manager.get_active_recovery_image);
	CuAssertPtrNotNull (test, manager.clear_recovery_image_region);
	CuAssertPtrNotNull (test, manager.free_recovery_image);
	CuAssertPtrNotNull (test, manager.write_recovery_image_data);
	CuAssertPtrNotNull (test, manager.activate_recovery_image);
	CuAssertPtrNotNull (test, manager.get_flash_update_manager);
	CuAssertPtrNotNull (test, manager.erase_all_recovery_regions);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (NULL, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init (&manager, NULL, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init (&manager, &image.base, NULL,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		NULL, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, NULL, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_bad_signature_ecc (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, ECC_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_malformed (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_bad_platform_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RECOVERY_IMAGE_INCOMPATIBLE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_flash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, FLASH_READ_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_image_header_too_small (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, IMAGE_HEADER_NOT_MINIMUM_SIZE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_image_header_bad_marker (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, IMAGE_HEADER_BAD_MARKER,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_image_header_too_long (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, IMAGE_HEADER_TOO_LONG,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_image_header_bad_format_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image,
		RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_image_header_bad_platform_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image,
		RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_image_header_bad_version_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image,
		RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_image_header_bad_image_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image,
		RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_section_header_bad_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image,
		RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_invalid_section_address (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image,
		RECOVERY_IMAGE_INVALID_SECTION_ADDRESS, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_release_null (CuTest *test)
{
	TEST_START;

	recovery_image_manager_release (NULL);
}

static void recovery_image_manager_test_add_observer_null (CuTest *test)
{
	struct recovery_image_manager_mock manager;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = recovery_image_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (NULL, &observer.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_add_observer (&manager.base, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = recovery_image_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_manager_test_remove_observer_null (CuTest *test)
{
	struct recovery_image_manager_mock manager;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = recovery_image_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_remove_observer (NULL, &observer.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_remove_observer (&manager.base, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = recovery_image_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_manager_test_get_active_recovery_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_active_recovery_image_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (NULL));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (NULL, 1);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_image_too_large (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager,
		RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN + 1);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_erase_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0,
        MOCK_ARG_NOT_NULL);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
        MOCK_ARG (0x10000));

    CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_image_in_use (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_image_in_use_multiple (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image *active1;
	struct recovery_image *active2;

	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active1 = manager.get_active_recovery_image (&manager);
	active2 = manager.get_active_recovery_image (&manager);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active1);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active2);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_image_not_in_use (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_extra_free_call (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);
	manager.free_recovery_image (&manager, active);

	active = manager.get_active_recovery_image (&manager);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_free_null_region (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	manager.get_active_recovery_image (&manager);
	manager.free_recovery_image (&manager, NULL);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_free_null_manager (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);
	manager.free_recovery_image (NULL, active);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_in_use_after_activate (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_with_valid_image_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct recovery_image_observer_mock observer;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_recovery_image_activated, &observer, 0,
		MOCK_ARG (&image));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		sizeof (data));

	status |= mock_expect (&observer.mock, observer.base.on_recovery_image_deactivated, &observer,
		0);

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_region_with_invalid_image_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct recovery_image_observer_mock observer;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (NULL, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = manager.write_recovery_image_data (&manager, NULL, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_without_clear (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_too_long (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t fill[RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN - sizeof (data) + 1] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data));

    status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (fill), MOCK_ARG (0x10000),
        MOCK_ARG_PTR_CONTAINS (fill, sizeof (fill)), MOCK_ARG (sizeof (fill)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_write_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_partial_write (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data));

    status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (fill), MOCK_ARG (0x10000),
        MOCK_ARG_PTR_CONTAINS (fill, sizeof (fill)), MOCK_ARG (sizeof (fill)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1,
		MOCK_ARG (0x100ff), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_multiple (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10000 + sizeof (data1) + sizeof (data2)),
		MOCK_ARG_PTR_CONTAINS (&data3, sizeof (data3)), MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_block_end (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_BLOCK_SIZE - sizeof (data)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data));

    status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (fill), MOCK_ARG (0x10000),
        MOCK_ARG_PTR_CONTAINS (fill, sizeof (fill)), MOCK_ARG (sizeof (fill)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x1fffc),
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_write_after_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x10000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10000 + sizeof (data1)),
		MOCK_ARG_PTR_CONTAINS (&data3, sizeof (data3)), MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = manager.write_recovery_image_data (&manager, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_write_after_partial_write (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);

    status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (fill), MOCK_ARG (0x10000),
        MOCK_ARG_PTR_CONTAINS (fill, sizeof (fill)), MOCK_ARG (sizeof (fill)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1,
		MOCK_ARG (0x100ff), MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10100),
		MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)), MOCK_ARG (sizeof (data2)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_restart_write (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data3, sizeof (data3)),
		MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_image_in_use (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	manager.free_recovery_image (&manager, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_incomplete_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_write_after_incomplete_image (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data),
		MOCK_ARG (0x10000),	MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_notify_observers (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct recovery_image_observer_mock observer;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_recovery_image_activated, &observer, 0,
		MOCK_ARG (&image));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_no_pending_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_no_pending_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct recovery_image_observer_mock observer;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_already_valid_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct recovery_image_observer_mock observer;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image, manager.get_active_recovery_image (&manager));

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_already_valid (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image, manager.get_active_recovery_image (&manager));

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_recovery_image_malformed (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_extra_data_written (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data1));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1),
		MOCK_ARG (0x10000),	MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_verify_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, FLASH_READ_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_verify_error_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image_observer_mock observer;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, FLASH_READ_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_verify_fail (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_verify_fail_ecc (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, ECC_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_activate_after_verify_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, FLASH_READ_FAILED,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_activate_after_verify_fail (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_write_after_activate (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image, manager.get_active_recovery_image (&manager));

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &image, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_write_after_activate_fail (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_with_active (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}


static void recovery_image_manager_test_activate_recovery_image_no_event_handler (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct recovery_image_observer_mock observer;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_recovery_image_activated = NULL;

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x10000,
		RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, &image.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_image_in_use (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash (&flash, 0x10000,
		RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_during_update (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x10000,
		RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_erase_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0,
        MOCK_ARG_NOT_NULL);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
        MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_valid_image_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x10000,
		RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= mock_expect (&observer.mock, observer.base.on_recovery_image_deactivated, &observer,
		0);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_invalid_image_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x10000,
		RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	manager.get_active_recovery_image (&manager);

	CuAssertPtrNotNull (test, manager.get_active_recovery_image);
	CuAssertPtrNotNull (test, manager.clear_recovery_image_region);
	CuAssertPtrNotNull (test, manager.free_recovery_image);
	CuAssertPtrNotNull (test, manager.write_recovery_image_data);
	CuAssertPtrNotNull (test, manager.activate_recovery_image);
	CuAssertPtrNotNull (test, manager.get_flash_update_manager);
	CuAssertPtrNotNull (test, manager.erase_all_recovery_regions);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_active_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_active_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = recovery_image_manager_init_two_region (NULL, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init_two_region (&manager, NULL, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, NULL, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, NULL,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		NULL, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, NULL, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, NULL, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_bad_platform_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, RECOVERY_IMAGE_INCOMPATIBLE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_bad_platform_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, RECOVERY_IMAGE_INCOMPATIBLE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_flash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, FLASH_READ_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_flash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, FLASH_READ_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_bad_signature_ecc (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, ECC_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_bad_signature_ecc (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, ECC_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_malformed (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_malformed (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_image_header_too_small (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, IMAGE_HEADER_NOT_MINIMUM_SIZE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_image_header_too_small (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, IMAGE_HEADER_NOT_MINIMUM_SIZE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_image_header_bad_marker (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, IMAGE_HEADER_BAD_MARKER,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_image_header_bad_marker (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, IMAGE_HEADER_BAD_MARKER,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_image_header_too_long (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, IMAGE_HEADER_TOO_LONG,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_image_header_too_long (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, IMAGE_HEADER_TOO_LONG,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_image_header_bad_format_length (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1,
		RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_image_header_bad_format_length (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2,
		RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_image_header_bad_platform_id (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1,
		RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_image_header_bad_platform_id (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2,
		RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_image_header_bad_version_id (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1,
		RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_image_header_bad_version_id (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2,
		RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_image_header_bad_image_length (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1,
		RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_image_header_bad_image_length (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2,
		RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_image_section_header_bad_length (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1,
		RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_image_section_header_bad_length (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2,
		RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region1_invalid_section_address (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1,
		RECOVERY_IMAGE_INVALID_SECTION_ADDRESS, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_init_two_region_region2_invalid_section_address (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2,
		RECOVERY_IMAGE_INVALID_SECTION_ADDRESS, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_active_recovery_image_two_region (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_active_recovery_image_two_region_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (NULL));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (NULL, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_region1_image_too_large (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN + 1);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_region2_image_too_large (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN + 1);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_erase_error_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0,
        MOCK_ARG_NOT_NULL);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
        MOCK_ARG (0x10000));

    CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_erase_error_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0,
        MOCK_ARG_NOT_NULL);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
        MOCK_ARG (0x20000));

    CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_in_use_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_in_use_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_in_use_multiple_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active1;
	struct recovery_image *active2;

	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active1 = manager.get_active_recovery_image (&manager);
	active2 = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active1);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active2);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_in_use_multiple_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active1;
	struct recovery_image *active2;

	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active1 = manager.get_active_recovery_image (&manager);
	active2 = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active1);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active2);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_extra_free_call_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);
	manager.free_recovery_image (&manager, active);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_extra_free_call_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);
	manager.free_recovery_image (&manager, active);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_free_null_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	manager.get_active_recovery_image (&manager);
	manager.free_recovery_image (&manager, NULL);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_free_null_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	manager.get_active_recovery_image (&manager);
	manager.free_recovery_image (&manager, NULL);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_free_null_manager_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);
	manager.free_recovery_image (NULL, active);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_free_null_manager_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);
	manager.free_recovery_image (NULL, active);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_in_use_after_activate_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0,  status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, sizeof (data));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_in_use_after_activate_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, sizeof (data));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_not_in_use_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_not_in_use_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_notify_observers_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_recovery_image_activated, &observer, 0,
		MOCK_ARG (&image1.base));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_clear_recovery_image_two_region_notify_observers_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_recovery_image_activated, &observer, 0,
		MOCK_ARG (&image2.base));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000,
		RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_without_clear (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_too_long (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t fill[RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN - sizeof (data) + 1] = {0};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

    status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (fill), MOCK_ARG (0x20000),
        MOCK_ARG_PTR_CONTAINS (fill, sizeof (fill)), MOCK_ARG (sizeof (fill)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_write_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_partial_write (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

    status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (fill), MOCK_ARG (0x20000),
        MOCK_ARG_PTR_CONTAINS (fill, sizeof (fill)), MOCK_ARG (sizeof (fill)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1, MOCK_ARG (0x200ff),
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_multiple (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x20000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x20000 + sizeof (data1) + sizeof (data2)),
		MOCK_ARG_PTR_CONTAINS (&data3, sizeof (data3)), MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_block_end (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_BLOCK_SIZE - sizeof (data)] = {0};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

    status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (fill), MOCK_ARG (0x20000),
        MOCK_ARG_PTR_CONTAINS (fill, sizeof (fill)), MOCK_ARG (sizeof (fill)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x2fffc),
		MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_write_after_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x20000 + sizeof (data1)),
		MOCK_ARG_PTR_CONTAINS (&data3, sizeof (data3)), MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = manager.write_recovery_image_data (&manager, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_write_after_partial_write (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

    status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (fill), MOCK_ARG (0x20000),
        MOCK_ARG_PTR_CONTAINS (fill, sizeof (fill)), MOCK_ARG (sizeof (fill)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1, MOCK_ARG (0x200ff),
		MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x20100), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_restart_write (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x20000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= flash_mock_expect_erase_flash_verify (&flash, 0x20000, RECOVERY_IMAGE_DATA_LEN);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data3, sizeof (data3)), MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_in_use (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	manager.free_recovery_image (&manager, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_write_recovery_image_data_two_region_write_after_incomplete_image (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x20000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data),
		MOCK_ARG (0x20000),	MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_region1_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_recovery_image_activated, &observer, 0,
		MOCK_ARG (&image1.base));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_region2_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_recovery_image_activated, &observer, 0,
		MOCK_ARG (&image2.base));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_no_pending_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_no_pending_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_no_pending_notify_observers_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_no_pending_notify_observers_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_write_after_incomplete_image_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE, status);

	status = mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000),	MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_write_after_incomplete_image_region2 (
CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE, status);

	status = mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000),	MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_after_incomplete_image_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_after_incomplete_image_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_verify_and_notify_observers_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_recovery_image_activated, &observer, 0,
		MOCK_ARG (&image1.base));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_verify_and_notify_observers_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_recovery_image_activated, &observer, 0,
		MOCK_ARG (&image2.base));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_verify_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_verify_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_malformed_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_malformed_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image1.base.verify, &image2, RECOVERY_IMAGE_MALFORMED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_extra_data_written_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data1));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data1),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data2),
		MOCK_ARG (0x10000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_extra_data_written_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data1));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data1),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data2),
		MOCK_ARG (0x20000 + sizeof (data1)), MOCK_ARG_PTR_CONTAINS (&data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_verify_error_notify_observers_region1
(CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, FLASH_READ_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_verify_error_notify_observers_region2
(CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, FLASH_READ_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_write_after_activate_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash_image, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_write_after_activate_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash_image, 0x20000, data,
		sizeof (data));

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_write_after_activate_fail_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash_image, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image1.mock, image1.base.verify, &image1, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_write_after_activate_fail_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash_image, 0x20000, data,
		sizeof (data));

	status = mock_expect (&image2.mock, image2.base.verify, &image2, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&hash), MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_with_active_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash_image, 0x10000, data,
		sizeof (data));

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test,  RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_with_active_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash_image, 0x20000, data,
		sizeof (data));

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test,  RECOVERY_IMAGE_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_no_event_handler_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct flash_mock flash_image;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	enum recovery_image_region active;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_recovery_image_activated = NULL;

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x10000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_activate_recovery_image_two_region_no_event_handler_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	struct recovery_image_observer_mock observer;
	struct host_state_manager state;
	enum recovery_image_region active;
	struct flash_mock flash_image;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash_image);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash);

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash_image.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash_image.base;
	image2.base.addr = 0x20000;

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_recovery_image_activated = NULL;

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash_image, 0x20000, sizeof (data));

	status |= mock_expect (&flash_image.mock, flash_image.base.write, &flash_image, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.write_recovery_image_data (&manager, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	active = host_state_manager_get_active_recovery_image (&state);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash_image);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_null_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, &image1.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_null_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, &image2.base, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_in_use_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_in_use_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image *active;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_recovery_image (&manager);

	status = flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE, status);

	manager.free_recovery_image (&manager, active);

	status = flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_erase_error_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0,
        MOCK_ARG_NOT_NULL);
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
        MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_erase_error_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0,
        MOCK_ARG_NOT_NULL);
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
        MOCK_ARG (0x20000));

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_valid_image_notify_observers_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= mock_expect (&observer.mock, observer.base.on_recovery_image_deactivated, &observer,
		0);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_invalid_image_notify_observers_region1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image1.mock, image1.base.verify, &image1, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_valid_image_notify_observers_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= mock_expect (&observer.mock, observer.base.on_recovery_image_deactivated, &observer,
		0);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_erase_all_recovery_regions_invalid_image_notify_observers_region2 (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image1;
	struct recovery_image_mock image2;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash_state;
	struct flash_mock flash;
	struct host_state_manager state;
	struct recovery_image_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_init_host_state (test, &state, &flash_state);

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	image1.base.flash = &flash.base;
	image1.base.addr = 0x10000;

	image2.base.flash = &flash.base;
	image2.base.addr = 0x20000;

	status = mock_expect (&image2.mock, image2.base.verify, &image2, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init_two_region (&manager, &image1.base, &image2.base, &state,
		&hash.base, &verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x10000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	status |= flash_mock_expect_erase_flash (&flash, 0x20000, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);

	CuAssertIntEquals (test, 0, status);

	status = manager.erase_all_recovery_regions (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));

	status = host_state_manager_save_active_recovery_image (&state, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_active_recovery_image (&manager));
	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image1);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	host_state_manager_release (&state);

	status = flash_mock_validate_and_release (&flash_state);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_set_port (CuTest *test)
{
	struct recovery_image_manager manager;

	TEST_START;

	recovery_image_manager_set_port (&manager, 1);
	CuAssertIntEquals (test, 1, recovery_image_manager_get_port (&manager));
}

static void recovery_image_manager_test_set_port_null (CuTest *test)
{
	TEST_START;

	recovery_image_manager_set_port (NULL, 1);
}

static void recovery_image_manager_test_get_port_null (CuTest *test)
{
	int status;

	TEST_START;

	status = recovery_image_manager_get_port (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);
}

static void recovery_image_manager_test_get_flash_update_manager (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000,
		RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, RECOVERY_IMAGE_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_flash_update_manager_after_write (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	CuAssertPtrNotNull (test, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_flash_update_manager_after_activate (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_testing_write_new_image (test, &manager, &flash, 0x10000, data,
		sizeof (data));

	CuAssertPtrNotNull (test, manager.get_flash_update_manager (&manager));

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG (&hash),
		MOCK_ARG (&verification), MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0),
		MOCK_ARG (&pfm_manager));
	CuAssertIntEquals (test, 0, status);

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_flash_update_manager_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.get_flash_update_manager (NULL));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_flash_update_manager_after_activate_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_mock image;
	struct recovery_image_manager manager;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.clear_recovery_image_region (&manager, 2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.get_flash_update_manager (&manager));

	status = manager.activate_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE, status);

	CuAssertPtrNotNull (test, manager.get_flash_update_manager (&manager));

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.get_hash, &image, 0, MOCK_ARG (&hash.base),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&image.mock, 1, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, buffer, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_with_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.get_hash, &image, 0, MOCK_ARG (&hash.base),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&image.mock, 1, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, offset, buffer, length,
		&total_len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN - offset, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = testing_validate_array (RECOVERY_IMAGE_HASH + 2, buffer,
		RECOVERY_IMAGE_HASH_LEN - offset);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.get_hash, &image, 0, MOCK_ARG (&hash.base),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&image.mock, 1, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, 0, buffer, length - 4, &total_len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN - 4, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, buffer, RECOVERY_IMAGE_HASH_LEN - 4);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_small_buffer_with_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	size_t offset = 2;
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.get_hash, &image, 0, MOCK_ARG (&hash.base),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&image.mock, 1, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, offset, buffer, length - 4,
		&total_len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN - 4, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = testing_validate_array (RECOVERY_IMAGE_HASH + offset, buffer,
		RECOVERY_IMAGE_HASH_LEN - 4);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_no_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_no_active_with_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int offset = 2;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, offset, buffer, length,
		&total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - offset, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH - offset);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_no_active_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, 0, buffer, length - 2, &total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - 2, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH - 2);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_no_active_small_buffer_with_offset (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	uint8_t zero[SHA256_HASH_LENGTH] = {0};
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int offset = 2;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG (NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, offset, buffer, length - 4,
		&total_len);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH - 4, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = testing_validate_array (zero, buffer, SHA256_HASH_LENGTH - 4);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_0_bytes_read (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, RECOVERY_IMAGE_HASH_LEN, buffer,
		length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_invalid_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager, SHA256_HASH_LENGTH, buffer,
		length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_LEN, total_len);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct recovery_image_manager manager;
	struct recovery_image_mock image;
	struct signature_verification_mock verification;
	struct pfm_manager_mock pfm_manager;
	struct flash_mock flash;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	image.base.flash = &flash.base;
	image.base.addr = 0x10000;

	status = mock_expect (&image.mock, image.base.verify, &image, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG ((uintptr_t) NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_init (&manager, &image.base, &hash.base,
		&verification.base, &pfm_manager.base, RECOVERY_IMAGE_MANAGER_IMAGE_MAX_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (NULL, SHA256_HASH_LENGTH, buffer,
		length, &total_len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_manager_get_measured_data (&manager, SHA256_HASH_LENGTH, NULL,
		length, &total_len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_manager_release (&manager);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_manager_test_get_measured_data_fail (CuTest *test)
{
	struct recovery_image_manager_mock manager;
	struct recovery_image_mock image;
	uint8_t buffer[SHA256_HASH_LENGTH];
	size_t length = sizeof (buffer);
	uint32_t total_len;
	int status;

	TEST_START;

	status = recovery_image_manager_mock_init (&manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&image);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.mock, manager.base.get_active_recovery_image, &manager,
		(intptr_t) &image.base);
	status |= mock_expect (&manager.mock, manager.base.free_recovery_image, &manager,
		0, MOCK_ARG (&image.base));

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&image.mock, image.base.get_hash, &image, RECOVERY_IMAGE_GET_HASH_FAILED,
		MOCK_ARG (manager.base.hash), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_get_measured_data (&manager.base, 0, buffer, length,
		&total_len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_GET_HASH_FAILED, status);

	status = recovery_image_mock_validate_and_release (&image);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&manager);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START (recovery_image_manager);

TEST (recovery_image_manager_test_init);
TEST (recovery_image_manager_test_init_null);
TEST (recovery_image_manager_test_init_bad_signature);
TEST (recovery_image_manager_test_init_bad_signature_ecc);
TEST (recovery_image_manager_test_init_malformed);
TEST (recovery_image_manager_test_init_bad_platform_id);
TEST (recovery_image_manager_test_init_flash_error);
TEST (recovery_image_manager_test_init_image_header_too_small);
TEST (recovery_image_manager_test_init_image_header_bad_marker);
TEST (recovery_image_manager_test_init_image_header_too_long);
TEST (recovery_image_manager_test_init_image_header_bad_format_length);
TEST (recovery_image_manager_test_init_image_header_bad_platform_id);
TEST (recovery_image_manager_test_init_image_header_bad_version_id);
TEST (recovery_image_manager_test_init_image_header_bad_image_length);
TEST (recovery_image_manager_test_init_section_header_bad_length);
TEST (recovery_image_manager_test_init_invalid_section_address);
TEST (recovery_image_manager_test_release_null);
TEST (recovery_image_manager_test_add_observer_null);
TEST (recovery_image_manager_test_remove_observer_null);
TEST (recovery_image_manager_test_get_active_recovery_image);
TEST (recovery_image_manager_test_get_active_recovery_image_null);
TEST (recovery_image_manager_test_clear_recovery_image_region_null);
TEST (recovery_image_manager_test_clear_recovery_image_region_image_too_large);
TEST (recovery_image_manager_test_clear_recovery_image_region);
TEST (recovery_image_manager_test_clear_recovery_image_region_erase_error);
TEST (recovery_image_manager_test_clear_recovery_image_region_image_in_use);
TEST (recovery_image_manager_test_clear_recovery_image_region_image_in_use_multiple);
TEST (recovery_image_manager_test_clear_recovery_image_region_image_not_in_use);
TEST (recovery_image_manager_test_clear_recovery_image_region_extra_free_call);
TEST (recovery_image_manager_test_clear_recovery_image_region_free_null_region);
TEST (recovery_image_manager_test_clear_recovery_image_region_free_null_manager);
TEST (recovery_image_manager_test_clear_recovery_image_region_in_use_after_activate);
TEST (recovery_image_manager_test_clear_recovery_image_region_with_valid_image_notify_observers);
TEST (recovery_image_manager_test_clear_recovery_image_region_with_invalid_image_notify_observers);
TEST (recovery_image_manager_test_write_recovery_image_data_null);
TEST (recovery_image_manager_test_write_recovery_image_data_without_clear);
TEST (recovery_image_manager_test_write_recovery_image_data_too_long);
TEST (recovery_image_manager_test_write_recovery_image_data_write_error);
TEST (recovery_image_manager_test_write_recovery_image_data_partial_write);
TEST (recovery_image_manager_test_write_recovery_image_data);
TEST (recovery_image_manager_test_write_recovery_image_data_multiple);
TEST (recovery_image_manager_test_write_recovery_image_data_block_end);
TEST (recovery_image_manager_test_write_recovery_image_data_write_after_error);
TEST (recovery_image_manager_test_write_recovery_image_data_write_after_partial_write);
TEST (recovery_image_manager_test_write_recovery_image_data_restart_write);
TEST (recovery_image_manager_test_write_recovery_image_data_image_in_use);
TEST (recovery_image_manager_test_activate_recovery_image_write_after_incomplete_image);
TEST (recovery_image_manager_test_activate_recovery_image_incomplete_image);
TEST (recovery_image_manager_test_activate_recovery_image);
TEST (recovery_image_manager_test_activate_recovery_image_notify_observers);
TEST (recovery_image_manager_test_activate_recovery_image_no_pending_image);
TEST (recovery_image_manager_test_activate_recovery_image_no_pending_notify_observers);
TEST (recovery_image_manager_test_activate_recovery_image_null);
TEST (recovery_image_manager_test_activate_recovery_image_already_valid_notify_observers);
TEST (recovery_image_manager_test_activate_recovery_image_already_valid);
TEST (recovery_image_manager_test_activate_recovery_image_recovery_image_malformed);
TEST (recovery_image_manager_test_activate_recovery_image_extra_data_written);
TEST (recovery_image_manager_test_activate_recovery_image_verify_error);
TEST (recovery_image_manager_test_activate_recovery_image_verify_error_notify_observers);
TEST (recovery_image_manager_test_activate_recovery_image_verify_fail);
TEST (recovery_image_manager_test_activate_recovery_image_verify_fail_ecc);
TEST (recovery_image_manager_test_activate_recovery_image_activate_after_verify_error);
TEST (recovery_image_manager_test_activate_recovery_image_activate_after_verify_fail);
TEST (recovery_image_manager_test_activate_recovery_image_write_after_activate);
TEST (recovery_image_manager_test_activate_recovery_image_write_after_activate_fail);
TEST (recovery_image_manager_test_activate_recovery_image_with_active);
TEST (recovery_image_manager_test_activate_recovery_image_no_event_handler);
TEST (recovery_image_manager_test_erase_all_recovery_regions);
TEST (recovery_image_manager_test_erase_all_recovery_regions_null);
TEST (recovery_image_manager_test_erase_all_recovery_regions_image_in_use);
TEST (recovery_image_manager_test_erase_all_recovery_regions_during_update);
TEST (recovery_image_manager_test_erase_all_recovery_regions_erase_error);
TEST (recovery_image_manager_test_erase_all_recovery_regions_valid_image_notify_observers);
TEST (recovery_image_manager_test_erase_all_recovery_regions_invalid_image_notify_observers);
TEST (recovery_image_manager_test_init_two_region);
TEST (recovery_image_manager_test_init_two_region_active_region1);
TEST (recovery_image_manager_test_init_two_region_active_region2);
TEST (recovery_image_manager_test_init_two_region_null);
TEST (recovery_image_manager_test_init_two_region_region1_bad_platform_id);
TEST (recovery_image_manager_test_init_two_region_region2_bad_platform_id);
TEST (recovery_image_manager_test_init_two_region_region1_flash_error);
TEST (recovery_image_manager_test_init_two_region_region2_flash_error);
TEST (recovery_image_manager_test_init_two_region_region1_bad_signature);
TEST (recovery_image_manager_test_init_two_region_region2_bad_signature);
TEST (recovery_image_manager_test_init_two_region_region1_bad_signature_ecc);
TEST (recovery_image_manager_test_init_two_region_region2_bad_signature_ecc);
TEST (recovery_image_manager_test_init_two_region_region1_malformed);
TEST (recovery_image_manager_test_init_two_region_region2_malformed);
TEST (recovery_image_manager_test_init_two_region_region1_image_header_too_small);
TEST (recovery_image_manager_test_init_two_region_region2_image_header_too_small);
TEST (recovery_image_manager_test_init_two_region_region1_image_header_bad_marker);
TEST (recovery_image_manager_test_init_two_region_region2_image_header_bad_marker);
TEST (recovery_image_manager_test_init_two_region_region1_image_header_too_long);
TEST (recovery_image_manager_test_init_two_region_region2_image_header_too_long);
TEST (recovery_image_manager_test_init_two_region_region1_image_header_bad_format_length);
TEST (recovery_image_manager_test_init_two_region_region2_image_header_bad_format_length);
TEST (recovery_image_manager_test_init_two_region_region1_image_header_bad_platform_id);
TEST (recovery_image_manager_test_init_two_region_region2_image_header_bad_platform_id);
TEST (recovery_image_manager_test_init_two_region_region1_image_header_bad_version_id);
TEST (recovery_image_manager_test_init_two_region_region2_image_header_bad_version_id);
TEST (recovery_image_manager_test_init_two_region_region1_image_header_bad_image_length);
TEST (recovery_image_manager_test_init_two_region_region2_image_header_bad_image_length);
TEST (recovery_image_manager_test_init_two_region_region1_image_section_header_bad_length);
TEST (recovery_image_manager_test_init_two_region_region2_image_section_header_bad_length);
TEST (recovery_image_manager_test_init_two_region_region1_invalid_section_address);
TEST (recovery_image_manager_test_init_two_region_region2_invalid_section_address);
TEST (recovery_image_manager_test_get_active_recovery_image_two_region);
TEST (recovery_image_manager_test_get_active_recovery_image_two_region_null);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_null);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_region1_image_too_large);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_region2_image_too_large);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_erase_error_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_erase_error_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_in_use_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_in_use_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_in_use_multiple_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_in_use_multiple_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_extra_free_call_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_extra_free_call_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_free_null_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_free_null_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_free_null_manager_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_free_null_manager_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_in_use_after_activate_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_in_use_after_activate_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_not_in_use_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_not_in_use_region2);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_notify_observers_region1);
TEST (recovery_image_manager_test_clear_recovery_image_two_region_notify_observers_region2);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_region1);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_region2);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_without_clear);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_too_long);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_write_error);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_partial_write);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_multiple);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_block_end);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_write_after_error);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_write_after_partial_write);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_restart_write);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_in_use);
TEST (recovery_image_manager_test_write_recovery_image_data_two_region_write_after_incomplete_image);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_region1_notify_observers);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_region2_notify_observers);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_no_pending_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_no_pending_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_no_pending_notify_observers_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_no_pending_notify_observers_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_null);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_write_after_incomplete_image_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_write_after_incomplete_image_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_after_incomplete_image_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_after_incomplete_image_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_verify_and_notify_observers_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_verify_and_notify_observers_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_verify_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_verify_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_malformed_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_malformed_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_extra_data_written_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_extra_data_written_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_verify_error_notify_observers_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_verify_error_notify_observers_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_write_after_activate_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_write_after_activate_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_write_after_activate_fail_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_write_after_activate_fail_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_with_active_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_with_active_region2);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_no_event_handler_region1);
TEST (recovery_image_manager_test_activate_recovery_image_two_region_no_event_handler_region2);
TEST (recovery_image_manager_test_erase_all_recovery_regions_region1);
TEST (recovery_image_manager_test_erase_all_recovery_regions_region2);
TEST (recovery_image_manager_test_erase_all_recovery_regions_null_region1);
TEST (recovery_image_manager_test_erase_all_recovery_regions_null_region2);
TEST (recovery_image_manager_test_erase_all_recovery_regions_in_use_region1);
TEST (recovery_image_manager_test_erase_all_recovery_regions_in_use_region2);
TEST (recovery_image_manager_test_erase_all_recovery_regions_erase_error_region1);
TEST (recovery_image_manager_test_erase_all_recovery_regions_erase_error_region2);
TEST (recovery_image_manager_test_erase_all_recovery_regions_valid_image_notify_observers_region1);
TEST (recovery_image_manager_test_erase_all_recovery_regions_invalid_image_notify_observers_region1);
TEST (recovery_image_manager_test_erase_all_recovery_regions_valid_image_notify_observers_region2);
TEST (recovery_image_manager_test_erase_all_recovery_regions_invalid_image_notify_observers_region2);
TEST (recovery_image_manager_test_set_port);
TEST (recovery_image_manager_test_set_port_null);
TEST (recovery_image_manager_test_get_port_null);
TEST (recovery_image_manager_test_get_flash_update_manager);
TEST (recovery_image_manager_test_get_flash_update_manager_after_write);
TEST (recovery_image_manager_test_get_flash_update_manager_after_activate);
TEST (recovery_image_manager_test_get_flash_update_manager_null);
TEST (recovery_image_manager_test_get_flash_update_manager_after_activate_fail);
TEST (recovery_image_manager_test_get_measured_data);
TEST (recovery_image_manager_test_get_measured_data_with_offset);
TEST (recovery_image_manager_test_get_measured_data_small_buffer);
TEST (recovery_image_manager_test_get_measured_data_small_buffer_with_offset);
TEST (recovery_image_manager_test_get_measured_data_no_active);
TEST (recovery_image_manager_test_get_measured_data_no_active_with_offset);
TEST (recovery_image_manager_test_get_measured_data_no_active_small_buffer);
TEST (recovery_image_manager_test_get_measured_data_no_active_small_buffer_with_offset);
TEST (recovery_image_manager_test_get_measured_data_0_bytes_read);
TEST (recovery_image_manager_test_get_measured_data_invalid_offset);
TEST (recovery_image_manager_test_get_measured_data_null);
TEST (recovery_image_manager_test_get_measured_data_fail);

TEST_SUITE_END;
