// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/firmware_update.h"
#include "flash/flash_common.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/firmware/firmware_image_mock.h"
#include "testing/mock/firmware/app_context_mock.h"
#include "testing/mock/firmware/firmware_update_notification_mock.h"
#include "testing/mock/firmware/key_manifest_mock.h"
#include "testing/mock/firmware/firmware_update_mock.h"
#include "testing/mock/firmware/firmware_update_observer_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/common/image_header_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/firmware/firmware_header_testing.h"


TEST_SUITE_LABEL ("firmware_update");


/**
 * Dependencies for testing.
 */
struct firmware_update_testing {
	HASH_TESTING_ENGINE hash;								/**< Hash engine for API arguments. */
	RSA_TESTING_ENGINE rsa;									/**< RSA engine for API arguments. */
	struct firmware_image_mock fw;							/**< Mock for the FW image updater.handler. */
	struct app_context_mock app;							/**< Mock for the application context. */
	struct key_manifest_mock manifest;						/**< Mock for the key updater.manifest. */
	struct firmware_header header;							/**< Header on the firmware image. */
	struct flash_mock flash;								/**< Mock for the updater.flash device. */
	struct firmware_flash_map map;							/**< Map of firmware images on updater.flash. */
	struct firmware_update_notification_mock handler;		/**< Mock for update notifications. */
	struct firmware_update_observer_mock observer;			/**< Mock for an update observer. */
	struct firmware_update test;							/**< Firmware updater for testing. */
	struct firmware_update_mock test_mock;					/**< Mock updater for testing. */
	bool is_mock;											/**< Flag indicating which updater was initialized. */
};


/**
 * Initialize a firmware header instance for update testing.
 *
 * @param test The test framework.
 * @param header The header to initialize.
 * @param flash The flash device to initialize the header from.
 * @param id The recovery ID to set in the header.
 */
static void firmware_update_testing_init_firmware_header (CuTest *test,
	struct firmware_header *header, struct flash_mock *flash, int id)
{
	uint8_t data[FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN];
	int status;

	memcpy (data, FIRMWARE_HEADER_FORMAT_2, sizeof (data));
	*((uint16_t*) &data[8]) = (uint16_t) id;
	*((uint16_t*) &data[11]) = (uint16_t) id;

	status = mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash->mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (data) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash->mock, 1, data + IMAGE_HEADER_BASE_LEN,
		sizeof (data) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (header, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash->mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Set expectations for querying the updater.flash page size.
 *
 * @param updater.flash The updater.flash mock to set expectations on.
 * @param page The page size to report.
 *
 * @return 0 if the expectations were set or non-zero if not.
 */
static int firmware_update_testing_flash_page_size (struct flash_mock *flash, uint32_t page)
{
	int status;

	status = mock_expect (&flash->mock, flash->base.get_page_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&flash->mock, 0, &page, sizeof (page), -1);

	return status;
}

/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param updater The testing components to initialize.
 * @param header The updater header firmware ID.
 */
static void firmware_update_testing_init_dependencies (CuTest *test,
	struct firmware_update_testing *updater, int header)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&updater->hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&updater->rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&updater->fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&updater->app);
	CuAssertIntEquals (test, 0, status);

	status = key_manifest_mock_init (&updater->manifest);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&updater->flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_notification_mock_init (&updater->handler);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_observer_mock_init (&updater->observer);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_init_firmware_header (test, &updater->header, &updater->flash, header);

	updater->map.active_addr = 0x10000;
	updater->map.active_size = 0x10000;
	updater->map.backup_addr = 0x20000;
	updater->map.backup_size = 0x10000;
	updater->map.staging_addr = 0x30000;
	updater->map.staging_size = 0x10000;
	updater->map.recovery_addr = 0x40000;
	updater->map.recovery_size = 0x10000;
	updater->map.rec_backup_addr = 0x50000;
	updater->map.rec_backup_size = 0x10000;

	updater->map.active_flash = &updater->flash.base;
	updater->map.backup_flash = &updater->flash.base;
	updater->map.staging_flash = &updater->flash.base;
	updater->map.recovery_flash = &updater->flash.base;
	updater->map.rec_backup_flash = &updater->flash.base;
}

/**
 * Initialize the test updater instance.
 *
 * @param test The testing framework.
 * @param updater The testing components to initialize.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 */
void firmware_update_testing_init_updater (CuTest *test, struct firmware_update_testing *updater,
	int allowed, int recovery)
{
	int status;

	updater->is_mock = false;

	status = firmware_update_init (&updater->test, &updater->map, &updater->app.base,
		&updater->fw.base, &updater->hash.base, &updater->rsa.base, allowed);
	CuAssertIntEquals (test, 0, status);

	firmware_update_set_recovery_revision (&updater->test, recovery);
}

/**
 * Initialize the mock updater instance.
 *
 * @param test The testing framework.
 * @param updater The testing components to initialize.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 */
void firmware_update_testing_init_updater_mock (CuTest *test,
	struct firmware_update_testing *updater, int allowed, int recovery)
{
	int status;

	updater->is_mock = true;

	status = firmware_update_mock_init (&updater->test_mock, &updater->map, &updater->app.base,
		&updater->fw.base, &updater->hash.base, &updater->rsa.base, allowed);
	CuAssertIntEquals (test, 0, status);

	firmware_update_set_recovery_revision (&updater->test_mock.base, recovery);
}

/**
 * Initialize a firmware updater for testing.
 *
 * @param test The testing framework.
 * @param updater The testing components to initialize.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 * @param header The header firmware ID.
 */
void firmware_update_testing_init (CuTest *test, struct firmware_update_testing *updater,
	int allowed, int recovery, int header)
{
	firmware_update_testing_init_dependencies (test, updater, header);
	firmware_update_testing_init_updater (test, updater, allowed, recovery);
}

/**
 * Initialize a mock firmware updater for testing.
 *
 * @param test The testing framework.
 * @param updater The testing components to initialize.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 * @param header The header firmware ID.
 */
void firmware_update_testing_init_mock (CuTest *test, struct firmware_update_testing *updater,
	int allowed, int recovery, int header)
{
	firmware_update_testing_init_dependencies (test, updater, header);
	firmware_update_testing_init_updater_mock (test, updater, allowed, recovery);
}

/**
 * Validate all mocks.
 *
 * @param test The testing framework.
 * @param updater The testing components to validate.
 */
void firmware_update_testing_validate (CuTest *test, struct firmware_update_testing *updater)
{
	int status;

	status = mock_validate (&updater->handler.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&updater->flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&updater->fw.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&updater->app.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&updater->manifest.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&updater->observer.mock);
	CuAssertIntEquals (test, 0, status);

	if (updater->is_mock) {
		status = mock_validate (&updater->test_mock.mock);
		CuAssertIntEquals (test, 0, status);
	}
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param updater The testing components to release.
 */
void firmware_update_testing_validate_and_release (CuTest *test,
	struct firmware_update_testing *updater)
{
	int status;

	status = firmware_update_notification_mock_validate_and_release (&updater->handler);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&updater->flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&updater->fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&updater->app);
	CuAssertIntEquals (test, 0, status);

	status = key_manifest_mock_validate_and_release (&updater->manifest);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_observer_mock_validate_and_release (&updater->observer);
	CuAssertIntEquals (test, 0, status);

	if (updater->is_mock) {
		status = firmware_update_mock_validate_and_release (&updater->test_mock);
		CuAssertIntEquals (test, 0, status);
	}
	else {
		firmware_update_release (&updater->test);
	}

	firmware_header_release (&updater->header);
	RSA_TESTING_ENGINE_RELEASE (&updater->rsa);
	HASH_TESTING_ENGINE_RELEASE (&updater->hash);
}

/*******************
 * Test cases
 *******************/

static void firmware_update_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct flash_mock flash;
	struct firmware_flash_map map;
	struct firmware_update updater;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.backup_addr = 0x20000;
	map.backup_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;
	map.recovery_addr = 0x40000;
	map.recovery_size = 0x10000;
	map.rec_backup_addr = 0x50000;
	map.rec_backup_size = 0x10000;

	map.active_flash = &flash.base;
	map.backup_flash = &flash.base;
	map.staging_flash = &flash.base;
	map.recovery_flash = &flash.base;
	map.rec_backup_flash = &flash.base;

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	firmware_update_release (&updater);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct flash_mock flash;
	struct firmware_flash_map map;
	struct firmware_update updater;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.backup_addr = 0x20000;
	map.backup_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;
	map.recovery_addr = 0x40000;
	map.recovery_size = 0x10000;
	map.rec_backup_addr = 0x50000;
	map.rec_backup_size = 0x10000;

	map.active_flash = &flash.base;
	map.backup_flash = &flash.base;
	map.staging_flash = &flash.base;
	map.recovery_flash = &flash.base;
	map.rec_backup_flash = &flash.base;

	status = firmware_update_init (NULL, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_init (&updater, NULL, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_init (&updater, &map, NULL, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_init (&updater, &map, &app.base, NULL, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, NULL, &rsa.base, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, NULL, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_init_no_recovery (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct flash_mock flash;
	struct firmware_flash_map map;
	struct firmware_update updater;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.backup_addr = 0x20000;
	map.backup_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;

	map.active_flash = &flash.base;
	map.backup_flash = &flash.base;
	map.staging_flash = &flash.base;
	map.recovery_flash = NULL;
	map.rec_backup_flash = NULL;

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	firmware_update_release (&updater);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_init_no_recovery_backup (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct flash_mock flash;
	struct firmware_flash_map map;
	struct firmware_update updater;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.backup_addr = 0x20000;
	map.backup_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;
	map.recovery_addr = 0x40000;
	map.recovery_size = 0x10000;

	map.active_flash = &flash.base;
	map.backup_flash = &flash.base;
	map.staging_flash = &flash.base;
	map.recovery_flash = &flash.base;
	map.rec_backup_flash = NULL;

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	firmware_update_release (&updater);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_init_no_backup (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct flash_mock flash;
	struct firmware_flash_map map;
	struct firmware_update updater;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;
	map.recovery_addr = 0x40000;
	map.recovery_size = 0x10000;
	map.rec_backup_addr = 0x50000;
	map.rec_backup_size = 0x10000;

	map.active_flash = &flash.base;
	map.backup_flash = NULL;
	map.staging_flash = &flash.base;
	map.recovery_flash = &flash.base;
	map.rec_backup_flash = &flash.base;

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	firmware_update_release (&updater);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_init_no_recovery_no_backup (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct flash_mock flash;
	struct firmware_flash_map map;
	struct firmware_update updater;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;

	map.active_flash = &flash.base;
	map.backup_flash = NULL;
	map.staging_flash = &flash.base;
	map.recovery_flash = NULL;
	map.rec_backup_flash = NULL;

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_FLASH_MAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_init_no_active_or_staging (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct flash_mock flash;
	struct firmware_flash_map map;
	struct firmware_update updater;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.backup_addr = 0x20000;
	map.backup_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;
	map.recovery_addr = 0x40000;
	map.recovery_size = 0x10000;
	map.rec_backup_addr = 0x50000;
	map.rec_backup_size = 0x10000;

	map.active_flash = NULL;
	map.backup_flash = &flash.base;
	map.staging_flash = &flash.base;
	map.recovery_flash = &flash.base;
	map.rec_backup_flash = &flash.base;

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_FLASH_MAP, status);

	map.active_flash = &flash.base;
	map.staging_flash = NULL;
	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_FLASH_MAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_release_null (CuTest *test)
{
	TEST_START;

	firmware_update_release (NULL);
}

static void firmware_update_test_release_no_init (CuTest *test)
{
	struct firmware_update updater;

	TEST_START;

	memset (&updater, 0, sizeof (updater));

	firmware_update_release (&updater);
}

static void firmware_update_test_set_recovery_good_null (CuTest *test)
{
	TEST_START;

	firmware_update_set_recovery_good (NULL, false);
}

static void firmware_update_test_set_recovery_revision_null (CuTest *test)
{
	TEST_START;

	firmware_update_set_recovery_revision (NULL, 2);
}

static void firmware_update_test_set_image_offset_null (CuTest *test)
{
	TEST_START;

	firmware_update_set_image_offset (NULL, 0x100);
}

static void firmware_update_test_add_observer_null (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (NULL, &updater.observer.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_add_observer (&updater.test, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_remove_observer_null (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_remove_observer (NULL, &updater.observer.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_remove_observer (&updater.test, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		 &updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_header_last (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (staging_data); i++) {
		staging_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x10000 + FLASH_PAGE_SIZE, 0x30000 + FLASH_PAGE_SIZE, staging_data + FLASH_PAGE_SIZE,
		sizeof (staging_data) - FLASH_PAGE_SIZE);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, FLASH_PAGE_SIZE);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_header_last_small_page (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (staging_data); i++) {
		staging_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, 32);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x10000 + 32,
		0x30000 + 32, staging_data + 32, sizeof (staging_data) - 32, 32);
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x10000,
		0x30000, staging_data, 32, 32);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_notifications (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, NULL);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_callback_null (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	memset (&updater.handler.base, 0, sizeof (updater.handler.base));

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20100, 0x10100,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10100, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10100, 0x30100,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_finalize_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_finalize_image_with_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test_mock.base, 0x100);
	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20100, 0x10100,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10100, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10100, 0x30100,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_with_observer (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	int zero = 0;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.observer.mock, updater.observer.base.on_update_start,
		&updater.observer, 0, MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_observer_removed (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_remove_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_extra_data_received (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_null (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_START_FAILURE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (NULL, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_verify_incomplete_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x30000, 5);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base, 5);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_INCOMPLETE_IMAGE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INCOMPLETE_IMAGE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_verify_fail_load (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFY_FAILURE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_LOAD_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_verify_invalid_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_INVALID_IMAGE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_verify_manifest_revoked (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw,
		FIRMWARE_IMAGE_MANIFEST_REVOKED, MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_INVALID_IMAGE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_MANIFEST_REVOKED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_verify_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw,
		FIRMWARE_IMAGE_VERIFY_FAILED, MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFY_FAILURE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_VERIFY_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_verify_rollback_disallowed (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 1, 1, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_INVALID_IMAGE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_REJECTED_ROLLBACK, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_verify_null_firmware_header (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 1, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_INVALID_IMAGE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_FIRMWARE_HEADER, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_verify_img_size_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		FIRMWARE_IMAGE_GET_SIZE_FAILED);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFY_FAILURE));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_GET_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_blocked_by_observer (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	int zero = 0;
	int error = OBSERVABLE_INVALID_ARGUMENT;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.observer.mock, updater.observer.base.on_update_start,
		&updater.observer, 0, MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));
	status |= mock_expect_output (&updater.observer.mock, 0, &error, sizeof (error), -1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SYSTEM_PREREQ_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_context_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	int zero = 0;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_add_observer (&updater.test, &updater.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.observer.mock, updater.observer.base.on_update_start,
		&updater.observer, 0, MOCK_ARG_PTR_CONTAINS (&zero, sizeof (zero)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app,
		APP_CONTEXT_SAVE_FAILED);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STATE_SAVE_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, APP_CONTEXT_SAVE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_backup_fail_load (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_FAILED));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_LOAD_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_backup_img_size_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		FIRMWARE_IMAGE_GET_SIZE_FAILED);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_FAILED));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_GET_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_backup_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_FAILED));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_page_size_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_page_size, &updater.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_erase_failure (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_write_staging_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x20000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_write_staging_error_header_last (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (active_data); i++) {
		active_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x10000 + FLASH_PAGE_SIZE, 0x20000 + FLASH_PAGE_SIZE, active_data + FLASH_PAGE_SIZE,
		sizeof (active_data) - FLASH_PAGE_SIZE);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x20000,
		active_data, FLASH_PAGE_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_write_staging_error_header_last_small_page (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (active_data); i++) {
		active_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, 32);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x10000 + 32,
		0x20000 + 32, active_data + 32, sizeof (active_data) - 32, 32);
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x10000,
		0x20000, active_data, 32, 32);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_write_staging_error_fail_recovery_erase (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_write_staging_error_fail_recovery (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_write_staging_error_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x123);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30123));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10123));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20123, 0x10123,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10123, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10123, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10123, 0x20123,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_header_last_image_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		RSA_ENCRYPT_LEN * 4);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, RSA_ENCRYPT_LEN * 4);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x20000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_header_last_header_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (staging_data); i++) {
		staging_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x10000 + FLASH_PAGE_SIZE, 0x30000 + FLASH_PAGE_SIZE, staging_data + FLASH_PAGE_SIZE,
		sizeof (staging_data) - FLASH_PAGE_SIZE);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x20000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_finalize_image_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x20000,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_finalize_image_error_with_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test_mock.base, 0x100);
	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20100, 0x10100,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10100, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10100, 0x30100,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10100, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10100, 0x20100,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_finalize_image_error_fail_recovery_erase (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_finalize_image_error_fail_recovery (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_finalize_image_error_fail_recovery_finalize (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x20000,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_INVALID_ARGUMENT, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_check_load_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CHK_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_LOAD_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_check_manifest_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CHK_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_KEY_MANIFEST, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_check_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, KEY_MANIFEST_REVOKE_CHECK_FAILED);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CHK_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, KEY_MANIFEST_REVOKE_CHECK_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_revocation (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_revocation_header_last (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[RSA_ENCRYPT_LEN * 4];
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (staging_data); i++) {
		staging_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x10000 + FLASH_PAGE_SIZE, 0x30000 + FLASH_PAGE_SIZE, staging_data + FLASH_PAGE_SIZE,
		sizeof (staging_data) - FLASH_PAGE_SIZE);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, FLASH_PAGE_SIZE);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x40000 + FLASH_PAGE_SIZE, 0x30000 + FLASH_PAGE_SIZE, staging_data + FLASH_PAGE_SIZE,
		sizeof (staging_data) - FLASH_PAGE_SIZE);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, FLASH_PAGE_SIZE);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_revocation_header_last_small_page (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[RSA_ENCRYPT_LEN * 4];
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (staging_data); i++) {
		staging_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, 32);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x10000 + 32,
		0x30000 + 32, staging_data + 32, sizeof (staging_data) - 32, 32);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, 32);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, 32);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x40000 + 32,
		0x30000 + 32, staging_data + 32, sizeof (staging_data) - 32, 32);
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x40000,
		0x30000, staging_data, 32, 32);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_revocation_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20100, 0x10100,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10100, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10100, 0x30100,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50100, 0x40100,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40100, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40100, 0x30100,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_revocation_finalize_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_revocation_finalize_image_with_offset (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test_mock.base, 0x100);
	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20100, 0x10100,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10100, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10100, 0x30100,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50100, 0x40100,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40100, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40100, 0x30100,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_backup_load_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_LOAD_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_backup_img_size_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		FIRMWARE_IMAGE_GET_SIZE_FAILED);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_GET_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_backup_recovery_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 3);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_page_size_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_page_size, &updater.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_erase_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x50000,
		recovery_data, sizeof (recovery_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_fail_header_last (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (recovery_data); i++) {
		recovery_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x40000 + FLASH_PAGE_SIZE, 0x50000 + FLASH_PAGE_SIZE, recovery_data + FLASH_PAGE_SIZE,
		sizeof (recovery_data) - FLASH_PAGE_SIZE);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x50000,
		recovery_data, FLASH_PAGE_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_fail_header_last_small_page (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (recovery_data); i++) {
		recovery_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, 32);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, 32);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x40000 + 32,
		0x50000 + 32, recovery_data + 32, sizeof (recovery_data) - 32, 32);
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x40000,
		0x50000, recovery_data, 32, 32);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_fail_finalize (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x50000,
		recovery_data, sizeof (recovery_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_restore_erase_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_restore_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_restore_fail_finalize (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x50000,
		recovery_data, sizeof (recovery_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_INVALID_ARGUMENT, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_revocation_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, KEY_MANIFEST_REVOKE_UPDATE_FAILED);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_FAILED));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, KEY_MANIFEST_REVOKE_UPDATE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_recovery_backup (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_recovery_backup_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 3);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_restore_no_recovery_backup (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x20000,
		recovery_data, sizeof (recovery_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_restore_no_recovery_backup_header_last (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (recovery_data); i++) {
		recovery_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x40000 + FLASH_PAGE_SIZE, 0x20000 + FLASH_PAGE_SIZE, recovery_data + FLASH_PAGE_SIZE,
		sizeof (recovery_data) - FLASH_PAGE_SIZE);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x20000,
		recovery_data, FLASH_PAGE_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_restore_no_recovery_backup_erase_fail (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_restore_no_recovery_backup_fail (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_cert_revocation_no_recovery (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.recovery_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_different_flash_devices (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct key_manifest_mock manifest;
	struct firmware_header header;
	struct flash_mock flash1;
	struct flash_mock flash2;
	struct flash_mock flash3;
	struct flash_mock flash4;
	struct flash_mock flash5;
	struct firmware_flash_map map;
	struct firmware_update updater;
	struct firmware_update_notification_mock handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = key_manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash4);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash5);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.backup_addr = 0x20000;
	map.backup_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;
	map.recovery_addr = 0x40000;
	map.recovery_size = 0x10000;
	map.rec_backup_addr = 0x50000;
	map.rec_backup_size = 0x10000;

	map.active_flash = &flash1.base;
	map.backup_flash = &flash2.base;
	map.staging_flash = &flash3.base;
	map.recovery_flash = &flash4.base;
	map.rec_backup_flash = &flash5.base;

	status = firmware_update_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base, 0);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_init_firmware_header (test, &header, &flash1, 0);
	firmware_update_set_recovery_revision (&updater, 0);

	status = firmware_update_notification_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&fw.mock, fw.base.load, &fw, 0, MOCK_ARG (&flash3), MOCK_ARG (0x30000));
	status |= mock_expect (&fw.mock, fw.base.verify, &fw, 0, MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&fw.mock, fw.base.get_firmware_header, &fw, (intptr_t) &header);
	status |= mock_expect (&fw.mock, fw.base.get_image_size, &fw, sizeof (staging_data));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&app.mock, app.base.save, &app, 0);

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&fw.mock, fw.base.load, &fw, 0, MOCK_ARG (&flash1), MOCK_ARG (0x10000));
	status |= mock_expect (&fw.mock, fw.base.get_image_size, &fw, sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&flash2, &flash1, 0x20000, 0x10000, active_data,
		sizeof (active_data));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&flash1, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&flash1, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&flash1, &flash3, 0x10000, 0x30000, staging_data,
		sizeof (staging_data));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&fw.mock, fw.base.load, &fw, 0, MOCK_ARG (&flash1), MOCK_ARG (0x10000));
	status |= mock_expect (&fw.mock, fw.base.get_key_manifest, &fw, (intptr_t) &manifest);
	status |= mock_expect (&manifest.mock, manifest.base.revokes_old_manifest, &manifest, 1);

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&fw.mock, fw.base.load, &fw, 0, MOCK_ARG (&flash4), MOCK_ARG (0x40000));
	status |= mock_expect (&fw.mock, fw.base.get_image_size, &fw, sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&flash5, &flash4, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&flash4, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&flash4, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&flash4, &flash3, 0x40000, 0x30000, staging_data,
		sizeof (staging_data));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&manifest.mock, manifest.base.update_revocation, &manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater, &handler.base);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_notification_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash4);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash5);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	status = key_manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	firmware_update_release (&updater);

	firmware_header_release (&header);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_run_update_different_flash_devices_finalize_image (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct firmware_image_mock fw;
	struct app_context_mock app;
	struct key_manifest_mock manifest;
	struct firmware_header header;
	struct flash_mock flash1;
	struct flash_mock flash2;
	struct flash_mock flash3;
	struct flash_mock flash4;
	struct flash_mock flash5;
	struct firmware_flash_map map;
	struct firmware_update_mock updater;
	struct firmware_update_notification_mock handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&app);
	CuAssertIntEquals (test, 0, status);

	status = key_manifest_mock_init (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash4);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash5);
	CuAssertIntEquals (test, 0, status);

	map.active_addr = 0x10000;
	map.active_size = 0x10000;
	map.backup_addr = 0x20000;
	map.backup_size = 0x10000;
	map.staging_addr = 0x30000;
	map.staging_size = 0x10000;
	map.recovery_addr = 0x40000;
	map.recovery_size = 0x10000;
	map.rec_backup_addr = 0x50000;
	map.rec_backup_size = 0x10000;

	map.active_flash = &flash1.base;
	map.backup_flash = &flash2.base;
	map.staging_flash = &flash3.base;
	map.recovery_flash = &flash4.base;
	map.rec_backup_flash = &flash5.base;

	status = firmware_update_mock_init (&updater, &map, &app.base, &fw.base, &hash.base, &rsa.base,
		0);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_init_firmware_header (test, &header, &flash1, 0);
	firmware_update_set_recovery_revision (&updater.base, 0);

	firmware_update_mock_enable_finalize_image (&updater);

	status = firmware_update_notification_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&fw.mock, fw.base.load, &fw, 0, MOCK_ARG (&flash3), MOCK_ARG (0x30000));
	status |= mock_expect (&fw.mock, fw.base.verify, &fw, 0, MOCK_ARG (&hash), MOCK_ARG (&rsa));
	status |= mock_expect (&fw.mock, fw.base.get_firmware_header, &fw, (intptr_t) &header);
	status |= mock_expect (&fw.mock, fw.base.get_image_size, &fw, sizeof (staging_data));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&app.mock, app.base.save, &app, 0);

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&fw.mock, fw.base.load, &fw, 0, MOCK_ARG (&flash1), MOCK_ARG (0x10000));
	status |= mock_expect (&fw.mock, fw.base.get_image_size, &fw, sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&flash2, &flash1, 0x20000, 0x10000, active_data,
		sizeof (active_data));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&flash1, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&flash1, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&flash1, &flash3, 0x10000, 0x30000, staging_data,
		sizeof (staging_data));
	status |= mock_expect (&updater.mock, firmware_update_mock_finalize_image, &updater, 0,
		MOCK_ARG (&flash1), MOCK_ARG (0x10000));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&fw.mock, fw.base.load, &fw, 0, MOCK_ARG (&flash1), MOCK_ARG (0x10000));
	status |= mock_expect (&fw.mock, fw.base.get_key_manifest, &fw, (intptr_t) &manifest);
	status |= mock_expect (&manifest.mock, manifest.base.revokes_old_manifest, &manifest, 1);

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&fw.mock, fw.base.load, &fw, 0, MOCK_ARG (&flash4), MOCK_ARG (0x40000));
	status |= mock_expect (&fw.mock, fw.base.get_image_size, &fw, sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&flash5, &flash4, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&flash4, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&flash4, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&flash4, &flash3, 0x40000, 0x30000, staging_data,
		sizeof (staging_data));
	status |= mock_expect (&updater.mock, firmware_update_mock_finalize_image, &updater, 0,
		MOCK_ARG (&flash4), MOCK_ARG (0x40000));

	status |= mock_expect (&handler.mock, handler.base.status_change, &handler, 0,
		MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&manifest.mock, manifest.base.update_revocation, &manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.base, &handler.base);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_notification_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash4);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash5);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_validate_and_release (&fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_validate_and_release (&app);
	CuAssertIntEquals (test, 0, status);

	status = key_manifest_mock_validate_and_release (&manifest);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_mock_validate_and_release (&updater);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_update_test_run_update_no_backup (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_write_staging_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_finalize_image_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	firmware_update_testing_init_updater_mock (test, &updater, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_FAILED));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_cert_revocation (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_recovery_erase_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_recovery_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_recovery_finalize_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater_mock (test, &updater, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad_finalize_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);
	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad_page_size_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_page_size, &updater.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad_erase_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad_update_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 5);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, 5);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad_finalize_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);
	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad_no_recovery (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.recovery_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad_cert_revocation (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_page_size_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_page_size, &updater.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_erase_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x50000,
		recovery_data, sizeof (recovery_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_finalize_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x50000,
		recovery_data, sizeof (recovery_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_restore_erase_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_restore_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_restore_finalize_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x50000,
		recovery_data, sizeof (recovery_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_recovery_backup_after_recovery_restore_erase_fail (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_recovery_backup_after_recovery_restore_fail (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000,
		sizeof (recovery_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_INVALID_ARGUMENT, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_backup_load_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_LOAD_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_backup_img_size_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		FIRMWARE_IMAGE_GET_SIZE_FAILED);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_GET_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_backup_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 3);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_recovery_backup_after_recovery_backup_fail (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 3);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_after_recovery_erase_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_after_recovery_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_no_backup_after_recovery_finalize_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.backup_flash = NULL;
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater_mock (test, &updater, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_bad (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_bad_page_size_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_page_size, &updater.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_bad_erase_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_bad_update_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_after_recovery_bad_finalize_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);
	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_REC_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_new_recovery_revision_higher (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 1);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_new_recovery_revision_lower (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 2, 1);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_same_revision_after_recovery_update (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 1);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_same_revision_after_cert_revocation (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 1);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 1);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_REVOKE_CERT));
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.update_revocation,
		&updater.manifest, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_recovery_bad_different_revision (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 1);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_run_update_same_revision_after_recovery_bad (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 1);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_prepare_staging (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x30000, 5);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base, 5);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_prepare_staging_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x30100, 5);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base, 5);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_prepare_staging_null_updater (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (NULL, &updater.handler.base, 5);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_prepare_staging_null_callback (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = flash_mock_expect_erase_flash_verify (&updater.flash, 0x30000, 5);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, NULL, 5);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_prepare_staging_image_too_large (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base, 0x10001);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_prepare_staging_image_too_large_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base,
		0x10001 - 0x100);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_prepare_staging_erase_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base, 5);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (int) -sizeof (staging_data),
		firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging_multiple_calls (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30000 + sizeof (staging_data)),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (int) -sizeof (staging_data),
		firmware_update_get_update_remaining (&updater.test));

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (int) -(sizeof (staging_data) * 2),
		firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30100),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (int) -sizeof (staging_data),
		firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging_null_updater (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE_FAIL));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (NULL, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, NULL,
		sizeof (staging_data));
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging_null_callback (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, NULL, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging_write_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));

	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);
	CuAssertIntEquals (test, 0, firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging_image_too_large (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.staging_size = 0x09;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging_image_too_large_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.staging_size = 0x109;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30100),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE_FAIL));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_write_to_staging_partial_write (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	/* The failed call for a partial write. */
	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash, 1,
		MOCK_ARG (0x30000), MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE_FAIL));

	/* A second call to ensure the internal state was correctly updated. */
	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data) - 1, MOCK_ARG (0x30001),
		MOCK_ARG_PTR_CONTAINS (staging_data + 1, sizeof (staging_data) - 1),
		MOCK_ARG (sizeof (staging_data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);
	CuAssertIntEquals (test, -1, firmware_update_get_update_remaining (&updater.test));

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base,
		staging_data + 1, sizeof (staging_data) - 1);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (int) -sizeof (staging_data),
		firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_multiple_prepare_and_write_cycles (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t staging_data2[] = {0x11, 0x12, 0x13, 0x14};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x30000, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x30000,
		sizeof (staging_data2));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data2), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data2, sizeof (staging_data2)),
		MOCK_ARG (sizeof (staging_data2)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, firmware_update_get_update_remaining (&updater.test));

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base,
		sizeof (staging_data2));
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data2,
		sizeof (staging_data2));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_multiple_prepare_and_write_cycles_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t staging_data2[] = {0x11, 0x12, 0x13, 0x14};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x30100, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data), MOCK_ARG (0x30100),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_PREP));
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x30100,
		sizeof (staging_data2));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_STAGING_WRITE));
	status |= mock_expect (&updater.flash.mock, updater.flash.base.write, &updater.flash,
		sizeof (staging_data2), MOCK_ARG (0x30100),
		MOCK_ARG_PTR_CONTAINS (staging_data2, sizeof (staging_data2)),
		MOCK_ARG (sizeof (staging_data2)));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, firmware_update_get_update_remaining (&updater.test));

	status = firmware_update_prepare_staging (&updater.test, &updater.handler.base,
		sizeof (staging_data2));
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_write_to_staging (&updater.test, &updater.handler.base, staging_data2,
		sizeof (staging_data2));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, firmware_update_get_update_remaining (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as good, so the update should proceed normally. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_extra_verify (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_verify_boot_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as good, so the update should proceed normally. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_extra_verify_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_image_offset (&updater.test_mock.base, 0x100);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_verify_boot_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_no_recovery (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.recovery_flash = NULL;
	updater.map.rec_backup_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = firmware_update_validate_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_set_recovery_revision (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	struct firmware_header header2;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 1);

	firmware_update_testing_init_firmware_header (test, &header2, &updater.flash, 0);
	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as good, so the update should proceed normally. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &header2);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
	firmware_header_release (&header2);
}

static void firmware_update_test_validate_recovery_image_bad (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_bad_extra_verify (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_verify_boot_image,
		&updater.test_mock, 1, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_load_verify_bad_format (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_INVALID_FORMAT, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_load_verify_bad_checksum (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_BAD_CHECKSUM, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_load_verify_manifest_format (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		KEY_MANIFEST_INVALID_FORMAT, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_load_verify_fw_header_min_size (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		IMAGE_HEADER_NOT_MINIMUM_SIZE, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_load_verify_fw_header_too_long (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		IMAGE_HEADER_TOO_LONG, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_load_verify_fw_header_bad_marker (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		IMAGE_HEADER_BAD_MARKER, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_load_verify_fw_header_bad_fmt_length (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_HEADER_BAD_FORMAT_LENGTH, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image validated as bad, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_offset_null (CuTest *test)
{
	int status;

	TEST_START;

	status = firmware_update_validate_recovery_image (NULL);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);
}

static void firmware_update_test_validate_recovery_image_load_failure (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_LOAD_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image state is unknown, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_verify_failure (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw,
		FIRMWARE_IMAGE_VERIFY_FAILED, MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_VERIFY_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image state is unknown, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_extra_verify_failure (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_verify_boot_image,
		&updater.test_mock, FIRMWARE_UPDATE_VERIFY_BOOT_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_VERIFY_BOOT_FAILED, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image state is unknown, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_image_load_verify_fw_header_no_memory (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_verify_boot_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_HEADER_NO_MEMORY, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, FIRMWARE_HEADER_NO_MEMORY, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image state is unknown, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test_mock.base, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_validate_recovery_null_firmware_header (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, true);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_validate_recovery_image (&updater.test);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_FIRMWARE_HEADER, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image state is unknown, so the update should update recovery first. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		&updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_header_last (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (active_data); i++) {
		active_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x40000 + FLASH_PAGE_SIZE, 0x10000 + FLASH_PAGE_SIZE, active_data + FLASH_PAGE_SIZE,
		sizeof (active_data) - FLASH_PAGE_SIZE);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x10000,
		active_data, FLASH_PAGE_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_header_last_small_page (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (active_data); i++) {
		active_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, 32);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x40000 + 32,
		0x10000 + 32, active_data + 32, sizeof (active_data) - 32, 32);
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x40000,
		0x10000, active_data, 32, 32);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_no_recovery (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.recovery_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_RECOVERY_IMAGE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_recovery_good (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_RESTORE_NOT_NEEDED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_with_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);
	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40100, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40100, 0x10100,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_finalize_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_finalize_image_with_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);
	firmware_update_set_image_offset (&updater.test_mock.base, 0x100);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40100, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40100, 0x10100,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_followed_by_update (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image will not be updated since it was previously restored to a good state. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		 &updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_followed_by_update_same_revision (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 1, 1);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image will not be updated since it was previously restored to a good state. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		 &updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_followed_by_update_different_revision (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 1);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image will not be updated since it was previously restored to a good state. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		 &updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_followed_by_update_null_header (
	CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t recovery_data[] = {0x21, 0x22, 0x23};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) NULL);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate (test, &updater);

	/* The recovery image will be updated since the recovery revision could not be determined. */

	status = mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_VERIFYING_IMAGE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_firmware_header, &updater.fw,
		(intptr_t) &updater.header);
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_SAVING_STATE));
	status |= mock_expect (&updater.app.mock, updater.app.base.save, &updater.app, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_ACTIVE));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATING_IMAGE));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_REVOCATION));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_key_manifest, &updater.fw,
		(intptr_t) &updater.manifest);
	status |= mock_expect (&updater.manifest.mock, updater.manifest.base.revokes_old_manifest,
		 &updater.manifest, 0);

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_CHECK_RECOVERY));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_BACKUP_RECOVERY));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (recovery_data));
	status |= flash_mock_expect_erase_copy_verify (&updater.flash, &updater.flash, 0x50000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&updater.handler.mock, updater.handler.base.status_change,
		&updater.handler, 0, MOCK_ARG (UPDATE_STATUS_UPDATE_RECOVERY));
	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x30000,
		staging_data, sizeof (staging_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_run_update (&updater.test, &updater.handler.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_null (CuTest *test)
{
	int status;

	TEST_START;

	status = firmware_update_restore_recovery_image (NULL);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);
}

static void firmware_update_test_restore_recovery_image_fail_load (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_LOAD_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_invalid_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_img_size_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		FIRMWARE_IMAGE_GET_SIZE_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_GET_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_page_size_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 4);

	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_page_size, &updater.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_erase_failure (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 4);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_write_active_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 4);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, 4);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_recovery_image_finalize_image_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_recovery_image (&updater.test_mock.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x40000,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_header_last (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (active_data); i++) {
		active_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash,
		0x10000 + FLASH_PAGE_SIZE, 0x40000 + FLASH_PAGE_SIZE, active_data + FLASH_PAGE_SIZE,
		sizeof (active_data) - FLASH_PAGE_SIZE);
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x40000,
		active_data, FLASH_PAGE_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_header_last_small_page (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[RSA_ENCRYPT_LEN * 4];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (active_data); i++) {
		active_data[i] = RSA_PRIVKEY_DER[i % RSA_PRIVKEY_DER_LEN];
	}

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, 32);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x10000 + 32,
		0x40000 + 32, active_data + 32, sizeof (active_data) - 32, 32);
	status |= flash_mock_expect_copy_flash_verify_ext (&updater.flash, &updater.flash, 0x10000,
		0x40000, active_data, 32, 32);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_no_recovery (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init_dependencies (test, &updater, 0);
	updater.map.recovery_flash = NULL;
	firmware_update_testing_init_updater (test, &updater, 0, 0);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_RECOVERY_IMAGE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_with_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);
	firmware_update_set_image_offset (&updater.test, 0x100);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10100, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10100, 0x40100,
		active_data, sizeof (active_data));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_finalize_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x40000,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_finalize_image_with_offset (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);
	firmware_update_set_image_offset (&updater.test_mock.base, 0x100);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40100));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10100, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10100, 0x40100,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, 0, MOCK_ARG (&updater.flash), MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test_mock.base);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_null (CuTest *test)
{
	int status;

	TEST_START;

	status = firmware_update_restore_active_image (NULL);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);
}

static void firmware_update_test_restore_active_image_fail_load (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_LOAD_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_invalid_image (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_img_size_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		FIRMWARE_IMAGE_GET_SIZE_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, FIRMWARE_IMAGE_GET_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_page_size_fail (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 4);

	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_page_size, &updater.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_erase_failure (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 4);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_write_active_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw, 4);

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, 4);
	status |= mock_expect (&updater.flash.mock, updater.flash.base.get_block_size, &updater.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_restore_active_image_finalize_image_error (CuTest *test)
{
	struct firmware_update_testing updater;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	firmware_update_testing_init_mock (test, &updater, 0, 0, 0);

	firmware_update_mock_enable_finalize_image (&updater.test_mock);

	firmware_update_set_recovery_good (&updater.test_mock.base, false);

	status = mock_expect (&updater.fw.mock, updater.fw.base.load, &updater.fw, 0,
		MOCK_ARG (&updater.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.verify, &updater.fw, 0,
		MOCK_ARG (&updater.hash), MOCK_ARG (&updater.rsa));
	status |= mock_expect (&updater.fw.mock, updater.fw.base.get_image_size, &updater.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&updater.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&updater.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&updater.flash, &updater.flash, 0x10000, 0x40000,
		active_data, sizeof (active_data));
	status |= mock_expect (&updater.test_mock.mock, firmware_update_mock_finalize_image,
		&updater.test_mock, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, MOCK_ARG (&updater.flash),
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = firmware_update_restore_active_image (&updater.test_mock.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_FINALIZE_IMG_FAILED, status);

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_is_recovery_good (CuTest *test)
{
	struct firmware_update_testing updater;

	TEST_START;

	firmware_update_testing_init (test, &updater, 0, 0, 0);

	firmware_update_set_recovery_good (&updater.test, false);
	CuAssertIntEquals (test, 0, firmware_update_is_recovery_good (&updater.test));

	firmware_update_set_recovery_good (&updater.test, true);
	CuAssertIntEquals (test, 1, firmware_update_is_recovery_good (&updater.test));

	firmware_update_testing_validate_and_release (test, &updater);
}

static void firmware_update_test_is_recovery_good_null (CuTest *test)
{
	TEST_START;

	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT,
		firmware_update_is_recovery_good (NULL));
}


TEST_SUITE_START (firmware_update);

TEST (firmware_update_test_init);
TEST (firmware_update_test_init_null);
TEST (firmware_update_test_init_no_recovery);
TEST (firmware_update_test_init_no_recovery_backup);
TEST (firmware_update_test_init_no_backup);
TEST (firmware_update_test_init_no_recovery_no_backup);
TEST (firmware_update_test_init_no_active_or_staging);
TEST (firmware_update_test_release_null);
TEST (firmware_update_test_release_no_init);
TEST (firmware_update_test_set_recovery_good_null);
TEST (firmware_update_test_set_recovery_revision_null);
TEST (firmware_update_test_set_image_offset_null);
TEST (firmware_update_test_add_observer_null);
TEST (firmware_update_test_remove_observer_null);
TEST (firmware_update_test_run_update);
TEST (firmware_update_test_run_update_header_last);
TEST (firmware_update_test_run_update_header_last_small_page);
TEST (firmware_update_test_run_update_no_notifications);
TEST (firmware_update_test_run_update_callback_null);
TEST (firmware_update_test_run_update_image_offset);
TEST (firmware_update_test_run_update_finalize_image);
TEST (firmware_update_test_run_update_finalize_image_with_offset);
TEST (firmware_update_test_run_update_with_observer);
TEST (firmware_update_test_run_update_observer_removed);
TEST (firmware_update_test_run_update_extra_data_received);
TEST (firmware_update_test_run_update_null);
TEST (firmware_update_test_run_update_verify_incomplete_image);
TEST (firmware_update_test_run_update_verify_fail_load);
TEST (firmware_update_test_run_update_verify_invalid_image);
TEST (firmware_update_test_run_update_verify_manifest_revoked);
TEST (firmware_update_test_run_update_verify_error);
TEST (firmware_update_test_run_update_verify_rollback_disallowed);
TEST (firmware_update_test_run_update_verify_null_firmware_header);
TEST (firmware_update_test_run_update_verify_img_size_error);
TEST (firmware_update_test_run_update_blocked_by_observer);
TEST (firmware_update_test_run_update_context_error);
TEST (firmware_update_test_run_update_backup_fail_load);
TEST (firmware_update_test_run_update_backup_img_size_error);
TEST (firmware_update_test_run_update_backup_error);
TEST (firmware_update_test_run_update_page_size_fail);
TEST (firmware_update_test_run_update_erase_failure);
TEST (firmware_update_test_run_update_write_staging_error);
TEST (firmware_update_test_run_update_write_staging_error_header_last);
TEST (firmware_update_test_run_update_write_staging_error_header_last_small_page);
TEST (firmware_update_test_run_update_write_staging_error_fail_recovery_erase);
TEST (firmware_update_test_run_update_write_staging_error_fail_recovery);
TEST (firmware_update_test_run_update_write_staging_error_image_offset);
TEST (firmware_update_test_run_update_header_last_image_fail);
TEST (firmware_update_test_run_update_header_last_header_fail);
TEST (firmware_update_test_run_update_finalize_image_error);
TEST (firmware_update_test_run_update_finalize_image_error_with_offset);
TEST (firmware_update_test_run_update_finalize_image_error_fail_recovery_erase);
TEST (firmware_update_test_run_update_finalize_image_error_fail_recovery);
TEST (firmware_update_test_run_update_finalize_image_error_fail_recovery_finalize);
TEST (firmware_update_test_run_update_cert_check_load_fail);
TEST (firmware_update_test_run_update_cert_check_manifest_fail);
TEST (firmware_update_test_run_update_cert_check_fail);
TEST (firmware_update_test_run_update_cert_revocation);
TEST (firmware_update_test_run_update_cert_revocation_header_last);
TEST (firmware_update_test_run_update_cert_revocation_header_last_small_page);
TEST (firmware_update_test_run_update_cert_revocation_image_offset);
TEST (firmware_update_test_run_update_cert_revocation_finalize_image);
TEST (firmware_update_test_run_update_cert_revocation_finalize_image_with_offset);
TEST (firmware_update_test_run_update_cert_backup_load_fail);
TEST (firmware_update_test_run_update_cert_backup_img_size_error);
TEST (firmware_update_test_run_update_cert_backup_recovery_fail);
TEST (firmware_update_test_run_update_recovery_page_size_fail);
TEST (firmware_update_test_run_update_recovery_erase_fail);
TEST (firmware_update_test_run_update_recovery_fail);
TEST (firmware_update_test_run_update_recovery_fail_header_last);
TEST (firmware_update_test_run_update_recovery_fail_header_last_small_page);
TEST (firmware_update_test_run_update_recovery_fail_finalize);
TEST (firmware_update_test_run_update_recovery_restore_erase_fail);
TEST (firmware_update_test_run_update_recovery_restore_fail);
TEST (firmware_update_test_run_update_recovery_restore_fail_finalize);
TEST (firmware_update_test_run_update_cert_revocation_fail);
TEST (firmware_update_test_run_update_no_recovery_backup);
TEST (firmware_update_test_run_update_no_recovery_backup_fail);
TEST (firmware_update_test_run_update_recovery_restore_no_recovery_backup);
TEST (firmware_update_test_run_update_recovery_restore_no_recovery_backup_header_last);
TEST (firmware_update_test_run_update_recovery_restore_no_recovery_backup_erase_fail);
TEST (firmware_update_test_run_update_recovery_restore_no_recovery_backup_fail);
TEST (firmware_update_test_run_update_cert_revocation_no_recovery);
TEST (firmware_update_test_run_update_different_flash_devices);
TEST (firmware_update_test_run_update_different_flash_devices_finalize_image);
TEST (firmware_update_test_run_update_no_backup);
TEST (firmware_update_test_run_update_no_backup_write_staging_error);
TEST (firmware_update_test_run_update_no_backup_finalize_image_error);
TEST (firmware_update_test_run_update_no_backup_cert_revocation);
TEST (firmware_update_test_run_update_no_backup_recovery_erase_fail);
TEST (firmware_update_test_run_update_no_backup_recovery_fail);
TEST (firmware_update_test_run_update_no_backup_recovery_finalize_fail);
TEST (firmware_update_test_run_update_recovery_bad);
TEST (firmware_update_test_run_update_recovery_bad_finalize_image);
TEST (firmware_update_test_run_update_recovery_bad_page_size_fail);
TEST (firmware_update_test_run_update_recovery_bad_erase_fail);
TEST (firmware_update_test_run_update_recovery_bad_update_fail);
TEST (firmware_update_test_run_update_recovery_bad_finalize_fail);
TEST (firmware_update_test_run_update_recovery_bad_no_recovery);
TEST (firmware_update_test_run_update_recovery_bad_cert_revocation);
TEST (firmware_update_test_run_update_after_recovery_page_size_fail);
TEST (firmware_update_test_run_update_after_recovery_erase_fail);
TEST (firmware_update_test_run_update_after_recovery_fail);
TEST (firmware_update_test_run_update_after_recovery_finalize_fail);
TEST (firmware_update_test_run_update_after_recovery_restore_erase_fail);
TEST (firmware_update_test_run_update_after_recovery_restore_fail);
TEST (firmware_update_test_run_update_after_recovery_restore_finalize_fail);
TEST (firmware_update_test_run_update_no_recovery_backup_after_recovery_restore_erase_fail);
TEST (firmware_update_test_run_update_no_recovery_backup_after_recovery_restore_fail);
TEST (firmware_update_test_run_update_after_recovery_backup_load_fail);
TEST (firmware_update_test_run_update_after_recovery_backup_img_size_error);
TEST (firmware_update_test_run_update_after_recovery_backup_fail);
TEST (firmware_update_test_run_update_no_recovery_backup_after_recovery_backup_fail);
TEST (firmware_update_test_run_update_no_backup_after_recovery_erase_fail);
TEST (firmware_update_test_run_update_no_backup_after_recovery_fail);
TEST (firmware_update_test_run_update_no_backup_after_recovery_finalize_fail);
TEST (firmware_update_test_run_update_after_recovery_bad);
TEST (firmware_update_test_run_update_after_recovery_bad_page_size_fail);
TEST (firmware_update_test_run_update_after_recovery_bad_erase_fail);
TEST (firmware_update_test_run_update_after_recovery_bad_update_fail);
TEST (firmware_update_test_run_update_after_recovery_bad_finalize_fail);
TEST (firmware_update_test_run_update_new_recovery_revision_higher);
TEST (firmware_update_test_run_update_new_recovery_revision_lower);
TEST (firmware_update_test_run_update_same_revision_after_recovery_update);
TEST (firmware_update_test_run_update_same_revision_after_cert_revocation);
TEST (firmware_update_test_run_update_recovery_bad_different_revision);
TEST (firmware_update_test_run_update_same_revision_after_recovery_bad);
TEST (firmware_update_test_prepare_staging);
TEST (firmware_update_test_prepare_staging_image_offset);
TEST (firmware_update_test_prepare_staging_null_updater);
TEST (firmware_update_test_prepare_staging_null_callback);
TEST (firmware_update_test_prepare_staging_image_too_large);
TEST (firmware_update_test_prepare_staging_image_too_large_image_offset);
TEST (firmware_update_test_prepare_staging_erase_error);
TEST (firmware_update_test_write_to_staging);
TEST (firmware_update_test_write_to_staging_multiple_calls);
TEST (firmware_update_test_write_to_staging_image_offset);
TEST (firmware_update_test_write_to_staging_null_updater);
TEST (firmware_update_test_write_to_staging_null_callback);
TEST (firmware_update_test_write_to_staging_write_fail);
TEST (firmware_update_test_write_to_staging_image_too_large);
TEST (firmware_update_test_write_to_staging_image_too_large_image_offset);
TEST (firmware_update_test_write_to_staging_partial_write);
TEST (firmware_update_test_multiple_prepare_and_write_cycles);
TEST (firmware_update_test_multiple_prepare_and_write_cycles_image_offset);
TEST (firmware_update_test_validate_recovery_image);
TEST (firmware_update_test_validate_recovery_image_offset);
TEST (firmware_update_test_validate_recovery_image_extra_verify);
TEST (firmware_update_test_validate_recovery_image_extra_verify_offset);
TEST (firmware_update_test_validate_recovery_image_no_recovery);
TEST (firmware_update_test_validate_recovery_image_set_recovery_revision);
TEST (firmware_update_test_validate_recovery_image_bad);
TEST (firmware_update_test_validate_recovery_image_bad_extra_verify);
TEST (firmware_update_test_validate_recovery_image_load_verify_bad_format);
TEST (firmware_update_test_validate_recovery_image_load_verify_bad_checksum);
TEST (firmware_update_test_validate_recovery_image_load_verify_manifest_format);
TEST (firmware_update_test_validate_recovery_image_load_verify_fw_header_min_size);
TEST (firmware_update_test_validate_recovery_image_load_verify_fw_header_too_long);
TEST (firmware_update_test_validate_recovery_image_load_verify_fw_header_bad_marker);
TEST (firmware_update_test_validate_recovery_image_load_verify_fw_header_bad_fmt_length);
TEST (firmware_update_test_validate_recovery_image_offset_null);
TEST (firmware_update_test_validate_recovery_image_load_failure);
TEST (firmware_update_test_validate_recovery_image_verify_failure);
TEST (firmware_update_test_validate_recovery_image_extra_verify_failure);
TEST (firmware_update_test_validate_recovery_image_load_verify_fw_header_no_memory);
TEST (firmware_update_test_validate_recovery_null_firmware_header);
TEST (firmware_update_test_restore_recovery_image);
TEST (firmware_update_test_restore_recovery_image_header_last);
TEST (firmware_update_test_restore_recovery_image_header_last_small_page);
TEST (firmware_update_test_restore_recovery_image_no_recovery);
TEST (firmware_update_test_restore_recovery_image_recovery_good);
TEST (firmware_update_test_restore_recovery_image_with_offset);
TEST (firmware_update_test_restore_recovery_image_finalize_image);
TEST (firmware_update_test_restore_recovery_image_finalize_image_with_offset);
TEST (firmware_update_test_restore_recovery_image_followed_by_update);
TEST (firmware_update_test_restore_recovery_image_followed_by_update_same_revision);
TEST (firmware_update_test_restore_recovery_image_followed_by_update_different_revision);
TEST (firmware_update_test_restore_recovery_image_followed_by_update_null_header);
TEST (firmware_update_test_restore_recovery_image_null);
TEST (firmware_update_test_restore_recovery_image_fail_load);
TEST (firmware_update_test_restore_recovery_image_invalid_image);
TEST (firmware_update_test_restore_recovery_image_img_size_error);
TEST (firmware_update_test_restore_recovery_image_page_size_fail);
TEST (firmware_update_test_restore_recovery_image_erase_failure);
TEST (firmware_update_test_restore_recovery_image_write_active_error);
TEST (firmware_update_test_restore_recovery_image_finalize_image_error);
TEST (firmware_update_test_restore_active_image);
TEST (firmware_update_test_restore_active_image_header_last);
TEST (firmware_update_test_restore_active_image_header_last_small_page);
TEST (firmware_update_test_restore_active_image_no_recovery);
TEST (firmware_update_test_restore_active_image_with_offset);
TEST (firmware_update_test_restore_active_image_finalize_image);
TEST (firmware_update_test_restore_active_image_finalize_image_with_offset);
TEST (firmware_update_test_restore_active_image_null);
TEST (firmware_update_test_restore_active_image_fail_load);
TEST (firmware_update_test_restore_active_image_invalid_image);
TEST (firmware_update_test_restore_active_image_img_size_error);
TEST (firmware_update_test_restore_active_image_page_size_fail);
TEST (firmware_update_test_restore_active_image_erase_failure);
TEST (firmware_update_test_restore_active_image_write_active_error);
TEST (firmware_update_test_restore_active_image_finalize_image_error);
TEST (firmware_update_test_is_recovery_good);
TEST (firmware_update_test_is_recovery_good_null);

TEST_SUITE_END;
