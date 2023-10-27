// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/firmware_logging.h"
#include "firmware/firmware_update_handler_revoke_after_reset.h"
#include "firmware/firmware_update_handler_revoke_after_reset_static.h"
#include "flash/flash_common.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/firmware/firmware_image_mock.h"
#include "testing/mock/firmware/app_context_mock.h"
#include "testing/mock/firmware/key_manifest_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/event_task_mock.h"
#include "testing/mock/system/security_manager_mock.h"
#include "testing/mock/system/security_policy_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/firmware/firmware_update_testing.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("firmware_update_handler_revoke_after_reset");


/**
 * Dependencies for testing.
 */
struct firmware_update_handler_revoke_after_reset_testing {
	HASH_TESTING_ENGINE hash;									/**< Hash engine for API arguments. */
	struct firmware_image_mock fw;								/**< Mock for the FW image updater.handler. */
	struct app_context_mock app;								/**< Mock for the application context. */
	struct key_manifest_mock manifest;							/**< Mock for the key updater.manifest. */
	struct security_manager_mock security;						/**< Mock for the device security manager. */
	struct security_policy_mock policy;							/**< Mock for the device security policy. */
	struct security_policy *policy_ptr;						/**< Pointer to the security policy. */
	struct firmware_header header;								/**< Header on the firmware image. */
	struct flash_mock flash;									/**< Mock for the updater.flash device. */
	struct logging_mock log;									/**< Mock for debug logging. */
	struct firmware_flash_map map;								/**< Map of firmware images on updater.flash. */
	struct firmware_update_state update_state;					/**< Context for the firmware updater. */
	struct firmware_update updater;								/**< Firmware updater for testing. */
	struct event_task_mock task;								/**< Mock for the updater task. */
	struct event_task_context context;							/**< Event context for event processing. */
	struct event_task_context *context_ptr;						/**< Pointer to the event context. */
	struct firmware_update_handler_state state;					/**< Context for the update handler. */
	struct firmware_update_handler_revoke_after_reset test;		/**< Update handler under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param header The updater header firmware ID.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 */
static void firmware_update_handler_revoke_after_reset_testing_init_dependencies (CuTest *test,
	struct firmware_update_handler_revoke_after_reset_testing *handler, int header, int allowed,
	int recovery)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&handler->hash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_image_mock_init (&handler->fw);
	CuAssertIntEquals (test, 0, status);

	status = app_context_mock_init (&handler->app);
	CuAssertIntEquals (test, 0, status);

	status = key_manifest_mock_init (&handler->manifest);
	CuAssertIntEquals (test, 0, status);

	status = security_manager_mock_init (&handler->security);
	CuAssertIntEquals (test, 0, status);

	status = security_policy_mock_init (&handler->policy);
	CuAssertIntEquals (test, 0, status);

	handler->policy_ptr = &handler->policy.base;

	status = flash_mock_init (&handler->flash);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	status = event_task_mock_init (&handler->task);
	CuAssertIntEquals (test, 0, status);

	firmware_update_testing_init_firmware_header (test, &handler->header, &handler->flash, header);

	handler->map.active_addr = 0x10000;
	handler->map.active_size = 0x10000;
	handler->map.backup_addr = 0x20000;
	handler->map.backup_size = 0x10000;
	handler->map.staging_addr = 0x30000;
	handler->map.staging_size = 0x10000;
	handler->map.recovery_addr = 0x40000;
	handler->map.recovery_size = 0x10000;
	handler->map.rec_backup_addr = 0x50000;
	handler->map.rec_backup_size = 0x10000;

	handler->map.active_flash = &handler->flash.base;
	handler->map.backup_flash = &handler->flash.base;
	handler->map.staging_flash = &handler->flash.base;
	handler->map.recovery_flash = &handler->flash.base;
	handler->map.rec_backup_flash = &handler->flash.base;

	memset (&handler->context, 0, sizeof (handler->context));
	handler->context_ptr = &handler->context;

	debug_log = &handler->log.base;

	status = firmware_update_init (&handler->updater, &handler->update_state, &handler->map,
		&handler->app.base, &handler->fw.base, &handler->security.base, &handler->hash.base,
		allowed);
	CuAssertIntEquals (test, 0, status);

	if (recovery >= 0) {
		firmware_update_set_recovery_revision (&handler->updater, recovery);
	}
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param header The updater header firmware ID.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 * @param recovery_boot Indicate a boot from recovery flash.
 */
static void firmware_update_handler_revoke_after_reset_testing_init (CuTest *test,
	struct firmware_update_handler_revoke_after_reset_testing *handler, int header, int allowed,
	int recovery, bool recovery_boot)
{
	int status;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, handler, header,
		allowed, recovery);

	status = firmware_update_handler_revoke_after_reset_init (&handler->test, &handler->state,
		&handler->updater, &handler->task.base, recovery_boot);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing that will update the recovery image during initialization.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param header The updater header firmware ID.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 * @param recovery_boot Indicate a boot from recovery flash.
 */
static void firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (
	CuTest *test, struct firmware_update_handler_revoke_after_reset_testing *handler, int header,
	int allowed, int recovery, bool recovery_boot)
{
	int status;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, handler, header,
		allowed, recovery);

	status = firmware_update_handler_revoke_after_reset_init_keep_recovery_updated (&handler->test,
		&handler->state, &handler->updater, &handler->task.base, recovery_boot);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param header The updater header firmware ID.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 * @param recovery_boot Indicate a boot from recovery flash.
 */
static void firmware_update_handler_revoke_after_reset_testing_init_static (CuTest *test,
	struct firmware_update_handler_revoke_after_reset_testing *handler,
	struct firmware_update_handler_revoke_after_reset *test_static, int header, int allowed,
	int recovery, bool recovery_boot)
{
	int status;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, handler, header,
		allowed, recovery);

	status = firmware_update_handler_init_state (&test_static->base, recovery_boot);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void firmware_update_handler_revoke_after_reset_testing_release_dependencies (CuTest *test,
	struct firmware_update_handler_revoke_after_reset_testing *handler)
{
	int status;

	debug_log = NULL;

	status = flash_mock_validate_and_release (&handler->flash);
	status |= firmware_image_mock_validate_and_release (&handler->fw);
	status |= app_context_mock_validate_and_release (&handler->app);
	status |= security_policy_mock_validate_and_release (&handler->policy);
	status |= security_manager_mock_validate_and_release (&handler->security);
	status |= key_manifest_mock_validate_and_release (&handler->manifest);
	status |= logging_mock_validate_and_release (&handler->log);
	status |= event_task_mock_validate_and_release (&handler->task);

	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&handler->header);
	HASH_TESTING_ENGINE_RELEASE (&handler->hash);
	firmware_update_release (&handler->updater);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void firmware_update_handler_revoke_after_reset_testing_validate_and_release (CuTest *test,
	struct firmware_update_handler_revoke_after_reset_testing *handler)
{
	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, handler);
	firmware_update_handler_revoke_after_reset_release (&handler->test);
}

/*******************
 * Test cases
 *******************/

static void firmware_update_handler_revoke_after_reset_test_init (CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = firmware_update_handler_revoke_after_reset_init (&handler.test, &handler.state,
		&handler.updater, &handler.task.base, false);
	CuAssertIntEquals (test, 0, status);

	/* Assert that the control interface is exactly the same as the base type.  No need to test this
	 * interface for the derived type. */
	CuAssertPtrEquals (test, firmware_update_handler_start_update,
		handler.test.base.base_ctrl.start_update);
	CuAssertPtrEquals (test, firmware_update_handler_get_status,
		handler.test.base.base_ctrl.get_status);
	CuAssertPtrEquals (test, firmware_update_handler_get_remaining_len,
		handler.test.base.base_ctrl.get_remaining_len);
	CuAssertPtrEquals (test, firmware_update_handler_prepare_staging,
		handler.test.base.base_ctrl.prepare_staging);
	CuAssertPtrEquals (test, firmware_update_handler_write_staging,
		handler.test.base.base_ctrl.write_staging);

	CuAssertPtrNotNull (test, handler.test.base.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base.base_event.execute);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_init_null (CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = firmware_update_handler_revoke_after_reset_init (NULL, &handler.state,
		&handler.updater, &handler.task.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_handler_revoke_after_reset_init (&handler.test, NULL,
		&handler.updater, &handler.task.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_handler_revoke_after_reset_init (&handler.test, &handler.state,
		NULL, &handler.task.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_handler_revoke_after_reset_init (&handler.test, &handler.state,
		&handler.updater, NULL, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_init_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = firmware_update_handler_revoke_after_reset_init_keep_recovery_updated (&handler.test,
		&handler.state, &handler.updater, &handler.task.base, false);
	CuAssertIntEquals (test, 0, status);

	/* Assert that the control interface is exactly the same as the base type.  No need to test this
	 * interface for the derived type. */
	CuAssertPtrEquals (test, firmware_update_handler_start_update,
		handler.test.base.base_ctrl.start_update);
	CuAssertPtrEquals (test, firmware_update_handler_get_status,
		handler.test.base.base_ctrl.get_status);
	CuAssertPtrEquals (test, firmware_update_handler_get_remaining_len,
		handler.test.base.base_ctrl.get_remaining_len);
	CuAssertPtrEquals (test, firmware_update_handler_prepare_staging,
		handler.test.base.base_ctrl.prepare_staging);
	CuAssertPtrEquals (test, firmware_update_handler_write_staging,
		handler.test.base.base_ctrl.write_staging);

	CuAssertPtrNotNull (test, handler.test.base.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base.base_event.execute);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_init_keep_recovery_updated_null (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = firmware_update_handler_revoke_after_reset_init_keep_recovery_updated (NULL,
		&handler.state, &handler.updater, &handler.task.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_handler_revoke_after_reset_init_keep_recovery_updated (&handler.test,
		NULL, &handler.updater, &handler.task.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_handler_revoke_after_reset_init_keep_recovery_updated (&handler.test,
		&handler.state, NULL, &handler.task.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = firmware_update_handler_revoke_after_reset_init_keep_recovery_updated (&handler.test,
		&handler.state, &handler.updater, NULL, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_static_init (CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, &handler, 0, 0, 0);

	/* Assert that the control interface is exactly the same as the base type.  No need to test this
	 * interface for the derived type. */
	CuAssertPtrEquals (test, firmware_update_handler_start_update,
		test_static.base.base_ctrl.start_update);
	CuAssertPtrEquals (test, firmware_update_handler_get_status,
		test_static.base.base_ctrl.get_status);
	CuAssertPtrEquals (test, firmware_update_handler_get_remaining_len,
		test_static.base.base_ctrl.get_remaining_len);
	CuAssertPtrEquals (test, firmware_update_handler_prepare_staging,
		test_static.base.base_ctrl.prepare_staging);
	CuAssertPtrEquals (test, firmware_update_handler_write_staging,
		test_static.base.base_ctrl.write_staging);

	CuAssertPtrNotNull (test, test_static.base.base_event.prepare);
	CuAssertPtrNotNull (test, test_static.base.base_event.execute);

	status = firmware_update_handler_init_state (&test_static.base, false);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_static_init_null (CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = firmware_update_handler_init_state (NULL, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	test_static.base.state = NULL;
	status = firmware_update_handler_init_state (&test_static.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	test_static.base.state = &handler.state;
	test_static.base.updater = NULL;
	status = firmware_update_handler_init_state (&test_static.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	test_static.base.updater = &handler.updater;
	test_static.base.task = NULL;
	status = firmware_update_handler_init_state (&test_static.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_static_init_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, &handler, 0, 0, 0);

	/* Assert that the control interface is exactly the same as the base type.  No need to test this
	 * interface for the derived type. */
	CuAssertPtrEquals (test, firmware_update_handler_start_update,
		test_static.base.base_ctrl.start_update);
	CuAssertPtrEquals (test, firmware_update_handler_get_status,
		test_static.base.base_ctrl.get_status);
	CuAssertPtrEquals (test, firmware_update_handler_get_remaining_len,
		test_static.base.base_ctrl.get_remaining_len);
	CuAssertPtrEquals (test, firmware_update_handler_prepare_staging,
		test_static.base.base_ctrl.prepare_staging);
	CuAssertPtrEquals (test, firmware_update_handler_write_staging,
		test_static.base.base_ctrl.write_staging);

	CuAssertPtrNotNull (test, test_static.base.base_event.prepare);
	CuAssertPtrNotNull (test, test_static.base.base_event.execute);

	status = firmware_update_handler_init_state (&test_static.base, false);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_static_init_keep_recovery_updated_null (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = firmware_update_handler_init_state (NULL, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	test_static.base.state = NULL;
	status = firmware_update_handler_init_state (&test_static.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	test_static.base.state = &handler.state;
	test_static.base.updater = NULL;
	status = firmware_update_handler_init_state (&test_static.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	test_static.base.updater = &handler.updater;
	test_static.base.task = NULL;
	status = firmware_update_handler_init_state (&test_static.base, false);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_release_null (CuTest *test)
{
	TEST_START;

	firmware_update_handler_revoke_after_reset_release (NULL);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_with_good_recovery_image (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_IMAGE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, true);

	status = mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw, 5);
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_with_bad_recovery_image (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_UPDATE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, false);

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: UPDATE_STATUS_UPDATE_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_with_bad_recovery_image_marked_as_good (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry_fail = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_IMAGE,
		.arg1 = 1,
		.arg2 = FIRMWARE_IMAGE_BAD_SIGNATURE
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_UPDATE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, true);

	status = mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw,
		FIRMWARE_IMAGE_BAD_SIGNATURE, MOCK_ARG_PTR (&handler.hash));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_fail, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_fail)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: UPDATE_STATUS_UPDATE_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_after_recovery_boot (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, true);

	firmware_update_set_recovery_good (&handler.updater, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x40000,
		active_data, sizeof (active_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);
	CuAssertIntEquals (test, 1, firmware_update_is_recovery_good (&handler.updater));

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_after_recovery_boot_restore_failure (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE,
		.arg1 = FIRMWARE_IMAGE_LOAD_FAILED,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, true);

	firmware_update_set_recovery_good (&handler.updater, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);
	CuAssertIntEquals (test, 1, firmware_update_is_recovery_good (&handler.updater));

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_revocation_fail (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_IMAGE,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_fail = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_REVOCATION_FAIL,
		.arg1 = UPDATE_STATUS_VERIFY_FAILURE,
		.arg2 = FIRMWARE_IMAGE_LOAD_FAILED
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, true);

	status = mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));

	/* Lock for state update: UPDATE_STATUS_VERIFY_FAILURE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_fail, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_fail)));

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_keep_recovery_updated_with_good_recovery_image (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t recovery_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_IMAGE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (test, &handler,
		0, 0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, true);

	status = mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (recovery_data));

	status |= flash_mock_expect_verify_copy (&handler.flash, 0x10000, active_data, &handler.flash,
		0x40000, recovery_data, sizeof (active_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw, 5);
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_keep_recovery_updated_with_bad_recovery_image (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_UPDATE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (test, &handler,
		0, 0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, false);

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: UPDATE_STATUS_UPDATE_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_keep_recovery_updated_with_bad_recovery_image_marked_as_good (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry_fail = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_IMAGE,
		.arg1 = 1,
		.arg2 = FIRMWARE_IMAGE_LOAD_FAILED
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_UPDATE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (test, &handler,
		0, 0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, true);

	status = mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_fail, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_fail)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: UPDATE_STATUS_UPDATE_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_keep_recovery_updated_after_recovery_boot (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (test, &handler,
		0, 0, 0, true);

	firmware_update_set_recovery_good (&handler.updater, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x40000,
		active_data, sizeof (active_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.base_event.prepare (&handler.test.base.base_event);
	CuAssertIntEquals (test, 1, firmware_update_is_recovery_good (&handler.updater));

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_static_init_with_good_recovery_image (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_IMAGE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, true);

	status = mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw, 5);
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	test_static.base.base_event.prepare (&test_static.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_static_init_with_bad_recovery_image (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_UPDATE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, false);

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: UPDATE_STATUS_UPDATE_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	test_static.base.base_event.prepare (&test_static.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_static_init_after_recovery_boot (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, true);

	firmware_update_set_recovery_good (&handler.updater, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x40000,
		active_data, sizeof (active_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	CuAssertIntEquals (test, 0, status);

	test_static.base.base_event.prepare (&test_static.base.base_event);
	CuAssertIntEquals (test, 1, firmware_update_is_recovery_good (&handler.updater));

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_static_init_keep_recovery_updated_with_good_recovery_image (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t recovery_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_IMAGE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, true);

	status = mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (recovery_data));

	status |= flash_mock_expect_verify_copy (&handler.flash, 0x10000, active_data, &handler.flash,
		0x40000, recovery_data, sizeof (active_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw, 5);
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	test_static.base.base_event.prepare (&test_static.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_static_init_keep_recovery_updated_with_bad_recovery_image (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_UPDATE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	firmware_update_set_recovery_good (&handler.updater, false);

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: UPDATE_STATUS_UPDATE_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x40000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x40000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_NONE_STARTED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	test_static.base.base_event.prepare (&test_static.base.base_event);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_prepare_static_init_keep_recovery_updated_after_recovery_boot (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, true);

	firmware_update_set_recovery_good (&handler.updater, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000, sizeof (active_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x40000,
		active_data, sizeof (active_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	CuAssertIntEquals (test, 0, status);

	test_static.base.base_event.prepare (&test_static.base.base_event);
	CuAssertIntEquals (test, 1, firmware_update_is_recovery_good (&handler.updater));

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_execute_run_update (CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_COMPLETE,
		.arg1 = 0,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (staging_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	status |= mock_expect (&handler.security.mock,
		handler.security.base.internal.get_security_policy, &handler.security, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.security.mock, 0, &handler.policy_ptr,
		sizeof (handler.policy_ptr), -1);
	status |= mock_expect (&handler.policy.mock, handler.policy.base.enforce_anti_rollback,
		&handler.policy, 1);

	/* Lock for state update: UPDATE_STATUS_SAVING_STATE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.app.mock, handler.app.base.save, &handler.app, 0);

	/* Lock for state update: UPDATE_STATUS_BACKUP_ACTIVE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&handler.flash, &handler.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_UPDATING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 1, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_run_update_failure (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_FAIL,
		.arg1 = UPDATE_STATUS_INVALID_IMAGE,
		.arg2 = FIRMWARE_IMAGE_BAD_SIGNATURE
	};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw,
		FIRMWARE_IMAGE_BAD_SIGNATURE, MOCK_ARG_PTR (&handler.hash));

	/* Lock for state update: UPDATE_STATUS_INVALID_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: FIRMWARE_IMAGE_BAD_SIGNATURE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test,
		(((FIRMWARE_IMAGE_BAD_SIGNATURE & 0x00ffffff) << 8) | UPDATE_STATUS_INVALID_IMAGE),
		status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_run_update_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_COMPLETE,
		.arg1 = 0,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (test, &handler,
		0, 0, 0, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (staging_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	status |= mock_expect (&handler.security.mock,
		handler.security.base.internal.get_security_policy, &handler.security, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.security.mock, 0, &handler.policy_ptr,
		sizeof (handler.policy_ptr), -1);
	status |= mock_expect (&handler.policy.mock, handler.policy.base.enforce_anti_rollback,
		&handler.policy, 1);

	/* Lock for state update: UPDATE_STATUS_SAVING_STATE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.app.mock, handler.app.base.save, &handler.app, 0);

	/* Lock for state update: UPDATE_STATUS_BACKUP_ACTIVE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&handler.flash, &handler.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_UPDATING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 1, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_run_update_static_init (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_COMPLETE,
		.arg1 = 0,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (staging_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	status |= mock_expect (&handler.security.mock,
		handler.security.base.internal.get_security_policy, &handler.security, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.security.mock, 0, &handler.policy_ptr,
		sizeof (handler.policy_ptr), -1);
	status |= mock_expect (&handler.policy.mock, handler.policy.base.enforce_anti_rollback,
		&handler.policy, 1);

	/* Lock for state update: UPDATE_STATUS_SAVING_STATE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.app.mock, handler.app.base.save, &handler.app, 0);

	/* Lock for state update: UPDATE_STATUS_BACKUP_ACTIVE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&handler.flash, &handler.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_UPDATING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	test_static.base.base_event.execute (&test_static.base.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 1, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_execute_run_update_static_init_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_START,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_UPDATE_COMPLETE,
		.arg1 = 0,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: UPDATE_STATUS_VERIFYING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x30000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (staging_data));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_firmware_header, &handler.fw,
		MOCK_RETURN_PTR (&handler.header));

	status |= mock_expect (&handler.security.mock,
		handler.security.base.internal.get_security_policy, &handler.security, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.security.mock, 0, &handler.policy_ptr,
		sizeof (handler.policy_ptr), -1);
	status |= mock_expect (&handler.policy.mock, handler.policy.base.enforce_anti_rollback,
		&handler.policy, 1);

	/* Lock for state update: UPDATE_STATUS_SAVING_STATE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.app.mock, handler.app.base.save, &handler.app, 0);

	/* Lock for state update: UPDATE_STATUS_BACKUP_ACTIVE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));
	status |= flash_mock_expect_erase_copy_verify (&handler.flash, &handler.flash, 0x20000, 0x10000,
		active_data, sizeof (active_data));

	/* Lock for state update: UPDATE_STATUS_UPDATING_IMAGE */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000, sizeof (staging_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x30000,
		staging_data, sizeof (staging_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	test_static.base.base_event.execute (&test_static.base.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 1, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_execute_prepare_staging (CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	size_t bytes = 100;
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_PREP */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x30000, bytes);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_prepare_staging_failure (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	size_t bytes = 100;
	bool reset = false;
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ERASE_FAIL,
		.arg1 = UPDATE_STATUS_STAGING_PREP_FAIL,
		.arg2 = FLASH_BLOCK_SIZE_FAILED
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_PREP */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.flash.mock, handler.flash.base.get_block_size, &handler.flash,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	/* Lock for state update: UPDATE_STATUS_STAGING_PREP_FAIL */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	/* Lock for state update: FLASH_BLOCK_SIZE_FAILED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test,
		(((FLASH_BLOCK_SIZE_FAILED & 0x00ffffff) << 8) | UPDATE_STATUS_STAGING_PREP_FAIL), status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_prepare_staging_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	size_t bytes = 100;
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (test, &handler,
		0, 0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_PREP */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x30000, bytes);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_prepare_staging_static_init (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;
	size_t bytes = 50;
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_PREP */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x30000, bytes);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	test_static.base.base_event.execute (&test_static.base.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_execute_prepare_staging_static_init_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;
	size_t bytes = 50;
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_PREP */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x30000, bytes);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	test_static.base.base_event.execute (&test_static.base.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_execute_write_staging (CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_WRITE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.flash.mock, handler.flash.base.write, &handler.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING;
	handler.context.buffer_length = sizeof (staging_data);
	memcpy (handler.context.event_buffer, staging_data, sizeof (staging_data));

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_write_staging_failure (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	bool reset = false;
	struct debug_log_entry_info entry_done = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_WRITE_FAIL,
		.arg1 = UPDATE_STATUS_STAGING_WRITE_FAIL,
		.arg2 = FLASH_WRITE_FAILED
	};

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_WRITE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.flash.mock, handler.flash.base.write, &handler.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	/* Lock for state update: UPDATE_STATUS_STAGING_WRITE_FAIL */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	/* Lock for state update: FLASH_WRITE_FAILED */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING;
	handler.context.buffer_length = sizeof (staging_data);
	memcpy (handler.context.event_buffer, staging_data, sizeof (staging_data));

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test,
		(((FLASH_WRITE_FAILED & 0x00ffffff) << 8) | UPDATE_STATUS_STAGING_WRITE_FAIL), status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_write_staging_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (test, &handler,
		0, 0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_WRITE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.flash.mock, handler.flash.base.write, &handler.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING;
	handler.context.buffer_length = sizeof (staging_data);
	memcpy (handler.context.event_buffer, staging_data, sizeof (staging_data));

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_write_staging_static_init (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_WRITE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.flash.mock, handler.flash.base.write, &handler.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING;
	handler.context.buffer_length = sizeof (staging_data);
	memcpy (handler.context.event_buffer, staging_data, sizeof (staging_data));

	test_static.base.base_event.execute (&test_static.base.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_execute_write_staging_static_init_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	/* Lock for state update: UPDATE_STATUS_STAGING_WRITE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.flash.mock, handler.flash.base.write, &handler.flash,
		sizeof (staging_data), MOCK_ARG (0x30000),
		MOCK_ARG_PTR_CONTAINS (staging_data, sizeof (staging_data)),
		MOCK_ARG (sizeof (staging_data)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING;
	handler.context.buffer_length = sizeof (staging_data);
	memcpy (handler.context.event_buffer, staging_data, sizeof (staging_data));

	test_static.base.base_event.execute (&test_static.base.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_execute_unknown_action (CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init (test, &handler, 0, 0, 0, false);

	handler.context.action = 8;

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_unknown_action_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_keep_recovery_updated (test, &handler,
		0, 0, 0, false);

	handler.context.action = 8;

	handler.test.base.base_event.execute (&handler.test.base.base_event, handler.context_ptr,
		&reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_ctrl.get_status (&handler.test.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_validate_and_release (test, &handler);
}

static void firmware_update_handler_revoke_after_reset_test_execute_unknown_action_static_init (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init (&handler.state, &handler.updater,
			&handler.task.base);
	int status;
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	handler.context.action = 8;

	test_static.base.base_event.execute (&test_static.base.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}

static void firmware_update_handler_revoke_after_reset_test_execute_unknown_action_static_init_keep_recovery_updated (
	CuTest *test)
{
	struct firmware_update_handler_revoke_after_reset_testing handler;
	struct firmware_update_handler_revoke_after_reset test_static =
		firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated (
			&handler.state, &handler.updater, &handler.task.base);
	int status;
	bool reset = false;

	TEST_START;

	firmware_update_handler_revoke_after_reset_testing_init_static (test, &handler, &test_static, 0,
		0, 0, false);

	handler.context.action = 8;

	test_static.base.base_event.execute (&test_static.base.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_ctrl.get_status (&test_static.base.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	firmware_update_handler_revoke_after_reset_testing_release_dependencies (test, &handler);
	firmware_update_handler_revoke_after_reset_release (&test_static);
}


TEST_SUITE_START (firmware_update_handler_revoke_after_reset);

TEST (firmware_update_handler_revoke_after_reset_test_init);
TEST (firmware_update_handler_revoke_after_reset_test_init_null);
TEST (firmware_update_handler_revoke_after_reset_test_init_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_init_keep_recovery_updated_null);
TEST (firmware_update_handler_revoke_after_reset_test_static_init);
TEST (firmware_update_handler_revoke_after_reset_test_static_init_null);
TEST (firmware_update_handler_revoke_after_reset_test_static_init_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_static_init_keep_recovery_updated_null);
TEST (firmware_update_handler_revoke_after_reset_test_release_null);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_with_good_recovery_image);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_with_bad_recovery_image);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_with_bad_recovery_image_marked_as_good);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_after_recovery_boot);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_after_recovery_boot_restore_failure);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_revocation_fail);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_keep_recovery_updated_with_good_recovery_image);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_keep_recovery_updated_with_bad_recovery_image);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_keep_recovery_updated_with_bad_recovery_image_marked_as_good);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_keep_recovery_updated_after_recovery_boot);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_static_init_with_good_recovery_image);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_static_init_with_bad_recovery_image);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_static_init_after_recovery_boot);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_static_init_keep_recovery_updated_with_good_recovery_image);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_static_init_keep_recovery_updated_with_bad_recovery_image);
TEST (firmware_update_handler_revoke_after_reset_test_prepare_static_init_keep_recovery_updated_after_recovery_boot);
TEST (firmware_update_handler_revoke_after_reset_test_execute_run_update);
TEST (firmware_update_handler_revoke_after_reset_test_execute_run_update_failure);
TEST (firmware_update_handler_revoke_after_reset_test_execute_run_update_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_execute_run_update_static_init);
TEST (firmware_update_handler_revoke_after_reset_test_execute_run_update_static_init_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_execute_prepare_staging);
TEST (firmware_update_handler_revoke_after_reset_test_execute_prepare_staging_failure);
TEST (firmware_update_handler_revoke_after_reset_test_execute_prepare_staging_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_execute_prepare_staging_static_init);
TEST (firmware_update_handler_revoke_after_reset_test_execute_prepare_staging_static_init_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_execute_write_staging);
TEST (firmware_update_handler_revoke_after_reset_test_execute_write_staging_failure);
TEST (firmware_update_handler_revoke_after_reset_test_execute_write_staging_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_execute_write_staging_static_init);
TEST (firmware_update_handler_revoke_after_reset_test_execute_write_staging_static_init_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_execute_unknown_action);
TEST (firmware_update_handler_revoke_after_reset_test_execute_unknown_action_keep_recovery_updated);
TEST (firmware_update_handler_revoke_after_reset_test_execute_unknown_action_static_init);
TEST (firmware_update_handler_revoke_after_reset_test_execute_unknown_action_static_init_keep_recovery_updated);

TEST_SUITE_END;
