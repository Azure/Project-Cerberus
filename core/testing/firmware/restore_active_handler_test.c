// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/firmware_logging.h"
#include "firmware/restore_active_handler.h"
#include "firmware/restore_active_handler_static.h"
#include "flash/flash_common.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/firmware/firmware_update_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/firmware/app_context_mock.h"
#include "testing/mock/firmware/firmware_image_mock.h"
#include "testing/mock/firmware/key_manifest_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/event_task_mock.h"
#include "testing/mock/system/security_manager_mock.h"
#include "testing/mock/system/security_policy_mock.h"


TEST_SUITE_LABEL ("restore_active_handler");


/**
 * Dependencies for testing.
 */
struct restore_active_handler_testing {
	HASH_TESTING_ENGINE hash;					/**< Hash engine for API arguments. */
	struct firmware_image_mock fw;				/**< Mock for the FW image interface. */
	struct app_context_mock app;				/**< Mock for the application context. */
	struct key_manifest_mock manifest;			/**< Mock for the key manifest. */
	struct security_manager_mock security;		/**< Mock for the device security manager. */
	struct security_policy_mock policy;			/**< Mock for the device security policy. */
	struct security_policy *policy_ptr;			/**< Pointer to the security policy. */
	struct firmware_header header;				/**< Header on the firmware image. */
	struct flash_mock flash;					/**< Mock for the updater flash device. */
	struct logging_mock log;					/**< Mock for debug logging. */
	struct firmware_flash_map map;				/**< Map of firmware images on flash. */
	struct firmware_update_state update_state;	/**< Context for the firmware updater. */
	struct firmware_update updater;				/**< Firmware updater for testing. */
	struct event_task_mock task;				/**< Mock for the updater task. */
	struct event_task_context context;			/**< Event context for event processing. */
	struct event_task_context *context_ptr;		/**< Pointer to the event context. */
	struct restore_active_handler test;			/**< Handler under test. */
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
static void restore_active_handler_testing_init_dependencies (CuTest *test,
	struct restore_active_handler_testing *handler, int header, int allowed, int recovery)
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
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void restore_active_handler_testing_release_dependencies (CuTest *test,
	struct restore_active_handler_testing *handler)
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
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param header The updater header firmware ID.
 * @param allowed The allowed firmware ID for the updater.
 * @param recovery The recovery firmware ID.
 */
static void restore_active_handler_testing_init (CuTest *test,
	struct restore_active_handler_testing *handler, int header, int allowed, int recovery)
{
	int status;

	restore_active_handler_testing_init_dependencies (test, handler, header, allowed, recovery);

	status = restore_active_handler_init (&handler->test, &handler->updater, &handler->task.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void restore_active_handler_testing_release (CuTest *test,
	struct restore_active_handler_testing *handler)
{
	restore_active_handler_release (&handler->test);
	restore_active_handler_testing_release_dependencies (test, handler);
}

/*******************
 * Test cases
 *******************/

static void restore_active_handler_test_init (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;

	TEST_START;

	restore_active_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = restore_active_handler_init (&handler.test, &handler.updater, &handler.task.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, handler.test.base.prepare);
	CuAssertPtrNotNull (test, handler.test.base.execute);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_init_null (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;

	TEST_START;

	restore_active_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = restore_active_handler_init (NULL, &handler.updater, &handler.task.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = restore_active_handler_init (&handler.test, NULL, &handler.task.base);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	status = restore_active_handler_init (&handler.test, &handler.updater, NULL);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	restore_active_handler_testing_release_dependencies (test, &handler);
}

static void restore_active_handler_test_static_init (CuTest *test)
{
	struct restore_active_handler_testing handler = {
		.test = restore_active_handler_static_init (&handler.updater, &handler.task.base)
	};

	TEST_START;

	CuAssertPtrEquals (test, NULL, handler.test.base.prepare);
	CuAssertPtrNotNull (test, handler.test.base.execute);

	restore_active_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_release_null (CuTest *test)
{
	TEST_START;

	restore_active_handler_release (NULL);
}

static void restore_active_handler_test_restore_from_recovery_flash (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base));

	CuAssertIntEquals (test, 0, status);

	status = restore_active_handler_restore_from_recovery_flash (&handler.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE, handler.context.action);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_static_init (CuTest *test)
{
	struct restore_active_handler_testing handler = {
		.test = restore_active_handler_static_init (&handler.updater, &handler.task.base)
	};
	int status;

	TEST_START;

	restore_active_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base));

	CuAssertIntEquals (test, 0, status);

	status = restore_active_handler_restore_from_recovery_flash (&handler.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE, handler.context.action);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_null (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	status = restore_active_handler_restore_from_recovery_flash (NULL);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_no_task (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = restore_active_handler_restore_from_recovery_flash (&handler.test);
	CuAssertIntEquals (test, EVENT_TASK_NO_TASK, status);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_task_busy (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = restore_active_handler_restore_from_recovery_flash (&handler.test);
	CuAssertIntEquals (test, EVENT_TASK_BUSY, status);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_get_context_error (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = restore_active_handler_restore_from_recovery_flash (&handler.test);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_notify_error (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base));

	CuAssertIntEquals (test, 0, status);

	status = restore_active_handler_restore_from_recovery_flash (&handler.test);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_and_log_error (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base));

	CuAssertIntEquals (test, 0, status);

	restore_active_handler_restore_from_recovery_flash_and_log_error (&handler.test);
	CuAssertIntEquals (test, RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE, handler.context.action);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_and_log_error_static_init (
	CuTest *test)
{
	struct restore_active_handler_testing handler = {
		.test = restore_active_handler_static_init (&handler.updater, &handler.task.base)
	};
	int status;

	TEST_START;

	restore_active_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base));

	CuAssertIntEquals (test, 0, status);

	restore_active_handler_restore_from_recovery_flash_and_log_error (&handler.test);
	CuAssertIntEquals (test, RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE, handler.context.action);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_and_log_error_null (
	CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_START,
		.arg1 = FIRMWARE_UPDATE_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	restore_active_handler_restore_from_recovery_flash_and_log_error (NULL);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_restore_from_recovery_flash_and_log_error_task_error (
	CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	void *null_ptr = NULL;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_START,
		.arg1 = EVENT_TASK_BUSY,
		.arg2 = 0
	};

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	restore_active_handler_restore_from_recovery_flash_and_log_error (&handler.test);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_log_start_restore_error (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ACTIVE_RESTORE_START,
		.arg1 = EVENT_TASK_BUSY,
		.arg2 = 0
	};

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	restore_active_handler_log_start_restore_error (EVENT_TASK_BUSY);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_execute_restore_active_different_images (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t recovery_data[] = {0x01, 0x02, 0x13, 0x04};
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
	bool reset = false;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	/* Compare images. */
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

	/* Restore active image. */
	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (recovery_data));

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE;

	handler.test.base.execute (&handler.test.base, handler.context_ptr, &reset);
	CuAssertIntEquals (test, false, reset);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_execute_restore_active_same_image (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t recovery_data[] = {0x01, 0x02, 0x03, 0x04};
	bool reset = false;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	/* Compare images. */
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

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE;

	handler.test.base.execute (&handler.test.base, handler.context_ptr, &reset);
	CuAssertIntEquals (test, false, reset);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_execute_restore_active_static_init (CuTest *test)
{
	struct restore_active_handler_testing handler = {
		.test = restore_active_handler_static_init (&handler.updater, &handler.task.base)
	};
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t recovery_data[] = {0x01, 0x02, 0x13, 0x04};
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
	bool reset = false;

	TEST_START;

	restore_active_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	/* Compare images. */
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

	/* Restore active image. */
	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
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

	handler.context.action = RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE;

	handler.test.base.execute (&handler.test.base, handler.context_ptr, &reset);
	CuAssertIntEquals (test, false, reset);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_execute_restore_active_compare_error (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t recovery_data[] = {0x01, 0x02, 0x13, 0x04};
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
	struct debug_log_entry_info entry_error = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_RECOVERY_COMPARE_FAIL,
		.arg1 = FIRMWARE_IMAGE_LOAD_FAILED,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	/* Compare images. */
	status = mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (active_data));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw,
		FIRMWARE_IMAGE_LOAD_FAILED, MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_error, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_error)));

	/* Restore active image. */
	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.hash));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_image_size, &handler.fw,
		sizeof (recovery_data));

	status |= firmware_update_testing_flash_page_size (&handler.flash, FLASH_PAGE_SIZE);
	status |= flash_mock_expect_erase_flash_verify (&handler.flash, 0x10000,
		sizeof (recovery_data));
	status |= flash_mock_expect_copy_flash_verify (&handler.flash, &handler.flash, 0x10000, 0x40000,
		recovery_data, sizeof (recovery_data));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE;

	handler.test.base.execute (&handler.test.base, handler.context_ptr, &reset);
	CuAssertIntEquals (test, false, reset);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_execute_restore_active_failure (CuTest *test)
{
	struct restore_active_handler_testing handler;
	int status;
	uint8_t active_data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t recovery_data[] = {0x01, 0x02, 0x13, 0x04};
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
		.arg1 = FIRMWARE_IMAGE_VERIFY_FAILED,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	/* Compare images. */
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

	/* Restore active image. */
	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x40000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.verify, &handler.fw,
		FIRMWARE_IMAGE_VERIFY_FAILED, MOCK_ARG_PTR (&handler.hash));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE;

	handler.test.base.execute (&handler.test.base, handler.context_ptr, &reset);
	CuAssertIntEquals (test, false, reset);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_execute_unknown_action (CuTest *test)
{
	struct restore_active_handler_testing handler;
	bool reset = false;

	TEST_START;

	restore_active_handler_testing_init (test, &handler, 0, 0, 0);

	handler.context.action = 4;

	handler.test.base.execute (&handler.test.base, handler.context_ptr, &reset);
	CuAssertIntEquals (test, false, reset);

	restore_active_handler_testing_release (test, &handler);
}

static void restore_active_handler_test_execute_unknown_action_static_init (CuTest *test)
{
	struct restore_active_handler_testing handler = {
		.test = restore_active_handler_static_init (&handler.updater, &handler.task.base)
	};
	bool reset = false;

	TEST_START;

	restore_active_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	handler.context.action = 8;

	handler.test.base.execute (&handler.test.base, handler.context_ptr, &reset);
	CuAssertIntEquals (test, false, reset);

	restore_active_handler_testing_release (test, &handler);
}


// *INDENT-OFF*
TEST_SUITE_START (restore_active_handler);

TEST (restore_active_handler_test_init);
TEST (restore_active_handler_test_init_null);
TEST (restore_active_handler_test_static_init);
TEST (restore_active_handler_test_release_null);
TEST (restore_active_handler_test_restore_from_recovery_flash);
TEST (restore_active_handler_test_restore_from_recovery_flash_static_init);
TEST (restore_active_handler_test_restore_from_recovery_flash_null);
TEST (restore_active_handler_test_restore_from_recovery_flash_no_task);
TEST (restore_active_handler_test_restore_from_recovery_flash_task_busy);
TEST (restore_active_handler_test_restore_from_recovery_flash_get_context_error);
TEST (restore_active_handler_test_restore_from_recovery_flash_notify_error);
TEST (restore_active_handler_test_restore_from_recovery_flash_and_log_error);
TEST (restore_active_handler_test_restore_from_recovery_flash_and_log_error_static_init);
TEST (restore_active_handler_test_restore_from_recovery_flash_and_log_error_null);
TEST (restore_active_handler_test_restore_from_recovery_flash_and_log_error_task_error);
TEST (restore_active_handler_test_log_start_restore_error);
TEST (restore_active_handler_test_execute_restore_active_different_images);
TEST (restore_active_handler_test_execute_restore_active_same_image);
TEST (restore_active_handler_test_execute_restore_active_static_init);
TEST (restore_active_handler_test_execute_restore_active_compare_error);
TEST (restore_active_handler_test_execute_restore_active_failure);
TEST (restore_active_handler_test_execute_unknown_action);
TEST (restore_active_handler_test_execute_unknown_action_static_init);

TEST_SUITE_END;
// *INDENT-ON*
