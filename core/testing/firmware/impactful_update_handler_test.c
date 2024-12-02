// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/firmware_logging.h"
#include "firmware/impactful_check.h"
#include "firmware/impactful_update_handler.h"
#include "firmware/impactful_update_handler_static.h"
#include "flash/flash_common.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/firmware/firmware_update_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/firmware/app_context_mock.h"
#include "testing/mock/firmware/firmware_image_mock.h"
#include "testing/mock/firmware/impactful_update_mock.h"
#include "testing/mock/firmware/key_manifest_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/event_task_mock.h"
#include "testing/mock/system/security_manager_mock.h"
#include "testing/mock/system/security_policy_mock.h"


TEST_SUITE_LABEL ("impactful_update_handler");


/**
 * Dependencies for testing.
 */
struct impactful_update_handler_testing {
	HASH_TESTING_ENGINE (hash);						/**< Hash engine for API arguments. */
	struct firmware_image_mock fw;					/**< Mock for the FW image interface. */
	struct app_context_mock app;					/**< Mock for the application context. */
	struct key_manifest_mock manifest;				/**< Mock for the key manifest. */
	struct security_manager_mock security;			/**< Mock for the device security manager. */
	struct security_policy_mock policy;				/**< Mock for the device security policy. */
	struct security_policy *policy_ptr;				/**< Pointer to the security policy. */
	struct firmware_header header;					/**< Header on the firmware image. */
	struct flash_mock flash;						/**< Mock for the updater flash device. */
	struct logging_mock log;						/**< Mock for debug logging. */
	struct firmware_flash_map map;					/**< Map of firmware images on flash. */
	struct firmware_update_state update_state;		/**< Context for the firmware updater. */
	struct firmware_update updater;					/**< Firmware updater for testing. */
	struct event_task_mock task;					/**< Mock for the updater task. */
	struct event_task_context context;				/**< Event context for event processing. */
	struct event_task_context *context_ptr;			/**< Pointer to the event context. */
	struct firmware_update_handler_state fw_state;	/**< Context for the firmware update handler. */
	struct firmware_update_handler fw_update;		/**< Handler for firmware updates. */
	struct impactful_update_mock impactful;			/**< Update extension for impactful updates. */
	struct impactful_update_handler test;			/**< Update handler under test. */
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
static void impactful_update_handler_testing_init_dependencies (CuTest *test,
	struct impactful_update_handler_testing *handler, int header, int allowed, int recovery)
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

	status = impactful_update_mock_init (&handler->impactful);
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

	status = firmware_update_handler_init (&handler->fw_update, &handler->fw_state,
		&handler->updater, &handler->task.base, false);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void impactful_update_handler_testing_release_dependencies (CuTest *test,
	struct impactful_update_handler_testing *handler)
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
	status |= impactful_update_mock_validate_and_release (&handler->impactful);

	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&handler->header);
	HASH_TESTING_ENGINE_RELEASE (&handler->hash);
	firmware_update_release (&handler->updater);
	firmware_update_handler_release (&handler->fw_update);
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
static void impactful_update_handler_testing_init (CuTest *test,
	struct impactful_update_handler_testing *handler, int header, int allowed, int recovery)
{
	int status;

	impactful_update_handler_testing_init_dependencies (test, handler, header, allowed, recovery);

	status = impactful_update_handler_init (&handler->test, &handler->fw_update,
		&handler->impactful.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void impactful_update_handler_testing_release (CuTest *test,
	struct impactful_update_handler_testing *handler)
{
	impactful_update_handler_release (&handler->test);
	impactful_update_handler_testing_release_dependencies (test, handler);
}

/*******************
 * Test cases
 *******************/

static void impactful_update_handler_test_init (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = impactful_update_handler_init (&handler.test, &handler.fw_update,
		&handler.impactful.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base_ctrl.start_update);
	CuAssertPtrNotNull (test, handler.test.base_ctrl.get_status);
	CuAssertPtrNotNull (test, handler.test.base_ctrl.get_remaining_len);
	CuAssertPtrNotNull (test, handler.test.base_ctrl.prepare_staging);
	CuAssertPtrNotNull (test, handler.test.base_ctrl.write_staging);

	CuAssertPtrEquals (test, NULL, handler.test.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base_event.execute);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_init_null (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = impactful_update_handler_init (NULL, &handler.fw_update, &handler.impactful.base);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = impactful_update_handler_init (&handler.test, NULL, &handler.impactful.base);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = impactful_update_handler_init (&handler.test, &handler.fw_update, NULL);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_handler_testing_release_dependencies (test, &handler);
}

static void impactful_update_handler_test_static_init (CuTest *test)
{
	struct impactful_update_handler_testing handler = {
		.test = impactful_update_handler_static_init (&handler.fw_update, &handler.impactful.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, handler.test.base_ctrl.start_update);
	CuAssertPtrNotNull (test, handler.test.base_ctrl.get_status);
	CuAssertPtrNotNull (test, handler.test.base_ctrl.get_remaining_len);
	CuAssertPtrNotNull (test, handler.test.base_ctrl.prepare_staging);
	CuAssertPtrNotNull (test, handler.test.base_ctrl.write_staging);

	CuAssertPtrEquals (test, NULL, handler.test.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base_event.execute);

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_release_null (CuTest *test)
{
	TEST_START;

	impactful_update_handler_release (NULL);
}

static void impactful_update_handler_test_get_status (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_get_status_static_init (CuTest *test)
{
	struct impactful_update_handler_testing handler = {
		.test = impactful_update_handler_static_init (&handler.fw_update, &handler.impactful.base)
	};
	int status;

	TEST_START;

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_get_status_null (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = handler.test.base_ctrl.get_status (NULL);
	CuAssertIntEquals (test, UPDATE_STATUS_UNKNOWN, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_get_remaining_len (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	int32_t length;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	/* Need to prepare staging flash for there to be any remaining length. */
	status = flash_mock_expect_erase_flash_verify (&handler.flash, 0x30000, 5);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&handler.updater, NULL, 5);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&handler.flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	length = handler.test.base_ctrl.get_remaining_len (&handler.test.base_ctrl);
	CuAssertIntEquals (test, 5, length);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_get_remaining_len_static_init (CuTest *test)
{
	struct impactful_update_handler_testing handler = {
		.test = impactful_update_handler_static_init (&handler.fw_update, &handler.impactful.base)
	};
	int status;
	int32_t length;

	TEST_START;

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	/* Need to prepare staging flash for there to be any remaining length. */
	status = flash_mock_expect_erase_flash_verify (&handler.flash, 0x30000, 15);
	CuAssertIntEquals (test, 0, status);

	status = firmware_update_prepare_staging (&handler.updater, NULL, 15);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&handler.flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	length = handler.test.base_ctrl.get_remaining_len (&handler.test.base_ctrl);
	CuAssertIntEquals (test, 15, length);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_get_remaining_len_null (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int32_t length;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	length = handler.test.base_ctrl.get_remaining_len (NULL);
	CuAssertIntEquals (test, 0, length);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_start_update (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.start_update (&handler.test.base_ctrl);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE, handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_STARTING, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_start_update_static_init (CuTest *test)
{
	struct impactful_update_handler_testing handler = {
		.test = impactful_update_handler_static_init (&handler.fw_update, &handler.impactful.base)
	};
	int status;

	TEST_START;

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.start_update (&handler.test.base_ctrl);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE, handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_STARTING, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_start_update_null (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = handler.test.base_ctrl.start_update (NULL);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_start_update_no_task (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.start_update (&handler.test.base_ctrl);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_TASK_NOT_RUNNING, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_start_update_task_busy (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.start_update (&handler.test.base_ctrl);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_start_update_get_context_error (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.start_update (&handler.test.base_ctrl);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_START_FAILURE, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_start_update_notify_error (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.start_update (&handler.test.base_ctrl);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_START_FAILURE, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_prepare_staging (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	size_t bytes = 1000;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	/* Notification will be sent against the firmware_update_handler instance. */
	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.fw_update.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.prepare_staging (&handler.test.base_ctrl, bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING, handler.context.action);
	CuAssertIntEquals (test, sizeof (bytes), handler.context.buffer_length);

	status = testing_validate_array ((uint8_t*) &bytes, handler.context.event_buffer,
		sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_STARTING, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_prepare_staging_static_init (CuTest *test)
{
	struct impactful_update_handler_testing handler = {
		.test = impactful_update_handler_static_init (&handler.fw_update, &handler.impactful.base)
	};
	int status;
	size_t bytes = 2000;

	TEST_START;

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	/* Notification will be sent against the firmware_update_handler instance. */
	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.fw_update.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.prepare_staging (&handler.test.base_ctrl, bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING, handler.context.action);
	CuAssertIntEquals (test, sizeof (bytes), handler.context.buffer_length);

	status = testing_validate_array ((uint8_t*) &bytes, handler.context.event_buffer,
		sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_STARTING, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_prepare_staging_null (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = handler.test.base_ctrl.prepare_staging (NULL, 100);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_prepare_staging_no_task (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.prepare_staging (&handler.test.base_ctrl, 100);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_TASK_NOT_RUNNING, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_prepare_staging_task_busy (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.prepare_staging (&handler.test.base_ctrl, 100);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_NONE_STARTED, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_prepare_staging_get_context_error (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.prepare_staging (&handler.test.base_ctrl, 100);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_START_FAILURE, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_prepare_staging_notify_error (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	/* Notification will be sent against the firmware_update_handler instance. */
	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.fw_update.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.prepare_staging (&handler.test.base_ctrl, 100);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_START_FAILURE, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_write_staging (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	/* Notification will be sent against the firmware_update_handler instance. */
	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.fw_update.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.write_staging (&handler.test.base_ctrl, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING, handler.context.action);
	CuAssertIntEquals (test, sizeof (staging_data), handler.context.buffer_length);

	status = testing_validate_array (staging_data, handler.context.event_buffer,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_STARTING, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_write_staging_static_init (CuTest *test)
{
	struct impactful_update_handler_testing handler = {
		.test = impactful_update_handler_static_init (&handler.fw_update, &handler.impactful.base)
	};
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

	TEST_START;

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	/* Notification will be sent against the firmware_update_handler instance. */
	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.fw_update.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.write_staging (&handler.test.base_ctrl, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING, handler.context.action);
	CuAssertIntEquals (test, sizeof (staging_data), handler.context.buffer_length);

	status = testing_validate_array (staging_data, handler.context.event_buffer,
		sizeof (staging_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, UPDATE_STATUS_STARTING, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_write_staging_null (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = handler.test.base_ctrl.write_staging (NULL, staging_data, sizeof (staging_data));
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = handler.test.base_ctrl.write_staging (&handler.test.base_ctrl, NULL,
		sizeof (staging_data));
	CuAssertIntEquals (test, FIRMWARE_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_write_staging_too_much_data (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	uint8_t staging_data[EVENT_TASK_CONTEXT_BUFFER_LENGTH + 1];

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

	status = handler.test.base_ctrl.write_staging (&handler.test.base_ctrl, staging_data,
		sizeof (staging_data));
	CuAssertIntEquals (test, FIRMWARE_UPDATE_TOO_MUCH_DATA, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_execute_run_update_impactless (CuTest *test)
{
	struct impactful_update_handler_testing handler;
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

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

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

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Additional handling for impactful updates. */
	/* Lock for status check. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.reset_authorization,
		&handler.impactful.base, 0);
	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.is_update_not_impactful,
		&handler.impactful.base, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 1, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_execute_run_update_impactful (CuTest *test)
{
	struct impactful_update_handler_testing handler;
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
	struct debug_log_entry_info entry_impactful = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE,
		.arg1 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

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

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Additional handling for impactful updates. */
	/* Lock for status check. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.reset_authorization,
		&handler.impactful.base, 0);
	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.is_update_not_impactful,
		&handler.impactful.base, IMPACTFUL_CHECK_IMPACTFUL_UPDATE);

	/* Lock for state update: UPDATE_STATUS_SUCCESS_NO_RESET */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_impactful,
		LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED), MOCK_ARG (sizeof (entry_impactful)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test,
		(((IMPACTFUL_CHECK_IMPACTFUL_UPDATE & 0x00ffffff) << 8) | UPDATE_STATUS_SUCCESS_NO_RESET),
		status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_execute_run_update_static_init (CuTest *test)
{
	struct impactful_update_handler_testing handler = {
		.test = impactful_update_handler_static_init (&handler.fw_update, &handler.impactful.base)
	};
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
	struct debug_log_entry_info entry_impactful = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE,
		.arg1 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	impactful_update_handler_testing_init_dependencies (test, &handler, 0, 0, 0);

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

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Additional handling for impactful updates. */
	/* Lock for status check. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.reset_authorization,
		&handler.impactful.base, 0);
	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.is_update_not_impactful,
		&handler.impactful.base, IMPACTFUL_CHECK_IMPACTFUL_UPDATE);

	/* Lock for state update: UPDATE_STATUS_SUCCESS_NO_RESET */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_impactful,
		LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED), MOCK_ARG (sizeof (entry_impactful)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test,
		(((IMPACTFUL_CHECK_IMPACTFUL_UPDATE & 0x00ffffff) << 8) | UPDATE_STATUS_SUCCESS_NO_RESET),
		status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_execute_run_update_failure (CuTest *test)
{
	struct impactful_update_handler_testing handler;
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

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

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

	/* Additional handling for impactful updates. */
	/* Lock for status check. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test,
		(((FIRMWARE_IMAGE_BAD_SIGNATURE & 0x00ffffff) << 8) | UPDATE_STATUS_INVALID_IMAGE), status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_execute_run_update_reset_auth_failure (CuTest *test)
{
	struct impactful_update_handler_testing handler;
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
	struct debug_log_entry_info entry_impactful = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_RESET_AUTH_FAIL,
		.arg1 = IMPACTFUL_UPDATE_RESET_AUTH_FAILED,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

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

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Additional handling for impactful updates. */
	/* Lock for status check. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.reset_authorization,
		&handler.impactful.base, IMPACTFUL_UPDATE_RESET_AUTH_FAILED);
	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_impactful,
		LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED), MOCK_ARG (sizeof (entry_impactful)));

	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.is_update_not_impactful,
		&handler.impactful.base, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 1, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_execute_run_update_impactful_check_failure (CuTest *test)
{
	struct impactful_update_handler_testing handler;
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
	struct debug_log_entry_info entry_impactful = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE,
		.arg1 = IMPACTFUL_UPDATE_IS_NOT_IMPACTFUL_FAILED,
		.arg2 = 0
	};
	bool reset = false;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

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

	/* Lock for state update: UPDATE_STATUS_CHECK_REVOCATION */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.fw.mock, handler.fw.base.load, &handler.fw, 0,
		MOCK_ARG_PTR (&handler.flash), MOCK_ARG (0x10000));
	status |= mock_expect (&handler.fw.mock, handler.fw.base.get_key_manifest, &handler.fw,
		MOCK_RETURN_PTR (&handler.manifest));
	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.revokes_old_manifest,
		&handler.manifest, 0);

	/* Lock for state update: UPDATE_STATUS_CHECK_RECOVERY */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_done, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_done)));
	status |= mock_expect (&handler.log.mock, handler.log.base.flush, &handler.log, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Additional handling for impactful updates. */
	/* Lock for status check. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.reset_authorization,
		&handler.impactful.base, 0);

	status |= mock_expect (&handler.impactful.mock, handler.impactful.base.is_update_not_impactful,
		&handler.impactful.base, IMPACTFUL_UPDATE_IS_NOT_IMPACTFUL_FAILED);

	/* Lock for state update: UPDATE_STATUS_SUCCESS_NO_RESET */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_impactful,
		LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED), MOCK_ARG (sizeof (entry_impactful)));

	CuAssertIntEquals (test, 0, status);

	handler.context.action = FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, (((IMPACTFUL_UPDATE_IS_NOT_IMPACTFUL_FAILED & 0x00ffffff) <<
			8) | UPDATE_STATUS_SUCCESS_NO_RESET), status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_execute_prepare_staging (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	size_t bytes = 100;
	bool reset = false;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

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

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	impactful_update_handler_testing_release (test, &handler);
}

static void impactful_update_handler_test_execute_write_staging (CuTest *test)
{
	struct impactful_update_handler_testing handler;
	int status;
	uint8_t staging_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	bool reset = false;

	TEST_START;

	impactful_update_handler_testing_init (test, &handler, 0, 0, 0);

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

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_ctrl.get_status (&handler.test.base_ctrl);
	CuAssertIntEquals (test, 0, status);

	impactful_update_handler_testing_release (test, &handler);
}


// *INDENT-OFF*
TEST_SUITE_START (impactful_update_handler);

TEST (impactful_update_handler_test_init);
TEST (impactful_update_handler_test_init_null);
TEST (impactful_update_handler_test_static_init);
TEST (impactful_update_handler_test_release_null);
TEST (impactful_update_handler_test_get_status);
TEST (impactful_update_handler_test_get_status_static_init);
TEST (impactful_update_handler_test_get_status_null);
TEST (impactful_update_handler_test_get_remaining_len);
TEST (impactful_update_handler_test_get_remaining_len_static_init);
TEST (impactful_update_handler_test_get_remaining_len_null);
TEST (impactful_update_handler_test_start_update);
TEST (impactful_update_handler_test_start_update_static_init);
TEST (impactful_update_handler_test_start_update_null);
TEST (impactful_update_handler_test_start_update_no_task);
TEST (impactful_update_handler_test_start_update_task_busy);
TEST (impactful_update_handler_test_start_update_get_context_error);
TEST (impactful_update_handler_test_start_update_notify_error);
TEST (impactful_update_handler_test_prepare_staging);
TEST (impactful_update_handler_test_prepare_staging_static_init);
TEST (impactful_update_handler_test_prepare_staging_null);
TEST (impactful_update_handler_test_prepare_staging_no_task);
TEST (impactful_update_handler_test_prepare_staging_task_busy);
TEST (impactful_update_handler_test_prepare_staging_get_context_error);
TEST (impactful_update_handler_test_prepare_staging_notify_error);
TEST (impactful_update_handler_test_write_staging);
TEST (impactful_update_handler_test_write_staging_static_init);
TEST (impactful_update_handler_test_write_staging_null);
TEST (impactful_update_handler_test_write_staging_too_much_data);
TEST (impactful_update_handler_test_execute_run_update_impactless);
TEST (impactful_update_handler_test_execute_run_update_impactful);
TEST (impactful_update_handler_test_execute_run_update_static_init);
TEST (impactful_update_handler_test_execute_run_update_failure);
TEST (impactful_update_handler_test_execute_run_update_reset_auth_failure);
TEST (impactful_update_handler_test_execute_run_update_impactful_check_failure);

/* These actions would not be called in this context in a real configuration, but these tests
 * ensure correct behavior if for some reason they are. */
TEST (impactful_update_handler_test_execute_prepare_staging);
TEST (impactful_update_handler_test_execute_write_staging);

TEST_SUITE_END;
// *INDENT-ON*
