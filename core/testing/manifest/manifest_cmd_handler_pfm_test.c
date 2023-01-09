// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_common.h"
#include "host_fw/host_state_manager.h"
#include "manifest/manifest_logging.h"
#include "manifest/pfm/manifest_cmd_handler_pfm.h"
#include "manifest/pfm/manifest_cmd_handler_pfm_static.h"
#include "spi_filter/spi_filter_logging.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/host_fw/host_processor_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/manifest_manager_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"
#include "testing/mock/system/event_task_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("manifest_cmd_handler_pfm");


/**
 * Dependencies for testing.
 */
struct manifest_cmd_handler_pfm_testing {
	HASH_TESTING_ENGINE hash;					/**< Hash engine for verification. */
	RSA_TESTING_ENGINE rsa;						/**< RSA engine for verification. */
	struct manifest_manager_mock manifest;		/**< Mock for the manifest manager. */
	struct logging_mock log;					/**< Mock for debug logging. */
	struct event_task_mock task;				/**< Mock for the command task. */
	struct host_processor_mock host;			/**< Mock for the host instance. */
	struct flash_mock flash;					/**< Mock for host stat flash. */
	struct host_state_manager host_state;		/**< Manager for host state. */
	struct spi_filter_interface_mock filter;	/**< Mock for the host SPI filter. */
	struct manifest_cmd_handler_state state;	/**< Context for the manifest handler. */
	struct manifest_cmd_handler_pfm test;		/**< Manifest handler under test. */
};


/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components.
 */
static void manifest_cmd_handler_pfm_testing_init_host_state (CuTest *test,
	struct manifest_cmd_handler_pfm_testing *handler)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	status = mock_expect (&handler->flash.mock, handler->flash.base.get_sector_size,
		&handler->flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler->flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&handler->flash.mock, handler->flash.base.read, &handler->flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&handler->flash.mock, 1, (uint8_t*) end, sizeof (end), 2);

	status |= mock_expect (&handler->flash.mock, handler->flash.base.read, &handler->flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&handler->flash.mock, 1, (uint8_t*) end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&handler->flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&handler->host_state, &handler->flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_pfm_testing_init_dependencies (CuTest *test,
	struct manifest_cmd_handler_pfm_testing *handler)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&handler->hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&handler->rsa);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_mock_init (&handler->manifest);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	status = event_task_mock_init (&handler->task);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_mock_init (&handler->host);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&handler->flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&handler->filter);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_init_host_state (test, handler);

	debug_log = &handler->log.base;
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_pfm_testing_init (CuTest *test,
	struct manifest_cmd_handler_pfm_testing *handler)
{
	int status;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, handler);

	status = manifest_cmd_handler_pfm_init (&handler->test, &handler->state,
		&handler->manifest.base, &handler->task.base, &handler->host.base, &handler->host_state,
		&handler->hash.base, &handler->rsa.base, &handler->filter.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing with no SPI filter.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_pfm_testing_init_no_spi_filter (CuTest *test,
	struct manifest_cmd_handler_pfm_testing *handler)
{
	int status;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, handler);

	status = manifest_cmd_handler_pfm_init (&handler->test, &handler->state,
		&handler->manifest.base, &handler->task.base, &handler->host.base, &handler->host_state,
		&handler->hash.base, &handler->rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_pfm_testing_init_static (CuTest *test,
	struct manifest_cmd_handler_pfm_testing *handler, struct manifest_cmd_handler_pfm *test_static)
{
	int status;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, handler);

	status = manifest_cmd_handler_pfm_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void manifest_cmd_handler_pfm_testing_release_dependencies (CuTest *test,
	struct manifest_cmd_handler_pfm_testing *handler)
{
	int status;

	debug_log = NULL;

	status = manifest_manager_mock_validate_and_release (&handler->manifest);
	status |= logging_mock_validate_and_release (&handler->log);
	status |= event_task_mock_validate_and_release (&handler->task);
	status |= host_processor_mock_validate_and_release (&handler->host);
	status |= flash_mock_validate_and_release (&handler->flash);
	status |= spi_filter_interface_mock_validate_and_release (&handler->filter);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&handler->host_state);
	HASH_TESTING_ENGINE_RELEASE (&handler->hash);
	RSA_TESTING_ENGINE_RELEASE (&handler->rsa);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void manifest_cmd_handler_pfm_testing_validate_and_release (CuTest *test,
	struct manifest_cmd_handler_pfm_testing *handler)
{
	manifest_cmd_handler_pfm_testing_release_dependencies (test, handler);
	manifest_cmd_handler_pfm_release (&handler->test);
}

/**
 * Set up expectations for logging the SPI filter configuration.
 *
 * @param test The testing framework.
 * @param handler The testing components.
 */
static void manifest_cmd_handler_pfm_testing_log_filter_config (CuTest *test,
	struct manifest_cmd_handler_pfm_testing *handler)
{
	int status;
	int port = 0;
	uint8_t mfg = 0;
	bool flag = false;
	spi_filter_cs ro = SPI_FILTER_CS_1;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_fixed = false;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_write_en = false;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_DIRTY;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_DUAL;
	bool allow_write = false;
	uint32_t region1_start = 0x10000;
	uint32_t region1_end = 0x20000;
	uint32_t region2_start = 0x300000;
	uint32_t region2_end = 0x400000;
	uint32_t region3_start = 0x600000;
	uint32_t region3_end = 0x1000000;
	uint32_t region4_start = 0x1010000;
	uint32_t region4_end = 0x1020000;
	uint32_t region5_start = 0x1300000;
	uint32_t region5_end = 0x1400000;
	uint32_t region6_start = 0x1600000;
	uint32_t region6_end = 0x1700000;
	uint32_t device_size = 0x2000000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 0,
		.arg2 = 0x00a00
	};
	struct debug_log_entry_info entry_region1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x100,
		.arg2 = 0x1000200
	};
	struct debug_log_entry_info entry_region2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x3000,
		.arg2 = 0x2004000
	};
	struct debug_log_entry_info entry_region3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x6000,
		.arg2 = 0x3010000
	};
	struct debug_log_entry_info entry_region4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x10100,
		.arg2 = 0x4010200
	};
	struct debug_log_entry_info entry_region5 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x13000,
		.arg2 = 0x5014000
	};
	struct debug_log_entry_info entry_region6 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x16000,
		.arg2 = 0x6017000
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 0,
		.arg2 = 0x2000000
	};

	status = mock_expect (&handler->filter.mock, handler->filter.base.get_port, &handler->filter,
		port);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_mfg_id, &handler->filter,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &mfg, sizeof (mfg), -1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_flash_size,
		&handler->filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &device_size, sizeof (device_size),
		-1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_filter_mode,
		&handler->filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &mode, sizeof (mode), -1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_filter_enabled,
		&handler->filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &flag, sizeof (flag), -1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_ro_cs, &handler->filter,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &ro, sizeof (ro), -1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_addr_byte_mode,
		&handler->filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &addr, sizeof (addr), -1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_fixed_addr_byte_mode,
		&handler->filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &addr_fixed, sizeof (addr_fixed),
		-1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_reset_addr_byte_mode,
		&handler->filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &addr_reset, sizeof (addr_reset),
		-1);

	status |= mock_expect (&handler->filter.mock,
		handler->filter.base.get_addr_byte_mode_write_enable_required, &handler->filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &addr_write_en,
		sizeof (addr_write_en), -1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_flash_dirty_state,
		&handler->filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &dirty, sizeof (dirty), -1);

	status |= mock_expect (&handler->filter.mock,
		handler->filter.base.are_all_single_flash_writes_allowed, &handler->filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 0, &allow_write, sizeof (allow_write),
		-1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_filter_rw_region,
		&handler->filter, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 1, &region1_start,
		sizeof (region1_start), -1);
	status |= mock_expect_output_tmp (&handler->filter.mock, 2, &region1_end, sizeof (region1_end),
		-1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_filter_rw_region,
		&handler->filter, 0, MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 1, &region2_start,
		sizeof (region2_start), -1);
	status |= mock_expect_output_tmp (&handler->filter.mock, 2, &region2_end, sizeof (region2_end),
		-1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_filter_rw_region,
		&handler->filter, 0, MOCK_ARG (3), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 1, &region3_start,
		sizeof (region3_start), -1);
	status |= mock_expect_output_tmp (&handler->filter.mock, 2, &region3_end, sizeof (region3_end),
		-1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_filter_rw_region,
		&handler->filter, 0, MOCK_ARG (4), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 1, &region4_start,
		sizeof (region4_start), -1);
	status |= mock_expect_output_tmp (&handler->filter.mock, 2, &region4_end, sizeof (region4_end),
		-1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_filter_rw_region,
		&handler->filter, 0, MOCK_ARG (5), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 1, &region5_start,
		sizeof (region5_start), -1);
	status |= mock_expect_output_tmp (&handler->filter.mock, 2, &region5_end, sizeof (region5_end),
		-1);

	status |= mock_expect (&handler->filter.mock, handler->filter.base.get_filter_rw_region,
		&handler->filter, 0, MOCK_ARG (6), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&handler->filter.mock, 1, &region6_start,
		sizeof (region6_start), -1);
	status |= mock_expect_output_tmp (&handler->filter.mock, 2, &region6_end, sizeof (region6_end),
		-1);

	status |= mock_expect (&handler->log.mock, handler->log.base.create_entry, &handler->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler->log.mock, handler->log.base.create_entry, &handler->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&handler->log.mock, handler->log.base.create_entry, &handler->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_region1,
			LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&handler->log.mock, handler->log.base.create_entry, &handler->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_region2,
			LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&handler->log.mock, handler->log.base.create_entry, &handler->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_region3,
			LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));
	status |= mock_expect (&handler->log.mock, handler->log.base.create_entry, &handler->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_region4,
			LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region4)));
	status |= mock_expect (&handler->log.mock, handler->log.base.create_entry, &handler->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_region5,
			LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region5)));
	status |= mock_expect (&handler->log.mock, handler->log.base.create_entry, &handler->log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_region6,
			LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region6)));

	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void manifest_cmd_handler_pfm_test_init (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_pfm_init (&handler.test, &handler.state, &handler.manifest.base,
		&handler.task.base, &handler.host.base, &handler.host_state, &handler.hash.base,
		&handler.rsa.base, &handler.filter.base);
	CuAssertIntEquals (test, 0, status);

	/* The base API will not be overridden and does not need to be tested. */
	CuAssertPtrEquals (test, manifest_cmd_handler_prepare_manifest,
		handler.test.base.base_cmd.prepare_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_store_manifest,
		handler.test.base.base_cmd.store_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_finish_manifest,
		handler.test.base.base_cmd.finish_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_get_status,
		handler.test.base.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, handler.test.base.base_event.prepare);
	CuAssertPtrEquals (test, manifest_cmd_handler_execute, handler.test.base.base_event.execute);

	CuAssertPtrNotNull (test, handler.test.base.activation);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_init_no_spi_filter (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_pfm_init (&handler.test, &handler.state, &handler.manifest.base,
		&handler.task.base, &handler.host.base, &handler.host_state, &handler.hash.base,
		&handler.rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_init_null (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_pfm_init (NULL, &handler.state, &handler.manifest.base,
		&handler.task.base, &handler.host.base, &handler.host_state, &handler.hash.base,
		&handler.rsa.base, &handler.filter.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_pfm_init (&handler.test, NULL, &handler.manifest.base,
		&handler.task.base, &handler.host.base, &handler.host_state, &handler.hash.base,
		&handler.rsa.base, &handler.filter.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_pfm_init (&handler.test, &handler.state, NULL,
		&handler.task.base, &handler.host.base, &handler.host_state, &handler.hash.base,
		&handler.rsa.base, &handler.filter.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_pfm_init (&handler.test, &handler.state, &handler.manifest.base,
		NULL, &handler.host.base, &handler.host_state, &handler.hash.base,
		&handler.rsa.base, &handler.filter.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_pfm_init (&handler.test, &handler.state, &handler.manifest.base,
		&handler.task.base, NULL, &handler.host_state, &handler.hash.base,
		&handler.rsa.base, &handler.filter.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_pfm_init (&handler.test, &handler.state, &handler.manifest.base,
		&handler.task.base, &handler.host.base, NULL, &handler.hash.base,
		&handler.rsa.base, &handler.filter.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_pfm_init (&handler.test, &handler.state, &handler.manifest.base,
		&handler.task.base, &handler.host.base, &handler.host_state, NULL,
		&handler.rsa.base, &handler.filter.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_pfm_init (&handler.test, &handler.state, &handler.manifest.base,
		&handler.task.base, &handler.host.base, &handler.host_state, &handler.hash.base,
		NULL, &handler.filter.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_pfm_testing_release_dependencies (test, &handler);
}

static void manifest_cmd_handler_pfm_test_static_init (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	struct manifest_cmd_handler_pfm test_static = manifest_cmd_handler_pfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base, &handler.host.base,
		&handler.host_state, &handler.hash.base, &handler.rsa.base, &handler.filter.base);
	int status;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, &handler);

	/* The base API will not be overridden and does not need to be tested. */
	CuAssertPtrEquals (test, manifest_cmd_handler_prepare_manifest,
		test_static.base.base_cmd.prepare_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_store_manifest,
		test_static.base.base_cmd.store_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_finish_manifest,
		test_static.base.base_cmd.finish_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_get_status, test_static.base.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, test_static.base.base_event.prepare);
	CuAssertPtrEquals (test, manifest_cmd_handler_execute, test_static.base.base_event.execute);

	CuAssertPtrNotNull (test, test_static.base.activation);

	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_pfm_release (&test_static);
}

static void manifest_cmd_handler_pfm_test_static_init_no_spi_filter (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	struct manifest_cmd_handler_pfm test_static = manifest_cmd_handler_pfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base, &handler.host.base,
		&handler.host_state, &handler.hash.base, &handler.rsa.base, NULL);
	int status;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_pfm_release (&test_static);
}

static void manifest_cmd_handler_pfm_test_static_init_null (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	struct manifest_cmd_handler_pfm test_static = manifest_cmd_handler_pfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base, &handler.host.base,
		&handler.host_state, &handler.hash.base, &handler.rsa.base, &handler.filter.base);
	int status;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_pfm_init_state (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.base.state = NULL;
	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.base.state = &handler.state;
	test_static.base.manifest = NULL;
	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.base.manifest = &handler.manifest.base;
	test_static.base.task = NULL;
	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.base.task = &handler.task.base;
	test_static.host = NULL;
	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.host = &handler.host.base;
	test_static.host_state = NULL;
	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.host_state = &handler.host_state;
	test_static.hash = NULL;
	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.hash = &handler.hash.base;
	test_static.rsa = NULL;
	status = manifest_cmd_handler_pfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_pfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_pfm_release (&test_static);
}

static void manifest_cmd_handler_pfm_test_release_null (CuTest *test)
{
	TEST_START;

	manifest_cmd_handler_pfm_release (NULL);
}

static void manifest_cmd_handler_pfm_test_get_status (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_cmd.get_status (&handler.test.base.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_get_status_static_init (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	struct manifest_cmd_handler_pfm test_static = manifest_cmd_handler_pfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base, &handler.host.base,
		&handler.host_state, &handler.hash.base, &handler.rsa.base, &handler.filter.base);
	int status;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_cmd.get_status (&test_static.base.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_pfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_pfm_release (&test_static);
}

static void manifest_cmd_handler_pfm_test_activation (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, 0, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_no_spi_filter (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_no_spi_filter (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, 0, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_prevalidated_flash (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, 0, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	host_state_manager_set_run_time_validation (&handler.host_state, HOST_STATE_PREVALIDATED_FLASH);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_ACTIVATION_PENDING, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_prevalidated_flash_and_pfm (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, 0, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	host_state_manager_set_run_time_validation (&handler.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_ACTIVATION_PENDING, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_nothing_to_verify (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, HOST_PROCESSOR_NOTHING_TO_VERIFY, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test,
		(((HOST_PROCESSOR_NOTHING_TO_VERIFY & 0x00ffffff) << 8) |
			MANIFEST_CMD_STATUS_ACTIVATION_FAIL),
		status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_verify_failure_no_config_recovery (
	CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_ACTIVATION_FAIL,
		.arg1 = 2,
		.arg2 = HOST_PROCESSOR_RUN_TIME_FAILED
	};

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	host_processor_set_port (&handler.host.base, 2);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, HOST_PROCESSOR_RUN_TIME_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.needs_config_recovery,
		&handler.host, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test,
		(((HOST_PROCESSOR_RUN_TIME_FAILED & 0x00ffffff) << 8) |
			MANIFEST_CMD_STATUS_ACTIVATION_FAIL),
		status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_verify_failure_with_config_recovery (
	CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_ACTIVATION_FAIL,
		.arg1 = 1,
		.arg2 = HOST_PROCESSOR_RUN_TIME_FAILED
	};
	struct debug_log_entry_info entry_flash = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_ACTIVATION_FLASH_ERROR,
		.arg1 = 1,
		.arg2 = HOST_PROCESSOR_RUN_TIME_FAILED
	};

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	host_processor_set_port (&handler.host.base, 1);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, HOST_PROCESSOR_RUN_TIME_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.needs_config_recovery,
		&handler.host, 1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_flash, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_flash)));

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Retry */
	status |= mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, HOST_PROCESSOR_RUN_TIME_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.needs_config_recovery,
		&handler.host, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test,
		(((HOST_PROCESSOR_RUN_TIME_FAILED & 0x00ffffff) << 8) |
			MANIFEST_CMD_STATUS_ACTIVATION_FAIL),
		status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_verify_failure_with_config_recovery_error (
	CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_ACTIVATION_FAIL,
		.arg1 = 3,
		.arg2 = HOST_PROCESSOR_RUN_TIME_FAILED
	};
	struct debug_log_entry_info entry_flash = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_ACTIVATION_FLASH_ERROR,
		.arg1 = 3,
		.arg2 = HOST_PROCESSOR_RUN_TIME_FAILED
	};

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	host_processor_set_port (&handler.host.base, 3);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, HOST_PROCESSOR_RUN_TIME_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.needs_config_recovery,
		&handler.host, HOST_PROCESSOR_NEEDS_RECOVERY_FAILED);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_flash, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_flash)));

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Retry */
	status |= mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, HOST_PROCESSOR_RUN_TIME_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.needs_config_recovery,
		&handler.host, 0);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test,
		(((HOST_PROCESSOR_RUN_TIME_FAILED & 0x00ffffff) << 8) |
			MANIFEST_CMD_STATUS_ACTIVATION_FAIL),
		status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_success_after_config_recovery (
	CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry_flash = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_ACTIVATION_FLASH_ERROR,
		.arg1 = 0,
		.arg2 = HOST_PROCESSOR_RUN_TIME_FAILED
	};

	TEST_START;

	manifest_cmd_handler_pfm_testing_init (test, &handler);

	host_processor_set_port (&handler.host.base, 0);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, HOST_PROCESSOR_RUN_TIME_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.needs_config_recovery,
		&handler.host, 1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_flash, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_flash)));

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Retry failure */
	status |= mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, HOST_PROCESSOR_RUN_TIME_FAILED, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	status |= mock_expect (&handler.host.mock, handler.host.base.needs_config_recovery,
		&handler.host, 1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry_flash, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_flash)));

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	/* Retry success */
	status |= mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, 0, MOCK_ARG_PTR (&handler.hash),
		MOCK_ARG_PTR (&handler.rsa));

	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_pfm_test_activation_static_init (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	struct manifest_cmd_handler_pfm test_static = manifest_cmd_handler_pfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base, &handler.host.base,
		&handler.host_state, &handler.hash.base, &handler.rsa.base, &handler.filter.base);
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_static (test, &handler, &test_static);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, 0, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_pfm_testing_log_filter_config (test, &handler);

	status = test_static.base.activation (&test_static.base, &reset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_pfm_release (&test_static);
}

static void manifest_cmd_handler_pfm_test_activation_static_init_no_spi_filter (CuTest *test)
{
	struct manifest_cmd_handler_pfm_testing handler;
	struct manifest_cmd_handler_pfm test_static = manifest_cmd_handler_pfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base, &handler.host.base,
		&handler.host_state, &handler.hash.base, &handler.rsa.base, NULL);
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_pfm_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.host.mock, handler.host.base.run_time_verification,
		&handler.host, 0, MOCK_ARG_PTR (&handler.hash), MOCK_ARG_PTR (&handler.rsa));
	CuAssertIntEquals (test, 0, status);

	status = test_static.base.activation (&test_static.base, &reset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_pfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_pfm_release (&test_static);
}


TEST_SUITE_START (manifest_cmd_handler_pfm);

TEST (manifest_cmd_handler_pfm_test_init);
TEST (manifest_cmd_handler_pfm_test_init_no_spi_filter);
TEST (manifest_cmd_handler_pfm_test_init_null);
TEST (manifest_cmd_handler_pfm_test_static_init);
TEST (manifest_cmd_handler_pfm_test_static_init_no_spi_filter);
TEST (manifest_cmd_handler_pfm_test_static_init_null);
TEST (manifest_cmd_handler_pfm_test_release_null);
TEST (manifest_cmd_handler_pfm_test_get_status);
TEST (manifest_cmd_handler_pfm_test_get_status_static_init);
TEST (manifest_cmd_handler_pfm_test_activation);
TEST (manifest_cmd_handler_pfm_test_activation_no_spi_filter);
TEST (manifest_cmd_handler_pfm_test_activation_prevalidated_flash);
TEST (manifest_cmd_handler_pfm_test_activation_prevalidated_flash_and_pfm);
TEST (manifest_cmd_handler_pfm_test_activation_nothing_to_verify);
TEST (manifest_cmd_handler_pfm_test_activation_verify_failure_no_config_recovery);
TEST (manifest_cmd_handler_pfm_test_activation_verify_failure_with_config_recovery);
TEST (manifest_cmd_handler_pfm_test_activation_verify_failure_with_config_recovery_error);
TEST (manifest_cmd_handler_pfm_test_activation_success_after_config_recovery);
TEST (manifest_cmd_handler_pfm_test_activation_static_init);
TEST (manifest_cmd_handler_pfm_test_activation_static_init_no_spi_filter);

TEST_SUITE_END;
