// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "spi_filter/spi_filter_logging.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("spi_filter");


/**
 * Tear down the test suite.
 *
 * @param test The test framework.
 */
static void spi_filter_testing_suite_tear_down (CuTest *test)
{
	debug_log = NULL;
}

/*******************
 * Test cases
 *******************/

static void spi_filter_test_log_configuration_port0 (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct logging_mock log;
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

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.get_port, &filter, port);

	status |= mock_expect (&filter.mock, filter.base.get_mfg_id, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mfg, sizeof (mfg), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_size, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &device_size, sizeof (device_size), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mode, sizeof (mode), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &flag, sizeof (flag), -1);

	status |= mock_expect (&filter.mock, filter.base.get_ro_cs, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &ro, sizeof (ro), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr, sizeof (addr), -1);

	status |= mock_expect (&filter.mock, filter.base.get_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_fixed, sizeof (addr_fixed), -1);

	status |= mock_expect (&filter.mock, filter.base.get_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_reset, sizeof (addr_reset), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode_write_enable_required,
		&filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_write_en, sizeof (addr_write_en), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_dirty_state, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &dirty, sizeof (dirty), -1);

	status |= mock_expect (&filter.mock, filter.base.are_all_single_flash_writes_allowed, &filter,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &allow_write, sizeof (allow_write), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region1_start, sizeof (region1_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region1_end, sizeof (region1_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region2_start, sizeof (region2_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region2_end, sizeof (region2_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region3_start, sizeof (region3_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region3_end, sizeof (region3_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (4),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region4_start, sizeof (region4_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region4_end, sizeof (region4_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (5),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region5_start, sizeof (region5_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region5_end, sizeof (region5_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (6),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region6_start, sizeof (region6_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region6_end, sizeof (region6_end), -1);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region4)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region5, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region5)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region6, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region6)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_configuration (&filter.base);
	debug_log = NULL;

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_configuration_port1 (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct logging_mock log;
	int status;
	int port = 1;
	uint8_t mfg = 1;
	bool flag = true;
	spi_filter_cs ro = SPI_FILTER_CS_0;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_fixed = true;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_write_en = true;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_NORMAL;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_BYPASS_CS0;
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
		.arg1 = 1,
		.arg2 = 0x79501
	};
	struct debug_log_entry_info entry_region1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1000100,
		.arg2 = 0x1000200
	};
	struct debug_log_entry_info entry_region2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1003000,
		.arg2 = 0x2004000
	};
	struct debug_log_entry_info entry_region3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1006000,
		.arg2 = 0x3010000
	};
	struct debug_log_entry_info entry_region4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1010100,
		.arg2 = 0x4010200
	};
	struct debug_log_entry_info entry_region5 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1013000,
		.arg2 = 0x5014000
	};
	struct debug_log_entry_info entry_region6 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1016000,
		.arg2 = 0x6017000
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 1,
		.arg2 = 0x2000000
	};

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.get_port, &filter, port);

	status |= mock_expect (&filter.mock, filter.base.get_mfg_id, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mfg, sizeof (mfg), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_size, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &device_size, sizeof (device_size), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mode, sizeof (mode), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &flag, sizeof (flag), -1);

	status |= mock_expect (&filter.mock, filter.base.get_ro_cs, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &ro, sizeof (ro), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr, sizeof (addr), -1);

	status |= mock_expect (&filter.mock, filter.base.get_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_fixed, sizeof (addr_fixed), -1);

	status |= mock_expect (&filter.mock, filter.base.get_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_reset, sizeof (addr_reset), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode_write_enable_required,
		&filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_write_en, sizeof (addr_write_en), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_dirty_state, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &dirty, sizeof (dirty), -1);

	status |= mock_expect (&filter.mock, filter.base.are_all_single_flash_writes_allowed, &filter,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &allow_write, sizeof (allow_write), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region1_start, sizeof (region1_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region1_end, sizeof (region1_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region2_start, sizeof (region2_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region2_end, sizeof (region2_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region3_start, sizeof (region3_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region3_end, sizeof (region3_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (4),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region4_start, sizeof (region4_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region4_end, sizeof (region4_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (5),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region5_start, sizeof (region5_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region5_end, sizeof (region5_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (6),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region6_start, sizeof (region6_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region6_end, sizeof (region6_end), -1);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region4)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region5, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region5)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region6, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region6)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_configuration (&filter.base);
	debug_log = NULL;

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_configuration_bypass_cs1 (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct logging_mock log;
	int status;
	int port = 2;
	uint8_t mfg = 2;
	bool flag = false;
	spi_filter_cs ro = SPI_FILTER_CS_1;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_fixed = false;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_write_en = false;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_DIRTY;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_BYPASS_CS1;
	bool allow_write = false;
	uint32_t region1_start = 0;
	uint32_t region1_end = 0;
	uint32_t region2_start = 0;
	uint32_t region2_end = 0;
	uint32_t region3_start = 0;
	uint32_t region3_end = 0;
	uint32_t region4_start = 0;
	uint32_t region4_end = 0;
	uint32_t region5_start = 0;
	uint32_t region5_end = 0;
	uint32_t region6_start = 0;
	uint32_t region6_end = 0;
	uint32_t device_size = 0x200000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 2,
		.arg2 = 0x92e02
	};
	struct debug_log_entry_info entry_region1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x1000000
	};
	struct debug_log_entry_info entry_region2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x2000000
	};
	struct debug_log_entry_info entry_region3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x3000000
	};
	struct debug_log_entry_info entry_region4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x4000000
	};
	struct debug_log_entry_info entry_region5 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x5000000
	};
	struct debug_log_entry_info entry_region6 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x6000000
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 2,
		.arg2 = 0x200000
	};

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.get_port, &filter, port);

	status |= mock_expect (&filter.mock, filter.base.get_mfg_id, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mfg, sizeof (mfg), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_size, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &device_size, sizeof (device_size), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mode, sizeof (mode), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &flag, sizeof (flag), -1);

	status |= mock_expect (&filter.mock, filter.base.get_ro_cs, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &ro, sizeof (ro), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr, sizeof (addr), -1);

	status |= mock_expect (&filter.mock, filter.base.get_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_fixed, sizeof (addr_fixed), -1);

	status |= mock_expect (&filter.mock, filter.base.get_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_reset, sizeof (addr_reset), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode_write_enable_required,
		&filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_write_en, sizeof (addr_write_en), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_dirty_state, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &dirty, sizeof (dirty), -1);

	status |= mock_expect (&filter.mock, filter.base.are_all_single_flash_writes_allowed, &filter,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &allow_write, sizeof (allow_write), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region1_start, sizeof (region1_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region1_end, sizeof (region1_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region2_start, sizeof (region2_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region2_end, sizeof (region2_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region3_start, sizeof (region3_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region3_end, sizeof (region3_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (4),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region4_start, sizeof (region4_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region4_end, sizeof (region4_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (5),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region5_start, sizeof (region5_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region5_end, sizeof (region5_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (6),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region6_start, sizeof (region6_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region6_end, sizeof (region6_end), -1);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region4)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region5, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region5)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region6, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region6)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_configuration (&filter.base);
	debug_log = NULL;

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_configuration_full_rw (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct logging_mock log;
	int status;
	int port = 0;
	uint8_t mfg = 0;
	bool flag = false;
	spi_filter_cs ro = SPI_FILTER_CS_1;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_fixed = true;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_write_en = false;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_DIRTY;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_DUAL;
	bool allow_write = false;
	uint32_t region1_start = 0x10000;
	uint32_t region1_end = 0x20000;
	uint32_t region2_start = 0x300000;
	uint32_t region2_end = 0x400000;
	uint32_t region3_start = 0;
	uint32_t region3_end = 0xffff0000;
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
		.arg2 = 0x0ca00
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
		.arg1 = 0,
		.arg2 = 0x3ffff00
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

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.get_port, &filter, port);

	status |= mock_expect (&filter.mock, filter.base.get_mfg_id, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mfg, sizeof (mfg), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_size, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &device_size, sizeof (device_size), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mode, sizeof (mode), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &flag, sizeof (flag), -1);

	status |= mock_expect (&filter.mock, filter.base.get_ro_cs, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &ro, sizeof (ro), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr, sizeof (addr), -1);

	status |= mock_expect (&filter.mock, filter.base.get_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_fixed, sizeof (addr_fixed), -1);

	status |= mock_expect (&filter.mock, filter.base.get_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_reset, sizeof (addr_reset), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode_write_enable_required,
		&filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_write_en, sizeof (addr_write_en), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_dirty_state, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &dirty, sizeof (dirty), -1);

	status |= mock_expect (&filter.mock, filter.base.are_all_single_flash_writes_allowed, &filter,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &allow_write, sizeof (allow_write), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region1_start, sizeof (region1_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region1_end, sizeof (region1_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region2_start, sizeof (region2_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region2_end, sizeof (region2_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region3_start, sizeof (region3_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region3_end, sizeof (region3_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (4),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region4_start, sizeof (region4_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region4_end, sizeof (region4_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (5),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region5_start, sizeof (region5_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region5_end, sizeof (region5_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (6),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region6_start, sizeof (region6_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region6_end, sizeof (region6_end), -1);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region4)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region5, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region5)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region6, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region6)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_configuration (&filter.base);
	debug_log = NULL;

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_configuration_unsupported_operations (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct logging_mock log;
	int status;
	int port = 0;
	uint8_t mfg = 0;
	bool flag = false;
	spi_filter_cs ro = SPI_FILTER_CS_1;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_fixed = true;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_DIRTY;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_DUAL;
	uint32_t region1_start = 0x10000;
	uint32_t region1_end = 0x20000;
	uint32_t region2_start = 0x300000;
	uint32_t region2_end = 0x400000;
	uint32_t region3_start = 0;
	uint32_t region3_end = 0xffff0000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 0,
		.arg2 = 0x0ca00
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
		.arg1 = 0,
		.arg2 = 0x3ffff00
	};
	struct debug_log_entry_info entry_region4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x0000000,
		.arg2 = 0x4000000
	};
	struct debug_log_entry_info entry_region5 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x0000000,
		.arg2 = 0x5000000
	};
	struct debug_log_entry_info entry_region6 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x0000000,
		.arg2 = 0x6000000
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.get_port, &filter, port);

	status |= mock_expect (&filter.mock, filter.base.get_mfg_id, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mfg, sizeof (mfg), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_size, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&filter.mock, filter.base.get_filter_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mode, sizeof (mode), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &flag, sizeof (flag), -1);

	status |= mock_expect (&filter.mock, filter.base.get_ro_cs, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &ro, sizeof (ro), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr, sizeof (addr), -1);

	status |= mock_expect (&filter.mock, filter.base.get_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_fixed, sizeof (addr_fixed), -1);

	status |= mock_expect (&filter.mock, filter.base.get_reset_addr_byte_mode, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode_write_enable_required,
		&filter, SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&filter.mock, filter.base.get_flash_dirty_state, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &dirty, sizeof (dirty), -1);

	status |= mock_expect (&filter.mock, filter.base.are_all_single_flash_writes_allowed, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region1_start, sizeof (region1_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region1_end, sizeof (region1_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region2_start, sizeof (region2_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region2_end, sizeof (region2_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region3_start, sizeof (region3_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region3_end, sizeof (region3_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (4), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (5), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (6), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region4)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region5, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region5)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region6, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region6)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_configuration (&filter.base);
	debug_log = NULL;

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_configuration_single_flash (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct logging_mock log;
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
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_SINGLE_CS0;
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
		.arg2 = 0xc0a00
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

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.get_port, &filter, port);

	status |= mock_expect (&filter.mock, filter.base.get_mfg_id, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mfg, sizeof (mfg), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_size, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &device_size, sizeof (device_size), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mode, sizeof (mode), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &flag, sizeof (flag), -1);

	status |= mock_expect (&filter.mock, filter.base.get_ro_cs, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &ro, sizeof (ro), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr, sizeof (addr), -1);

	status |= mock_expect (&filter.mock, filter.base.get_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_fixed, sizeof (addr_fixed), -1);

	status |= mock_expect (&filter.mock, filter.base.get_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_reset, sizeof (addr_reset), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode_write_enable_required,
		&filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_write_en, sizeof (addr_write_en), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_dirty_state, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &dirty, sizeof (dirty), -1);

	status |= mock_expect (&filter.mock, filter.base.are_all_single_flash_writes_allowed, &filter,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &allow_write, sizeof (allow_write), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region1_start, sizeof (region1_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region1_end, sizeof (region1_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region2_start, sizeof (region2_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region2_end, sizeof (region2_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region3_start, sizeof (region3_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region3_end, sizeof (region3_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (4),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region4_start, sizeof (region4_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region4_end, sizeof (region4_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (5),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region5_start, sizeof (region5_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region5_end, sizeof (region5_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (6),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region6_start, sizeof (region6_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region6_end, sizeof (region6_end), -1);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region4)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region5, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region5)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region6, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region6)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_configuration (&filter.base);
	debug_log = NULL;

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_configuration_single_flash_cs1 (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct logging_mock log;
	int status;
	int port = 1;
	uint8_t mfg = 1;
	bool flag = true;
	spi_filter_cs ro = SPI_FILTER_CS_0;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_fixed = true;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_write_en = true;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_NORMAL;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_SINGLE_CS1;
	bool allow_write = true;
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
		.arg1 = 1,
		.arg2 = 0x338501
	};
	struct debug_log_entry_info entry_region1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1000100,
		.arg2 = 0x1000200
	};
	struct debug_log_entry_info entry_region2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1003000,
		.arg2 = 0x2004000
	};
	struct debug_log_entry_info entry_region3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1006000,
		.arg2 = 0x3010000
	};
	struct debug_log_entry_info entry_region4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1010100,
		.arg2 = 0x4010200
	};
	struct debug_log_entry_info entry_region5 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1013000,
		.arg2 = 0x5014000
	};
	struct debug_log_entry_info entry_region6 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1016000,
		.arg2 = 0x6017000
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 1,
		.arg2 = 0x2000000
	};

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.get_port, &filter, port);

	status |= mock_expect (&filter.mock, filter.base.get_mfg_id, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mfg, sizeof (mfg), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_size, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &device_size, sizeof (device_size), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &mode, sizeof (mode), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &flag, sizeof (flag), -1);

	status |= mock_expect (&filter.mock, filter.base.get_ro_cs, &filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &ro, sizeof (ro), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr, sizeof (addr), -1);

	status |= mock_expect (&filter.mock, filter.base.get_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_fixed, sizeof (addr_fixed), -1);

	status |= mock_expect (&filter.mock, filter.base.get_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_reset, sizeof (addr_reset), -1);

	status |= mock_expect (&filter.mock, filter.base.get_addr_byte_mode_write_enable_required,
		&filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &addr_write_en, sizeof (addr_write_en), -1);

	status |= mock_expect (&filter.mock, filter.base.get_flash_dirty_state, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &dirty, sizeof (dirty), -1);

	status |= mock_expect (&filter.mock, filter.base.are_all_single_flash_writes_allowed, &filter,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &allow_write, sizeof (allow_write), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region1_start, sizeof (region1_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region1_end, sizeof (region1_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region2_start, sizeof (region2_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region2_end, sizeof (region2_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region3_start, sizeof (region3_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region3_end, sizeof (region3_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (4),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region4_start, sizeof (region4_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region4_end, sizeof (region4_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (5),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region5_start, sizeof (region5_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region5_end, sizeof (region5_end), -1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_rw_region, &filter, 0, MOCK_ARG (6),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 1, &region6_start, sizeof (region6_start), -1);
	status |= mock_expect_output (&filter.mock, 2, &region6_end, sizeof (region6_end), -1);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region4)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region5, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region5)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region6, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region6)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_configuration (&filter.base);
	debug_log = NULL;

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_configuration_null (CuTest *test)
{
	struct logging_mock log;
	int status;

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_configuration (NULL);
	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_filter_config_port0 (CuTest *test)
{
	struct logging_mock log;
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
	uint32_t region_start[3] = {
		0x10000, 0x300000, 0x600000
	};
	uint32_t region_end[3] = {
		0x20000, 0x400000, 0x1000000
	};
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
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 0,
		.arg2 = 0x2000000
	};

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_filter_config (port, mfg, flag, ro, addr, addr_fixed, addr_reset, addr_write_en,
		dirty, mode, allow_write, region_start, region_end, 3, device_size);
	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_filter_config_port1 (CuTest *test)
{
	struct logging_mock log;
	int status;
	int port = 1;
	uint8_t mfg = 1;
	bool flag = true;
	spi_filter_cs ro = SPI_FILTER_CS_0;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_fixed = true;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_write_en = true;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_NORMAL;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_BYPASS_CS0;
	bool allow_write = false;
	uint32_t region_start[3] = {
		0x10000, 0x300000, 0x600000
	};
	uint32_t region_end[3] = {
		0x20000, 0x400000, 0x1000000
	};
	uint32_t device_size = 0x2000000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 1,
		.arg2 = 0x79501
	};
	struct debug_log_entry_info entry_region1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1000100,
		.arg2 = 0x1000200
	};
	struct debug_log_entry_info entry_region2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1003000,
		.arg2 = 0x2004000
	};
	struct debug_log_entry_info entry_region3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1006000,
		.arg2 = 0x3010000
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 1,
		.arg2 = 0x2000000
	};

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_filter_config (port, mfg, flag, ro, addr, addr_fixed, addr_reset, addr_write_en,
		dirty, mode, allow_write, region_start, region_end, 3, device_size);
	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_filter_config_bypass_cs1 (CuTest *test)
{
	struct logging_mock log;
	int status;
	int port = 2;
	uint8_t mfg = 2;
	bool flag = false;
	spi_filter_cs ro = SPI_FILTER_CS_1;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_fixed = false;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_write_en = false;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_DIRTY;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_BYPASS_CS1;
	bool allow_write = false;
	uint32_t region_start[3] = {0};
	uint32_t region_end[3] = {0};
	uint32_t device_size = 0x200000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 2,
		.arg2 = 0x92e02
	};
	struct debug_log_entry_info entry_region1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x1000000
	};
	struct debug_log_entry_info entry_region2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x2000000
	};
	struct debug_log_entry_info entry_region3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x2000000,
		.arg2 = 0x3000000
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 2,
		.arg2 = 0x200000
	};

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_filter_config (port, mfg, flag, ro, addr, addr_fixed, addr_reset, addr_write_en,
		dirty, mode, allow_write, region_start, region_end, 3, device_size);
	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_filter_config_full_fw (CuTest *test)
{
	struct logging_mock log;
	int status;
	int port = 0;
	uint8_t mfg = 0;
	bool flag = false;
	spi_filter_cs ro = SPI_FILTER_CS_1;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_fixed = true;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_write_en = false;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_DIRTY;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_DUAL;
	bool allow_write = false;
	uint32_t region_start[3] = {
		0x10000, 0x300000, 0
	};
	uint32_t region_end[3] = {
		0x20000, 0x400000, 0xffff0000
	};
	uint32_t device_size = 0x2000000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 0,
		.arg2 = 0x0ca00
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
		.arg1 = 0,
		.arg2 = 0x3ffff00
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 0,
		.arg2 = 0x2000000
	};

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_filter_config (port, mfg, flag, ro, addr, addr_fixed, addr_reset, addr_write_en,
		dirty, mode, allow_write, region_start, region_end, 3, device_size);
	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_filter_config_two_regions (CuTest *test)
{
	struct logging_mock log;
	int status;
	int port = 0;
	uint8_t mfg = 0;
	bool flag = false;
	spi_filter_cs ro = SPI_FILTER_CS_1;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_fixed = false;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_3;
	bool addr_write_en = true;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_DIRTY;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_DUAL;
	bool allow_write = false;
	uint32_t region_start[2] = {
		0x10000, 0x300000
	};
	uint32_t region_end[2] = {
		0x20000, 0x400000
	};
	uint32_t device_size = 0x2000000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 0,
		.arg2 = 0x20a00
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
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 0,
		.arg2 = 0x2000000
	};

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_filter_config (port, mfg, flag, ro, addr, addr_fixed, addr_reset, addr_write_en,
		dirty, mode, allow_write, region_start, region_end, 2, device_size);
	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_filter_config_single_flash (CuTest *test)
{
	struct logging_mock log;
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
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_SINGLE_CS0;
	bool allow_write = false;
	uint32_t region_start[3] = {
		0x10000, 0x300000, 0x600000
	};
	uint32_t region_end[3] = {
		0x20000, 0x400000, 0x1000000
	};
	uint32_t device_size = 0x2000000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 0,
		.arg2 = 0xc0a00
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
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 0,
		.arg2 = 0x2000000
	};

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_filter_config (port, mfg, flag, ro, addr, addr_fixed, addr_reset, addr_write_en,
		dirty, mode, allow_write, region_start, region_end, 3, device_size);
	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spi_filter_test_log_filter_config_single_flash_cs1 (CuTest *test)
{
	struct logging_mock log;
	int status;
	int port = 1;
	uint8_t mfg = 1;
	bool flag = true;
	spi_filter_cs ro = SPI_FILTER_CS_0;
	spi_filter_address_mode addr = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_fixed = true;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_4;
	bool addr_write_en = true;
	spi_filter_flash_state dirty = SPI_FILTER_FLASH_STATE_NORMAL;
	spi_filter_flash_mode mode = SPI_FILTER_FLASH_SINGLE_CS1;
	bool allow_write = true;
	uint32_t region_start[3] = {
		0x10000, 0x300000, 0x600000
	};
	uint32_t region_end[3] = {
		0x20000, 0x400000, 0x1000000
	};
	uint32_t device_size = 0x2000000;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_CONFIG,
		.arg1 = 1,
		.arg2 = 0x338501
	};
	struct debug_log_entry_info entry_region1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1000100,
		.arg2 = 0x1000200
	};
	struct debug_log_entry_info entry_region2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1003000,
		.arg2 = 0x2004000
	};
	struct debug_log_entry_info entry_region3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_FILTER_REGION,
		.arg1 = 0x1006000,
		.arg2 = 0x3010000
	};
	struct debug_log_entry_info entry_size = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_SPI_FILTER,
		.msg_index = SPI_FILTER_LOGGING_DEVICE_SIZE,
		.arg1 = 1,
		.arg2 = 0x2000000
	};

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_size, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_size)));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region1)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region2)));
	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_region3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_region3)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;
	spi_filter_log_filter_config (port, mfg, flag, ro, addr, addr_fixed, addr_reset, addr_write_en,
		dirty, mode, allow_write, region_start, region_end, 3, device_size);
	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START (spi_filter);

TEST (spi_filter_test_log_configuration_port0);
TEST (spi_filter_test_log_configuration_port1);
TEST (spi_filter_test_log_configuration_bypass_cs1);
TEST (spi_filter_test_log_configuration_null);
TEST (spi_filter_test_log_configuration_full_rw);
TEST (spi_filter_test_log_configuration_unsupported_operations);
TEST (spi_filter_test_log_configuration_single_flash);
TEST (spi_filter_test_log_configuration_single_flash_cs1);
TEST (spi_filter_test_log_filter_config_port0);
TEST (spi_filter_test_log_filter_config_port1);
TEST (spi_filter_test_log_filter_config_bypass_cs1);
TEST (spi_filter_test_log_filter_config_full_fw);
TEST (spi_filter_test_log_filter_config_two_regions);
TEST (spi_filter_test_log_filter_config_single_flash);
TEST (spi_filter_test_log_filter_config_single_flash_cs1);

/* Tear down after the tests in this suite have run. */
TEST (spi_filter_testing_suite_tear_down);

TEST_SUITE_END;
