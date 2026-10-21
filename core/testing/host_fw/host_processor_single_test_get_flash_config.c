// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "host_processor_single_testing.h"
#include "testing.h"
#include "recovery/recovery_image_header.h"


TEST_SUITE_LABEL ("host_processor_single");


/*******************
 * Test cases
 *******************/

static void host_processor_single_test_get_flash_config_bypass_nv_cs0_not_dirty_no_override (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs0_not_dirty_override_cs0 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs0_not_dirty_override_cs1 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs0_dirty_no_override (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have dirty flash in bypass mode. */
	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs0_dirty_override_cs0 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have dirty flash in bypass mode. */
	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs0_dirty_override_cs1 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have dirty flash in bypass mode. */
	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs1_not_dirty_no_override (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs1_not_dirty_override_cs0 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs1_not_dirty_override_cs1 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs1_dirty_no_override (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have dirty flash in bypass mode. */
	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs1_dirty_override_cs0 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have dirty flash in bypass mode. */
	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_bypass_nv_cs1_dirty_override_cs1 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have dirty flash in bypass mode. */
	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs0_not_dirty_no_override (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS0;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs0_not_dirty_override_cs0 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS0;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs0_not_dirty_override_cs1 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS1;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs0_dirty_no_override (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS0;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs0_dirty_override_cs0 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS0;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs0_dirty_override_cs1 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS1;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs1_not_dirty_no_override (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS1;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs1_not_dirty_override_cs0 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS0;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs1_not_dirty_override_cs1 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS1;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs1_dirty_no_override (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS1;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs1_dirty_override_cs0 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS0;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_nv_cs1_dirty_override_cs1 (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS1;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_filter_bypass_cs0 (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_BYPASS_CS0;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	/* It should not be possible for the filter mode to be out of sync with the host state. */
	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_filter_bypass_cs1 (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_BYPASS_CS1;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	/* It should not be possible for the filter mode to be out of sync with the host state. */
	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_active_filter_dual (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_DUAL;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	/* Single flash handling never sets the filter mode to dual flash, so this configuration should
	 * not be possible. */
	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_DUAL, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_activate_on_por_only (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host_state_manager_save_read_only_activation_events (&host.host_state,
		HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_activate_on_por_and_reset (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host_state_manager_save_read_only_activation_events (&host.host_state,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_activate_on_por_and_at_run_time (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host_state_manager_save_read_only_activation_events (&host.host_state,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS0, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_static_init (CuTest *test)
{
	struct host_processor_single_testing host = {
		.test = host_processor_single_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base,
			&host.recovery_manager.base)
	};
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init_static (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_BYPASS_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_static_init_pulse_reset (CuTest *test)
{
	struct host_processor_single_testing host = {
		.test = host_processor_single_static_init_pulse_reset (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base,
			&host.recovery_manager.base, 100)
	};
	int status;
	spi_filter_flash_mode hw_mode = SPI_FILTER_FLASH_SINGLE_CS1;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init_static (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter, 0,
		MOCK_ARG_NOT_NULL);
	status = mock_expect_output (&host.filter.mock, 0, &hw_mode, sizeof (hw_mode), -1);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FILTER_FLASH_SINGLE_CS1, mode);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, current_ro);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, next_ro);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, apply_next_ro);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_null (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host.test.base.get_flash_config (NULL, &mode, &current_ro, &next_ro, &apply_next_ro);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.get_flash_config (&host.test.base, NULL, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, NULL, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, NULL,
		&apply_next_ro);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_get_flash_config_filter_mode_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	spi_filter_flash_mode mode;
	spi_filter_cs current_ro;
	spi_filter_cs next_ro;
	enum host_read_only_activation apply_next_ro;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.get_filter_mode, &host.filter,
		SPI_FILTER_GET_FILTER_MODE_FAILED, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_flash_config (&host.test.base, &mode, &current_ro, &next_ro,
		&apply_next_ro);
	CuAssertIntEquals (test, SPI_FILTER_GET_FILTER_MODE_FAILED, status);

	host_processor_single_testing_validate_and_release (test, &host);
}


// *INDENT-OFF*
TEST_SUITE_START (host_processor_single_get_flash_config);

TEST (host_processor_single_test_get_flash_config_bypass_nv_cs0_not_dirty_no_override);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs0_not_dirty_override_cs0);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs0_not_dirty_override_cs1);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs0_dirty_no_override);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs0_dirty_override_cs0);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs0_dirty_override_cs1);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs1_not_dirty_no_override);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs1_not_dirty_override_cs0);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs1_not_dirty_override_cs1);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs1_dirty_no_override);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs1_dirty_override_cs0);
TEST (host_processor_single_test_get_flash_config_bypass_nv_cs1_dirty_override_cs1);
TEST (host_processor_single_test_get_flash_config_active_nv_cs0_not_dirty_no_override);
TEST (host_processor_single_test_get_flash_config_active_nv_cs0_not_dirty_override_cs0);
TEST (host_processor_single_test_get_flash_config_active_nv_cs0_not_dirty_override_cs1);
TEST (host_processor_single_test_get_flash_config_active_nv_cs0_dirty_no_override);
TEST (host_processor_single_test_get_flash_config_active_nv_cs0_dirty_override_cs0);
TEST (host_processor_single_test_get_flash_config_active_nv_cs0_dirty_override_cs1);
TEST (host_processor_single_test_get_flash_config_active_nv_cs1_not_dirty_no_override);
TEST (host_processor_single_test_get_flash_config_active_nv_cs1_not_dirty_override_cs0);
TEST (host_processor_single_test_get_flash_config_active_nv_cs1_not_dirty_override_cs1);
TEST (host_processor_single_test_get_flash_config_active_nv_cs1_dirty_no_override);
TEST (host_processor_single_test_get_flash_config_active_nv_cs1_dirty_override_cs0);
TEST (host_processor_single_test_get_flash_config_active_nv_cs1_dirty_override_cs1);
TEST (host_processor_single_test_get_flash_config_active_filter_bypass_cs0);
TEST (host_processor_single_test_get_flash_config_active_filter_bypass_cs1);
TEST (host_processor_single_test_get_flash_config_active_filter_dual);
TEST (host_processor_single_test_get_flash_config_activate_on_por_only);
TEST (host_processor_single_test_get_flash_config_activate_on_por_and_reset);
TEST (host_processor_single_test_get_flash_config_activate_on_por_and_at_run_time);
TEST (host_processor_single_test_get_flash_config_static_init);
TEST (host_processor_single_test_get_flash_config_static_init_pulse_reset);
TEST (host_processor_single_test_get_flash_config_null);
TEST (host_processor_single_test_get_flash_config_filter_mode_error);

TEST_SUITE_END;
// *INDENT-ON*
