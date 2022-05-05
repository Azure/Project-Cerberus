// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "recovery/ocp_recovery_device.h"
#include "testing/mock/recovery/ocp_recovery_device_hw_mock.h"
#include "testing/mock/recovery/ocp_recovery_device_variable_cms_mock.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("ocp_recovery_device");


/**
 * The maximum number of CMS regions that are defined for testing.
 */
#define	OCP_RECOVERY_DEVICE_TESTING_MAX_CMS		5

/* Lengths of the recovery memory regions. */
#define	OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN			1024
#define	OCP_RECOVERY_DEVICE_TESTING_CMS_1_LEN			128
#define	OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN			16
#define	OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN			4

/* The number of 32-bit words make up each recovery memory region. */
#define	OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS			(OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN / 4)
#define	OCP_RECOVERY_DEVICE_TESTING_CMS_1_WORDS			(OCP_RECOVERY_DEVICE_TESTING_CMS_1_LEN / 4)
#define	OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS			(OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN / 4)
#define	OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS			(OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN / 4)

/**
 * Dependencies for testing OCP Recovery handling.
 */
struct ocp_recovery_device_testing {
	struct ocp_recovery_device_hw_mock hw;						/**< Mock for the recovery HW interface. */
	struct ocp_recovery_device_variable_cms_mock log;			/**< Mock for a log-backed CMS. */
	struct ocp_recovery_device_state state;						/**< Variable state of the recovery handler. */
	struct ocp_recovery_device test;							/**< Recovery handler under test. */
	uint8_t cms_0[OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN];		/**< Buffer for CMS code R/W region (type 0). */
	uint8_t cms_1[OCP_RECOVERY_DEVICE_TESTING_CMS_1_LEN];		/**< Buffer for CMS log RO region (type 1). */
	uint8_t cms_5[OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN];		/**< Buffer for CMS vendor R/W region (type 5). */
	uint8_t cms_6[OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN];		/**< Buffer for CMS vendor RO region (type 6). */
	struct ocp_recovery_device_cms cms[OCP_RECOVERY_DEVICE_TESTING_MAX_CMS];	/**< List of CMS regions. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param recovery Testing dependencies to initialize.
 */
static void ocp_recovery_device_testing_init_dependencies (CuTest *test,
	struct ocp_recovery_device_testing *recovery)
{
	int status;

	status = ocp_recovery_device_hw_mock_init (&recovery->hw);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_variable_cms_mock_init (&recovery->log);
	CuAssertIntEquals (test, 0, status);

	memset (recovery->cms_0, 0, sizeof (recovery->cms_0));
	memset (recovery->cms_1, 0, sizeof (recovery->cms_1));
	memset (recovery->cms_5, 0, sizeof (recovery->cms_5));
	memset (recovery->cms_6, 0, sizeof (recovery->cms_6));

	recovery->cms[0].base_addr = recovery->cms_0;
	recovery->cms[0].length = sizeof (recovery->cms_0);
	recovery->cms[0].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE;

	recovery->cms[1].base_addr = recovery->cms_1;
	recovery->cms[1].length = sizeof (recovery->cms_1);
	recovery->cms[1].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_LOG;

	recovery->cms[2].variable = &recovery->log.base;
	recovery->cms[2].length = 0;
	recovery->cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_LOG;

	recovery->cms[3].base_addr = recovery->cms_5;
	recovery->cms[3].length = sizeof (recovery->cms_5);
	recovery->cms[3].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW;

	recovery->cms[4].base_addr = recovery->cms_6;
	recovery->cms[4].length = sizeof (recovery->cms_6);
	recovery->cms[4].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RO;
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param recovery Testing dependencies to release.
 */
static void ocp_recovery_device_testing_release_dependencies (CuTest *test,
	struct ocp_recovery_device_testing *recovery)
{
	int status;

	status = ocp_recovery_device_hw_mock_validate_and_release (&recovery->hw);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_variable_cms_mock_validate_and_release (&recovery->log);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize on OCP Recovery device handler for testing.  Control how the HW interface gets
 * configured for use with the handler.
 *
 * @param test The test framework.
 * @param recovery Testing components to initialize.
 * @param cms_list The list of memory regions to use for testing.
 * @param cms_count The number of memory regions in the list.
 * @param reset_device True to enable reset_device support in the HW interface.
 * @param reset_management True to enable reset_management support in the HW interface.
 * @param activate_recovery True to enable activate_recovery support in the HW interface.
 * @param force_recovery True to support forced recovery in the HW interface.
 */
static void ocp_recovery_device_testing_init_config_hw_interface (CuTest *test,
	struct ocp_recovery_device_testing *recovery,
	struct ocp_recovery_device_cms *cms_list, size_t cms_count, bool reset_device,
	bool reset_management, bool activate_recovery, bool force_recovery)
{
	ocp_recovery_device_testing_init_dependencies (test, recovery);

	if (!reset_device) {
		recovery->hw.base.reset_device = NULL;
	}
	if (!reset_management) {
		recovery->hw.base.reset_management = NULL;
	}
	if (!activate_recovery) {
		recovery->hw.base.activate_recovery = NULL;
	}
	recovery->hw.base.supports_forced_recovery = force_recovery;

	ocp_recovery_device_init (&recovery->test, &recovery->state, &recovery->hw.base, cms_list,
		cms_count);
}

/**
 * Initialize an OCP Recovery device handler for testing.  This initialized the HW interface to the
 * default values from the mock (i.e. all the pointers are set and force recovery is false).
 *
 * @param test The test framework.
 * @param recovery Testing components to initialize.
 * @param cms_list The list of memory regions to use for testing.
 * @param cms_count The number of memory regions in the list.
 */
static void ocp_recovery_device_testing_init (CuTest *test,
	struct ocp_recovery_device_testing *recovery,
	struct ocp_recovery_device_cms *cms_list, size_t cms_count)
{
	ocp_recovery_device_testing_init_dependencies (test, recovery);
	ocp_recovery_device_testing_init_config_hw_interface (test, recovery, cms_list, cms_count,
		true, true, true, false);
}

/**
 * Release OCP recovery handling test components and validate all mocks.
 *
 * @param test The test framework.
 * @param recovery Testing components to release.
 */
static void ocp_recovery_device_testing_release (CuTest *test,
	struct ocp_recovery_device_testing *recovery)
{
	ocp_recovery_device_testing_release_dependencies (test, recovery);
	ocp_recovery_device_release (&recovery->test);
}

/**
 * Check the device status response for a specific protocol status code.
 *
 * @param test The test framework.
 * @param recovery Testing components to use for the check.
 * @param protocol_status The expected protocol status code.
 */
static void ocp_recovery_device_testing_check_protocol_status (CuTest *test,
	struct ocp_recovery_device_testing *recovery, uint8_t protocol_status)
{
	int status;
	uint8_t expected[] = {
		0x00,protocol_status,0x00,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00
	};
	enum ocp_recovery_device_status_code status_code = 0;
	enum ocp_recovery_recovery_reason_code reason_code = 0;
	struct ocp_recovery_device_status_vendor vendor = {
		.failure_id = 0,
		.error_code = 0
	};
	union ocp_recovery_device_cmd_buffer output;

	status = ocp_recovery_device_start_new_command (&recovery->test,
		OCP_RECOVERY_CMD_DEVICE_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery->hw.mock, recovery->hw.base.get_device_status, &recovery->hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&recovery->hw.mock, 0, &status_code, sizeof (status_code), -1);
	status |= mock_expect_output (&recovery->hw.mock, 1, &reason_code, sizeof (reason_code), -1);
	status |= mock_expect_output (&recovery->hw.mock, 2, &vendor, sizeof (vendor), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery->test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&recovery->hw.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Check the recovery status response for a specific recovery status code.
 *
 * @param test The test framework.
 * @param recovery Testing components to use for the check.
 * @param recovery_status The expected recovery status code.
 */
static void ocp_recovery_device_testing_check_recovery_status (CuTest *test,
	struct ocp_recovery_device_testing *recovery, uint8_t recovery_status)
{
	int status;
	uint8_t expected[] = {
		recovery_status,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	status = ocp_recovery_device_start_new_command (&recovery->test,
		OCP_RECOVERY_CMD_RECOVERY_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery->test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Check the indirect status response for specific region information.
 *
 * @param test The test framework.
 * @param recovery Testing components to use for the check.
 * @param indirect_status The expected indirect status code.
 * @param region_type The expected indirect region type.
 * @param indirect_size The expected indirect region size.
 */
static void ocp_recovery_device_testing_check_indirect_status (CuTest *test,
	struct ocp_recovery_device_testing *recovery, uint8_t indirect_status, uint8_t region_type,
	uint32_t indirect_size)
{
	int status;
	uint8_t expected[] = {
		indirect_status, region_type, indirect_size & 0xff, (indirect_size >> 8) & 0xff,
		(indirect_size >> 16) & 0xff, (indirect_size >> 24) & 0xff
	};
	union ocp_recovery_device_cmd_buffer output;

	status = ocp_recovery_device_start_new_command (&recovery->test,
		OCP_RECOVERY_CMD_INDIRECT_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery->test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Set the indirect control values for a particular region and offset.
 *
 * @param test The test framework.
 * @param recovery Testing components to use for the check.
 * @param cms The memory region to select.
 * @param offset The offset in the region to access.
 */
static void ocp_recovery_device_testing_set_indirect_ctrl (CuTest *test,
	struct ocp_recovery_device_testing *recovery, uint8_t cms, uint32_t offset)
{
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			cms, 0x00, offset & 0xff, (offset >> 8) & 0xff, (offset >> 16) & 0xff,
			(offset >> 24) & 0xff
		}
	};
	size_t msg_length = 6;

	status = ocp_recovery_device_start_new_command (&recovery->test,
		OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery->test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Check the indirect control values for a particular region and offset.
 *
 * @param test The test framework.
 * @param recovery Testing components to use for the check.
 * @param cms The expected memory region to check.
 * @param offset The expected offset in the region to check.
 */
static void ocp_recovery_device_testing_check_indirect_ctrl (CuTest *test,
	struct ocp_recovery_device_testing *recovery, uint8_t cms, uint32_t offset)
{
	int status;
	uint8_t expected[] = {
		cms, 0x00, offset & 0xff, (offset >> 8) & 0xff, (offset >> 16) & 0xff,
		(offset >> 24) & 0xff
	};
	union ocp_recovery_device_cmd_buffer output;

	status = ocp_recovery_device_start_new_command (&recovery->test,
		OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery->test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void ocp_recovery_device_test_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_init_ro_region_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[1].length += 1;
	recovery.cms[4].length -= 1;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_init_ro_polling_region_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[1].length += 1;
	recovery.cms[1].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_LOG_POLLING;
	recovery.cms[4].length -= 1;
	recovery.cms[4].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RO_POLLING;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_init_null (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init (NULL, &recovery.state, &recovery.hw.base, NULL, 0);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	status = ocp_recovery_device_init (&recovery.test, NULL, &recovery.hw.base, NULL, 0);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	status = ocp_recovery_device_init (&recovery.test, &recovery.state, NULL, NULL, 0);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base, NULL, 1);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
}

static void ocp_recovery_device_test_init_rw_region_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[0].length += 1;
	recovery.cms[3].length -= 1;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED, status);

	recovery.cms[0].length -= 1;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
}

static void ocp_recovery_device_test_init_rw_polling_region_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[0].length += 1;
	recovery.cms[0].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE_POLLING;
	recovery.cms[3].length -= 1;
	recovery.cms[3].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW_POLLING;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED, status);

	recovery.cms[0].length -= 1;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
}

static void ocp_recovery_device_test_init_log_region_rw (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_LOG, status);

	recovery.cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_LOG, status);

	recovery.cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE_POLLING;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_LOG, status);

	recovery.cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW_POLLING;
	status = ocp_recovery_device_init (&recovery.test, &recovery.state, &recovery.hw.base,
		recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_LOG, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
}

static void ocp_recovery_device_test_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, NULL, 0);
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_static_init_ro_region_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[1].length += 1;
	recovery.cms[4].length -= 1;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_static_init_ro_polling_region_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[1].length += 1;
	recovery.cms[1].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_LOG_POLLING;
	recovery.cms[4].length -= 1;
	recovery.cms[4].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RO_POLLING;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_init_state_null (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (NULL,
		&recovery.hw.base, NULL, 0);
	int status;

	TEST_START;

	status = ocp_recovery_device_init_state (NULL);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);
}

static void ocp_recovery_device_test_static_init_rw_region_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[0].length += 1;
	recovery.cms[3].length -= 1;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED, status);

	recovery.cms[0].length -= 1;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
}

static void ocp_recovery_device_test_static_init_rw_polling_region_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[0].length += 1;
	recovery.cms[0].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE_POLLING;
	recovery.cms[3].length -= 1;
	recovery.cms[3].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW_POLLING;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED, status);

	recovery.cms[0].length -= 1;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
}

static void ocp_recovery_device_test_static_init_log_region_rw (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_LOG, status);

	recovery.cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_LOG, status);

	recovery.cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE_POLLING;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_LOG, status);

	recovery.cms[2].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW_POLLING;
	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RW_LOG, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
}

static void ocp_recovery_device_test_release_null (CuTest *test)
{
	TEST_START;

	ocp_recovery_device_release (NULL);
}

static void ocp_recovery_device_test_prot_cap_no_optional_support (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x11,0x00,0x00,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_device = NULL;
	recovery.hw.base.reset_management = NULL;
	recovery.hw.base.activate_recovery = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_prot_cap_supports_device_reset (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x19,0x00,0x00,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_management = NULL;
	recovery.hw.base.activate_recovery = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_prot_cap_management_reset (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x15,0x00,0x00,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_device = NULL;
	recovery.hw.base.activate_recovery = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_prot_cap_all_resets_forced_recovery (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x1f,0x00,0x00,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.activate_recovery = NULL;
	recovery.hw.base.supports_forced_recovery = true;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_prot_cap_cms_regions (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x31,0x00,0x01,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms, 1);

	recovery.hw.base.reset_device = NULL;
	recovery.hw.base.reset_management = NULL;
	recovery.hw.base.activate_recovery = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_prot_cap_activate_recovery_image (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0xb1,0x00,0x01,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms, 1);

	recovery.hw.base.reset_device = NULL;
	recovery.hw.base.reset_management = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_prot_cap_activate_recovery_image_no_cms_regions (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x11,0x00,0x00,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_device = NULL;
	recovery.hw.base.reset_management = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_prot_cap_all_optional_support (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0xbf,0x00,0x02,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms, 2);

	recovery.hw.base.supports_forced_recovery = true;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_prot_cap_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, 3);
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0xbf,0x00,0x03,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	recovery.hw.base.supports_forced_recovery = true;

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_prot_cap_write_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t message[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x11,0x00,0x00,0x10,0x00
	};

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test,
		(union ocp_recovery_device_cmd_buffer*) message, sizeof (message));
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_device_id_no_vendor_string (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x00,0x00,0x22,0x11,0x44,0x33,0x66,0x55,0x88,0x77,0x05,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};
	struct ocp_recovery_device_id hw_id = {
		.base = {
			.id_type = 0,
			.vendor_length = 0,
			.pci = {
				.vendor_id = 0x1122,
				.device_id = 0x3344,
				.subsystem_vendor_id = 0x5566,
				.subsystem_device_id = 0x7788,
				.revsion_id = 0x05
			}
		}
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	memset (hw_id.base.pci.pad, 0, sizeof (hw_id.base.pci.pad));

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_DEVICE_ID);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.get_device_id, &recovery.hw,
		2 + sizeof (struct ocp_recovery_device_id_pci), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&recovery.hw.mock, 0, &hw_id, sizeof (hw_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_device_id_with_vendor_string (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x02,0x04,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,
		0xee,0xff,0x00,0x00,0x00,0x00,0x00,0x00,'T','e','s','t'
	};
	struct ocp_recovery_device_id hw_id = {
		.base = {
			.id_type = 2,
			.vendor_length = 4,
			.uuid = {
				.uuid = {
					0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
				}
			},
		},
		.vendor_string = "Test"
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	memset (hw_id.base.uuid.pad, 0, sizeof (hw_id.base.uuid.pad));

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_DEVICE_ID);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.get_device_id, &recovery.hw,
		2 + sizeof (struct ocp_recovery_device_id_uuid) + 4, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&recovery.hw.mock, 0, &hw_id, sizeof (hw_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_device_id_get_id_error (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_DEVICE_ID);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.get_device_id, &recovery.hw,
		OCP_RECOVERY_DEVICE_GET_DEV_ID_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_GET_DEV_ID_FAILED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_device_id_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	uint8_t expected[] = {
		0x00,0x00,0x22,0x11,0x44,0x33,0x66,0x55,0x88,0x77,0x05,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};
	struct ocp_recovery_device_id hw_id = {
		.base = {
			.id_type = 0,
			.vendor_length = 0,
			.pci = {
				.vendor_id = 0x1122,
				.device_id = 0x3344,
				.subsystem_vendor_id = 0x5566,
				.subsystem_device_id = 0x7788,
				.revsion_id = 0x05
			}
		}
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_DEVICE_ID);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.get_device_id, &recovery.hw,
		2 + sizeof (struct ocp_recovery_device_id_pci), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&recovery.hw.mock, 0, &hw_id, sizeof (hw_id), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_device_id_write_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t message[] = {
		0x00,0x00,0x22,0x11,0x44,0x33,0x66,0x55,0x88,0x77,0x05,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_DEVICE_ID);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test,
		(union ocp_recovery_device_cmd_buffer*) message, sizeof (message));
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_device_status (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x06,0x00,0x0f,0x00,0x00,0x00,0x05,0x01,0x33,0x22,0x11,0x7f
	};
	enum ocp_recovery_device_status_code status_code = 0x06;
	enum ocp_recovery_recovery_reason_code reason_code = 0x0f;
	struct ocp_recovery_device_status_vendor vendor = {
		.failure_id = 0x1,
		.error_code = 0x7f112233
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_DEVICE_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.get_device_status, &recovery.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&recovery.hw.mock, 0, &status_code, sizeof (status_code), -1);
	status |= mock_expect_output (&recovery.hw.mock, 1, &reason_code, sizeof (reason_code), -1);
	status |= mock_expect_output (&recovery.hw.mock, 2, &vendor, sizeof (vendor), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_device_status_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	uint8_t expected[] = {
		0x0e,0x00,0x05,0x00,0x00,0x00,0x05,0x10,0x56,0x34,0x12,0x7f
	};
	enum ocp_recovery_device_status_code status_code = 0x0e;
	enum ocp_recovery_recovery_reason_code reason_code = 0x05;
	struct ocp_recovery_device_status_vendor vendor = {
		.failure_id = 0x10,
		.error_code = 0x7f123456
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_DEVICE_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.get_device_status, &recovery.hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&recovery.hw.mock, 0, &status_code, sizeof (status_code), -1);
	status |= mock_expect_output (&recovery.hw.mock, 1, &reason_code, sizeof (reason_code), -1);
	status |= mock_expect_output (&recovery.hw.mock, 2, &vendor, sizeof (vendor), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_device_status_write_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t message[] = {
		0x06,0x00,0x0f,0x00,0x00,0x00,0x05,0x01,0x33,0x22,0x11,0x7f
	};

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_DEVICE_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test,
		(union ocp_recovery_device_cmd_buffer*) message, sizeof (message));
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_read_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_device (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.reset_device, &recovery.hw, 0,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_management (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x00,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.reset_management, &recovery.hw, 0,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_device_with_forced_recovery (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x0f,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x0f,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.supports_forced_recovery = true;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.reset_device, &recovery.hw, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_management_with_forced_recovery (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x0f,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x0f,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.supports_forced_recovery = true;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.reset_management, &recovery.hw, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_device_no_reset_forced_recovery (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x0f,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x0f,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.supports_forced_recovery = true;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_device_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_device = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_management_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x00,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_management = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_forced_recovery_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x0f,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_enable_bus_mastering (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x01
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_incomplete_command (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00
		}
	};
	size_t msg_length = 2;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMD_INCOMPLETE, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_extra_bytes (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x00,0x00,0x00
		}
	};
	size_t msg_length = 4;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_reset_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x0f,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x0f,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	recovery.hw.base.supports_forced_recovery = true;

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.reset_management, &recovery.hw, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&test_static, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_recovery_status_no_cms_regions (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_RECOVERY_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_status_no_activate_support (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_config_hw_interface (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, true, true, false, false);

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_RECOVERY_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_status_recovery_supported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_RECOVERY_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_status_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	uint8_t expected[] = {
		0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_RECOVERY_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_recovery_status_write_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t message[] = {
		0x00,0x00
	};

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_RECOVERY_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test,
		(union ocp_recovery_device_cmd_buffer*) message, sizeof (message));
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_read_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_read_request_no_cms_regions (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_image (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.activate_recovery, &recovery.hw, 0,
		MOCK_ARG (&recovery.cms[0]), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x03);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_no_activate_image (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_only_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x01,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	recovery.cms[1].type = 0;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_only_activate_image (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_image_failure (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;
	bool auth_error = false;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.activate_recovery, &recovery.hw,
		OCP_RECOVERY_DEVICE_ACTIVATE_REC_FAILED, MOCK_ARG (&recovery.cms[0]), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&recovery.hw.mock, 1, &auth_error, sizeof (auth_error), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_ACTIVATE_REC_FAILED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x0c);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_image_auth_failure (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;
	bool auth_error = true;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.activate_recovery, &recovery.hw,
		OCP_RECOVERY_DEVICE_ACTIVATE_REC_FAILED, MOCK_ARG (&recovery.cms[0]), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&recovery.hw.mock, 1, &auth_error, sizeof (auth_error), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_ACTIVATE_REC_FAILED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x0d);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_image_non_code_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x01,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x01,0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMS_NOT_CODE_REGION, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x0f);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_no_activate_image_non_code_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x01,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x01,0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMS_NOT_CODE_REGION, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x0f);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_image_non_zero_cms_index (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			OCP_RECOVERY_DEVICE_TESTING_MAX_CMS - 1,0x01,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS - 1,0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	/* Turn this into a code region. */
	recovery.cms[OCP_RECOVERY_DEVICE_TESTING_MAX_CMS - 1].type = 0;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.activate_recovery, &recovery.hw, 0,
		MOCK_ARG (&recovery.cms[OCP_RECOVERY_DEVICE_TESTING_MAX_CMS - 1]),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x03);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_image_cms_out_of_range (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			OCP_RECOVERY_DEVICE_TESTING_MAX_CMS,0x01,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_no_activate_image_cms_out_of_range (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			OCP_RECOVERY_DEVICE_TESTING_MAX_CMS,0x01,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_recovery_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_config_hw_interface (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, true, true, false, false);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x00);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_recovery_unsupported_no_activate (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_config_hw_interface (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, true, true, false, false);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x00);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_recovery_unsupported_only_activate (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_config_hw_interface (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, true, true, false, false);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x00);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_recovery_unsupported_only_cms (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x01,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_config_hw_interface (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, true, true, false, false);

	recovery.cms[1].type = 0;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x00);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_only_non_code_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x01,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_only_out_of_range_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			OCP_RECOVERY_DEVICE_TESTING_MAX_CMS,0x00,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	recovery.cms[1].type = 0;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_activate_image_stored_image (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x02,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_no_activate_image_stored_image (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x02,0x00
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_recovery_status (test, &recovery, 0x01);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_incomplete_command (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x0f
		}
	};
	size_t msg_length = 2;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMD_INCOMPLETE, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_extra_bytes (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x0f,0x00
		}
	};
	size_t msg_length = 4;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_recovery_ctrl_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x01,0x0f
		}
	};
	size_t msg_length = 3;
	uint8_t expected[] = {
		0x00,0x01,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.activate_recovery, &recovery.hw, 0,
		MOCK_ARG (&recovery.cms[0]), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&test_static, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_RECOVERY_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_hw_status (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_HW_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_hw_status_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_HW_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_hw_status_write_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t message[] = {
		0x02,0x00,0x40,0x00,0x00
	};

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_HW_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test,
		(union ocp_recovery_device_cmd_buffer*) message, sizeof (message));
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_status_default_cms_0 (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[6] = {
		0x00,0x00,0x00,0x01,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_INDIRECT_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_status_unaligned_region_length (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[6] = {
		0x00,0x00,0x00,0x01,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	recovery.cms[0].length -= 2;

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_INDIRECT_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_status_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_INDIRECT_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_status_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	uint8_t expected[6] = {
		0x00,0x00,0x00,0x01,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_INDIRECT_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_indirect_status_write_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t message[] = {
		0x00,0x00,0x00,0x01,0x00,0x00
	};

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_INDIRECT_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test,
		(union ocp_recovery_device_cmd_buffer*) message, sizeof (message));
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_read_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		0x00,0x00,0x00,0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_read_request_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_cms_0 (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		0x00,0x00,0x00,0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_set_offset (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x10,0x20,0x30,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		0x00,0x00,0x10,0x20,0x30,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_non_zero_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			OCP_RECOVERY_DEVICE_TESTING_MAX_CMS - 1,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS - 1,0x00,0x00,0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 6,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_out_of_range_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			OCP_RECOVERY_DEVICE_TESTING_MAX_CMS,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS,0x00,0x00,0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 7, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_offset_not_4byte_aligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00,0x21,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		0x01,0x00,0x24,0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		OCP_RECOVERY_DEVICE_TESTING_CMS_1_WORDS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_cms_log (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		0x02,0x00,0x00,0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log, 256);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		256 / 4);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_cms_log_size_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		0x02,0x00,0x00,0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log, 257);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		260 / 4);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_cms_log_size_error (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		0x02,0x00,0x00,0x00,0x00,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		OCP_RECOVERY_DEVICE_CMS_SIZE_FAILED);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test,
		OCP_RECOVERY_CMD_INDIRECT_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMS_SIZE_FAILED, status);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_incomplete_command (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 5;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMD_INCOMPLETE, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_extra_bytes (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 7;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_ctrl_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x02,0x00,0x04,0x03,0x02,0x00
		}
	};
	size_t msg_length = 6;
	uint8_t expected[] = {
		0x02,0x00,0x04,0x03,0x02,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&test_static, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_indirect_data_read (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[252];
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_0, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	memcpy (expected, recovery.cms_0, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_sequential (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[3][252];
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_0, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	memcpy (expected[0], recovery.cms_0, sizeof (expected[0]));
	memcpy (expected[1], &recovery.cms_0[sizeof (expected[0])], sizeof (expected[0]));
	memcpy (expected[2], &recovery.cms_0[sizeof (expected[0]) * 2], sizeof (expected[0]));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected[0]), status);

	status = testing_validate_array (expected[0], output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, sizeof (expected[0]));

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected[0]), status);

	status = testing_validate_array (expected[1], output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, sizeof (expected[0]) * 2);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected[0]), status);

	status = testing_validate_array (expected[2], output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, sizeof (expected[0]) * 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_less_than_max (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[OCP_RECOVERY_DEVICE_TESTING_CMS_1_LEN];
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_1, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, sizeof (recovery.cms_1));
	memcpy (expected, recovery.cms_1, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 1, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		OCP_RECOVERY_DEVICE_TESTING_CMS_1_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 1, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_at_offset (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[252];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = 0x40;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_0, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	memcpy (expected, &recovery.cms_0[offset], sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0,
		offset + sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_less_than_max_at_offset (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	const uint32_t offset = 0x40;
	uint8_t expected[OCP_RECOVERY_DEVICE_TESTING_CMS_1_LEN - offset];
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_1, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, sizeof (recovery.cms_1));
	memcpy (expected, &recovery.cms_1[offset], sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 1, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		OCP_RECOVERY_DEVICE_TESTING_CMS_1_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 1,
		offset + sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_sequential_with_wrap (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected_end[0x40];
	uint8_t expected_wrap[2][252];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN - sizeof (expected_end);

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_0, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	memcpy (expected_end, &recovery.cms_0[offset], sizeof (expected_end));
	memcpy (expected_wrap[0], recovery.cms_0, sizeof (expected_wrap[0]));
	memcpy (expected_wrap[1], &recovery.cms_0[sizeof (expected_wrap[0])],
		sizeof (expected_wrap[0]));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_end), status);

	status = testing_validate_array (expected_end, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_wrap[0]), status);

	status = testing_validate_array (expected_wrap[0], output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, sizeof (expected_wrap[0]));

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_wrap[0]), status);

	status = testing_validate_array (expected_wrap[1], output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, sizeof (expected_wrap));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_sequential_with_wrap_status_sticky_on_read (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected_end[0x40];
	uint8_t expected_wrap[2][252];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN - sizeof (expected_end);

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_0, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	memcpy (expected_end, &recovery.cms_0[offset], sizeof (expected_end));
	memcpy (expected_wrap[0], recovery.cms_0, sizeof (expected_wrap[0]));
	memcpy (expected_wrap[1], &recovery.cms_0[sizeof (expected_wrap[0])],
		sizeof (expected_wrap[0]));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_end), status);

	status = testing_validate_array (expected_end, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_wrap[0]), status);

	status = testing_validate_array (expected_wrap[0], output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	/* Don't read the indirect status here to make sure the status stays after the next command. */
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, sizeof (expected_wrap[0]));

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_wrap[0]), status);

	status = testing_validate_array (expected_wrap[1], output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, sizeof (expected_wrap));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_at_offset_out_of_range (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN + 4;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_5, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN);
	memcpy (expected, recovery.cms_5, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_at_offset_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN - 4];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = 2;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_5, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN);
	memcpy (expected, &recovery.cms_5[4], sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_at_offset_out_of_range_unaligned (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN + 3;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_5, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN);
	memcpy (expected, recovery.cms_5, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_unaligned_region_length (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	size_t data_length = 13;
	uint8_t expected[16] = {0};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memset (output.bytes, 0xff, sizeof (output.bytes));
	memcpy (recovery.cms_5, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, sizeof (recovery.cms_5));
	memcpy (expected, recovery.cms_5, data_length);
	recovery.cms[3].length = data_length;
	recovery.cms[3].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RO;

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 6, 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, 16);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[252];
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (expected, HASH_TESTING_FULL_BLOCK_2048, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		sizeof (expected), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected, sizeof (expected), 2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		HASH_TESTING_FULL_BLOCK_2048_LEN / 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log_at_offset (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[16];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = 0x40;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (expected, HASH_TESTING_FULL_BLOCK_2048, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		offset + sizeof (expected));

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		sizeof (expected), MOCK_ARG (offset), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected, sizeof (expected), 2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		offset + sizeof (expected));

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		(offset + sizeof (expected)) / 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2,
		offset + sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log_sequential_with_wrap (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected_end[4];
	uint8_t expected_start[252];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = sizeof (expected_start);

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (expected_end, &HASH_TESTING_FULL_BLOCK_2048[252], sizeof (expected_end));
	memcpy (expected_start, HASH_TESTING_FULL_BLOCK_2048, sizeof (expected_start));

	/* Read the end of the log. */
	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		sizeof (expected_end), MOCK_ARG (offset), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected_end, sizeof (expected_end), 2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_end), status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		HASH_TESTING_FULL_BLOCK_2048_LEN / 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	status = testing_validate_array (expected_end, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	/* Wrap around and read the beginning. */
	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		sizeof (expected_start), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected_start, sizeof (expected_start),
		2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_start), status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 1,
		HASH_TESTING_FULL_BLOCK_2048_LEN / 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2, sizeof (expected_start));

	status = testing_validate_array (expected_start, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	/* Read the end again. */
	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		sizeof (expected_end), MOCK_ARG (offset), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected_end, sizeof (expected_end), 2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected_end), status);

	status = testing_validate_array (expected_end, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		HASH_TESTING_FULL_BLOCK_2048_LEN / 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log_at_offset_out_of_range (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[16];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = 0x40;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (expected, HASH_TESTING_FULL_BLOCK_2048, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		offset - 4);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		sizeof (expected), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected, sizeof (expected), 2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		offset - 4);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 1,
		(offset - 4) / 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log_at_offset_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	const size_t length = 16;
	uint8_t expected[length - 4];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = 2;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (expected, &HASH_TESTING_FULL_BLOCK_2048[4], sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log, length);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		sizeof (expected), MOCK_ARG (4), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected, sizeof (expected), 2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log, length);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1, length/ 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2, length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log_at_offset_out_of_range_unaligned (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	const size_t length = 0x40;
	uint8_t expected[16];
	union ocp_recovery_device_cmd_buffer output;
	uint32_t offset = length + 3;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (expected, HASH_TESTING_FULL_BLOCK_2048, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log, length);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		sizeof (expected), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected, sizeof (expected), 2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log, length);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 1, length / 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log_unaligned_log_data (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	size_t data_length = 15;
	uint8_t expected[16] = {0};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memset (output.bytes, 0xff, sizeof (output.bytes));
	memcpy (expected, HASH_TESTING_FULL_BLOCK_2048, data_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		data_length);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		data_length, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (252));
	status |= mock_expect_output (&recovery.log.mock, 1, expected, data_length, 2);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		data_length);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1, 4);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 2, 16);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log_size_error (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		OCP_RECOVERY_DEVICE_CMS_SIZE_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMS_SIZE_FAILED, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_from_log_data_error (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 2, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.log.mock, recovery.log.base.get_size, &recovery.log,
		HASH_TESTING_FULL_BLOCK_2048_LEN);

	status |= mock_expect (&recovery.log.mock, recovery.log.base.get_data, &recovery.log,
		OCP_RECOVERY_DEVICE_CMS_DATA_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (252));

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMS_DATA_FAILED, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_min_region (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN];
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_6, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, sizeof (expected));
	memcpy (expected, recovery.cms_6, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 4, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 6,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 4, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_min_region_multiple (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN];
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (recovery.cms_6, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, sizeof (expected));
	memcpy (expected, recovery.cms_6, sizeof (expected));

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 4, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 6,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 4, sizeof (expected));

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	memset (&output, 0, sizeof (output));
	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 6,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 4, sizeof (expected));

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	memset (&output, 0, sizeof (output));
	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 6,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 4, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_out_of_range_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 7, 0);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_read_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 252;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_0, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_sequential (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message[3];
	size_t msg_length = 252;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message[0].bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);
	memcpy (message[1].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length], msg_length);
	memcpy (message[2].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length * 2], msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[0], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[0].bytes, recovery.cms_0, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[1], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[1].bytes, &recovery.cms_0[msg_length], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length * 2);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[2], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[2].bytes, &recovery.cms_0[msg_length * 2], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length * 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_less_than_max (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 128;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_0, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_at_offset (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 252;
	uint32_t offset = 0x40;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, &recovery.cms_0[offset], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, offset + msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_less_than_max_at_offset (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 128;
	uint32_t offset = 0x40;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, &recovery.cms_0[offset], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, offset + msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_sequential_with_wrap (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message[3];
	size_t msg_length = 0x40;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN - 0x40;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message[0].bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);
	memcpy (message[1].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length], msg_length);
	memcpy (message[2].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length * 2], msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[0], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[0].bytes, &recovery.cms_0[offset], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[1], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[1].bytes, recovery.cms_0, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[2], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[2].bytes, &recovery.cms_0[msg_length], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length * 2);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_sequential_with_wrap_status_sticky_on_write (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message[3];
	size_t msg_length = 0x40;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN - 0x40;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message[0].bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);
	memcpy (message[1].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length], msg_length);
	memcpy (message[2].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length * 2], msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[0], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[0].bytes, &recovery.cms_0[offset], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[1], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[1].bytes, recovery.cms_0, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	/* Don't read the indirect status here to make sure the status stays after the next command. */
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[2], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[2].bytes, &recovery.cms_0[msg_length], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length * 2);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_at_offset_out_of_range (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN + 4;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_5, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_at_offset_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 252;
	uint32_t offset = 0x41;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, &recovery.cms_0[0x44], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, 0x44 + msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_at_offset_out_of_range_unaligned (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN + 2;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_5, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 5;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_5, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, 8);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_sequential_unaligned (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message[3];
	size_t msg_length = 6;
	size_t aligned_length = 8;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memset (&message, 0, sizeof (message));
	memcpy (message[0].bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);
	memcpy (message[1].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length], msg_length);
	memcpy (message[2].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length * 2], msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[0], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[0].bytes, recovery.cms_0, aligned_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, aligned_length);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[1], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[1].bytes, &recovery.cms_0[aligned_length], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, aligned_length * 2);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[2], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[2].bytes, &recovery.cms_0[aligned_length * 2],
		msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, aligned_length * 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_wrap_in_middle (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 252;
	size_t msg_end = 16;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN - msg_end;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, &recovery.cms_0[offset], msg_end);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&message.bytes[msg_end], recovery.cms_0, msg_length - msg_end);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length - msg_end);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_sequential_with_wrap_in_middle (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message[3];
	size_t msg_length = 252;
	size_t msg_end = 16;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN - (msg_end + msg_length);

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message[0].bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);
	memcpy (message[1].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length], msg_length);
	memcpy (message[2].bytes, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[msg_length * 2], msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[0], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[0].bytes, &recovery.cms_0[offset], msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN - msg_end);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[1], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[1].bytes, &recovery.cms_0[offset + msg_length],
		msg_end);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&message[1].bytes[msg_end], recovery.cms_0,
		msg_length - msg_end);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length - msg_end);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message[2], msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message[2].bytes, &recovery.cms_0[msg_length - msg_end],
		msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0,
		(msg_length * 2) - msg_end);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_min_region (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);
	recovery.cms[3].length = OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN;

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_5, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_min_region_multiple (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);
	recovery.cms[3].length = OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN;

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_5, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, msg_length);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	memset (recovery.cms_5, 0, sizeof (recovery.cms_5));
	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_5, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, msg_length);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	memset (recovery.cms_5, 0, sizeof (recovery.cms_5));
	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, recovery.cms_5, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_multiple_wrap_single_write (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN * 4;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);
	recovery.cms[3].length = OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN;

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&message.bytes[OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN * 3],
		recovery.cms_5, OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3,
		OCP_RECOVERY_DEVICE_TESTING_CMS_6_LEN);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_zero_length (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 0;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_out_of_range_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 252;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 7, 0);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_ro_cms (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = OCP_RECOVERY_DEVICE_TESTING_CMS_1_LEN;
	uint8_t expected[OCP_RECOVERY_DEVICE_TESTING_CMS_1_LEN];
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 1, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_CMS, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x02, 1,
		OCP_RECOVERY_DEVICE_TESTING_CMS_1_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 1, 0);

	/* Cleared on read. */
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 1,
		OCP_RECOVERY_DEVICE_TESTING_CMS_1_WORDS);

	/* Trigger the error again. */
	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_CMS, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	/* Don't read the indirect status here to make sure the status stays after the next command. */
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 1, 0);

	/* Sticky on CMS switch. */
	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, 0);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x02, 0,
		OCP_RECOVERY_DEVICE_TESTING_CMS_0_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, 0);

	/* Trigger the error again. */
	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 1, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_RO_CMS, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	/* Don't read the indirect status here to make sure the status stays after the next command. */
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 1, 0);

	/* Sticky on read. */
	memcpy (recovery.cms_1, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		OCP_RECOVERY_DEVICE_TESTING_CMS_1_LEN);
	memcpy (expected, recovery.cms_1, sizeof (expected));

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x02, 1,
		OCP_RECOVERY_DEVICE_TESTING_CMS_1_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 1, sizeof (expected));

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_unsupported (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 252;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_write_and_read_full_region (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 3, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, msg_length);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, msg_length, status);

	status = testing_validate_array (message.bytes, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 5,
		OCP_RECOVERY_DEVICE_TESTING_CMS_5_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 3, msg_length);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_status_sticky_on_cms_change (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = 252;
	size_t msg_end = 16;
	uint32_t offset = OCP_RECOVERY_DEVICE_TESTING_CMS_0_LEN - msg_end;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, recovery.cms,
		OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 0, offset);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (message.bytes, &recovery.cms_0[offset], msg_end);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&message.bytes[msg_end], recovery.cms_0, msg_length - msg_end);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	/* Don't read the indirect status here to make sure the status stays after the next command. */
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 0, msg_length - msg_end);

	/* Change the active CMS and confirm the previous status is still there. */
	ocp_recovery_device_testing_set_indirect_ctrl (test, &recovery, 1, 0);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_indirect_status (test, &recovery, 0x01, 1,
		OCP_RECOVERY_DEVICE_TESTING_CMS_1_WORDS);
	ocp_recovery_device_testing_check_indirect_ctrl (test, &recovery, 1, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_indirect_data_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	union ocp_recovery_device_cmd_buffer message;
	size_t msg_length = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	memcpy (message.bytes, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, msg_length);

	/* Change the length of the default region instead of changing the active CMS. */
	recovery.cms[0].length = OCP_RECOVERY_DEVICE_TESTING_CMS_5_LEN;

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&test_static, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, msg_length, status);

	status = testing_validate_array (message.bytes, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_vendor (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_VENDOR);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_vendor_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, OCP_RECOVERY_DEVICE_TESTING_MAX_CMS);
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_VENDOR);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_vendor_write_request (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t message[] = {
		0x02,0x00,0x40,0x00,0x00
	};

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_VENDOR);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test,
		(union ocp_recovery_device_cmd_buffer*) message, sizeof (message));
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_start_new_command_null (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (NULL, OCP_RECOVERY_CMD_VENDOR);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_start_new_command_invalid_low (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, 0x21);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NACK, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_start_new_command_invalid_high (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, 0x2d);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NACK, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_read_request_null (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_device = NULL;
	recovery.hw.base.reset_management = NULL;
	recovery.hw.base.activate_recovery = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (NULL, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	status = ocp_recovery_device_read_request (&recovery.test, NULL);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_read_request_no_active_command (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_read_request_repeated_call (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x11,0x00,0x00,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_device = NULL;
	recovery.hw.base.reset_management = NULL;
	recovery.hw.base.activate_recovery = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_write_request_null (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00
		}
	};
	size_t msg_length = 2;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (NULL, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	status = ocp_recovery_device_write_request (&recovery.test, NULL, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_write_request_no_active_command (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00
		}
	};
	size_t msg_length = 2;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_write_request_repeated_call (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00,0x00
		}
	};
	size_t msg_length = 3;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.reset_device, &recovery.hw, 0,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_clear_protocol_error (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00,0x00
		}
	};
	size_t msg_length = 3;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	recovery.hw.base.reset_device = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 2);
	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);
	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 0);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_clear_protocol_error_sticky_after_successful_read (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x01,0x00
		}
	};
	size_t msg_length = 2;
	uint8_t expected[] = {
		'O','C','P',' ','R','E','C','V',0x01,0x00,0x17,0x00,0x00,0x10,0x00
	};
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	/* Trigger a protocol error. */
	recovery.hw.base.reset_device = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_CMD_INCOMPLETE, status);

	/* Read capabilities to issue a successful request. */
	recovery.hw.base.activate_recovery = NULL;
	recovery.hw.base.supports_forced_recovery = true;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, output.bytes, status);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_clear_protocol_error_sticky_after_successful_write (
	CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message = {
		.bytes = {
			0x00,0x00,0x00,0x00,0x00,0x00
		}
	};
	size_t msg_length = 6;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	/* Trigger a protocol error. */
	recovery.hw.base.reset_device = NULL;

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_UNSUPPORTED, status);

	/* Issue a supported write command. */
	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&recovery.hw.mock, recovery.hw.base.reset_management, &recovery.hw, 0,
		MOCK_ARG (false));
	CuAssertIntEquals (test, 0, status);

	message.bytes[0] = 0x02;
	msg_length = 3;

	status = ocp_recovery_device_write_request (&recovery.test, &message, msg_length);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 1);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_checksum_failure_read (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_checksum_failure (&recovery.test);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 4);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_checksum_failure_write (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_RESET);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_checksum_failure (&recovery.test);

	status = ocp_recovery_device_write_request (&recovery.test, &message, 2);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 4);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_checksum_failure_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, 3);
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_PROT_CAP);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_checksum_failure (&test_static);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_checksum_failure_null (CuTest *test)
{
	TEST_START;

	ocp_recovery_device_checksum_failure (NULL);
}

static void ocp_recovery_device_test_write_overflow_read (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_write_overflow (&recovery.test);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_write_overflow_write (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_write_overflow (&recovery.test);

	status = ocp_recovery_device_write_request (&recovery.test, &message, 2);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_write_overflow_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, 3);
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_write_overflow (&test_static);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_write_overflow_null (CuTest *test)
{
	TEST_START;

	ocp_recovery_device_write_overflow (NULL);
}

static void ocp_recovery_device_test_write_incomplete_read (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_write_incomplete (&recovery.test);

	status = ocp_recovery_device_read_request (&recovery.test, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_write_incomplete_write (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	int status;
	union ocp_recovery_device_cmd_buffer message;

	TEST_START;

	ocp_recovery_device_testing_init (test, &recovery, NULL, 0);

	status = ocp_recovery_device_start_new_command (&recovery.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_write_incomplete (&recovery.test);

	status = ocp_recovery_device_write_request (&recovery.test, &message, 2);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_check_protocol_status (test, &recovery, 3);

	ocp_recovery_device_testing_release (test, &recovery);
}

static void ocp_recovery_device_test_write_incomplete_static_init (CuTest *test)
{
	struct ocp_recovery_device_testing recovery;
	struct ocp_recovery_device test_static = ocp_recovery_device_static_init (&recovery.state,
		&recovery.hw.base, recovery.cms, 3);
	int status;
	union ocp_recovery_device_cmd_buffer output;

	TEST_START;

	ocp_recovery_device_testing_init_dependencies (test, &recovery);

	status = ocp_recovery_device_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_device_start_new_command (&test_static, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_write_incomplete (&test_static);

	status = ocp_recovery_device_read_request (&test_static, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND, status);

	ocp_recovery_device_testing_release_dependencies (test, &recovery);
	ocp_recovery_device_release (&test_static);
}

static void ocp_recovery_device_test_write_incomplete_null (CuTest *test)
{
	TEST_START;

	ocp_recovery_device_write_incomplete (NULL);
}


TEST_SUITE_START (ocp_recovery_device);

TEST (ocp_recovery_device_test_init);
TEST (ocp_recovery_device_test_init_ro_region_unaligned);
TEST (ocp_recovery_device_test_init_ro_polling_region_unaligned);
TEST (ocp_recovery_device_test_init_null);
TEST (ocp_recovery_device_test_init_rw_region_unaligned);
TEST (ocp_recovery_device_test_init_rw_polling_region_unaligned);
TEST (ocp_recovery_device_test_init_log_region_rw);
TEST (ocp_recovery_device_test_static_init);
TEST (ocp_recovery_device_test_static_init_ro_region_unaligned);
TEST (ocp_recovery_device_test_static_init_ro_polling_region_unaligned);
TEST (ocp_recovery_device_test_init_state_null);
TEST (ocp_recovery_device_test_static_init_rw_region_unaligned);
TEST (ocp_recovery_device_test_static_init_rw_polling_region_unaligned);
TEST (ocp_recovery_device_test_static_init_log_region_rw);
TEST (ocp_recovery_device_test_release_null);
TEST (ocp_recovery_device_test_prot_cap_no_optional_support);
TEST (ocp_recovery_device_test_prot_cap_supports_device_reset);
TEST (ocp_recovery_device_test_prot_cap_management_reset);
TEST (ocp_recovery_device_test_prot_cap_all_resets_forced_recovery);
TEST (ocp_recovery_device_test_prot_cap_cms_regions);
TEST (ocp_recovery_device_test_prot_cap_activate_recovery_image);
TEST (ocp_recovery_device_test_prot_cap_activate_recovery_image_no_cms_regions);
TEST (ocp_recovery_device_test_prot_cap_all_optional_support);
TEST (ocp_recovery_device_test_prot_cap_static_init);
TEST (ocp_recovery_device_test_prot_cap_write_request);
TEST (ocp_recovery_device_test_device_id_no_vendor_string);
TEST (ocp_recovery_device_test_device_id_with_vendor_string);
TEST (ocp_recovery_device_test_device_id_get_id_error);
TEST (ocp_recovery_device_test_device_id_static_init);
TEST (ocp_recovery_device_test_device_id_write_request);
TEST (ocp_recovery_device_test_device_status);
TEST (ocp_recovery_device_test_device_status_static_init);
TEST (ocp_recovery_device_test_device_status_write_request);
TEST (ocp_recovery_device_test_reset_read_request);
TEST (ocp_recovery_device_test_reset_device);
TEST (ocp_recovery_device_test_reset_management);
TEST (ocp_recovery_device_test_reset_device_with_forced_recovery);
TEST (ocp_recovery_device_test_reset_management_with_forced_recovery);
TEST (ocp_recovery_device_test_reset_device_no_reset_forced_recovery);
TEST (ocp_recovery_device_test_reset_device_unsupported);
TEST (ocp_recovery_device_test_reset_management_unsupported);
TEST (ocp_recovery_device_test_reset_forced_recovery_unsupported);
TEST (ocp_recovery_device_test_reset_enable_bus_mastering);
TEST (ocp_recovery_device_test_reset_incomplete_command);
TEST (ocp_recovery_device_test_reset_extra_bytes);
TEST (ocp_recovery_device_test_reset_static_init);
TEST (ocp_recovery_device_test_recovery_status_no_cms_regions);
TEST (ocp_recovery_device_test_recovery_status_no_activate_support);
TEST (ocp_recovery_device_test_recovery_status_recovery_supported);
TEST (ocp_recovery_device_test_recovery_status_static_init);
TEST (ocp_recovery_device_test_recovery_status_write_request);
TEST (ocp_recovery_device_test_recovery_ctrl_read_request);
TEST (ocp_recovery_device_test_recovery_ctrl_read_request_no_cms_regions);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_image);
TEST (ocp_recovery_device_test_recovery_ctrl_no_activate_image);
TEST (ocp_recovery_device_test_recovery_ctrl_only_cms);
TEST (ocp_recovery_device_test_recovery_ctrl_only_activate_image);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_image_failure);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_image_auth_failure);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_image_non_code_cms);
TEST (ocp_recovery_device_test_recovery_ctrl_no_activate_image_non_code_cms);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_image_non_zero_cms_index);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_image_cms_out_of_range);
TEST (ocp_recovery_device_test_recovery_ctrl_no_activate_image_cms_out_of_range);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_recovery_unsupported);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_recovery_unsupported_no_activate);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_recovery_unsupported_only_activate);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_recovery_unsupported_only_cms);
TEST (ocp_recovery_device_test_recovery_ctrl_only_non_code_cms);
TEST (ocp_recovery_device_test_recovery_ctrl_only_out_of_range_cms);
TEST (ocp_recovery_device_test_recovery_ctrl_activate_image_stored_image);
TEST (ocp_recovery_device_test_recovery_ctrl_no_activate_image_stored_image);
TEST (ocp_recovery_device_test_recovery_ctrl_incomplete_command);
TEST (ocp_recovery_device_test_recovery_ctrl_extra_bytes);
TEST (ocp_recovery_device_test_recovery_ctrl_static_init);
TEST (ocp_recovery_device_test_hw_status);
TEST (ocp_recovery_device_test_hw_status_static_init);
TEST (ocp_recovery_device_test_hw_status_write_request);
TEST (ocp_recovery_device_test_indirect_status_default_cms_0);
TEST (ocp_recovery_device_test_indirect_status_unaligned_region_length);
TEST (ocp_recovery_device_test_indirect_status_unsupported);
TEST (ocp_recovery_device_test_indirect_status_static_init);
TEST (ocp_recovery_device_test_indirect_status_write_request);
TEST (ocp_recovery_device_test_indirect_ctrl_read_request);
TEST (ocp_recovery_device_test_indirect_ctrl_read_request_unsupported);
TEST (ocp_recovery_device_test_indirect_ctrl_cms_0);
TEST (ocp_recovery_device_test_indirect_ctrl_set_offset);
TEST (ocp_recovery_device_test_indirect_ctrl_non_zero_cms);
TEST (ocp_recovery_device_test_indirect_ctrl_out_of_range_cms);
TEST (ocp_recovery_device_test_indirect_ctrl_offset_not_4byte_aligned);
TEST (ocp_recovery_device_test_indirect_ctrl_cms_log);
TEST (ocp_recovery_device_test_indirect_ctrl_cms_log_size_unaligned);
TEST (ocp_recovery_device_test_indirect_ctrl_cms_log_size_error);
TEST (ocp_recovery_device_test_indirect_ctrl_unsupported);
TEST (ocp_recovery_device_test_indirect_ctrl_incomplete_command);
TEST (ocp_recovery_device_test_indirect_ctrl_extra_bytes);
TEST (ocp_recovery_device_test_indirect_ctrl_static_init);
TEST (ocp_recovery_device_test_indirect_data_read);
TEST (ocp_recovery_device_test_indirect_data_read_sequential);
TEST (ocp_recovery_device_test_indirect_data_read_less_than_max);
TEST (ocp_recovery_device_test_indirect_data_read_at_offset);
TEST (ocp_recovery_device_test_indirect_data_read_less_than_max_at_offset);
TEST (ocp_recovery_device_test_indirect_data_read_sequential_with_wrap);
TEST (ocp_recovery_device_test_indirect_data_read_sequential_with_wrap_status_sticky_on_read);
TEST (ocp_recovery_device_test_indirect_data_read_at_offset_out_of_range);
TEST (ocp_recovery_device_test_indirect_data_read_at_offset_unaligned);
TEST (ocp_recovery_device_test_indirect_data_read_at_offset_out_of_range_unaligned);
TEST (ocp_recovery_device_test_indirect_data_read_unaligned_region_length);
TEST (ocp_recovery_device_test_indirect_data_read_from_log);
TEST (ocp_recovery_device_test_indirect_data_read_from_log_at_offset);
TEST (ocp_recovery_device_test_indirect_data_read_from_log_sequential_with_wrap);
TEST (ocp_recovery_device_test_indirect_data_read_from_log_at_offset_out_of_range);
TEST (ocp_recovery_device_test_indirect_data_read_from_log_at_offset_unaligned);
TEST (ocp_recovery_device_test_indirect_data_read_from_log_at_offset_out_of_range_unaligned);
TEST (ocp_recovery_device_test_indirect_data_read_from_log_unaligned_log_data);
TEST (ocp_recovery_device_test_indirect_data_read_from_log_size_error);
TEST (ocp_recovery_device_test_indirect_data_read_from_log_data_error);
TEST (ocp_recovery_device_test_indirect_data_read_min_region);
TEST (ocp_recovery_device_test_indirect_data_read_min_region_multiple);
TEST (ocp_recovery_device_test_indirect_data_read_out_of_range_cms);
TEST (ocp_recovery_device_test_indirect_data_read_unsupported);
TEST (ocp_recovery_device_test_indirect_data_write);
TEST (ocp_recovery_device_test_indirect_data_write_sequential);
TEST (ocp_recovery_device_test_indirect_data_write_less_than_max);
TEST (ocp_recovery_device_test_indirect_data_write_at_offset);
TEST (ocp_recovery_device_test_indirect_data_write_less_than_max_at_offset);
TEST (ocp_recovery_device_test_indirect_data_write_sequential_with_wrap);
TEST (ocp_recovery_device_test_indirect_data_write_sequential_with_wrap_status_sticky_on_write);
TEST (ocp_recovery_device_test_indirect_data_write_at_offset_out_of_range);
TEST (ocp_recovery_device_test_indirect_data_write_at_offset_unaligned);
TEST (ocp_recovery_device_test_indirect_data_write_at_offset_out_of_range_unaligned);
TEST (ocp_recovery_device_test_indirect_data_write_unaligned);
TEST (ocp_recovery_device_test_indirect_data_write_sequential_unaligned);
TEST (ocp_recovery_device_test_indirect_data_write_wrap_in_middle);
TEST (ocp_recovery_device_test_indirect_data_write_sequential_with_wrap_in_middle);
TEST (ocp_recovery_device_test_indirect_data_write_min_region);
TEST (ocp_recovery_device_test_indirect_data_write_min_region_multiple);
TEST (ocp_recovery_device_test_indirect_data_write_multiple_wrap_single_write);
TEST (ocp_recovery_device_test_indirect_data_write_zero_length);
TEST (ocp_recovery_device_test_indirect_data_write_out_of_range_cms);
TEST (ocp_recovery_device_test_indirect_data_write_ro_cms);
TEST (ocp_recovery_device_test_indirect_data_write_unsupported);
TEST (ocp_recovery_device_test_indirect_data_write_and_read_full_region);
TEST (ocp_recovery_device_test_indirect_data_status_sticky_on_cms_change);
TEST (ocp_recovery_device_test_indirect_data_static_init);
TEST (ocp_recovery_device_test_vendor);
TEST (ocp_recovery_device_test_vendor_static_init);
TEST (ocp_recovery_device_test_vendor_write_request);
TEST (ocp_recovery_device_test_start_new_command_null);
TEST (ocp_recovery_device_test_start_new_command_invalid_low);
TEST (ocp_recovery_device_test_start_new_command_invalid_high);
TEST (ocp_recovery_device_test_read_request_null);
TEST (ocp_recovery_device_test_read_request_no_active_command);
TEST (ocp_recovery_device_test_read_request_repeated_call);
TEST (ocp_recovery_device_test_write_request_null);
TEST (ocp_recovery_device_test_write_request_no_active_command);
TEST (ocp_recovery_device_test_write_request_repeated_call);
TEST (ocp_recovery_device_test_clear_protocol_error);
TEST (ocp_recovery_device_test_clear_protocol_error_sticky_after_successful_read);
TEST (ocp_recovery_device_test_clear_protocol_error_sticky_after_successful_write);
TEST (ocp_recovery_device_test_checksum_failure_read);
TEST (ocp_recovery_device_test_checksum_failure_write);
TEST (ocp_recovery_device_test_checksum_failure_static_init);
TEST (ocp_recovery_device_test_checksum_failure_null);
TEST (ocp_recovery_device_test_write_overflow_read);
TEST (ocp_recovery_device_test_write_overflow_write);
TEST (ocp_recovery_device_test_write_overflow_static_init);
TEST (ocp_recovery_device_test_write_overflow_null);
TEST (ocp_recovery_device_test_write_incomplete_read);
TEST (ocp_recovery_device_test_write_incomplete_write);
TEST (ocp_recovery_device_test_write_incomplete_static_init);
TEST (ocp_recovery_device_test_write_incomplete_null);

TEST_SUITE_END;
