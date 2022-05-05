// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "recovery/ocp_recovery_smbus.h"
#include "recovery/recovery_logging.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/recovery/ocp_recovery_device_hw_mock.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("ocp_recovery_smbus");


/* Length of the recovery memory region. */
#define	OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN			8

/* The number of 32-bit words make up the recovery memory region. */
#define	OCP_RECOVERY_SMBUS_TESTING_CMS_0_WORDS			(OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN / 4)

/**
 * Dependencies for testing the OCP Recovery SMBus layer.
 */
struct ocp_recovery_smbus_testing {
	struct ocp_recovery_device_hw_mock hw;					/**< Mock for the recovery HW interface. */
	struct logging_mock log;								/**< Mock for the debug log. */
	struct ocp_recovery_device_state dev_state;				/**< Variable state of the recovery handler. */
	struct ocp_recovery_device device;						/**< Device recovery handler. */
	uint8_t cms_0[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN];	/**< Buffer for CMS code R/W region (type 0). */
	struct ocp_recovery_device_cms cms[1];					/**< List of CMS regions. */
	struct ocp_recovery_smbus_state state;					/**< Variable state for the SMBus handler. */
	struct ocp_recovery_smbus test;							/**< The SMBus handler under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param smbus Testing dependencies to initialize.
 */
static void ocp_recovery_smbus_testing_init_dependencies (CuTest *test,
	struct ocp_recovery_smbus_testing *smbus)
{
	int status;

	status = ocp_recovery_device_hw_mock_init (&smbus->hw);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&smbus->log);
	CuAssertIntEquals (test, 0, status);

	smbus->hw.base.supports_forced_recovery = true;

	memset (smbus->cms_0, 0, sizeof (smbus->cms_0));

	smbus->cms[0].base_addr = smbus->cms_0;
	smbus->cms[0].length = sizeof (smbus->cms_0);
	smbus->cms[0].type = OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE;

	status = ocp_recovery_device_init (&smbus->device, &smbus->dev_state, &smbus->hw.base,
		smbus->cms, 1);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param smbus Testing dependencies to release.
 */
static void ocp_recovery_smbus_testing_release_dependencies (CuTest *test,
	struct ocp_recovery_smbus_testing *smbus)
{
	int status;

	status = ocp_recovery_device_hw_mock_validate_and_release (&smbus->hw);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&smbus->log);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_device_release (&smbus->device);
}

/**
 * Initialize on OCP Recovery SMBus handler for testing.
 *
 * @param test The test framework.
 * @param smbus Testing components to initialize.
 */
static void ocp_recovery_smbus_testing_init (CuTest *test,
	struct ocp_recovery_smbus_testing *smbus)
{
	int status;

	ocp_recovery_smbus_testing_init_dependencies (test, smbus);

	status = ocp_recovery_smbus_init (&smbus->test, &smbus->state, &smbus->device);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release OCP recovery SMBus handling test components and validate all mocks.
 *
 * @param test The test framework.
 * @param smbus Testing components to release.
 */
static void ocp_recovery_smbus_testing_release (CuTest *test,
	struct ocp_recovery_smbus_testing *smbus)
{
	ocp_recovery_smbus_testing_release_dependencies (test, smbus);
	ocp_recovery_smbus_release (&smbus->test);
}

/**
 * Check the device status response for a specific protocol status code.
 *
 * @param test The test framework.
 * @param smbus Testing components to use for the check.
 * @param protocol_status The expected protocol status code.
 */
static void ocp_recovery_smbus_testing_check_protocol_status (CuTest *test,
	struct ocp_recovery_smbus_testing *smbus, uint8_t protocol_status)
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
	const union ocp_recovery_smbus_cmd_buffer *output = NULL;

	status = ocp_recovery_smbus_receive_byte (&smbus->test, OCP_RECOVERY_CMD_DEVICE_STATUS);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&smbus->hw.mock, smbus->hw.base.get_device_status, &smbus->hw, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&smbus->hw.mock, 0, &status_code, sizeof (status_code), -1);
	status |= mock_expect_output (&smbus->hw.mock, 1, &reason_code, sizeof (reason_code), -1);
	status |= mock_expect_output (&smbus->hw.mock, 2, &vendor, sizeof (vendor), -1);

	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_transmit_bytes (&smbus->test, 0x69, &output);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, output);

	status = testing_validate_array (expected, output->block_cmd.payload.bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&smbus->hw.mock);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void ocp_recovery_smbus_test_init (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init_dependencies (test, &smbus);

	status = ocp_recovery_smbus_init (&smbus.test, &smbus.state, &smbus.device);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_init_null (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init_dependencies (test, &smbus);

	status = ocp_recovery_smbus_init (NULL, &smbus.state, &smbus.device);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_INVALID_ARGUMENT, status);

	status = ocp_recovery_smbus_init (&smbus.test, NULL, &smbus.device);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_INVALID_ARGUMENT, status);

	status = ocp_recovery_smbus_init (&smbus.test, &smbus.state, NULL);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_INVALID_ARGUMENT, status);

	ocp_recovery_smbus_testing_release_dependencies (test, &smbus);
}

static void ocp_recovery_smbus_test_static_init (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	struct ocp_recovery_smbus test_static = ocp_recovery_smbus_static_init (&smbus.state,
		&smbus.device);
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init_dependencies (test, &smbus);

	status = ocp_recovery_smbus_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_static_init_null (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	struct ocp_recovery_smbus test_static = ocp_recovery_smbus_static_init (NULL, &smbus.device);
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init_dependencies (test, &smbus);

	status = ocp_recovery_smbus_init_state (NULL);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_INVALID_ARGUMENT, status);

	status = ocp_recovery_smbus_init_state (&test_static);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_INVALID_ARGUMENT, status);

	ocp_recovery_smbus_testing_release_dependencies (test, &smbus);
}

static void ocp_recovery_smbus_test_release_null (CuTest *test)
{
	TEST_START;

	ocp_recovery_smbus_release (NULL);
}

static void ocp_recovery_smbus_test_block_write_command_no_pec (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xaa);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	ocp_recovery_smbus_stop (&smbus.test);
	CuAssertIntEquals (test, 0x55, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0xaa, smbus.cms_0[1]);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_with_pec (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xaa);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x29);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	ocp_recovery_smbus_stop (&smbus.test);
	CuAssertIntEquals (test, 0x55, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0xaa, smbus.cms_0[1]);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_with_bad_pec (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_OCP_PEC_ERROR,
		.arg1 = 0x29,
		.arg2 = 0x35
	};

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	status = mock_expect (&smbus.log.mock, smbus.log.base.create_entry, &smbus.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xaa);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x35);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	debug_log = &smbus.log.base;
	ocp_recovery_smbus_stop (&smbus.test);
	debug_log = NULL;
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	ocp_recovery_smbus_testing_check_protocol_status (test, &smbus, 4);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_twice (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	uint8_t cms_data[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN] = {
		0x55,0xaa,0x00,0x00,0x11,0x22,0x00,0x00
	};

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xaa);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	status = testing_validate_array (cms_data, smbus.cms_0, 4);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x11);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x22);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	status = testing_validate_array (cms_data, smbus.cms_0, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_with_pec_twice (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	uint8_t cms_data[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN] = {
		0x55,0xaa,0x00,0x00,0x11,0x22,0x00,0x00
	};

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xaa);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x29);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	status = testing_validate_array (cms_data, smbus.cms_0, 4);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x11);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x22);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x97);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	status = testing_validate_array (cms_data, smbus.cms_0, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_call_stop_twice (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xaa);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	ocp_recovery_smbus_stop (&smbus.test);
	CuAssertIntEquals (test, 0x55, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0xaa, smbus.cms_0[1]);
	CuAssertIntEquals (test, 0, smbus.cms_0[4]);
	CuAssertIntEquals (test, 0, smbus.cms_0[5]);

	ocp_recovery_smbus_stop (&smbus.test);
	CuAssertIntEquals (test, 0x55, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0xaa, smbus.cms_0[1]);
	CuAssertIntEquals (test, 0, smbus.cms_0[4]);
	CuAssertIntEquals (test, 0, smbus.cms_0[5]);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_overflow_buffer (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	int i;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_OCP_WRITE_OVERFLOW,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	status = mock_expect (&smbus.log.mock, smbus.log.base.create_entry, &smbus.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xff);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 256; i++) {
		status = ocp_recovery_smbus_receive_byte (&smbus.test, i);
		CuAssertIntEquals (test, 0, status);
	}

	debug_log = &smbus.log.base;
	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	debug_log = NULL;
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_OVERFLOW, status);

	ocp_recovery_smbus_stop (&smbus.test);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	ocp_recovery_smbus_testing_check_protocol_status (test, &smbus, 3);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_overflow_multiple (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	int i;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_OCP_WRITE_OVERFLOW,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	status = mock_expect (&smbus.log.mock, smbus.log.base.create_entry, &smbus.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xff);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 256; i++) {
		status = ocp_recovery_smbus_receive_byte (&smbus.test, i);
		CuAssertIntEquals (test, 0, status);
	}

	debug_log = &smbus.log.base;

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_OVERFLOW, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x56);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_NACK, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x57);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_NACK, status);

	ocp_recovery_smbus_stop (&smbus.test);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	debug_log = NULL;

	ocp_recovery_smbus_testing_check_protocol_status (test, &smbus, 3);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_incomplete_data (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_OCP_WRITE_INCOMPLETE,
		.arg1 = 2,
		.arg2 = 2
	};

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	status = mock_expect (&smbus.log.mock, smbus.log.base.create_entry, &smbus.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	debug_log = &smbus.log.base;
	ocp_recovery_smbus_stop (&smbus.test);
	debug_log = NULL;
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	ocp_recovery_smbus_testing_check_protocol_status (test, &smbus, 3);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_zero_bytes (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_OCP_WRITE_ERROR,
		.arg1 = OCP_RECOVERY_DEVICE_CMD_INCOMPLETE,
		.arg2 = 0
	};

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	status = mock_expect (&smbus.log.mock, smbus.log.base.create_entry, &smbus.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_CTRL);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x00);
	CuAssertIntEquals (test, 0, status);

	debug_log = &smbus.log.base;
	ocp_recovery_smbus_stop (&smbus.test);
	debug_log = NULL;

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_full_memory_region_with_pec (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	uint8_t cms_data[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
	};
	size_t i;

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN; i++) {
		status = ocp_recovery_smbus_receive_byte (&smbus.test, cms_data[i]);
		CuAssertIntEquals (test, 0, status);
	}

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x9c);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	status = testing_validate_array (cms_data, smbus.cms_0, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_invalid_command (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_MAX_VALID + 1);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_NACK, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_NACK, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_NACK, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xaa);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_NACK, status);

	ocp_recovery_smbus_stop (&smbus.test);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_write_command_static_init (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	struct ocp_recovery_smbus test_static = ocp_recovery_smbus_static_init (&smbus.state,
		&smbus.device);
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init_dependencies (test, &smbus);

	status = ocp_recovery_smbus_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&test_static, 0x69);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&test_static, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&test_static, 0x02);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&test_static, 0x55);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&test_static, 0xaa);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	status = ocp_recovery_smbus_receive_byte (&test_static, 0x29);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0, smbus.cms_0[1]);

	ocp_recovery_smbus_stop (&test_static);
	CuAssertIntEquals (test, 0x55, smbus.cms_0[0]);
	CuAssertIntEquals (test, 0xaa, smbus.cms_0[1]);

	ocp_recovery_smbus_testing_release_dependencies (test, &smbus);
	ocp_recovery_smbus_release (&test_static);
}

static void ocp_recovery_smbus_test_block_read_command (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	uint8_t cms_data[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
	};
	union ocp_recovery_smbus_cmd_buffer expected;
	const union ocp_recovery_smbus_cmd_buffer *output = NULL;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.block_cmd.byte_count = OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN;
	memcpy (expected.block_cmd.payload.bytes, cms_data, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	expected.bytes[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN + 1] = 0x31;

	ocp_recovery_smbus_testing_init (test, &smbus);

	memcpy (smbus.cms_0, cms_data, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_transmit_bytes (&smbus.test, 0x69, &output);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, output);

	status = testing_validate_array (expected.bytes, output->bytes, sizeof (expected.bytes));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	status = testing_validate_array (cms_data, smbus.cms_0, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_read_command_twice (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	uint8_t cms_data[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
	};
	union ocp_recovery_smbus_cmd_buffer expected;
	const union ocp_recovery_smbus_cmd_buffer *output = NULL;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.block_cmd.byte_count = OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN;
	memcpy (expected.block_cmd.payload.bytes, cms_data, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	expected.bytes[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN + 1] = 0x31;

	ocp_recovery_smbus_testing_init (test, &smbus);

	memcpy (smbus.cms_0, cms_data, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_transmit_bytes (&smbus.test, 0x69, &output);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, output);

	status = testing_validate_array (expected.bytes, output->bytes, sizeof (expected.bytes));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	status = testing_validate_array (cms_data, smbus.cms_0, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	output = NULL;
	status = ocp_recovery_smbus_transmit_bytes (&smbus.test, 0x69, &output);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, output);

	status = testing_validate_array (expected.bytes, output->bytes, sizeof (expected.bytes));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	status = testing_validate_array (cms_data, smbus.cms_0, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_read_command_failure (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	union ocp_recovery_smbus_cmd_buffer expected;
	const union ocp_recovery_smbus_cmd_buffer *output = NULL;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_OCP_READ_ERROR,
		.arg1 = OCP_RECOVERY_DEVICE_UNSUPPORTED,
		.arg2 = 0
	};

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.block_cmd.byte_count = 0;
	expected.bytes[1] = 0x76;

	ocp_recovery_smbus_testing_init (test, &smbus);

	status = mock_expect (&smbus.log.mock, smbus.log.base.create_entry, &smbus.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_HW_STATUS);
	CuAssertIntEquals (test, 0, status);

	debug_log = &smbus.log.base;
	status = ocp_recovery_smbus_transmit_bytes (&smbus.test, 0x69, &output);
	debug_log = NULL;
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, output);

	status = testing_validate_array (expected.bytes, output->bytes, sizeof (expected.bytes));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_read_invalid_command (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	union ocp_recovery_smbus_cmd_buffer expected;
	const union ocp_recovery_smbus_cmd_buffer *output = NULL;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.block_cmd.byte_count = 0;
	expected.bytes[1] = 0x4c;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_MIN_VALID - 1);
	CuAssertIntEquals (test, OCP_RECOVERY_SMBUS_NACK, status);

	status = ocp_recovery_smbus_transmit_bytes (&smbus.test, 0x69, &output);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, output);

	status = testing_validate_array (expected.bytes, output->bytes, sizeof (expected.bytes));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&smbus.test);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_block_read_command_static_init (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	struct ocp_recovery_smbus test_static = ocp_recovery_smbus_static_init (&smbus.state,
		&smbus.device);
	int status;
	uint8_t cms_data[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN] = {
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08
	};
	union ocp_recovery_smbus_cmd_buffer expected;
	const union ocp_recovery_smbus_cmd_buffer *output = NULL;

	TEST_START;

	memset (&expected, 0, sizeof (expected));
	expected.block_cmd.byte_count = OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN;
	memcpy (expected.block_cmd.payload.bytes, cms_data, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	expected.bytes[OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN + 1] = 0x31;

	ocp_recovery_smbus_testing_init_dependencies (test, &smbus);

	status = ocp_recovery_smbus_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	memcpy (smbus.cms_0, cms_data, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);

	ocp_recovery_smbus_start (&test_static, 0x69);

	status = ocp_recovery_smbus_receive_byte (&test_static, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_transmit_bytes (&test_static, 0x69, &output);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, output);

	status = testing_validate_array (expected.bytes, output->bytes, sizeof (expected.bytes));
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (&test_static);

	status = testing_validate_array (cms_data, smbus.cms_0, OCP_RECOVERY_SMBUS_TESTING_CMS_0_LEN);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_testing_release_dependencies (test, &smbus);
	ocp_recovery_smbus_release (&test_static);
}

static void ocp_recovery_smbus_test_start_null (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (NULL, 0x69);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_stop_null (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x02);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0x55);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, 0xaa);
	CuAssertIntEquals (test, 0, status);

	ocp_recovery_smbus_stop (NULL);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_receive_byte_null (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;

	TEST_START;

	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (NULL, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}

static void ocp_recovery_smbus_test_transmit_bytes_null (CuTest *test)
{
	struct ocp_recovery_smbus_testing smbus;
	int status;
	const union ocp_recovery_smbus_cmd_buffer *output;

	TEST_START;


	ocp_recovery_smbus_testing_init (test, &smbus);

	ocp_recovery_smbus_start (&smbus.test, 0x69);

	status = ocp_recovery_smbus_receive_byte (&smbus.test, OCP_RECOVERY_CMD_INDIRECT_DATA);
	CuAssertIntEquals (test, 0, status);

	status = ocp_recovery_smbus_transmit_bytes (NULL, 0x69, &output);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	status = ocp_recovery_smbus_transmit_bytes (&smbus.test, 0x69, NULL);
	CuAssertIntEquals (test, OCP_RECOVERY_DEVICE_INVALID_ARGUMENT, status);

	ocp_recovery_smbus_testing_release (test, &smbus);
}


TEST_SUITE_START (ocp_recovery_smbus);

TEST (ocp_recovery_smbus_test_init);
TEST (ocp_recovery_smbus_test_init_null);
TEST (ocp_recovery_smbus_test_static_init);
TEST (ocp_recovery_smbus_test_static_init_null);
TEST (ocp_recovery_smbus_test_release_null);
TEST (ocp_recovery_smbus_test_block_write_command_no_pec);
TEST (ocp_recovery_smbus_test_block_write_command_with_pec);
TEST (ocp_recovery_smbus_test_block_write_command_with_bad_pec);
TEST (ocp_recovery_smbus_test_block_write_command_twice);
TEST (ocp_recovery_smbus_test_block_write_command_with_pec_twice);
TEST (ocp_recovery_smbus_test_block_write_command_call_stop_twice);
TEST (ocp_recovery_smbus_test_block_write_command_overflow_buffer);
TEST (ocp_recovery_smbus_test_block_write_command_overflow_multiple);
TEST (ocp_recovery_smbus_test_block_write_command_incomplete_data);
TEST (ocp_recovery_smbus_test_block_write_command_zero_bytes);
TEST (ocp_recovery_smbus_test_block_write_command_full_memory_region_with_pec);
TEST (ocp_recovery_smbus_test_block_write_invalid_command);
TEST (ocp_recovery_smbus_test_block_write_command_static_init);
TEST (ocp_recovery_smbus_test_block_read_command);
TEST (ocp_recovery_smbus_test_block_read_command_twice);
TEST (ocp_recovery_smbus_test_block_read_command_failure);
TEST (ocp_recovery_smbus_test_block_read_invalid_command);
TEST (ocp_recovery_smbus_test_block_read_command_static_init);
TEST (ocp_recovery_smbus_test_start_null);
TEST (ocp_recovery_smbus_test_stop_null);
TEST (ocp_recovery_smbus_test_receive_byte_null);
TEST (ocp_recovery_smbus_test_transmit_bytes_null);

TEST_SUITE_END;
