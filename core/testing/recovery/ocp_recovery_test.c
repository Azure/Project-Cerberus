// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "recovery/ocp_recovery.h"


TEST_SUITE_LABEL ("ocp_recovery");


/*******************
 * Test cases
 *******************/

static void ocp_recovery_test_prot_cap_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		'O','C','P',' ','R','E','C','V',
		0x01,0x02,
		0x03,0x04,0x05,0x06,0x07
	};
	struct ocp_recovery_prot_cap *msg;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_prot_cap));

	msg = (struct ocp_recovery_prot_cap*) raw_buffer;
	CuAssertPtrEquals (test, raw_buffer, msg->magic_string);
	CuAssertIntEquals (test, 0x01, msg->major_version);
	CuAssertIntEquals (test, 0x02, msg->minor_version);
	CuAssertIntEquals (test, 0x0403, msg->capabilities);
	CuAssertIntEquals (test, 0x05, msg->cms_regions);
	CuAssertIntEquals (test, 0x06, msg->max_response_time);
	CuAssertIntEquals (test, 0x07, msg->heartbeat_period);

	CuAssertIntEquals (test, (1U << 6),
		OCP_RECOVERY_PROT_CAP_RESPONSE_TIME_US (msg->max_response_time));
	CuAssertIntEquals (test, (1U << 7),
		OCP_RECOVERY_PROT_CAP_HEARTBEAT_US (msg->heartbeat_period));

	raw_buffer[14] = 0;
	CuAssertIntEquals (test, 0, OCP_RECOVERY_PROT_CAP_HEARTBEAT_US (msg->heartbeat_period));
}

static void ocp_recovery_test_device_id_format (CuTest *test)
{
	uint8_t raw_buffer[255];
	struct ocp_recovery_device_id *msg;
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (raw_buffer); i++) {
		raw_buffer[i] = i + 1;
	}

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_device_id));

	msg = (struct ocp_recovery_device_id*) raw_buffer;
	CuAssertIntEquals (test, 0x01, msg->base.id_type);
	CuAssertIntEquals (test, 0x02, msg->base.vendor_length);

	CuAssertIntEquals (test, 0x0403, msg->base.pci.vendor_id);
	CuAssertIntEquals (test, 0x0605, msg->base.pci.device_id);
	CuAssertIntEquals (test, 0x0807, msg->base.pci.subsystem_vendor_id);
	CuAssertIntEquals (test, 0x0a09, msg->base.pci.subsystem_device_id);
	CuAssertIntEquals (test, 0x0b, msg->base.pci.revsion_id);
	CuAssertPtrEquals (test, &raw_buffer[11], msg->base.pci.pad);

	CuAssertPtrEquals (test, &raw_buffer[2], msg->base.iana.enterprise_id);
	CuAssertPtrEquals (test, &raw_buffer[6], msg->base.iana.product_id);
	CuAssertPtrEquals (test, &raw_buffer[18], msg->base.iana.pad);

	CuAssertPtrEquals (test, &raw_buffer[2], msg->base.uuid.uuid);
	CuAssertPtrEquals (test, &raw_buffer[18], msg->base.uuid.pad);

	CuAssertPtrEquals (test, &raw_buffer[2], msg->base.pnp.vendor_id);
	CuAssertPtrEquals (test, &raw_buffer[5], msg->base.pnp.product_id);
	CuAssertPtrEquals (test, &raw_buffer[9], msg->base.pnp.pad);

	CuAssertPtrEquals (test, &raw_buffer[2], msg->base.acpi.vendor_id);
	CuAssertPtrEquals (test, &raw_buffer[6], msg->base.acpi.product_id);
	CuAssertPtrEquals (test, &raw_buffer[9], msg->base.acpi.pad);

	CuAssertIntEquals (test, 0x0403, msg->base.nvme.vendor_id);
	CuAssertPtrEquals (test, &raw_buffer[4], msg->base.nvme.serial_num);

	CuAssertPtrEquals (test, &raw_buffer[24], msg->vendor_string);
}

static void ocp_recovery_test_device_status_format (CuTest *test)
{
	uint8_t raw_buffer[255];
	struct ocp_recovery_device_status *msg;
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (raw_buffer); i++) {
		raw_buffer[i] = i + 1;
	}

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_device_status));

	msg = (struct ocp_recovery_device_status*) raw_buffer;
	CuAssertIntEquals (test, 0x01, msg->base.status);
	CuAssertIntEquals (test, 0x02, msg->base.protocol_status);
	CuAssertIntEquals (test, 0x0403, msg->base.recovery_reason);
	CuAssertIntEquals (test, 0x0605, msg->base.heartbeat);
	CuAssertIntEquals (test, 0x07, msg->base.vendor_length);
	CuAssertPtrEquals (test, &raw_buffer[7], msg->vendor_status);
}

static void ocp_recovery_test_reset_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x01,0x02,0x03
	};
	struct ocp_recovery_reset *msg;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_reset));

	msg = (struct ocp_recovery_reset*) raw_buffer;
	CuAssertIntEquals (test, 0x01, msg->reset_ctrl);
	CuAssertIntEquals (test, 0x02, msg->forced_recovery);
	CuAssertIntEquals (test, 0x03, msg->intf_control);
}

static void ocp_recovery_test_recovery_ctrl_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x01,0x02,0x03
	};
	struct ocp_recovery_recovery_ctrl *msg;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_recovery_ctrl));

	msg = (struct ocp_recovery_recovery_ctrl*) raw_buffer;
	CuAssertIntEquals (test, 0x01, msg->cms);
	CuAssertIntEquals (test, 0x02, msg->recovery_image);
	CuAssertIntEquals (test, 0x03, msg->activate);
}

static void ocp_recovery_test_recovery_status_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x01,0x02
	};
	struct ocp_recovery_recovery_status *msg;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_recovery_status));

	msg = (struct ocp_recovery_recovery_status*) raw_buffer;
	CuAssertIntEquals (test, 0x01, msg->status);
	CuAssertIntEquals (test, 0x02, msg->vendor_status);
}

static void ocp_recovery_test_hw_status_format (CuTest *test)
{
	uint8_t raw_buffer[255];
	struct ocp_recovery_hw_status *msg;
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (raw_buffer); i++) {
		raw_buffer[i] = i + 1;
	}

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_hw_status));

	msg = (struct ocp_recovery_hw_status*) raw_buffer;
	CuAssertIntEquals (test, 0x01, msg->base.status);
	CuAssertIntEquals (test, 0x02, msg->base.vendor_status);
	CuAssertIntEquals (test, 0x0403, msg->base.temperature);
	CuAssertIntEquals (test, 0x05, msg->base.vendor_length);
	CuAssertPtrEquals (test, &raw_buffer[5], msg->vendor_hw_status);
}

static void ocp_recovery_test_indirect_ctrl_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x01,0x02,0x03,0x04,0x05,0x06
	};
	struct ocp_recovery_indirect_ctrl *msg;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_indirect_ctrl));

	msg = (struct ocp_recovery_indirect_ctrl*) raw_buffer;
	CuAssertIntEquals (test, 0x01, msg->cms);
	CuAssertIntEquals (test, 0x02, msg->reserved);
	CuAssertIntEquals (test, 0x06050403, msg->offset);
}

static void ocp_recovery_test_indirect_status_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x01,0x02,0x03,0x04,0x05,0x06
	};
	struct ocp_recovery_indirect_status *msg;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_indirect_status));

	msg = (struct ocp_recovery_indirect_status*) raw_buffer;
	CuAssertIntEquals (test, 0x01, msg->status);
	CuAssertIntEquals (test, 0x02, msg->type);
	CuAssertIntEquals (test, 0x06050403, msg->size);
}

static void ocp_recovery_test_indirect_data_format (CuTest *test)
{
	uint8_t raw_buffer[255];
	struct ocp_recovery_indirect_data *msg;
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (raw_buffer); i++) {
		raw_buffer[i] = i + 1;
	}

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_indirect_data));

	msg = (struct ocp_recovery_indirect_data*) raw_buffer;
	CuAssertPtrEquals (test, raw_buffer, msg->data);
}

static void ocp_recovery_test_vendor_format (CuTest *test)
{
	uint8_t raw_buffer[255];
	struct ocp_recovery_vendor *msg;
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (raw_buffer); i++) {
		raw_buffer[i] = i + 1;
	}

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ocp_recovery_vendor));

	msg = (struct ocp_recovery_vendor*) raw_buffer;
	CuAssertPtrEquals (test, raw_buffer, msg->vendor);
}


TEST_SUITE_START (ocp_recovery);

TEST (ocp_recovery_test_prot_cap_format);
TEST (ocp_recovery_test_device_id_format);
TEST (ocp_recovery_test_device_status_format);
TEST (ocp_recovery_test_reset_format);
TEST (ocp_recovery_test_recovery_ctrl_format);
TEST (ocp_recovery_test_recovery_status_format);
TEST (ocp_recovery_test_hw_status_format);
TEST (ocp_recovery_test_indirect_ctrl_format);
TEST (ocp_recovery_test_indirect_status_format);
TEST (ocp_recovery_test_indirect_data_format);
TEST (ocp_recovery_test_vendor_format);

TEST_SUITE_END;
