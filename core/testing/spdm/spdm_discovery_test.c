// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "spdm/spdm_discovery.h"
#include "spdm/spdm_discovery_static.h"


TEST_SUITE_LABEL ("spdm_discovery");


/*******************
 * Test cases
 *******************/

static void spdm_discovery_test_device_id_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x05,
		0x01,0x02,0x03,0x04,
		0x06,
		0x10,0x11,0x12,0x13,0x14,0x15,
		0x20,0x21,0x22,0x23,0x24,0x25,
		0x30,0x31,0x32,0x33,0x34,0x35,
		0x40,0x41,0x42,0x43,0x44,0x45,
	};
	struct spdm_discovery_device_id *discovery = (struct spdm_discovery_device_id*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct spdm_discovery_device_id));

	CuAssertIntEquals (test, 0x05, discovery->header.completion_code);
	CuAssertIntEquals (test, 0x04030201, discovery->header.device_id_len);
	CuAssertIntEquals (test, 0x06, discovery->header.descriptor_count);

	CuAssertIntEquals (test, 0x1110, discovery->descriptor[0].descriptor_type);
	CuAssertIntEquals (test, 0x1312, discovery->descriptor[0].descriptor_len);
	CuAssertIntEquals (test, 0x1514, discovery->descriptor[0].descriptor_data);

	CuAssertIntEquals (test, 0x2120, discovery->descriptor[1].descriptor_type);
	CuAssertIntEquals (test, 0x2322, discovery->descriptor[1].descriptor_len);
	CuAssertIntEquals (test, 0x2524, discovery->descriptor[1].descriptor_data);

	CuAssertIntEquals (test, 0x3130, discovery->descriptor[2].descriptor_type);
	CuAssertIntEquals (test, 0x3332, discovery->descriptor[2].descriptor_len);
	CuAssertIntEquals (test, 0x3534, discovery->descriptor[2].descriptor_data);

	CuAssertIntEquals (test, 0x4140, discovery->descriptor[3].descriptor_type);
	CuAssertIntEquals (test, 0x4342, discovery->descriptor[3].descriptor_len);
	CuAssertIntEquals (test, 0x4544, discovery->descriptor[3].descriptor_data);
}

static void spdm_discovery_test_device_id_init (CuTest *test)
{
	struct spdm_discovery_device_id discovery;

	TEST_START;

	memset (&discovery, 0x55, sizeof (discovery));

	spdm_discovery_device_id_init (&discovery, 0x1234, 0x5678, 0x9abc, 0xdef0);

	CuAssertIntEquals (test, 0, discovery.header.completion_code);
	CuAssertIntEquals (test, 24, discovery.header.device_id_len);
	CuAssertIntEquals (test, 4, discovery.header.descriptor_count);

	CuAssertIntEquals (test, 0x0000, discovery.descriptor[0].descriptor_type);
	CuAssertIntEquals (test, 2, discovery.descriptor[0].descriptor_len);
	CuAssertIntEquals (test, 0x1234, discovery.descriptor[0].descriptor_data);

	CuAssertIntEquals (test, 0x0100, discovery.descriptor[1].descriptor_type);
	CuAssertIntEquals (test, 2, discovery.descriptor[1].descriptor_len);
	CuAssertIntEquals (test, 0x5678, discovery.descriptor[1].descriptor_data);

	CuAssertIntEquals (test, 0x0101, discovery.descriptor[2].descriptor_type);
	CuAssertIntEquals (test, 2, discovery.descriptor[2].descriptor_len);
	CuAssertIntEquals (test, 0x9abc, discovery.descriptor[2].descriptor_data);

	CuAssertIntEquals (test, 0x0102, discovery.descriptor[3].descriptor_type);
	CuAssertIntEquals (test, 2, discovery.descriptor[3].descriptor_len);
	CuAssertIntEquals (test, 0xdef0, discovery.descriptor[3].descriptor_data);
}

static void spdm_discovery_test_device_id_init_null (CuTest *test)
{
	TEST_START;

	spdm_discovery_device_id_init (NULL, 0x1234, 0x5678, 0x9abc, 0xdef0);
}

static void spdm_discovery_test_device_id_static_init (CuTest *test)
{
	struct spdm_discovery_device_id discovery =
		spdm_discovery_device_id_static_init (0x1122, 0x3344, 0x5566, 0x7788);

	TEST_START;

	CuAssertIntEquals (test, 0, discovery.header.completion_code);
	CuAssertIntEquals (test, 24, discovery.header.device_id_len);
	CuAssertIntEquals (test, 4, discovery.header.descriptor_count);

	CuAssertIntEquals (test, 0x0000, discovery.descriptor[0].descriptor_type);
	CuAssertIntEquals (test, 2, discovery.descriptor[0].descriptor_len);
	CuAssertIntEquals (test, 0x1122, discovery.descriptor[0].descriptor_data);

	CuAssertIntEquals (test, 0x0100, discovery.descriptor[1].descriptor_type);
	CuAssertIntEquals (test, 2, discovery.descriptor[1].descriptor_len);
	CuAssertIntEquals (test, 0x3344, discovery.descriptor[1].descriptor_data);

	CuAssertIntEquals (test, 0x0101, discovery.descriptor[2].descriptor_type);
	CuAssertIntEquals (test, 2, discovery.descriptor[2].descriptor_len);
	CuAssertIntEquals (test, 0x5566, discovery.descriptor[2].descriptor_data);

	CuAssertIntEquals (test, 0x0102, discovery.descriptor[3].descriptor_type);
	CuAssertIntEquals (test, 2, discovery.descriptor[3].descriptor_len);
	CuAssertIntEquals (test, 0x7788, discovery.descriptor[3].descriptor_data);
}


TEST_SUITE_START (spdm_discovery);

TEST (spdm_discovery_test_device_id_format);
TEST (spdm_discovery_test_device_id_init);
TEST (spdm_discovery_test_device_id_init_null);
TEST (spdm_discovery_test_device_id_static_init);

TEST_SUITE_END;
