// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "crypto/checksum.h"

TEST_SUITE_LABEL ("checksum");


/*******************
 * Test cases
 *******************/

static void checksum_test_crc8 (CuTest *test)
{
	uint8_t crc;
	uint8_t buf[16];

	TEST_START;

	buf[0] = 0x0F;
	buf[1] = 15;
	buf[2] = 0xAA;
	buf[3] = 0x01;
	buf[4] = 0x0B;
	buf[5] = 0x0A;
	buf[6] = 0x80;
	buf[7] = 0x7E;
	buf[8] = 0x00;
	buf[9] = 0x00;
	buf[10] = 0x01;
	buf[11] = 0xAA;
	buf[12] = 0xBB;
	buf[13] = 0xCC;
	buf[14] = 0xDD;
	buf[15] = 0xEE;

	crc = checksum_crc8 (0x2A, buf, 16);
	CuAssertIntEquals (test, 0xF1, crc);
}

static void checksum_test_crc8_null (CuTest *test)
{
	uint8_t crc;

	TEST_START;

	crc = checksum_crc8 (0x2A, NULL, 16);
	CuAssertIntEquals (test, 0, crc);
}

static void checksum_test_crc8_zero_length (CuTest *test)
{
	uint8_t crc;
	uint8_t buf[17];

	TEST_START;

	buf[0] = 0x0F;
	buf[1] = 15;
	buf[2] = 0xAA;
	buf[3] = 0x01;
	buf[4] = 0x0B;
	buf[5] = 0x0A;
	buf[6] = 0x80;
	buf[7] = 0x7E;
	buf[8] = 0x00;
	buf[9] = 0x00;
	buf[10] = 0x01;
	buf[11] = 0xAA;
	buf[12] = 0xBB;
	buf[13] = 0xCC;
	buf[14] = 0xDD;
	buf[15] = 0xEE;
	buf[16] = 0xAA;

	crc = checksum_crc8 (0x2A, buf, 0);
	CuAssertIntEquals (test, 0, crc);
}

static void checksum_test_init_smbus_crc8 (CuTest *test)
{
	uint8_t crc;

	TEST_START;

	crc = checksum_init_smbus_crc8 (0x2A);
	CuAssertIntEquals (test, 0xd6, crc);
}

static void checksum_test_update_smbus_crc8 (CuTest *test)
{
	uint8_t crc;
	uint8_t buf[3] = {0x01, 0x02, 0x03};

	TEST_START;

	crc = checksum_update_smbus_crc8 (0, buf, sizeof (buf));
	CuAssertIntEquals (test, 0x48, crc);
}

static void checksum_test_update_smbus_crc8_null (CuTest *test)
{
	uint8_t crc;

	TEST_START;

	crc = checksum_update_smbus_crc8 (0x55, NULL, 16);
	CuAssertIntEquals (test, 0x55, crc);
}

static void checksum_test_update_smbus_crc8_zero_length (CuTest *test)
{
	uint8_t crc;
	uint8_t buf[3] = {0x01, 0x02, 0x03};

	TEST_START;

	crc = checksum_update_smbus_crc8 (0xaa, buf, 0);
	CuAssertIntEquals (test, 0xaa, crc);
}


TEST_SUITE_START (checksum);

TEST (checksum_test_crc8);
TEST (checksum_test_crc8_null);
TEST (checksum_test_crc8_zero_length);
TEST (checksum_test_init_smbus_crc8);
TEST (checksum_test_update_smbus_crc8);
TEST (checksum_test_update_smbus_crc8_null);
TEST (checksum_test_update_smbus_crc8_zero_length);

TEST_SUITE_END;
