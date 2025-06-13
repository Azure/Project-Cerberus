// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing.h"
#include "mmio/mmio_register_block.h"
#include "testing/mock/mmio/mmio_register_block_mock.h"


TEST_SUITE_LABEL ("mmio_register_block");


/*******************
 * Test cases
 *******************/

static void mmio_register_block_test_read_bit_set (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 1;
	uint8_t bit = 0;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_clear (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 0xfffffffe;
	uint8_t bit = 0;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_set_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t value = 0x200;
	uint8_t bit = 9;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_clear_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t value = 0xffffefff;
	uint8_t bit = 12;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_max_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 0x80000000;
	uint8_t bit = 31;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_null (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x3000;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit (NULL, reg, 0, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_read_bit (&block.base, reg, 0, NULL);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_invalid_bit_number (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit (&block.base, reg, 32, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_read_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit (&block.base, reg, 0, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_set (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 0;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, bit, true);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_clear (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 0;
	uint32_t updated = 0xfffffffe;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, bit, false);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_set_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0;
	uint8_t bit = 13;
	uint32_t updated = 0x2000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, bit, true);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_clear_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 23;
	uint32_t updated = 0xff7fffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, bit, false);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_max_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0;
	uint8_t bit = 31;
	uint32_t updated = 0x80000000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, bit, true);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_set_already_set (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0x80000;
	uint8_t bit = 19;
	uint32_t updated = 0x80000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, bit, true);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_clear_already_clear (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xffffbfff;
	uint8_t bit = 14;
	uint32_t updated = 0xffffbfff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, bit, false);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_null (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x3000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (NULL, reg, 0, true);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_invald_bit_number (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, 32, true);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_read_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, 0, true);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_write_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, MMIO_REGISTER_WRITE32_FAILED,
		MOCK_ARG (reg), MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit (&block.base, reg, 0, true);
	CuAssertIntEquals (test, MMIO_REGISTER_WRITE32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 0;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x12000;
	uint32_t current = 0;
	uint8_t bit = 14;
	uint32_t updated = 0x4000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_max_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 31;
	uint32_t updated = 0x80000000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_already_set (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x3000;
	uint32_t current = 0x10;
	uint8_t bit = 4;
	uint32_t updated = 0x10;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_null (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x4000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit (NULL, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_invalid_bit_number (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit (&block.base, reg, 32);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_read_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit (&block.base, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_write_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, MMIO_REGISTER_WRITE32_FAILED,
		MOCK_ARG (reg), MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit (&block.base, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_WRITE32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 0;
	uint32_t updated = 0xfffffffe;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 25;
	uint32_t updated = 0xfdffffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_max_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 31;
	uint32_t updated = 0x7fffffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_already_cleared (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xfffffbff;
	uint8_t bit = 10;
	uint32_t updated = 0xfffffbff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_null (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x4000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit (NULL, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_invalid_bit_number (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit (&block.base, reg, 32);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_read_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit (&block.base, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_write_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t updated = 0xfffffffe;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, MMIO_REGISTER_WRITE32_FAILED,
		MOCK_ARG (reg), MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit (&block.base, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_WRITE32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_single_bit (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_multiple_bits (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t value = 0xfffffff6;
	uint8_t bit = 0;
	uint8_t bits = 5;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x16, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_single_bit_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x3000;
	uint32_t value = 0xfffdffff;
	uint8_t bit = 17;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_multiple_bits_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x4000;
	uint32_t value = 0x3fc0;
	uint8_t bit = 6;
	uint8_t bits = 7;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x7f, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_single_bit_max_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 0x80000000;
	uint8_t bit = 31;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_multiple_bits_max_bits (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t value = 0xfffffff6;
	uint8_t bit = 0;
	uint8_t bits = 32;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, value, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_null (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (NULL, reg, 0, bits, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_read_bits (&block.base, reg, 0, bits, NULL);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_invalid_bit_number (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, 32, 1, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_invalid_bit_count (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, 0, 33, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_invalid_bit_range (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, 13, 20, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_read_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits (&block.base, reg, 0, bits, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_single_bit (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_single_bit (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 0;
	uint8_t bits = 1;
	uint32_t updated = 0xfffffffe;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_multiple_bits (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0;
	uint32_t value = 0x1f;
	uint8_t bit = 0;
	uint8_t bits = 5;
	uint32_t updated = 0x1f;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_multiple_bits (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 0;
	uint8_t bits = 10;
	uint32_t updated = 0xfffffc00;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_single_bit_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x3000;
	uint32_t current = 0;
	uint32_t value = 1;
	uint8_t bit = 21;
	uint8_t bits = 1;
	uint32_t updated = 0x200000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_single_bit_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 15;
	uint8_t bits = 1;
	uint32_t updated = 0xffff7fff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_multiple_bits_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x4000;
	uint32_t current = 0;
	uint32_t value = 0x7f;
	uint8_t bit = 14;
	uint8_t bits = 7;
	uint32_t updated = 0x1fc000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_multiple_bits_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x4000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 5;
	uint8_t bits = 12;
	uint32_t updated = 0xfffe001f;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_single_bit_max_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0;
	uint32_t value = 1;
	uint8_t bit = 31;
	uint8_t bits = 1;
	uint32_t updated = 0x80000000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_single_bit_max_offset (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 31;
	uint8_t bits = 1;
	uint32_t updated = 0x7fffffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_multiple_bits_max_bits (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0;
	uint32_t value = 0xffffffff;
	uint8_t bit = 0;
	uint8_t bits = 32;
	uint32_t updated = 0xffffffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_multiple_bits_max_bits (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 0;
	uint8_t bits = 32;
	uint32_t updated = 0;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_both_set_and_clear (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0xa5000;
	uint32_t value = 0x5a;
	uint8_t bit = 12;
	uint8_t bits = 7;
	uint32_t updated = 0xda000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_same_value (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0x5a005a50;
	uint32_t value = 0x69;	// 0x69 << 6 == 0x1a40
	uint8_t bit = 6;
	uint8_t bits = 7;
	uint32_t updated = 0x5a005a50;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_extra_bits_in_value (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x2000;
	uint32_t current = 0xa5a5a5a5;
	uint32_t value = 0xffff37;
	uint8_t bit = 8;
	uint8_t bits = 7;
	uint32_t updated = 0xa5a5b7a5;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_null (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (NULL, reg, bit, bits, value);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_invalid_bit_number (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, 32, 1, value);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_invalid_bit_count (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, 0, 33, value);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_invalid_bit_range (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, 13, 20, value);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_read_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_write_error (CuTest *test)
{
	struct mmio_register_block_mock block;
	uintptr_t reg = 0x1000;
	uint32_t current = 0;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, MMIO_REGISTER_WRITE32_FAILED,
		MOCK_ARG (reg), MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, MMIO_REGISTER_WRITE32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}


static void mmio_register_block_test_read_bit_set_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 1;
	uint8_t bit = 0;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_clear_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0xfffffffe;
	uint8_t bit = 0;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_set_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0x200;
	uint8_t bit = 9;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_clear_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0xffffefff;
	uint8_t bit = 12;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_max_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0x80000000;
	uint8_t bit = 31;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, bit, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_null_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t reg = 0x3000;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (NULL, reg, 0, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, 0, NULL);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_invalid_bit_number_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, 32, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_get_physical_address_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base,
		MMIO_REGISTER_GET_PHYSICAL_ADDRESS_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, 0, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_GET_PHYSICAL_ADDRESS_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bit_read_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	int status;
	bool out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bit_by_addr (&block.base, reg, 0, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_set_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 0;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, bit, true);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_clear_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 0;
	uint32_t updated = 0xfffffffe;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, bit, false);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_set_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 13;
	uint32_t updated = 0x2000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, bit, true);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_clear_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 23;
	uint32_t updated = 0xff7fffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, bit, false);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_max_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 31;
	uint32_t updated = 0x80000000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, bit, true);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_set_already_set_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0x80000;
	uint8_t bit = 19;
	uint32_t updated = 0x80000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, bit, true);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_clear_already_clear_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffbfff;
	uint8_t bit = 14;
	uint32_t updated = 0xffffbfff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, bit, false);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_null_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t reg = 0x3000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (NULL, reg, 0, true);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_invald_bit_number_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, 32, true);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_read_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, 0, true);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bit_write_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block,	MMIO_REGISTER_WRITE32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bit_by_addr (&block.base, reg, 0, true);
	CuAssertIntEquals (test, MMIO_REGISTER_WRITE32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 0;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit_by_addr (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 14;
	uint32_t updated = 0x4000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit_by_addr (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_max_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint8_t bit = 31;
	uint32_t updated = 0x80000000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit_by_addr (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_already_set_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0x10;
	uint8_t bit = 4;
	uint32_t updated = 0x10;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit_by_addr (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_null_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t reg = 0x4000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit_by_addr (NULL, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_invalid_bit_number_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit_by_addr (&block.base, reg, 32);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_read_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit_by_addr (&block.base, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_set_bit_write_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block,	MMIO_REGISTER_WRITE32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_set_bit_by_addr (&block.base, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_WRITE32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 0;
	uint32_t updated = 0xfffffffe;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit_by_addr (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 25;
	uint32_t updated = 0xfdffffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit_by_addr (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_max_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint8_t bit = 31;
	uint32_t updated = 0x7fffffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit_by_addr (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_already_cleared_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xfffffbff;
	uint8_t bit = 10;
	uint32_t updated = 0xfffffbff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit_by_addr (&block.base, reg, bit);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_null_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t reg = 0x4000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit_by_addr (NULL, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_invalid_bit_number_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit_by_addr (&block.base, reg, 32);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_read_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit_by_addr (&block.base, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_clear_bit_write_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t updated = 0xfffffffe;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block,	MMIO_REGISTER_WRITE32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_clear_bit_by_addr (&block.base, reg, 0);
	CuAssertIntEquals (test, MMIO_REGISTER_WRITE32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_single_bit_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_multiple_bits_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0xfffffff6;
	uint8_t bit = 0;
	uint8_t bits = 5;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x16, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_single_bit_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0xfffdffff;
	uint8_t bit = 17;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_multiple_bits_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0x3fc0;
	uint8_t bit = 6;
	uint8_t bits = 7;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x7f, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_single_bit_max_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0x80000000;
	uint8_t bit = 31;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_multiple_bits_max_bits_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 0xfffffff6;
	uint8_t bit = 0;
	uint8_t bits = 32;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &value, sizeof (value), -1);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, bit, bits, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, value, out);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_null_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t reg = 0x1000;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (NULL, reg, 0, bits, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, 0, bits, NULL);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_invalid_bit_number_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, 32, 1, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_invalid_bit_count_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, 0, 33, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_invalid_bit_range_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, 13, 20, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_read_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, 0, bits, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_read_bits_get_physical_address_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint8_t bits = 1;
	int status;
	uint32_t out;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base,
		MMIO_REGISTER_GET_PHYSICAL_ADDRESS_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_read_bits_by_addr (&block.base, reg, 0, bits, &out);
	CuAssertIntEquals (test, MMIO_REGISTER_GET_PHYSICAL_ADDRESS_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_single_bit_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_single_bit_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 0;
	uint8_t bits = 1;
	uint32_t updated = 0xfffffffe;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_multiple_bits_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t value = 0x1f;
	uint8_t bit = 0;
	uint8_t bits = 5;
	uint32_t updated = 0x1f;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_multiple_bits_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 0;
	uint8_t bits = 10;
	uint32_t updated = 0xfffffc00;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_single_bit_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t value = 1;
	uint8_t bit = 21;
	uint8_t bits = 1;
	uint32_t updated = 0x200000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_single_bit_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 15;
	uint8_t bits = 1;
	uint32_t updated = 0xffff7fff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_multiple_bits_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t value = 0x7f;
	uint8_t bit = 14;
	uint8_t bits = 7;
	uint32_t updated = 0x1fc000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_multiple_bits_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 5;
	uint8_t bits = 12;
	uint32_t updated = 0xfffe001f;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_single_bit_max_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t value = 1;
	uint8_t bit = 31;
	uint8_t bits = 1;
	uint32_t updated = 0x80000000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_single_bit_max_offset_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 31;
	uint8_t bits = 1;
	uint32_t updated = 0x7fffffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_set_multiple_bits_max_bits_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t value = 0xffffffff;
	uint8_t bit = 0;
	uint8_t bits = 32;
	uint32_t updated = 0xffffffff;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_clear_multiple_bits_max_bits_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xffffffff;
	uint32_t value = 0;
	uint8_t bit = 0;
	uint8_t bits = 32;
	uint32_t updated = 0;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_both_set_and_clear_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xa5000;
	uint32_t value = 0x5a;
	uint8_t bit = 12;
	uint8_t bits = 7;
	uint32_t updated = 0xda000;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_same_value_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0x5a005a50;
	uint32_t value = 0x69;	// 0x69 << 6 == 0x1a40
	uint8_t bit = 6;
	uint8_t bits = 7;
	uint32_t updated = 0x5a005a50;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_extra_bits_in_value_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0xa5a5a5a5;
	uint32_t value = 0xffff37;
	uint8_t bit = 8;
	uint8_t bits = 7;
	uint32_t updated = 0xa5a5b7a5;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_null_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t reg = 0x1000;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (NULL, reg, bit, bits, value);
	CuAssertIntEquals (test, MMIO_REGISTER_INVALID_ARGUMENT, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_invalid_bit_number_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint32_t value = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, 32, 1, value);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_invalid_bit_count_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint32_t value = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, 0, 33, value);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_invalid_bit_range_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint32_t value = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, 13, 20, value);
	CuAssertIntEquals (test, MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_read_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, MMIO_REGISTER_READ32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, MMIO_REGISTER_READ32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_write_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint64_t reg_offset = 0x1000;
	uint32_t current = 0;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	uint32_t updated = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.read32, &block, 0, MOCK_ARG (reg_offset),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &current, sizeof (current), -1);

	status |= mock_expect (&block.mock, block.base.write32, &block,	MMIO_REGISTER_WRITE32_FAILED,
		MOCK_ARG (reg_offset), MOCK_ARG (updated));

	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, MMIO_REGISTER_WRITE32_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_test_write_bits_get_physical_address_error_by_addr (CuTest *test)
{
	struct mmio_register_block_mock block;
	uint64_t base_address = 0x1000;
	uint64_t reg = 0x2000;
	uint32_t value = 1;
	uint8_t bit = 0;
	uint8_t bits = 1;
	int status;

	TEST_START;

	status = mmio_register_block_mock_init (&block);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&block.mock, block.base.get_physical_address, &block.base,
		MMIO_REGISTER_GET_PHYSICAL_ADDRESS_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&block.mock, 1, &base_address, sizeof (base_address), -1);
	CuAssertIntEquals (test, 0, status);

	status = mmio_register_block_write_bits_by_addr (&block.base, reg, bit, bits, value);
	CuAssertIntEquals (test, MMIO_REGISTER_GET_PHYSICAL_ADDRESS_FAILED, status);

	status = mmio_register_block_mock_validate_and_release (&block);
	CuAssertIntEquals (test, 0, status);
}


// *INDENT-OFF*
TEST_SUITE_START (mmio_register_block);

TEST (mmio_register_block_test_read_bit_set);
TEST (mmio_register_block_test_read_bit_clear);
TEST (mmio_register_block_test_read_bit_set_offset);
TEST (mmio_register_block_test_read_bit_clear_offset);
TEST (mmio_register_block_test_read_bit_max_offset);
TEST (mmio_register_block_test_read_bit_null);
TEST (mmio_register_block_test_read_bit_invalid_bit_number);
TEST (mmio_register_block_test_read_bit_read_error);
TEST (mmio_register_block_test_write_bit_set);
TEST (mmio_register_block_test_write_bit_clear);
TEST (mmio_register_block_test_write_bit_set_offset);
TEST (mmio_register_block_test_write_bit_clear_offset);
TEST (mmio_register_block_test_write_bit_max_offset);
TEST (mmio_register_block_test_write_bit_set_already_set);
TEST (mmio_register_block_test_write_bit_clear_already_clear);
TEST (mmio_register_block_test_write_bit_null);
TEST (mmio_register_block_test_write_bit_invald_bit_number);
TEST (mmio_register_block_test_write_bit_read_error);
TEST (mmio_register_block_test_write_bit_write_error);
TEST (mmio_register_block_test_set_bit);
TEST (mmio_register_block_test_set_bit_offset);
TEST (mmio_register_block_test_set_bit_max_offset);
TEST (mmio_register_block_test_set_bit_already_set);
TEST (mmio_register_block_test_set_bit_null);
TEST (mmio_register_block_test_set_bit_invalid_bit_number);
TEST (mmio_register_block_test_set_bit_read_error);
TEST (mmio_register_block_test_set_bit_write_error);
TEST (mmio_register_block_test_clear_bit);
TEST (mmio_register_block_test_clear_bit_offset);
TEST (mmio_register_block_test_clear_bit_max_offset);
TEST (mmio_register_block_test_clear_bit_already_cleared);
TEST (mmio_register_block_test_clear_bit_null);
TEST (mmio_register_block_test_clear_bit_invalid_bit_number);
TEST (mmio_register_block_test_clear_bit_read_error);
TEST (mmio_register_block_test_clear_bit_write_error);
TEST (mmio_register_block_test_read_bits_single_bit);
TEST (mmio_register_block_test_read_bits_multiple_bits);
TEST (mmio_register_block_test_read_bits_single_bit_offset);
TEST (mmio_register_block_test_read_bits_multiple_bits_offset);
TEST (mmio_register_block_test_read_bits_single_bit_max_offset);
TEST (mmio_register_block_test_read_bits_multiple_bits_max_bits);
TEST (mmio_register_block_test_read_bits_null);
TEST (mmio_register_block_test_read_bits_invalid_bit_number);
TEST (mmio_register_block_test_read_bits_invalid_bit_count);
TEST (mmio_register_block_test_read_bits_invalid_bit_range);
TEST (mmio_register_block_test_read_bits_read_error);
TEST (mmio_register_block_test_write_bits_set_single_bit);
TEST (mmio_register_block_test_write_bits_clear_single_bit);
TEST (mmio_register_block_test_write_bits_set_multiple_bits);
TEST (mmio_register_block_test_write_bits_clear_multiple_bits);
TEST (mmio_register_block_test_write_bits_set_single_bit_offset);
TEST (mmio_register_block_test_write_bits_clear_single_bit_offset);
TEST (mmio_register_block_test_write_bits_set_multiple_bits_offset);
TEST (mmio_register_block_test_write_bits_clear_multiple_bits_offset);
TEST (mmio_register_block_test_write_bits_set_single_bit_max_offset);
TEST (mmio_register_block_test_write_bits_clear_single_bit_max_offset);
TEST (mmio_register_block_test_write_bits_set_multiple_bits_max_bits);
TEST (mmio_register_block_test_write_bits_clear_multiple_bits_max_bits);
TEST (mmio_register_block_test_write_bits_both_set_and_clear);
TEST (mmio_register_block_test_write_bits_same_value);
TEST (mmio_register_block_test_write_bits_extra_bits_in_value);
TEST (mmio_register_block_test_write_bits_null);
TEST (mmio_register_block_test_write_bits_invalid_bit_number);
TEST (mmio_register_block_test_write_bits_invalid_bit_count);
TEST (mmio_register_block_test_write_bits_invalid_bit_range);
TEST (mmio_register_block_test_write_bits_read_error);
TEST (mmio_register_block_test_write_bits_write_error);
TEST (mmio_register_block_test_read_bit_set_by_addr);
TEST (mmio_register_block_test_read_bit_clear_by_addr);
TEST (mmio_register_block_test_read_bit_set_offset_by_addr);
TEST (mmio_register_block_test_read_bit_clear_offset_by_addr);
TEST (mmio_register_block_test_read_bit_max_offset_by_addr);
TEST (mmio_register_block_test_read_bit_null_by_addr);
TEST (mmio_register_block_test_read_bit_invalid_bit_number_by_addr);
TEST (mmio_register_block_test_read_bit_read_error_by_addr);
TEST (mmio_register_block_test_read_bit_get_physical_address_error_by_addr);
TEST (mmio_register_block_test_write_bit_set_by_addr);
TEST (mmio_register_block_test_write_bit_clear_by_addr);
TEST (mmio_register_block_test_write_bit_set_offset_by_addr);
TEST (mmio_register_block_test_write_bit_clear_offset_by_addr);
TEST (mmio_register_block_test_write_bit_max_offset_by_addr);
TEST (mmio_register_block_test_write_bit_set_already_set_by_addr);
TEST (mmio_register_block_test_write_bit_clear_already_clear_by_addr);
TEST (mmio_register_block_test_write_bit_null_by_addr);
TEST (mmio_register_block_test_write_bit_invald_bit_number_by_addr);
TEST (mmio_register_block_test_write_bit_read_error_by_addr);
TEST (mmio_register_block_test_write_bit_write_error_by_addr);
TEST (mmio_register_block_test_set_bit_by_addr);
TEST (mmio_register_block_test_set_bit_offset_by_addr);
TEST (mmio_register_block_test_set_bit_max_offset_by_addr);
TEST (mmio_register_block_test_set_bit_already_set_by_addr);
TEST (mmio_register_block_test_set_bit_null_by_addr);
TEST (mmio_register_block_test_set_bit_invalid_bit_number_by_addr);
TEST (mmio_register_block_test_set_bit_read_error_by_addr);
TEST (mmio_register_block_test_set_bit_write_error_by_addr);
TEST (mmio_register_block_test_clear_bit_by_addr);
TEST (mmio_register_block_test_clear_bit_offset_by_addr);
TEST (mmio_register_block_test_clear_bit_max_offset_by_addr);
TEST (mmio_register_block_test_clear_bit_already_cleared_by_addr);
TEST (mmio_register_block_test_clear_bit_null_by_addr);
TEST (mmio_register_block_test_clear_bit_invalid_bit_number_by_addr);
TEST (mmio_register_block_test_clear_bit_read_error_by_addr);
TEST (mmio_register_block_test_clear_bit_write_error_by_addr);
TEST (mmio_register_block_test_read_bits_single_bit_by_addr);
TEST (mmio_register_block_test_read_bits_multiple_bits_by_addr);
TEST (mmio_register_block_test_read_bits_single_bit_offset_by_addr);
TEST (mmio_register_block_test_read_bits_multiple_bits_offset_by_addr);
TEST (mmio_register_block_test_read_bits_single_bit_max_offset_by_addr);
TEST (mmio_register_block_test_read_bits_multiple_bits_max_bits_by_addr);
TEST (mmio_register_block_test_read_bits_null_by_addr);
TEST (mmio_register_block_test_read_bits_invalid_bit_number_by_addr);
TEST (mmio_register_block_test_read_bits_invalid_bit_count_by_addr);
TEST (mmio_register_block_test_read_bits_invalid_bit_range_by_addr);
TEST (mmio_register_block_test_read_bits_read_error_by_addr);
TEST (mmio_register_block_test_read_bits_get_physical_address_error_by_addr);
TEST (mmio_register_block_test_write_bits_set_single_bit_by_addr);
TEST (mmio_register_block_test_write_bits_clear_single_bit_by_addr);
TEST (mmio_register_block_test_write_bits_set_multiple_bits_by_addr);
TEST (mmio_register_block_test_write_bits_clear_multiple_bits_by_addr);
TEST (mmio_register_block_test_write_bits_set_single_bit_offset_by_addr);
TEST (mmio_register_block_test_write_bits_clear_single_bit_offset_by_addr);
TEST (mmio_register_block_test_write_bits_set_multiple_bits_offset_by_addr);
TEST (mmio_register_block_test_write_bits_clear_multiple_bits_offset_by_addr);
TEST (mmio_register_block_test_write_bits_set_single_bit_max_offset_by_addr);
TEST (mmio_register_block_test_write_bits_clear_single_bit_max_offset_by_addr);
TEST (mmio_register_block_test_write_bits_set_multiple_bits_max_bits_by_addr);
TEST (mmio_register_block_test_write_bits_clear_multiple_bits_max_bits_by_addr);
TEST (mmio_register_block_test_write_bits_both_set_and_clear_by_addr);
TEST (mmio_register_block_test_write_bits_same_value_by_addr);
TEST (mmio_register_block_test_write_bits_extra_bits_in_value_by_addr);
TEST (mmio_register_block_test_write_bits_null_by_addr);
TEST (mmio_register_block_test_write_bits_invalid_bit_number_by_addr);
TEST (mmio_register_block_test_write_bits_invalid_bit_count_by_addr);
TEST (mmio_register_block_test_write_bits_invalid_bit_range_by_addr);
TEST (mmio_register_block_test_write_bits_read_error_by_addr);
TEST (mmio_register_block_test_write_bits_write_error_by_addr);
TEST (mmio_register_block_test_write_bits_get_physical_address_error_by_addr);

TEST_SUITE_END;
// *INDENT-ON*
