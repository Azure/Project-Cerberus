// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "pcisig/tdisp/tdisp_tdi_context_manager.h"

TEST_SUITE_LABEL ("tdisp_tdi_context_manager");

/*******************
 * Test cases
 *******************/

static void tdisp_tdi_context_clear_test (CuTest *test)
{
	struct tdisp_tdi_context context = {
		.bind_p2p_address_mask = 0xff,
		.default_ide_stream_id = 0x55,
		.lock_flags = 0xffff,
		.mmio_reporting_offset = 0xffffffffffffffff,
		.tdi_context_mask = 0xffff,
	};
	uint8_t zero[sizeof (context)] = {};
	int status;

	TEST_START;

	status = tdisp_tdi_context_clear (&context);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, &context, sizeof (context));
	CuAssertIntEquals (test, 0, status);
}

static void tdisp_tdi_context_clear_test_null (CuTest *test)
{
	int status;

	TEST_START;

	status = tdisp_tdi_context_clear (NULL);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);
}

static void tdisp_tdi_context_set_start_nonce_test (CuTest *test)
{
	struct tdisp_tdi_context context = {};
	uint8_t nonce[sizeof (context.start_interface_nonce)] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	};
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_start_nonce (&context, nonce, sizeof (nonce));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MASK_NONCE, context.tdi_context_mask);

	status = testing_validate_array (nonce, context.start_interface_nonce, sizeof (nonce));
	CuAssertIntEquals (test, 0, status);
}

static void tdisp_tdi_context_set_start_nonce_test_null (CuTest *test)
{
	struct tdisp_tdi_context context = {};
	uint8_t nonce[sizeof (context.start_interface_nonce)] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	};
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_start_nonce (NULL, nonce, sizeof (nonce));
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);

	status = tdisp_tdi_context_set_start_nonce (&context, NULL, sizeof (nonce));
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);

	status = tdisp_tdi_context_set_start_nonce (&context, nonce, 0);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);
}

static void tdisp_tdi_context_set_lock_flags_test (CuTest *test)
{
	struct tdisp_tdi_context context = {};
	uint16_t lock_flags = 0xaa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_lock_flags (&context, lock_flags);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, lock_flags, context.lock_flags);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS, context.tdi_context_mask);
}

static void tdisp_tdi_context_set_lock_flags_test_null (CuTest *test)
{
	uint16_t lock_flags = 0xaa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_lock_flags (NULL, lock_flags);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);
}

static void tdisp_tdi_context_set_default_ide_stream_test (CuTest *test)
{
	struct tdisp_tdi_context context = {};
	uint8_t ide_stream_id = 0xaa;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_default_ide_stream (&context, ide_stream_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ide_stream_id, context.default_ide_stream_id);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MASK_DEFAULT_IDE_STREAM_ID,
		context.tdi_context_mask);
}

static void tdisp_tdi_context_set_default_ide_stream_test_null (CuTest *test)
{
	uint8_t ide_stream_id = 0xaa;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_default_ide_stream (NULL, ide_stream_id);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);
}

static void tdisp_tdi_context_set_mmio_reporting_offset_test (CuTest *test)
{
	struct tdisp_tdi_context context = {};
	uint64_t mmio_reporting_offset = 0xaa55aa55aa55aa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_mmio_reporting_offset (&context, mmio_reporting_offset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, mmio_reporting_offset, context.mmio_reporting_offset);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MASK_MMIO_REPORTING_OFFSET,
		context.tdi_context_mask);
}

static void tdisp_tdi_context_set_mmio_reporting_offset_test_null (CuTest *test)
{
	uint64_t mmio_reporting_offset = 0xaa55aa55aa55aa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_mmio_reporting_offset (NULL, mmio_reporting_offset);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);
}

static void tdisp_tdi_context_set_bind_p2p_address_mask_test (CuTest *test)
{
	struct tdisp_tdi_context context = {};
	uint64_t address_mask = 0xaa55aa55aa55aa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_bind_p2p_address_mask (&context, address_mask);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, address_mask, context.bind_p2p_address_mask);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MASK_BIND_P2P_ADDRESS_MASK,
		context.tdi_context_mask);
}

static void tdisp_tdi_context_set_bind_p2p_address_mask_test_null (CuTest *test)
{
	uint64_t address_mask = 0xaa55aa55aa55aa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_bind_p2p_address_mask (NULL, address_mask);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);
}

static void tdisp_tdi_context_set_reserved_test (CuTest *test)
{
	struct tdisp_tdi_context context = {};
	uint32_t value = 0xaa55aa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_reserved (&context, 2, value);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, value, context.reserved[2]);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MASK_RESERVED_2, context.tdi_context_mask);
}

static void tdisp_tdi_context_set_reserved_test_null (CuTest *test)
{
	uint32_t value = 0xaa55aa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_reserved (NULL, 2, value);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);
}

static void tdisp_tdi_context_set_reserved_test_invalid_arg (CuTest *test)
{
	struct tdisp_tdi_context context = {};
	uint32_t value = 0xaa55aa55;
	int status;

	TEST_START;

	status = tdisp_tdi_context_set_reserved (&context, 10, value);
	CuAssertIntEquals (test, TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT, status);
}

// *INDENT-OFF*
TEST_SUITE_START (tdisp_tdi_context_manager);

TEST (tdisp_tdi_context_clear_test);
TEST (tdisp_tdi_context_clear_test_null);
TEST (tdisp_tdi_context_set_start_nonce_test);
TEST (tdisp_tdi_context_set_start_nonce_test_null);
TEST (tdisp_tdi_context_set_lock_flags_test);
TEST (tdisp_tdi_context_set_lock_flags_test_null);
TEST (tdisp_tdi_context_set_default_ide_stream_test);
TEST (tdisp_tdi_context_set_default_ide_stream_test_null);
TEST (tdisp_tdi_context_set_mmio_reporting_offset_test);
TEST (tdisp_tdi_context_set_mmio_reporting_offset_test_null);
TEST (tdisp_tdi_context_set_bind_p2p_address_mask_test);
TEST (tdisp_tdi_context_set_bind_p2p_address_mask_test_null);
TEST (tdisp_tdi_context_set_reserved_test);
TEST (tdisp_tdi_context_set_reserved_test_null);
TEST (tdisp_tdi_context_set_reserved_test_invalid_arg);

TEST_SUITE_END;
// *INDENT-ON*
