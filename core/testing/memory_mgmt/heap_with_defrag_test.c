// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "memory_mgmt/heap_with_defrag.h"


TEST_SUITE_LABEL ("heap_with_defrag");


static uint8_t heap[4096];
static struct heap_with_defrag_stats stats;


/**
 * Helper function to verify heap allocator stats after all allocations have been freed
 *
 * @param test The test framework
 * @param heap_size Size of heap to check
 */
static void heap_with_defrag_testing_check_stats_empty (CuTest *test, size_t heap_size)
{
	int status;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 0, stats.total_allocated_size);
	CuAssertIntEquals (test, 0, stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, heap_size - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_free_size);
	CuAssertIntEquals (test, heap_size, stats.total_free_size_w_overhead);
}

/**
 * Helper function to verify heap allocator stats after n constant size allocations
 *
 * @param test The test framework
 * @param num_allocation Number of constant size allocations
 * @param allocation_size Constant allocation size
 */
static void heap_with_defrag_testing_check_stats_constant_size_alloc (CuTest *test,
	int num_allocation, size_t allocation_size)
{
	int status;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, num_allocation, stats.num_allocated_blocks);
	CuAssertIntEquals (test, num_allocation * allocation_size, stats.total_allocated_size);
	CuAssertIntEquals (test,
		stats.total_allocated_size + num_allocation * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);
}

/**
 * Helper function to verify memory block contents
 *
 * @param test The test framework
 * @param value Value memory block contents should all be at
 * @param block Pointer to beginning of block
 * @param size Size of memory block
 */
static void heap_with_defrag_testing_check_value (CuTest *test, uint8_t value, uint8_t *block,
	size_t size)
{
	for (size_t i = 0; i < size; ++i) {
		CuAssertIntEquals (test, value, block[i]);
	}
}


/*******************
 * Test cases
 *******************/

static void heap_with_defrag_test_macros (CuTest *test)
{
	uint8_t block_with_ctrl_header[] = {
		0xAA, 0x92, 0x02, 0x21,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1, 0x12, 0x21,
		0xA4, 0xB4, 0xC4, 0xD4, 0xE4, 0xF4, 0x14, 0x24,
		0x19, 0x92
	};
	struct heap_with_defrag_ctrl_block *hdr =
		heap_with_defrag_get_ctrl_block_header (
		&block_with_ctrl_header[sizeof (struct heap_with_defrag_ctrl_block)]);

	TEST_START;

	CuAssertIntEquals (test, sizeof (struct heap_with_defrag_ctrl_block),
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN);
	CuAssertPtrEquals (test, block_with_ctrl_header, hdr);
}

static void heap_with_defrag_test_init (CuTest *test)
{
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);
}

static void heap_with_defrag_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = heap_with_defrag_init (NULL, sizeof (heap));
	CuAssertIntEquals (test, HEAP_WITH_DEFRAG_INVALID_ARGUMENT, status);

	status = heap_with_defrag_init (heap, HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN);
	CuAssertIntEquals (test, HEAP_WITH_DEFRAG_INVALID_ARGUMENT, status);
}

static void heap_with_defrag_test_allocate (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);
}

static void heap_with_defrag_test_allocate_unaligned_size (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (1);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);
}

static void heap_with_defrag_test_allocate_min_num_allocations (CuTest *test)
{
	size_t max_allocation_size = sizeof (heap) - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN;
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (max_allocation_size);
	CuAssertPtrNotNull (test, block);

	CuAssertPtrEquals (test, NULL, heap_with_defrag_allocate (1));

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, max_allocation_size, stats.total_allocated_size);
	CuAssertIntEquals (test, sizeof (heap), stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 0, stats.num_free_blocks);
	CuAssertIntEquals (test, 0, stats.total_free_size);
	CuAssertIntEquals (test, 0, stats.total_free_size_w_overhead);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_max_allocations_two_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	size_t remaining_size = sizeof (heap) - 1000 - 2 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (1000);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 1000);

	block2 = heap_with_defrag_allocate (remaining_size);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, remaining_size);

	CuAssertPtrEquals (test, NULL, heap_with_defrag_allocate (1));

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 1000 + remaining_size, stats.total_allocated_size);
	CuAssertIntEquals (test, sizeof (heap), stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 0, stats.num_free_blocks);
	CuAssertIntEquals (test, 0, stats.total_free_size);
	CuAssertIntEquals (test, 0, stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xBB, block2, remaining_size);

	heap_with_defrag_free (block2);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 1000);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 1000);

	heap_with_defrag_free (block1);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_large_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 2000);

	block3 = heap_with_defrag_allocate (300);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 300);

	block4 = heap_with_defrag_allocate (400);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 400);

	block5 = heap_with_defrag_allocate (500);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3300, stats.total_allocated_size);
	CuAssertIntEquals (test, 3300 + 5 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 300);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 500);
	heap_with_defrag_free (block5);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_large_blocks_free_different_order (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 2000);

	block3 = heap_with_defrag_allocate (300);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 300);

	block4 = heap_with_defrag_allocate (400);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 400);

	block5 = heap_with_defrag_allocate (500);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3300, stats.total_allocated_size);
	CuAssertIntEquals (test, 3300 + 5 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 500);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 300);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_large_and_small_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 2000);

	block3 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 4);

	block4 = heap_with_defrag_allocate (400);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 400);

	block5 = heap_with_defrag_allocate (16);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate (24);
	CuAssertPtrNotNull (test, block6);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate (8);
	CuAssertPtrNotNull (test, block7);

	memset (block7, 0xFA, 8);

	block8 = heap_with_defrag_allocate (300);
	CuAssertPtrNotNull (test, block8);

	memset (block8, 0xFC, 300);

	block9 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block9);

	memset (block9, 0xFD, 4);

	block10 = heap_with_defrag_allocate (500);
	CuAssertPtrNotNull (test, block10);

	memset (block10, 0xFE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);
	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_large_and_small_blocks_free_different_order (
	CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 2000);

	block3 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 4);

	block4 = heap_with_defrag_allocate (400);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 400);

	block5 = heap_with_defrag_allocate (16);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate (24);
	CuAssertPtrNotNull (test, block6);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate (8);
	CuAssertPtrNotNull (test, block7);

	memset (block7, 0xFA, 8);

	block8 = heap_with_defrag_allocate (300);
	CuAssertPtrNotNull (test, block8);

	memset (block8, 0xFC, 300);

	block9 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block9);

	memset (block9, 0xFD, 4);

	block10 = heap_with_defrag_allocate (500);
	CuAssertPtrNotNull (test, block10);

	memset (block10, 0xFE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_blocks_large_first (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 2000);

	block4 = heap_with_defrag_allocate (400);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 400);

	block8 = heap_with_defrag_allocate (300);
	CuAssertPtrNotNull (test, block8);

	memset (block8, 0xFC, 300);

	block10 = heap_with_defrag_allocate (500);
	CuAssertPtrNotNull (test, block10);

	memset (block10, 0xFE, 500);

	block3 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 4);

	block5 = heap_with_defrag_allocate (16);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate (24);
	CuAssertPtrNotNull (test, block6);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate (8);
	CuAssertPtrNotNull (test, block7);

	memset (block7, 0xFA, 8);

	block9 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block9);

	memset (block9, 0xFD, 4);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);
	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_blocks_large_first_free_different_order (
	CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 2000);

	block4 = heap_with_defrag_allocate (400);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 400);

	block8 = heap_with_defrag_allocate (300);
	CuAssertPtrNotNull (test, block8);

	memset (block8, 0xFC, 300);

	block10 = heap_with_defrag_allocate (500);
	CuAssertPtrNotNull (test, block10);

	memset (block10, 0xFE, 500);

	block3 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 4);

	block5 = heap_with_defrag_allocate (16);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate (24);
	CuAssertPtrNotNull (test, block6);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate (8);
	CuAssertPtrNotNull (test, block7);

	memset (block7, 0xFA, 8);

	block9 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block9);

	memset (block9, 0xFD, 4);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_blocks_small_first (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block10 = heap_with_defrag_allocate (500);
	CuAssertPtrNotNull (test, block10);

	memset (block10, 0xFE, 500);

	block3 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 4);

	block5 = heap_with_defrag_allocate (16);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate (24);
	CuAssertPtrNotNull (test, block6);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate (8);
	CuAssertPtrNotNull (test, block7);

	memset (block7, 0xFA, 8);

	block9 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block9);

	memset (block9, 0xFD, 4);

	block1 = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 2000);

	block4 = heap_with_defrag_allocate (400);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 400);

	block8 = heap_with_defrag_allocate (300);
	CuAssertPtrNotNull (test, block8);

	memset (block8, 0xFC, 300);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);
	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_blocks_small_first_free_different_order (
	CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block3 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 4);

	block5 = heap_with_defrag_allocate (16);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate (24);
	CuAssertPtrNotNull (test, block6);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate (8);
	CuAssertPtrNotNull (test, block7);

	memset (block7, 0xFA, 8);

	block9 = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block9);

	memset (block9, 0xFD, 4);

	block1 = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 2000);

	block4 = heap_with_defrag_allocate (400);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 400);

	block8 = heap_with_defrag_allocate (300);
	CuAssertPtrNotNull (test, block8);

	memset (block8, 0xFC, 300);

	block10 = heap_with_defrag_allocate (500);
	CuAssertPtrNotNull (test, block10);

	memset (block10, 0xFE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_multiple_free_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (768);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 768);

	block2 = heap_with_defrag_allocate (768);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 2, 768);

	block3 = heap_with_defrag_allocate (768);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 3, 768);

	block4 = heap_with_defrag_allocate (768);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 4, 768);

	block5 = heap_with_defrag_allocate (768);
	CuAssertPtrNotNull (test, block5);

	memset (block5, 0xEE, 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 5, 768);

	heap_with_defrag_free (block2);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_free (block4);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 3, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	block4 = heap_with_defrag_allocate (768);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0x11, 768);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	block2 = heap_with_defrag_allocate (64);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0x22, 64);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * 4 + 64, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	block6 = heap_with_defrag_allocate (768);
	CuAssertPtrNotNull (test, block6);

	memset (block6, 0x33, 768);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 6, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * 5 + 64, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 0, stats.num_free_blocks);
	CuAssertIntEquals (test, 0, stats.total_free_size);
	CuAssertIntEquals (test, 0, stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 768);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 768);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 768);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0x22, block2, 64);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0x11, block4, 768);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0x33, block6, 768);
	heap_with_defrag_free (block6);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_max_num_allocations_zero (CuTest *test)
{
	void *block[200];
	int i_block = 0;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate (0);
	} while (block[i_block++] != NULL);

	i_block -= 2;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (heap) / (HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN),
		stats.num_allocated_blocks);
	CuAssertIntEquals (test, 0, stats.total_allocated_size);
	CuAssertIntEquals (test, sizeof (heap), stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 0, stats.num_free_blocks);
	CuAssertIntEquals (test, 0, stats.total_free_size);
	CuAssertIntEquals (test, 0, stats.total_free_size_w_overhead);

	while (i_block >= 0) {
		heap_with_defrag_free (block[i_block--]);
	}

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_max_num_allocations_non_zero (CuTest *test)
{
	void *block[200];
	int i_block = 0;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate (4);

		if (block[i_block] != NULL) {
			memset (block[i_block], i_block, 4);
		}
	} while (block[i_block++] != NULL);

	i_block -= 2;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (heap) / (4 + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN) - 1,
		stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, sizeof (heap) - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN - 32,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, 32, stats.total_free_size);
	CuAssertIntEquals (test, 64, stats.total_free_size_w_overhead);

	while (i_block >= 0) {
		heap_with_defrag_testing_check_value (test, i_block, block[i_block], 4);
		heap_with_defrag_free (block[i_block--]);
	}

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_max_num_allocations_zero_limited_heap (CuTest *test)
{
	void *block[200];
	int i_block = 0;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, 256);
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate (0);
	} while (block[i_block++] != NULL);

	i_block -= 2;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 256 / (HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN),
		stats.num_allocated_blocks);
	CuAssertIntEquals (test, 0, stats.total_allocated_size);
	CuAssertIntEquals (test, 256, stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 0, stats.num_free_blocks);
	CuAssertIntEquals (test, 0, stats.total_free_size);
	CuAssertIntEquals (test, 0, stats.total_free_size_w_overhead);

	while (i_block >= 0) {
		heap_with_defrag_free (block[i_block--]);
	}

	heap_with_defrag_testing_check_stats_empty (test, 256);
}

static void heap_with_defrag_test_allocate_max_num_allocations_non_zero_limited_heap (CuTest *test)
{
	void *block[200];
	int i_block = 0;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, 256);
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate (4);

		if (block[i_block] != NULL) {
			memset (block[i_block], i_block, 4);
		}
	} while (block[i_block++] != NULL);

	i_block -= 2;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 256 / (4 + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN) - 1,
		stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, 256 - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN - 8,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, 8, stats.total_free_size);
	CuAssertIntEquals (test, 40, stats.total_free_size_w_overhead);

	while (i_block >= 0) {
		heap_with_defrag_testing_check_value (test, i_block, block[i_block], 4);
		heap_with_defrag_free (block[i_block--]);
	}

	heap_with_defrag_testing_check_stats_empty (test, 256);
}

static void heap_with_defrag_test_allocate_combine_free_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate (1);
	CuAssertPtrNotNull (test, block1);

	memset (block1, 0xAA, 1);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	block2 = heap_with_defrag_allocate (1);
	CuAssertPtrNotNull (test, block2);

	memset (block2, 0xBB, 1);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 2, 4);

	block3 = heap_with_defrag_allocate (1);
	CuAssertPtrNotNull (test, block3);

	memset (block3, 0xCC, 1);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 3, 4);

	block4 = heap_with_defrag_allocate (1);
	CuAssertPtrNotNull (test, block4);

	memset (block4, 0xDD, 1);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 4, 4);

	heap_with_defrag_testing_check_value (test, 0xBB, block2, 1);
	heap_with_defrag_free (block2);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	/*
	 * Test combining with next block
	 * 1: block 2 and block 3, where block 3 address < block 2 address
	 */
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 1);
	heap_with_defrag_free (block3);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	/*
	 * Test combining with previous block and next block
	 * 1: block 4 and block 2+3, where block 4 address < block 2+3 address
	 * 2: free_list head and block 2+3+4, where block 2+3+4 address > free_list head address
	 */
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 1);
	heap_with_defrag_free (block4);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	/*
	 * Test combining with previous block
	 * 2: free_list head and block 1, where block 1 address > free_list head address
	 */
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 1);
	heap_with_defrag_free (block1);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_then_free_in_same_order (CuTest *test)
{
	void *block[200];
	size_t allocated_size = 0;
	int i_block = 0;
	int num_blocks;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate (4 * i_block);

		if (block[i_block] != NULL) {
			memset (block[i_block], i_block, 4 * i_block);
			allocated_size += (4 * i_block);
		}
	} while (block[i_block++] != NULL);

	num_blocks = i_block - 1;
	i_block = 0;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, num_blocks, stats.num_allocated_blocks);
	CuAssertIntEquals (test, allocated_size, stats.total_allocated_size);
	CuAssertIntEquals (test, allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN * num_blocks,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, 36, stats.total_free_size);
	CuAssertIntEquals (test, 68, stats.total_free_size_w_overhead);

	while (num_blocks > 0) {
		heap_with_defrag_testing_check_value (test, i_block, block[i_block], 4 * i_block);
		heap_with_defrag_free (block[i_block++]);
		num_blocks--;
	}

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_then_free_in_different_order (CuTest *test)
{
	void *block[200];
	size_t allocated_size = 0;
	int i_block = 0;
	int n_block;
	int num_blocks;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate (4 * i_block);

		if (block[i_block] != NULL) {
			memset (block[i_block], i_block, 4 * i_block);
			allocated_size += (4 * i_block);
		}
	} while (block[i_block++] != NULL);

	num_blocks = i_block - 1;
	i_block = 0;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, num_blocks, stats.num_allocated_blocks);
	CuAssertIntEquals (test, allocated_size, stats.total_allocated_size);
	CuAssertIntEquals (test, allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN * num_blocks,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, 36, stats.total_free_size);
	CuAssertIntEquals (test, 68, stats.total_free_size_w_overhead);

	n_block = num_blocks - 1;

	while (num_blocks > 0) {
		heap_with_defrag_testing_check_value (test, i_block, block[i_block], 4 * i_block);
		heap_with_defrag_free (block[i_block++]);

		heap_with_defrag_testing_check_value (test, n_block, block[n_block], 4 * n_block);
		heap_with_defrag_free (block[n_block--]);

		num_blocks -= 2;
	}

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_random_pattern (CuTest *test)
{
	void *block[10];
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block[0] = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block[0]);

	memset (block[0], 0xAA, 100);

	block[1] = heap_with_defrag_allocate (700);
	CuAssertPtrNotNull (test, block[1]);

	memset (block[1], 0xBB, 700);

	block[2] = heap_with_defrag_allocate (5);
	CuAssertPtrNotNull (test, block[2]);

	memset (block[2], 0xCC, 5);

	heap_with_defrag_testing_check_value (test, 0xBB, block[1], 700);

	heap_with_defrag_free (block[1]);

	block[3] = heap_with_defrag_allocate (50);
	CuAssertPtrNotNull (test, block[3]);

	memset (block[3], 0xDD, 50);

	heap_with_defrag_testing_check_value (test, 0xCC, block[2], 5);

	heap_with_defrag_free (block[2]);

	block[4] = heap_with_defrag_allocate (2000);
	CuAssertPtrNotNull (test, block[4]);

	memset (block[4], 0xEE, 2000);

	block[5] = heap_with_defrag_allocate (10);
	CuAssertPtrNotNull (test, block[5]);

	memset (block[5], 0xFF, 10);

	block[6] = heap_with_defrag_allocate (1000);
	CuAssertPtrNotNull (test, block[6]);

	memset (block[6], 0xAB, 1000);

	heap_with_defrag_testing_check_value (test, 0xFF, block[5], 10);

	heap_with_defrag_free (block[5]);

	heap_with_defrag_testing_check_value (test, 0xAA, block[0], 100);

	heap_with_defrag_free (block[0]);

	block[7] = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block[7]);

	memset (block[7], 0xAC, 100);

	heap_with_defrag_testing_check_value (test, 0xEE, block[4], 2000);

	heap_with_defrag_free (block[4]);

	block[8] = heap_with_defrag_allocate (1000);
	CuAssertPtrNotNull (test, block[8]);

	memset (block[8], 0xAD, 1000);

	heap_with_defrag_testing_check_value (test, 0xDD, block[3], 50);

	heap_with_defrag_free (block[3]);

	block[9] = heap_with_defrag_allocate (20);
	CuAssertPtrNotNull (test, block[9]);

	memset (block[9], 0xAE, 20);

	block[0] = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block[0]);

	memset (block[0], 0xAF, 100);

	block[1] = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block[1]);

	memset (block[1], 0xBA, 100);

	heap_with_defrag_testing_check_value (test, 0xAD, block[8], 1000);

	heap_with_defrag_free (block[8]);

	block[3] = heap_with_defrag_allocate (100);
	CuAssertPtrNotNull (test, block[3]);

	memset (block[3], 0xBC, 100);

	heap_with_defrag_testing_check_value (test, 0xAF, block[0], 100);

	heap_with_defrag_free (block[0]);

	heap_with_defrag_testing_check_value (test, 0xBA, block[1], 100);

	heap_with_defrag_free (block[1]);

	heap_with_defrag_testing_check_value (test, 0xBC, block[3], 100);

	heap_with_defrag_free (block[3]);

	heap_with_defrag_testing_check_value (test, 0xAB, block[6], 1000);

	heap_with_defrag_free (block[6]);

	heap_with_defrag_testing_check_value (test, 0xAC, block[7], 100);

	heap_with_defrag_free (block[7]);

	heap_with_defrag_testing_check_value (test, 0xAE, block[9], 20);

	heap_with_defrag_free (block[9]);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zero (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (0);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 0);
}

static void heap_with_defrag_test_allocate_no_memory (CuTest *test)
{
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL,
		heap_with_defrag_allocate (sizeof (heap) - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN + 1));

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_value (test, 0, block, 1 * 4);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);
}

static void heap_with_defrag_test_allocate_zeroize_unaligned_size (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate_zeroize (1, 1);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_value (test, 0, block, 1 * 4);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);
}

static void heap_with_defrag_test_allocate_zeroize_min_num_allocations (CuTest *test)
{
	size_t max_allocation_size = sizeof (heap) - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN;
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate_zeroize (1, max_allocation_size);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_value (test, 0, block, max_allocation_size);

	CuAssertPtrEquals (test, NULL, heap_with_defrag_allocate_zeroize (1, 1));

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, max_allocation_size, stats.total_allocated_size);
	CuAssertIntEquals (test, sizeof (heap), stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 0, stats.num_free_blocks);
	CuAssertIntEquals (test, 0, stats.total_free_size);
	CuAssertIntEquals (test, 0, stats.total_free_size_w_overhead);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_max_allocations_two_blocks (CuTest *test)
{
	size_t remaining_size = sizeof (heap) - 1000 - 2 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN;
	void *block1;
	void *block2;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 1000);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 1 * 1000);

	block2 = heap_with_defrag_allocate_zeroize (1, remaining_size);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, remaining_size);

	CuAssertPtrEquals (test, NULL, heap_with_defrag_allocate_zeroize (1, 1));

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 1000 + remaining_size, stats.total_allocated_size);
	CuAssertIntEquals (test, sizeof (heap), stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 0, stats.num_free_blocks);
	CuAssertIntEquals (test, 0, stats.total_free_size);
	CuAssertIntEquals (test, 0, stats.total_free_size_w_overhead);

	heap_with_defrag_free (block2);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 1000);

	heap_with_defrag_free (block1);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_multiple_large_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 100);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 2000);

	memset (block2, 0xBB, 2000);

	block3 = heap_with_defrag_allocate_zeroize (1, 300);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 300);

	memset (block3, 0xCC, 300);

	block4 = heap_with_defrag_allocate_zeroize (1, 400);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 400);

	memset (block4, 0xDD, 400);

	block5 = heap_with_defrag_allocate_zeroize (1, 500);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 500);

	memset (block5, 0xEE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3300, stats.total_allocated_size);
	CuAssertIntEquals (test, 3300 + 5 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 300);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 500);
	heap_with_defrag_free (block5);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_multiple_large_blocks_free_different_order (
	CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 100);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 2000);

	memset (block2, 0xBB, 2000);

	block3 = heap_with_defrag_allocate_zeroize (1, 300);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 300);

	memset (block3, 0xCC, 300);

	block4 = heap_with_defrag_allocate_zeroize (1, 400);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 400);

	memset (block4, 0xDD, 400);

	block5 = heap_with_defrag_allocate_zeroize (1, 500);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 500);

	memset (block5, 0xEE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3300, stats.total_allocated_size);
	CuAssertIntEquals (test, 3300 + 5 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 500);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 300);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_multiple_large_and_small_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 100);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 2000);

	memset (block2, 0xBB, 2000);

	block3 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 4);

	memset (block3, 0xCC, 4);

	block4 = heap_with_defrag_allocate_zeroize (1, 400);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 400);

	memset (block4, 0xDD, 400);

	block5 = heap_with_defrag_allocate_zeroize (1, 16);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 16);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate_zeroize (1, 24);
	CuAssertPtrNotNull (test, block6);

	heap_with_defrag_testing_check_value (test, 0, block6, 24);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate_zeroize (1, 8);
	CuAssertPtrNotNull (test, block7);

	heap_with_defrag_testing_check_value (test, 0, block7, 8);

	memset (block7, 0xFA, 8);

	block8 = heap_with_defrag_allocate_zeroize (1, 300);
	CuAssertPtrNotNull (test, block8);

	heap_with_defrag_testing_check_value (test, 0, block8, 300);

	memset (block8, 0xFC, 300);

	block9 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block9);

	heap_with_defrag_testing_check_value (test, 0, block9, 4);

	memset (block9, 0xFD, 4);

	block10 = heap_with_defrag_allocate_zeroize (1, 500);
	CuAssertPtrNotNull (test, block10);

	heap_with_defrag_testing_check_value (test, 0, block10, 500);

	memset (block10, 0xFE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);
	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void
heap_with_defrag_test_allocate_zeroize_multiple_large_and_small_blocks_free_different_order (
	CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 100);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 2000);

	memset (block2, 0xBB, 2000);

	block3 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 4);

	memset (block3, 0xCC, 4);

	block4 = heap_with_defrag_allocate_zeroize (1, 400);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 400);

	memset (block4, 0xDD, 400);

	block5 = heap_with_defrag_allocate_zeroize (1, 16);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 16);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate_zeroize (1, 24);
	CuAssertPtrNotNull (test, block6);

	heap_with_defrag_testing_check_value (test, 0, block6, 24);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate_zeroize (1, 8);
	CuAssertPtrNotNull (test, block7);

	heap_with_defrag_testing_check_value (test, 0, block7, 8);

	memset (block7, 0xFA, 8);

	block8 = heap_with_defrag_allocate_zeroize (1, 300);
	CuAssertPtrNotNull (test, block8);

	heap_with_defrag_testing_check_value (test, 0, block8, 300);

	memset (block8, 0xFC, 300);

	block9 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block9);

	heap_with_defrag_testing_check_value (test, 0, block9, 4);

	memset (block9, 0xFD, 4);

	block10 = heap_with_defrag_allocate_zeroize (1, 500);
	CuAssertPtrNotNull (test, block10);

	heap_with_defrag_testing_check_value (test, 0, block10, 500);

	memset (block10, 0xFE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_multiple_blocks_large_first (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 100);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 2000);

	memset (block2, 0xBB, 2000);

	block4 = heap_with_defrag_allocate_zeroize (1, 400);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 400);

	memset (block4, 0xDD, 400);

	block8 = heap_with_defrag_allocate_zeroize (1, 300);
	CuAssertPtrNotNull (test, block8);

	heap_with_defrag_testing_check_value (test, 0, block8, 300);

	memset (block8, 0xFC, 300);

	block10 = heap_with_defrag_allocate_zeroize (1, 500);
	CuAssertPtrNotNull (test, block10);

	heap_with_defrag_testing_check_value (test, 0, block10, 500);

	memset (block10, 0xFE, 500);

	block3 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 4);

	memset (block3, 0xCC, 4);

	block5 = heap_with_defrag_allocate_zeroize (1, 16);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 16);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate_zeroize (1, 24);
	CuAssertPtrNotNull (test, block6);

	heap_with_defrag_testing_check_value (test, 0, block6, 24);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate_zeroize (1, 8);
	CuAssertPtrNotNull (test, block7);

	heap_with_defrag_testing_check_value (test, 0, block7, 8);

	memset (block7, 0xFA, 8);

	block9 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block9);

	heap_with_defrag_testing_check_value (test, 0, block9, 4);

	memset (block9, 0xFD, 4);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);
	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_multiple_blocks_large_first_free_different_order
(
	CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 100);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 2000);

	memset (block2, 0xBB, 2000);

	block4 = heap_with_defrag_allocate_zeroize (1, 400);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 400);

	memset (block4, 0xDD, 400);

	block8 = heap_with_defrag_allocate_zeroize (1, 300);
	CuAssertPtrNotNull (test, block8);

	heap_with_defrag_testing_check_value (test, 0, block8, 300);

	memset (block8, 0xFC, 300);

	block10 = heap_with_defrag_allocate_zeroize (1, 500);
	CuAssertPtrNotNull (test, block10);

	heap_with_defrag_testing_check_value (test, 0, block10, 500);

	memset (block10, 0xFE, 500);

	block3 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 4);

	memset (block3, 0xCC, 4);

	block5 = heap_with_defrag_allocate_zeroize (1, 16);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 16);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate_zeroize (1, 24);
	CuAssertPtrNotNull (test, block6);

	heap_with_defrag_testing_check_value (test, 0, block6, 24);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate_zeroize (1, 8);
	CuAssertPtrNotNull (test, block7);

	heap_with_defrag_testing_check_value (test, 0, block7, 8);

	memset (block7, 0xFA, 8);

	block9 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block9);

	heap_with_defrag_testing_check_value (test, 0, block9, 4);

	memset (block9, 0xFD, 4);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_multiple_blocks_small_first (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block3 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 4);

	memset (block3, 0xCC, 4);

	block5 = heap_with_defrag_allocate_zeroize (1, 16);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 16);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate_zeroize (1, 24);
	CuAssertPtrNotNull (test, block6);

	heap_with_defrag_testing_check_value (test, 0, block6, 24);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate_zeroize (1, 8);
	CuAssertPtrNotNull (test, block7);

	heap_with_defrag_testing_check_value (test, 0, block7, 8);

	memset (block7, 0xFA, 8);

	block9 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block9);

	heap_with_defrag_testing_check_value (test, 0, block9, 4);

	memset (block9, 0xFD, 4);

	block1 = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 100);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 2000);

	memset (block2, 0xBB, 2000);

	block4 = heap_with_defrag_allocate_zeroize (1, 400);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 400);

	memset (block4, 0xDD, 400);

	block8 = heap_with_defrag_allocate_zeroize (1, 300);
	CuAssertPtrNotNull (test, block8);

	heap_with_defrag_testing_check_value (test, 0, block8, 300);

	memset (block8, 0xFC, 300);

	block10 = heap_with_defrag_allocate_zeroize (1, 500);
	CuAssertPtrNotNull (test, block10);

	heap_with_defrag_testing_check_value (test, 0, block10, 500);

	memset (block10, 0xFE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);
	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_multiple_blocks_small_first_free_different_order
(
	CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	void *block7;
	void *block8;
	void *block9;
	void *block10;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block3 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 4);

	memset (block3, 0xCC, 4);

	block5 = heap_with_defrag_allocate_zeroize (1, 16);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 16);

	memset (block5, 0xEE, 16);

	block6 = heap_with_defrag_allocate_zeroize (1, 24);
	CuAssertPtrNotNull (test, block6);

	heap_with_defrag_testing_check_value (test, 0, block6, 24);

	memset (block6, 0xFF, 24);

	block7 = heap_with_defrag_allocate_zeroize (1, 8);
	CuAssertPtrNotNull (test, block7);

	heap_with_defrag_testing_check_value (test, 0, block7, 8);

	memset (block7, 0xFA, 8);

	block9 = heap_with_defrag_allocate_zeroize (1, 4);
	CuAssertPtrNotNull (test, block9);

	heap_with_defrag_testing_check_value (test, 0, block9, 4);

	memset (block9, 0xFD, 4);

	block1 = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 100);

	memset (block1, 0xAA, 100);

	block2 = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 2000);

	memset (block2, 0xBB, 2000);

	block4 = heap_with_defrag_allocate_zeroize (1, 400);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 400);

	memset (block4, 0xDD, 400);

	block8 = heap_with_defrag_allocate_zeroize (1, 300);
	CuAssertPtrNotNull (test, block8);

	heap_with_defrag_testing_check_value (test, 0, block8, 300);

	memset (block8, 0xFC, 300);

	block10 = heap_with_defrag_allocate_zeroize (1, 500);
	CuAssertPtrNotNull (test, block10);

	heap_with_defrag_testing_check_value (test, 0, block10, 500);

	memset (block10, 0xFE, 500);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3356, stats.total_allocated_size);
	CuAssertIntEquals (test, 3356 + 10 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xFC, block8, 300);
	heap_with_defrag_free (block8);
	heap_with_defrag_testing_check_value (test, 0xBB, block2, 2000);
	heap_with_defrag_free (block2);
	heap_with_defrag_testing_check_value (test, 0xCC, block3, 4);
	heap_with_defrag_free (block3);
	heap_with_defrag_testing_check_value (test, 0xAA, block1, 100);
	heap_with_defrag_free (block1);
	heap_with_defrag_testing_check_value (test, 0xFD, block9, 4);
	heap_with_defrag_free (block9);
	heap_with_defrag_testing_check_value (test, 0xEE, block5, 16);
	heap_with_defrag_free (block5);
	heap_with_defrag_testing_check_value (test, 0xFF, block6, 24);
	heap_with_defrag_free (block6);
	heap_with_defrag_testing_check_value (test, 0xFE, block10, 500);
	heap_with_defrag_free (block10);
	heap_with_defrag_testing_check_value (test, 0xDD, block4, 400);
	heap_with_defrag_free (block4);
	heap_with_defrag_testing_check_value (test, 0xFA, block7, 8);
	heap_with_defrag_free (block7);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_multiple_free_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	void *block5;
	void *block6;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 768);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 1 * 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 768);

	block2 = heap_with_defrag_allocate_zeroize (1, 768);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 1 * 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 2, 768);

	block3 = heap_with_defrag_allocate_zeroize (1, 768);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 1 * 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 3, 768);

	block4 = heap_with_defrag_allocate_zeroize (1, 768);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 1 * 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 4, 768);

	block5 = heap_with_defrag_allocate_zeroize (1, 768);
	CuAssertPtrNotNull (test, block5);

	heap_with_defrag_testing_check_value (test, 0, block5, 1 * 768);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 5, 768);

	heap_with_defrag_free (block2);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_free (block4);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 3, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	block4 = heap_with_defrag_allocate_zeroize (1, 768);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 1 * 768);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	block2 = heap_with_defrag_allocate_zeroize (1, 64);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 1 * 64);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 5, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * 4 + 64, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	block6 = heap_with_defrag_allocate_zeroize (1, 768);
	CuAssertPtrNotNull (test, block6);

	heap_with_defrag_testing_check_value (test, 0, block6, 1 * 768);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 6, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 768 * 5 + 64, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 0, stats.num_free_blocks);
	CuAssertIntEquals (test, 0, stats.total_free_size);
	CuAssertIntEquals (test, 0, stats.total_free_size_w_overhead);

	heap_with_defrag_free (block1);
	heap_with_defrag_free (block3);
	heap_with_defrag_free (block5);
	heap_with_defrag_free (block2);
	heap_with_defrag_free (block4);
	heap_with_defrag_free (block6);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_max_num_allocations (CuTest *test)
{
	void *block[200];
	int i_block = 0;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate_zeroize (1, 4);
		if (block[i_block] != NULL) {
			heap_with_defrag_testing_check_value (test, 0, block[i_block], 1 * 4);
		}
	} while (block[i_block++] != NULL);

	i_block -= 2;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (heap) / (4 + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN) - 1,
		stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, sizeof (heap) - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN - 32,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, 32, stats.total_free_size);
	CuAssertIntEquals (test, 64, stats.total_free_size_w_overhead);

	while (i_block >= 0) {
		heap_with_defrag_free (block[i_block--]);
	}

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_max_num_allocations_limited_heap (CuTest *test)
{
	void *block[200];
	int i_block = 0;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, 256);
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate_zeroize (1, 4);
		if (block[i_block] != NULL) {
			heap_with_defrag_testing_check_value (test, 0, block[i_block], 1 * 4);
		}
	} while (block[i_block++] != NULL);

	i_block -= 2;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 256 / (4 + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN) - 1,
		stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, 256 - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN - 8,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, 8, stats.total_free_size);
	CuAssertIntEquals (test, 40, stats.total_free_size_w_overhead);

	while (i_block >= 0) {
		heap_with_defrag_free (block[i_block--]);
	}

	heap_with_defrag_testing_check_stats_empty (test, 256);
}

static void heap_with_defrag_test_allocate_zeroize_combine_free_blocks (CuTest *test)
{
	void *block1;
	void *block2;
	void *block3;
	void *block4;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block1 = heap_with_defrag_allocate_zeroize (1, 1);
	CuAssertPtrNotNull (test, block1);

	heap_with_defrag_testing_check_value (test, 0, block1, 1 * 1);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	block2 = heap_with_defrag_allocate_zeroize (1, 1);
	CuAssertPtrNotNull (test, block2);

	heap_with_defrag_testing_check_value (test, 0, block2, 1 * 1);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 2, 4);

	block3 = heap_with_defrag_allocate_zeroize (1, 1);
	CuAssertPtrNotNull (test, block3);

	heap_with_defrag_testing_check_value (test, 0, block3, 1 * 1);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 3, 4);

	block4 = heap_with_defrag_allocate_zeroize (1, 1);
	CuAssertPtrNotNull (test, block4);

	heap_with_defrag_testing_check_value (test, 0, block4, 1 * 1);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 4, 4);

	heap_with_defrag_free (block2);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	/*
	 * Test combining with next block
	 * 1: block 2 and block 3, where block 3 address < block 2 address
	 */
	heap_with_defrag_free (block3);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	/*
	 * Test combining with previous block and next block
	 * 1: block 4 and block 2+3, where block 4 address < block 2+3 address
	 * 2: free_list head and block 2+3+4, where block 2+3+4 address > free_list head address
	 */
	heap_with_defrag_free (block4);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4 * stats.num_allocated_blocks, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + stats.num_allocated_blocks *
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		stats.num_free_blocks * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	/*
	 * Test combining with previous block
	 * 2: free_list head and block 1, where block 1 address > free_list head address
	 */
	heap_with_defrag_free (block1);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_random_pattern (CuTest *test)
{
	void *block[10];
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block[0] = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block[0]);

	heap_with_defrag_testing_check_value (test, 0, block[0], 1 * 100);

	block[1] = heap_with_defrag_allocate_zeroize (1, 700);
	CuAssertPtrNotNull (test, block[1]);

	heap_with_defrag_testing_check_value (test, 0, block[1], 1 * 700);

	block[2] = heap_with_defrag_allocate_zeroize (1, 5);
	CuAssertPtrNotNull (test, block[2]);

	heap_with_defrag_testing_check_value (test, 0, block[2], 1 * 5);

	heap_with_defrag_free (block[1]);

	block[3] = heap_with_defrag_allocate_zeroize (1, 50);
	CuAssertPtrNotNull (test, block[3]);

	heap_with_defrag_testing_check_value (test, 0, block[3], 1 * 50);

	heap_with_defrag_free (block[2]);

	block[4] = heap_with_defrag_allocate_zeroize (1, 2000);
	CuAssertPtrNotNull (test, block[4]);

	heap_with_defrag_testing_check_value (test, 0, block[4], 1 * 2000);

	block[5] = heap_with_defrag_allocate_zeroize (1, 10);
	CuAssertPtrNotNull (test, block[5]);

	heap_with_defrag_testing_check_value (test, 0, block[5], 1 * 10);

	block[6] = heap_with_defrag_allocate_zeroize (1, 1000);
	CuAssertPtrNotNull (test, block[6]);

	heap_with_defrag_testing_check_value (test, 0, block[6], 1 * 1000);

	heap_with_defrag_free (block[5]);
	heap_with_defrag_free (block[0]);

	block[7] = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block[7]);

	heap_with_defrag_testing_check_value (test, 0, block[7], 1 * 100);

	heap_with_defrag_free (block[4]);

	block[8] = heap_with_defrag_allocate_zeroize (1, 1000);
	CuAssertPtrNotNull (test, block[8]);

	heap_with_defrag_testing_check_value (test, 0, block[8], 1 * 1000);

	heap_with_defrag_free (block[3]);

	block[9] = heap_with_defrag_allocate_zeroize (1, 20);
	CuAssertPtrNotNull (test, block[9]);

	heap_with_defrag_testing_check_value (test, 0, block[9], 1 * 20);

	block[0] = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block[0]);

	heap_with_defrag_testing_check_value (test, 0, block[0], 1 * 100);

	block[1] = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block[1]);

	heap_with_defrag_testing_check_value (test, 0, block[1], 1 * 100);

	heap_with_defrag_free (block[8]);

	block[3] = heap_with_defrag_allocate_zeroize (1, 100);
	CuAssertPtrNotNull (test, block[3]);

	heap_with_defrag_testing_check_value (test, 0, block[3], 1 * 100);

	heap_with_defrag_free (block[0]);
	heap_with_defrag_free (block[1]);
	heap_with_defrag_free (block[3]);
	heap_with_defrag_free (block[6]);
	heap_with_defrag_free (block[7]);
	heap_with_defrag_free (block[9]);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_then_free_in_same_order (CuTest *test)
{
	void *block[200];
	size_t allocated_size = 0;
	int i_block = 0;
	int num_blocks;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate_zeroize (1, 4 * i_block);

		if (block[i_block] != NULL) {
			heap_with_defrag_testing_check_value (test, 0, block[i_block], 4 * i_block);
			memset (block[i_block], i_block, 4 * i_block);
			allocated_size += (4 * i_block);
		}
	} while (block[i_block++] != NULL);

	num_blocks = i_block - 1;
	i_block = 0;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, num_blocks, stats.num_allocated_blocks);
	CuAssertIntEquals (test, allocated_size, stats.total_allocated_size);
	CuAssertIntEquals (test, allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN * num_blocks,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, 36, stats.total_free_size);
	CuAssertIntEquals (test, 68, stats.total_free_size_w_overhead);

	while (num_blocks > 0) {
		heap_with_defrag_testing_check_value (test, i_block, block[i_block], 4 * i_block);
		heap_with_defrag_free (block[i_block++]);
		num_blocks--;
	}

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_then_free_in_different_order (CuTest *test)
{
	void *block[200];
	size_t allocated_size = 0;
	int i_block = 0;
	int n_block;
	int num_blocks;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	do {
		block[i_block] = heap_with_defrag_allocate_zeroize (1, 4 * i_block);

		if (block[i_block] != NULL) {
			memset (block[i_block], i_block, 4 * i_block);
			allocated_size += (4 * i_block);
		}
	} while (block[i_block++] != NULL);

	num_blocks = i_block - 1;
	i_block = 0;

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, num_blocks, stats.num_allocated_blocks);
	CuAssertIntEquals (test, allocated_size, stats.total_allocated_size);
	CuAssertIntEquals (test, allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN * num_blocks,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, 36, stats.total_free_size);
	CuAssertIntEquals (test, 68, stats.total_free_size_w_overhead);

	n_block = num_blocks - 1;

	while (num_blocks > 0) {
		heap_with_defrag_testing_check_value (test, i_block, block[i_block], 4 * i_block);
		heap_with_defrag_free (block[i_block++]);

		heap_with_defrag_testing_check_value (test, n_block, block[n_block], 4 * n_block);
		heap_with_defrag_free (block[n_block--]);

		num_blocks -= 2;
	}

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_allocate_zeroize_zero (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate_zeroize (1, 0);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 0);
}

static void heap_with_defrag_test_allocate_zeroize_no_memory (CuTest *test)
{
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, heap_with_defrag_allocate_zeroize (1, sizeof (heap) -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN + 1));

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (1000);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 1000);

	memset (block, 0xAA, 1000);

	block = heap_with_defrag_reallocate (block, 3000);
	CuAssertPtrNotNull (test, block);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 3000, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		2 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block, 1000);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate_new_size_same (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (1000);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 1000);

	memset (block, 0xAA, 1000);

	block = heap_with_defrag_reallocate (block, 1000);
	CuAssertPtrNotNull (test, block);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 1000, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block, 1000);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate_new_size_same_after_rounding_up (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (4);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	memset (block, 0xAA, 4);

	block = heap_with_defrag_reallocate (block, 1);
	CuAssertPtrNotNull (test, block);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 4, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block, 1);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate_new_size_smaller (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (1000);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 1000);

	memset (block, 0xAA, 1000);

	block = heap_with_defrag_reallocate (block, 500);
	CuAssertPtrNotNull (test, block);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 500, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		2 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_testing_check_value (test, 0xAA, block, 500);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate_new_size_too_large (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (1);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	CuAssertPtrEquals (test, NULL, heap_with_defrag_reallocate (block, 4069));

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate_zero_new_size (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (1000);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 1000);

	memset (block, 0xAA, 1000);

	block = heap_with_defrag_reallocate (block, 0);
	CuAssertPtrNotNull (test, block);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 0, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		2 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate_zero_old_size (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (0);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 0);

	block = heap_with_defrag_reallocate (block, 1000);
	CuAssertPtrNotNull (test, block);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 1000, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 2, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		2 * HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate_zero_new_and_old_size (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (0);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 0);

	block = heap_with_defrag_reallocate (block, 0);
	CuAssertPtrNotNull (test, block);

	status = heap_with_defrag_get_stats (&stats);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, stats.num_allocated_blocks);
	CuAssertIntEquals (test, 0, stats.total_allocated_size);
	CuAssertIntEquals (test, stats.total_allocated_size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,
		stats.total_allocated_size_w_overhead);
	CuAssertIntEquals (test, 1, stats.num_free_blocks);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead -
		HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN,	stats.total_free_size);
	CuAssertIntEquals (test, sizeof (heap) - stats.total_allocated_size_w_overhead,
		stats.total_free_size_w_overhead);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_reallocate_null_ptr (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_reallocate (NULL, 1);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_free (CuTest *test)
{
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (1);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_empty (test, sizeof (heap));
}

static void heap_with_defrag_test_free_null (CuTest *test)
{
	struct heap_with_defrag_ctrl_block *cb;
	void *block;
	int status;

	TEST_START;

	status = heap_with_defrag_init (heap, sizeof (heap));
	CuAssertIntEquals (test, 0, status);

	block = heap_with_defrag_allocate (1);
	CuAssertPtrNotNull (test, block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	heap_with_defrag_free (NULL);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);

	cb = heap_with_defrag_get_ctrl_block_header (block);

	cb->magic = 0;

	heap_with_defrag_free (block);

	heap_with_defrag_testing_check_stats_constant_size_alloc (test, 1, 4);
}

static void heap_with_defrag_test_get_stats_null (CuTest *test)
{
	int status;

	TEST_START;

	status = heap_with_defrag_get_stats (NULL);
	CuAssertIntEquals (test, HEAP_WITH_DEFRAG_INVALID_ARGUMENT, status);
}


// *INDENT-OFF*
TEST_SUITE_START (heap_with_defrag);

TEST (heap_with_defrag_test_macros);
TEST (heap_with_defrag_test_init);
TEST (heap_with_defrag_test_init_null);
TEST (heap_with_defrag_test_allocate);
TEST (heap_with_defrag_test_allocate_unaligned_size);
TEST (heap_with_defrag_test_allocate_min_num_allocations);
TEST (heap_with_defrag_test_allocate_max_allocations_two_blocks);
TEST (heap_with_defrag_test_allocate_multiple_large_blocks);
TEST (heap_with_defrag_test_allocate_multiple_large_blocks_free_different_order);
TEST (heap_with_defrag_test_allocate_multiple_large_and_small_blocks);
TEST (heap_with_defrag_test_allocate_multiple_large_and_small_blocks_free_different_order);
TEST (heap_with_defrag_test_allocate_multiple_blocks_large_first);
TEST (heap_with_defrag_test_allocate_multiple_blocks_large_first_free_different_order);
TEST (heap_with_defrag_test_allocate_multiple_blocks_small_first);
TEST (heap_with_defrag_test_allocate_multiple_blocks_small_first_free_different_order);
TEST (heap_with_defrag_test_allocate_multiple_free_blocks);
TEST (heap_with_defrag_test_allocate_max_num_allocations_zero);
TEST (heap_with_defrag_test_allocate_max_num_allocations_non_zero);
TEST (heap_with_defrag_test_allocate_max_num_allocations_zero_limited_heap);
TEST (heap_with_defrag_test_allocate_max_num_allocations_non_zero_limited_heap);
TEST (heap_with_defrag_test_allocate_combine_free_blocks);
TEST (heap_with_defrag_test_allocate_then_free_in_same_order);
TEST (heap_with_defrag_test_allocate_then_free_in_different_order);
TEST (heap_with_defrag_test_allocate_random_pattern);
TEST (heap_with_defrag_test_allocate_zero);
TEST (heap_with_defrag_test_allocate_no_memory);
TEST (heap_with_defrag_test_allocate_zeroize);
TEST (heap_with_defrag_test_allocate_zeroize_unaligned_size);
TEST (heap_with_defrag_test_allocate_zeroize_min_num_allocations);
TEST (heap_with_defrag_test_allocate_zeroize_max_allocations_two_blocks);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_large_blocks);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_large_blocks_free_different_order);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_large_and_small_blocks);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_large_and_small_blocks_free_different_order);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_blocks_large_first);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_blocks_large_first_free_different_order);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_blocks_small_first);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_blocks_small_first_free_different_order);
TEST (heap_with_defrag_test_allocate_zeroize_multiple_free_blocks);
TEST (heap_with_defrag_test_allocate_zeroize_max_num_allocations);
TEST (heap_with_defrag_test_allocate_zeroize_max_num_allocations_limited_heap);
TEST (heap_with_defrag_test_allocate_zeroize_combine_free_blocks);
TEST (heap_with_defrag_test_allocate_zeroize_random_pattern);
TEST (heap_with_defrag_test_allocate_zeroize_then_free_in_same_order);
TEST (heap_with_defrag_test_allocate_zeroize_then_free_in_different_order);
TEST (heap_with_defrag_test_allocate_zeroize_zero);
TEST (heap_with_defrag_test_allocate_zeroize_no_memory);
TEST (heap_with_defrag_test_reallocate);
TEST (heap_with_defrag_test_reallocate_new_size_same);
TEST (heap_with_defrag_test_reallocate_new_size_same_after_rounding_up);
TEST (heap_with_defrag_test_reallocate_new_size_smaller);
TEST (heap_with_defrag_test_reallocate_new_size_too_large);
TEST (heap_with_defrag_test_reallocate_zero_new_size);
TEST (heap_with_defrag_test_reallocate_zero_old_size);
TEST (heap_with_defrag_test_reallocate_zero_new_and_old_size);
TEST (heap_with_defrag_test_reallocate_null_ptr);
TEST (heap_with_defrag_test_free);
TEST (heap_with_defrag_test_free_null);
TEST (heap_with_defrag_test_get_stats_null);

TEST_SUITE_END;
// *INDENT-ON*
