// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <string.h>
#include "heap_with_defrag.h"
#include "common/common_math.h"


#define HEAP_WITH_DEFRAG_BLOCK_MAGIC_NUM				0xAA920221

/**
 * Get address of block contents from control block address.
 *
 * @param ptr Pointer to control block of type struct heap_with_defrag_ctrl_block
 */
#define HEAP_WITH_DEFRAG_BLOCK_CONTENTS(ptr)            \
	(((uint8_t*) ptr) + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN)

/**
 * Get address of end of block.
 *
 * @param ptr Pointer to control block of type struct heap_with_defrag_ctrl_block
 */
#define HEAP_WITH_DEFRAG_BLOCK_END(ptr)                 \
	((struct heap_with_defrag_ctrl_block*) (HEAP_WITH_DEFRAG_BLOCK_CONTENTS(ptr) + ptr->size))

/**
 * Round up input size so it is DWORD aligned.
 *
 * @param size Input size
 *
 * @return Size rounded up to nearest DWORD
 */
#define heap_with_defrag_round_to_nearest_dword(size)  (((size) + 3) & ~((size_t) 3))


/* Linked list of control block headers of allocated memory blocks.  This list starts off empty
 * then every newly allocated block will be added to the beginning of this list. */
static struct heap_with_defrag_ctrl_block *allocated_list = NULL;

/* Linked list of control block headers of free memory blocks.  This list starts off with a single
 * node from the entire available heap size.  Every deallocation will result in blocks being added
 * to this list.  List entries are ordered by increasing memory address, and every deallocation will
 * result in freed block being combined with node right before or after it if contiguous. */
static struct heap_with_defrag_ctrl_block *free_list = NULL;


/**
 * Setup heap allocator
 *
 * @param heap_addr Address of heap memory to utilize
 * @param heap_len Length of heap memory.
 *
 * @return 0 if completed successfully, or an error code if not.
 */
int heap_with_defrag_init (const void *heap_addr, size_t heap_len)
{
	if ((heap_addr == NULL) || (heap_len <= HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN)) {
		return HEAP_WITH_DEFRAG_INVALID_ARGUMENT;
	}

	free_list = (struct heap_with_defrag_ctrl_block*) heap_addr;
	allocated_list = NULL;
	free_list->magic = HEAP_WITH_DEFRAG_BLOCK_MAGIC_NUM;
	free_list->size = heap_len - HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN;
	free_list->next = NULL;
	free_list->prev = NULL;

	return 0;
}

/**
 * Allocate memory of requested size
 *
 * @param size Size of block to allocate
 *
 * @return pointer to memory location allocated of at least requested size, or NULL if it fails
 */
void* heap_with_defrag_allocate (size_t size)
{
	struct heap_with_defrag_ctrl_block *runner = free_list;
	size_t alloc_size;

	size = heap_with_defrag_round_to_nearest_dword (size);
	alloc_size = size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN;

	// Find first free block that can fit requested allocation
	while (runner != NULL) {
		if (runner->size == size) {
			// If block is exactly the size we need, then remove from free list
			if (runner->prev == NULL) {
				free_list = runner->next;

				if (runner->next != NULL) {
					runner->next->prev = NULL;
				}
			}
			else {
				runner->prev->next = runner->next;

				if (runner->next != NULL) {
					runner->next->prev = runner->prev;
				}
			}

			break;
		}
		else if (runner->size >= alloc_size) {
			/* If the block is larger than what we need, then trim off end of block for the newly
			 * allocated block.  All new allocations must come from within the memory of an existing
			 * block or exactly match the size of an existing block. An inefficiency with this
			 * approach is free_list nodes with size greater than the requested size, but less than
			 * alloc_size, will fail the allocation. The alternative would be to reuse the existing
			 * block that is larger than it needs to be, but that introduces new corner cases that
			 * would need to be considered. */
			runner->size -= alloc_size;
			runner = HEAP_WITH_DEFRAG_BLOCK_END (runner);

			break;
		}

		runner = runner->next;
	}

	if (runner != NULL) {
		// Set up control block of new block then add to beginning of allocated list
		runner->magic = HEAP_WITH_DEFRAG_BLOCK_MAGIC_NUM;
		runner->size = size;
		runner->next = allocated_list;
		runner->prev = NULL;

		if (allocated_list != NULL) {
			allocated_list->prev = runner;
		}

		allocated_list = runner;

		return HEAP_WITH_DEFRAG_BLOCK_CONTENTS (runner);
	}

	// No block large enough found in free list
	return NULL;
}

/**
 * Allocate then zeroize memory of requested size
 *
 * @param num_items Number of elements to allocate
 * @param size Size each element to allocate
 *
 * @return pointer to memory location allocated of at least requested size, or NULL if it fails
 */
void* heap_with_defrag_allocate_zeroize (size_t num_items, size_t size)
{
	size_t total_size = num_items * size;
	void *block = heap_with_defrag_allocate (total_size);

	if (block != NULL) {
		memset (block, 0, total_size);
	}

	return block;
}

/**
 * Get allocated size of block from control block header
 *
 * @param addr Address of block
 *
 * @return Size of allocated block if block is valid, 0 otherwise
 */
static size_t heap_with_defrag_get_block_size (void *addr)
{
	struct heap_with_defrag_ctrl_block *block_hdr;

	if (addr == NULL) {
		return 0;
	}

	block_hdr = heap_with_defrag_get_ctrl_block_header (addr);

	return block_hdr->size;
}

/**
 * Swap previously allocated block for a block of new size while preserving contents up to new size
 *
 * @param addr Pointer to previously allocated block, or NULL to allocate new block
 * @param size Size of new block to allocate.  If 0, old block is freed without allocating new block
 *
 * @return pointer to memory location allocated of at least requested size, or NULL if it fails
 */
void* heap_with_defrag_reallocate (void *addr, size_t size)
{
	void *new_addr;
	size_t old_size;

	old_size = heap_with_defrag_get_block_size (addr);

	/* Check if we need to do anything */
	if (old_size == heap_with_defrag_round_to_nearest_dword (size)) {
		return addr;
	}

	new_addr = heap_with_defrag_allocate (size);
	if (new_addr == NULL) {
		return NULL;
	}
	else if (addr != NULL) {
		/* Can be later optimized by checking if following block is free and large enough in cases
		 * where new size is larger than original size, or by trimming block and creating a new free
		 * block in cases where new size is smaller than original size. */
		memcpy (new_addr, addr, min (size, old_size));
		heap_with_defrag_free (addr);
	}

	return new_addr;
}

/**
 * Free allocated block
 *
 * @param addr Address of allocated block to free
 */
void heap_with_defrag_free (void *addr)
{
	struct heap_with_defrag_ctrl_block *free_block = NULL;
	struct heap_with_defrag_ctrl_block *runner = free_list;
	struct heap_with_defrag_ctrl_block *runner_next;
	bool in_free_list = false;

	if (addr == NULL) {
		return;
	}

	free_block = heap_with_defrag_get_ctrl_block_header (addr);

	// Check if block to free is valid
	if (free_block->magic != HEAP_WITH_DEFRAG_BLOCK_MAGIC_NUM) {
		return;
	}

	// Remove from allocated list
	if (free_block->prev == NULL) {
		allocated_list = free_block->next;

		if (free_block->next != NULL) {
			free_block->next->prev = NULL;
		}
	}
	else {
		free_block->prev->next = free_block->next;

		if (free_block->next != NULL) {
			free_block->next->prev = free_block->prev;
		}
	}

	free_block->next = NULL;
	free_block->prev = NULL;

	// Add freed block to free list

	// If free list is empty, set head to free_block
	if (runner == NULL) {
		free_list = free_block;

		return;
	}

	// Get block right before free_block in memory address order
	while ((runner->next != NULL) && (runner->next < free_block)) {
		runner = runner->next;
	}

	if (runner > free_block) {
		/* If free_block comes before all nodes in free list, then loop above would not be entered,
		 * and runner will still be after free_block.  If thats the case, then free_block should
		 * become head of the free list. */
		free_list = free_block;
		free_block->next = runner;
		runner->prev = free_block;
		runner_next = runner;
		in_free_list = true;
	}
	else {
		runner_next = runner->next;

		// Since not freed block is not first entry, check if we can combine with previous block
		if (HEAP_WITH_DEFRAG_BLOCK_END (runner) == free_block) {
			runner->size += free_block->size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN;
			free_block->magic = 0;
			free_block->size = 0;
			free_block->prev = NULL;
			free_block->next = NULL;

			free_block = runner;
			in_free_list = true;
		}
	}

	// Check if we can combine freed block (or combined block) with next block
	if ((runner_next != NULL) && (HEAP_WITH_DEFRAG_BLOCK_END (free_block) == runner_next)) {
		free_block->size += (runner_next->size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN);
		free_block->next = runner_next->next;

		if (runner_next->next != NULL) {
			runner_next->next->prev = free_block;
		}

		if (!in_free_list) {
			free_block->prev = runner_next->prev;
			runner_next->prev->next = free_block;
		}

		runner_next->magic = 0;
		runner_next->size = 0;
		runner_next->prev = NULL;
		runner_next->next = NULL;
		in_free_list = true;
	}

	if (!in_free_list) {
		free_block->next = runner->next;
		free_block->prev = runner;
		runner->next = free_block;

		if (free_block->next != NULL) {
			free_block->next->prev = free_block;
		}
	}
}

/**
 * Get heap allocater statistics
 *
 * @param stats Container to fill up with statistics
 *
 * @return 0 if completed successfully, or an error code if not.
 */
int heap_with_defrag_get_stats (struct heap_with_defrag_stats *stats)
{
	struct heap_with_defrag_ctrl_block *runner = allocated_list;

	if (stats == NULL) {
		return HEAP_WITH_DEFRAG_INVALID_ARGUMENT;
	}

	memset (stats, 0, sizeof (struct heap_with_defrag_stats));

	while (runner != NULL) {
		stats->total_allocated_size += runner->size;
		stats->total_allocated_size_w_overhead +=
			(runner->size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN);
		++stats->num_allocated_blocks;
		runner = runner->next;
	}

	runner = free_list;

	while (runner != NULL) {
		stats->total_free_size += runner->size;
		stats->total_free_size_w_overhead +=
			(runner->size + HEAP_WITH_DEFRAG_CTRL_BLOCK_HEADER_LEN);
		++stats->num_free_blocks;
		runner = runner->next;
	}

	return 0;
}
