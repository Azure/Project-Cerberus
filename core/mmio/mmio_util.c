// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mmio_util.h"


/**
 * Utility function to perform 32bits MMIO register read.
 * No arguments check performed.
 *
 * @param src Pointer to 32 bits MMIO register to read
 *
 * @return Returns register value
 */
uint32_t mmio_register_read32 (const uint32_t *src)
{
	return ((const volatile uint32_t*) src)[0];
}

/**
 * Utility function to perform 32bits MMIO register write.
 * No arguments check
 *
 * @param dst 32 bits MMIO register address to be written
 * @param value Register value to write
  */
void mmio_register_write32 (uint32_t *dst, uint32_t value)
{
	((volatile uint32_t*) dst)[0] = value;
}

/**
 * Utility function to read block of MMIO registers
 * No arguments check.
 *
 * @param dst Destination buffer to receive read data
 * @param src Pointer to MMIO registers block to read
 * @param dwrods_count Number of DWORDs to be read
 */
void mmio_register_block_read32 (uint32_t *dst, const uint32_t *src, size_t dwords_count)
{
	while (dwords_count) {
		dst[0] = mmio_register_read32 (src);
		dst++;
		src++;
		dwords_count--;
	}
}

/**
 * Utility function to write block of MMIO registers
 * No arguments check.
 *
 * @param dst Pointer to MMIO registers block to be written
 * @param src Source buffer to be written
 * @param dwrods_count Number of DWORDs to be written
 */
void mmio_register_block_write32 (uint32_t *dst, const uint32_t *src, size_t dwords_count)
{
	while (dwords_count) {
		mmio_register_write32 (dst, src[0]);
		dst++;
		src++;
		dwords_count--;
	}
}
