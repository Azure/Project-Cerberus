// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MMIO_UTIL_H_
#define MMIO_UTIL_H_

#include <stddef.h>
#include <stdint.h>


uint32_t mmio_register_read32 (const uint32_t *src);
void mmio_register_write32 (uint32_t *dst, uint32_t value);

void mmio_register_block_read32 (uint32_t *dst, const uint32_t *src, size_t dwords_count);
void mmio_register_block_write32 (uint32_t *dst, const uint32_t *src, size_t dwords_count);


#endif	/* MMIO_UTIL_H_ */
