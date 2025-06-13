// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MMIO_REGISTER_BLOCK_H_
#define MMIO_REGISTER_BLOCK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


/**
 * This interface provide an abstraction for accessing block of MMIO registers.
 */
struct mmio_register_block {
	/**
	 * Perform any required map operations to make this register block operational
	 * Caller is supposed to call this method before issuing any read/write
	 * requests and must call unmap() once read/write operations are completed. Even though the
	 * caller should always follow map()/unmap() pattern, the map() call would still succeed even
	 * if called on already mapped block. The debug log message will be logged as a warning
	 * of this mismatched as indication of potential logic issue.
	 *
	 * @param register_block - mmio_register_block instance
	 *
	 * @return 0 if successful, error otherwise
	 */
	int (*map) (const struct mmio_register_block *register_block);

	/**
	 * Performs any unmapping/cleanup. Must be called once read/write operations completed.
	 * The caller must always follow map()/unmap() pattern, however, calling this function
	 * on already unmaped block will result in no op. Debug log message will be logged to indicate
	 * potential logic issue.
	 *
	 * @param register_block - mmio_register_block instance
	 *
	 */
	void (*unmap) (const struct mmio_register_block *register_block);

	/**
	 * Read single 32 bits MMIO register. Before using this function map() call should be
	 * successfully completed.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param register_offset - register offset inside this block
	 * @param dest - register value destination
	 *
	 * @return 0 - if successful, error code otherwise
	 */
	int (*read32) (const struct mmio_register_block *register_block, uintptr_t register_offset,
		uint32_t *dest);

	/**
	 * Writes single 32 bits value into MMIO register. Before using this function map() call
	 * should be successfully completed.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param register_offset - register offset inside this block
	 * @param value - value to be written
	 *
	 * @return 0 - if successful, error code otherwise
	 */
	int (*write32) (const struct mmio_register_block *register_block, uintptr_t register_offset,
		uint32_t value);

	/**
	 * Reads multiple sequential 32 bits registers into provided destination. Before using this
	 * function map() call should be successfully completed.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param block_offset - offset inside this block
	 * @param dest - pointer to destination buffer
	 * @param dwords_count - number of sequential 32 bits registers to read
	 *
	 * @return 0 - if successful, error code otherwise
	 */
	int (*block_read32) (const struct mmio_register_block *register_block, uintptr_t block_offset,
		uint32_t *dest, size_t dwords_count);

	/**
	 * Writes multiple sequential 32 bits registers. Before using this function map() call
	 * should be successfully completed.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param block_offset - offset inside this block
	 * @param src - pointer to source buffer
	 * @param dwords_count - number of sequential 32 bits registers to write
	 *
	 * @return 0 - if successful, error code otherwise
	 */
	int (*block_write32) (const struct mmio_register_block *register_block, uintptr_t block_offset,
		const uint32_t *src, size_t dwords_count);

	/**
	 * Read single 32 bits MMIO register using its physical address. Before using this function
	 * map() call should be successfully completed.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param physical_address - physical register address, must be inside this block
	 * @param dest - register value destination
	 *
	 * @return 0 - if successful, error code otherwise
	 */
	int (*read32_by_addr) (const struct mmio_register_block *register_block,
		uint64_t physical_address, uint32_t *dest);

	/**
	 * Writes single 32 bits value into MMIO register specified by its physicaladdress. Before
	 * using this function map() call should be successfully completed.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param physical_address - physical register address, must be inside this block
	 * @param value - value to be written
	 *
	 * @return 0 - if successful, error code otherwise
	 */
	int (*write32_by_addr) (const struct mmio_register_block *register_block,
		uint64_t physical_address, uint32_t value);

	/**
	 * Reads multiple sequential 32 bits registers into provided destination based on block physical
	 * address. Before using this function map() call should be successfully completed.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param physical_address - physical address of the block, must be inside this register block
	 * @param dest - pointer to destination buffer
	 * @param dwords_count - number of sequential 32 bits registers to read
	 *
	 * @return 0 - if successful, error code otherwise
	 */
	int (*block_read32_by_addr) (const struct mmio_register_block *register_block,
		uint64_t physical_address, uint32_t *dest, size_t dwords_count);

	/**
	 * Writes multiple sequential 32 bits registers specified by physcal address. Before using
	 * this function map() call should be successfully completed.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param physical_address - physical address of the block, must be inside this register block
	 * @param src - pointer to source buffer
	 * @param dwords_count - number of sequential 32 bits registers to write
	 *
	 * @return 0 - if successful, error code otherwise
	 */
	int (*block_write32_by_addr) (const struct mmio_register_block *register_block,
		uint64_t physical_address, const uint32_t *src, size_t dwords_count);

	/**
	 * Determine the physical address for a specified location within the register block.  Depending
	 * on the device configuration, this address may be larger than pointers used by the local
	 * processor.
	 *
	 * It's not required to map the register block before calling this function.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param offset - offset inside the block
	 * @param address - output for the physical address
	 *
	 * @param 0 - if successful, error code otherwise.
	 */
	int (*get_physical_address) (const struct mmio_register_block *register_block, uintptr_t offset,
		uint64_t *address);

	/**
	 * Determine the offset for a specified physical address within the register block. Address
	 * must be within the register block
	 *
	 * It's not required to map the register block before calling this function.
	 *
	 * @param register_block - mmio_register_block instance
	 * @param sddress - physical address inside the block
	 * @param offset - output for address offset within the block
	 *
	 * @param 0 - if successful, error code otherwise.
	 */
	int (*get_address_offset) (const struct mmio_register_block *register_block, uint64_t address,
		uintptr_t *offset);
};


int mmio_register_block_read_bit (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_num, bool *value);
int mmio_register_block_write_bit (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_num, bool value);
int mmio_register_block_set_bit (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_num);
int mmio_register_block_clear_bit (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_num);

int mmio_register_block_read_bits (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_offset, uint8_t bit_count, uint32_t *value);
int mmio_register_block_write_bits (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_offset, uint8_t bit_count, uint32_t value);


int mmio_register_block_read_bit_by_addr (const struct mmio_register_block *register_block,
	uint64_t physical_address, uint8_t bit_num, bool *value);
int mmio_register_block_write_bit_by_addr (const struct mmio_register_block *register_block,
	uint64_t physical_address, uint8_t bit_num, bool value);
int mmio_register_block_set_bit_by_addr (const struct mmio_register_block *register_block,
	uint64_t physical_address, uint8_t bit_num);
int mmio_register_block_clear_bit_by_addr (const struct mmio_register_block *register_block,
	uint64_t physical_address, uint8_t bit_num);

int mmio_register_block_read_bits_by_addr (const struct mmio_register_block *register_block,
	uint64_t physical_address, uint8_t bit_offset, uint8_t bit_count, uint32_t *value);
int mmio_register_block_write_bits_by_addr (const struct mmio_register_block *register_block,
	uint64_t physical_address, uint8_t bit_offset, uint8_t bit_count, uint32_t value);


#define	MMIO_REGISTER_ERROR(code)		ROT_ERROR (ROT_MODULE_MMIO_REGISTER, code)

/**
 * Error codes that can be generated by the MMIO register block interface.
 *
 * Note: Commented error codes have been deprecated.
 */
enum {
	MMIO_REGISTER_INVALID_ARGUMENT = MMIO_REGISTER_ERROR (0x00),				/**< Input parameter is null or not valid. */
	MMIO_REGISTER_NO_MEMORY = MMIO_REGISTER_ERROR (0x01),						/**< Memory allocation failed. */
	MMIO_REGISTER_MAP_FAILED = MMIO_REGISTER_ERROR (0x02),						/**< Failed to peform internal map operation */
	MMIO_REGISTER_READ32_FAILED = MMIO_REGISTER_ERROR (0x03),					/**< Failed to read 32bits register */
	MMIO_REGISTER_WRITE32_FAILED = MMIO_REGISTER_ERROR (0x04),					/**< Failed to write 32bits register */
	MMIO_REGISTER_BLOCK_READ32_FAILED = MMIO_REGISTER_ERROR (0x05),				/**< Failed to read registers block */
	MMIO_REGISTER_BLOCK_WRITE32_FAILED = MMIO_REGISTER_ERROR (0x06),			/**< Failed to write registers block */
	MMIO_REGISTER_UNALIGNED_ADDRESS = MMIO_REGISTER_ERROR (0x07),				/**< Unaligned memory address. */
	MMIO_REGISTER_UNALIGNED_OFFSET = MMIO_REGISTER_ERROR (0x08),				/**< Unaligned register offset detected. */
	MMIO_REGISTER_UNALIGNED_SIZE = MMIO_REGISTER_ERROR (0x09),					/**< Unaligned block size detected. */
	MMIO_REGISTER_OFFSET_OUT_OF_RANGE = MMIO_REGISTER_ERROR (0x0A),				/**< Register offset is out of range. */
	MMIO_REGISTER_NOT_MAPPED = MMIO_REGISTER_ERROR (0x0B),						/**< Memory is not mapped before accessing registers */
	MMIO_REGISTER_BIT_OUT_OF_RANGE = MMIO_REGISTER_ERROR (0x0C),				/**< Bit number larger than the register size. */
	MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE = MMIO_REGISTER_ERROR (0x0D),			/**< Set of bits larger than the register size. */
	MMIO_REGISTER_ADDRESS_OUT_OF_RANGE = MMIO_REGISTER_ERROR (0x0E),			/**< Register physical address is out of range */
	MMIO_REGISTER_READ32_BY_ADDR_FAILED = MMIO_REGISTER_ERROR (0x0F),			/**< Failed to read 32bits register by physical address */
	MMIO_REGISTER_WRITE32_BY_ADDR_FAILED = MMIO_REGISTER_ERROR (0x10),			/**< Failed to write 32bits register by physical address */
	MMIO_REGISTER_BLOCK_READ32_BY_ADDR_FAILED = MMIO_REGISTER_ERROR (0x11),		/**< Failed to read register block by physical address */
	MMIO_REGISTER_BLOCK_WRITE32_BY_ADDR_FAILED = MMIO_REGISTER_ERROR (0x12),	/**< Failed to write register block by physical address */
	MMIO_REGISTER_GET_PHYSICAL_ADDRESS_FAILED = MMIO_REGISTER_ERROR (0x13),		/**< Failed to convert offset to physical address */
	MMIO_REGISTER_GET_ADDRESS_OFFSET_FAILED = MMIO_REGISTER_ERROR (0x14),		/**< Failed to convert physical address to offset */
};


#endif	// MMIO_REGISTER_BLOCK_H_
