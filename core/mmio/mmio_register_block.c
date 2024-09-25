// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mmio_register_block.h"


/**
 * Read the value of a single bit in an MMIO register.
 *
 * The register must already be mapped.
 *
 * @param register_block The MMIO register block containing the target register.
 * @param register_offset Offset in the MMIO block for the register to read.
 * @param bit_num The bit number to read.  This must be less than 32.
 * @param value Output for the bit value.
 *
 * @return 0 if the bit was read successfully or an error code.
 */
int mmio_register_block_read_bit (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_num, bool *value)
{
	uint32_t temp;
	int status;

	if (value == NULL) {
		return MMIO_REGISTER_INVALID_ARGUMENT;
	}

	status = mmio_register_block_read_bits (register_block, register_offset, bit_num, 1, &temp);
	if (status == 0) {
		*value = temp;
	}

	return status;
}

/**
 * Write a single bit in an MMIO register.  The rest of the register contents will remain
 * unmodified.
 *
 * The register must already be mapped.
 *
 * @param register_block The MMIO register block containing the target register.
 * @param register_offset Offset in the MMIO block for the register to modify.
 * @param bit_num The bit number to set.  This must be less than 32.
 * @param value The bit vlaue to write.
 *
 * @return 0 if the bit was written in the register or an error code.
 */
int mmio_register_block_write_bit (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_num, bool value)
{
	return mmio_register_block_write_bits (register_block, register_offset, bit_num, 1,
		(value) ? 1 : 0);
}

/**
 * Set a single bit in an MMIO register.  The rest of the register contents will remain unmodified.
 *
 * The register must already be mapped.
 *
 * @param register_block The MMIO register block containing the target register.
 * @param register_offset Offset in the MMIO block for the register to modify.
 * @param bit_num The bit number to set.  This must be less than 32.
 *
 * @return 0 if the bit was set in the register or an error code.
 */
int mmio_register_block_set_bit (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_num)
{
	return mmio_register_block_write_bits (register_block, register_offset, bit_num, 1, 1);
}

/**
 * Clear a single bit in an MMIO register.  The rest of the register contents will remain
 * unmodified.
 *
 * The register must already be mapped.
 *
 * @param register_block The MMIO register block containing the target register.
 * @param register_offset Offset in the MMIO block for the register to modify.
 * @param bit_num The bit number to clear.  This must be less than 32.
 *
 * @return 0 if the bit was cleared in the register or an error code.
 */
int mmio_register_block_clear_bit (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_num)
{
	return mmio_register_block_write_bits (register_block, register_offset, bit_num, 1, 0);
}

/**
 * Read a contiguous set of bits from an MMIO register.
 *
 * The register must already be mapped.
 *
 * @param register_block The MMIO register block containing the target register.
 * @param register_offset Offset in the MMIO block for the register to read.
 * @param bit_offset The offset in the register of the bits to read.  This will be the lowest bit
 * position read and must be less than 32.
 * @param bit_count The number of bits to read.  This can be at most 32 bits, depending on the bit
 * offset being read.
 * @param value Output for the bit values.  The data will be stored in bit position 0 and masked
 * based on the number of bits being read.
 *
 * @return 0 if the bits were read successfully or an error code.
 */
int mmio_register_block_read_bits (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_offset, uint8_t bit_count, uint32_t *value)
{
	uint32_t reg_value;
	uint32_t mask;
	int status;

	if ((register_block == NULL) || (value == NULL)) {
		return MMIO_REGISTER_INVALID_ARGUMENT;
	}

	if (bit_offset > 31) {
		return MMIO_REGISTER_BIT_OUT_OF_RANGE;
	}

	if ((bit_count > 32) || ((bit_offset + bit_count) > 32)) {
		return MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE;
	}

	status = register_block->read32 (register_block, register_offset, &reg_value);
	if (status != 0) {
		return status;
	}

	mask = 0xffffffff >> (32 - bit_count);
	*value = (reg_value >> bit_offset) & mask;

	return 0;
}

/**
 * Write a contiguous set of bits to an MMIO register.  The rest of the register contents will
 * remain unmodified.
 *
 * The register must already be mapped.
 *
 * @param register_block The MMIO register block containing the target register.
 * @param register_offset Offset in the MMIO block for the register to modify.
 * @param bit_offset The offset in the register of the bits to write.  This will be the lowest bit
 * position written and must be less than 32.
 * @param bit_count The number of bits to write.  This can be at most 32 bits, depending on the bit
 * offset being written.
 * @param value The value to write.  The data must be stored in bit position 0 of this argument.  It
 * will be masked based on the number bits being written.
 *
 * @return 0 if the register was written successfully or an error code.
 */
int mmio_register_block_write_bits (const struct mmio_register_block *register_block,
	uintptr_t register_offset, uint8_t bit_offset, uint8_t bit_count, uint32_t value)
{
	uint32_t reg_value;
	uint32_t mask;
	int status;

	if (register_block == NULL) {
		return MMIO_REGISTER_INVALID_ARGUMENT;
	}

	if (bit_offset > 31) {
		return MMIO_REGISTER_BIT_OUT_OF_RANGE;
	}

	if ((bit_count > 32) || ((bit_offset + bit_count) > 32)) {
		return MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE;
	}

	status = register_block->read32 (register_block, register_offset, &reg_value);
	if (status != 0) {
		return status;
	}

	mask = (0xffffffff >> (32 - bit_count)) << bit_offset;
	reg_value = (reg_value & ~mask) | ((value << bit_offset) & mask);

	return register_block->write32 (register_block, register_offset, reg_value);
}
