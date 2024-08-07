// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef I2C_MASTER_INTERFACE_H_
#define I2C_MASTER_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


/**
 * Defines the interface to an I2C master
 */
struct i2c_master_interface {
	/**
	 * Execute an I2C write register using provided interface
	 *
	 * @param i2c I2C master interface to use
	 * @param slave_addr I2C slave device address
	 * @param reg_addr I2C register address
	 * @param reg_addr_len I2C register address length
	 * @param data Transaction data buffer
	 * @param len Transaction data length
	 *
	 * @return Transfer status, 0 if success or an error code.
	 */
	int (*write_reg) (struct i2c_master_interface *i2c, uint16_t slave_addr, uint32_t reg_addr,
		size_t reg_addr_len, uint8_t *data, size_t len);

	/**
	 * Execute an I2C read register using provided interface
	 *
	 * @param i2c I2C master interface to use
	 * @param slave_addr I2C slave device address
	 * @param reg_addr I2C register address
	 * @param reg_addr_len I2C register address length
	 * @param data Transaction data buffer
	 * @param len Transaction data length
	 *
	 * @return Transfer status, 0 if success or an error code.
	 */
	int (*read_reg) (struct i2c_master_interface *i2c, uint16_t slave_addr, uint32_t reg_addr,
		size_t reg_addr_len, uint8_t *data, size_t len);

	/**
	 * Execute an I2C write using provided interface
	 *
	 * @param i2c I2C master interface to use
	 * @param slave_addr I2C slave device address
	 * @param data Transaction data buffer
	 * @param len Transaction data length
	 *
	 * @return Transfer status, 0 if success or an error code described in platform_errno.h
	 */
	int (*write) (struct i2c_master_interface *i2c, uint16_t slave_addr, uint8_t *data, size_t len);
};


#define	I2C_MASTER_ERROR(code)		ROT_ERROR (ROT_MODULE_I2C_MASTER, code)

/**
 * Error codes that can be generated by an I2C master driver.
 */
enum {
	I2C_MASTER_INVALID_ARGUMENT = I2C_MASTER_ERROR (0x00),	/**< Input parameter is null or not valid. */
	I2C_MASTER_NO_MEMORY = I2C_MASTER_ERROR (0x01),			/**< Memory allocation failed. */
	I2C_MASTER_WRITE_REG_FAILED = I2C_MASTER_ERROR (0x02),	/**< Could not write to a register. */
	I2C_MASTER_READ_REG_FAILED = I2C_MASTER_ERROR (0x03),	/**< Could not read from a register. */
	I2C_MASTER_BUSY = I2C_MASTER_ERROR (0x04),				/**< The I2C master is busy executing a transaction. */
	I2C_MASTER_TIMEOUT = I2C_MASTER_ERROR (0x05),			/**< The I2C transaction timed out. */
};


#endif	/* I2C_MASTER_INTERFACE_H_ */
