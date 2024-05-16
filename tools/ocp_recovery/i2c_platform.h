// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef I2C_PLATFORM_H_
#define I2C_PLATFORM_H_


#include <stdint.h>


#define	FAILURE		(-1)
#define	SUCCESS		(0)


/**
 * Execute and initialization of i2c adapter.
 *
 * @param port i2c adapter command port number.
 *
 * @return i2c_init success or fail status.
 */
int i2c_init (uint8_t port);

/**
 * Execute and aardvark i2c block read command against the target device.
 *
 * @param cmd The command code to send to the device.
 * @param addr The i2c slave address.
 * @param payload Output buffer to the command payload.
 * @param length The amount of data to read from the device.
 *
 * @return i2c read success or fail status.
 */
int i2c_read (uint8_t cmd, int8_t addr, uint8_t *payload, int16_t length);

/**
 * Execute an i2c block write command against the target device.
 *
 * @param cmd The command code to send to the device.
 * @param addr The i2c slave address.
 * @param payload Write data to i2c device.
 * @param length Length of the payload.
 *
 * @return i2c write success or fail status.
 */
int i2c_write (int8_t addr, uint8_t *payload, int16_t length);


#endif	//I2C_PLATFORM_H_
