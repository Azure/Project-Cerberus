// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef I2C_MASTER_MOCK_H_
#define I2C_MASTER_MOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "i2c/i2c_master_interface.h"
#include "mock.h"


/**
 * I2C master API mock
 */
struct i2c_master_mock {
	struct i2c_master_interface master;         /**< I2C communication instance*/
	struct mock mock;                           /**< Mock instance*/
};

int i2c_master_mock_init (struct i2c_master_mock *mock);
void i2c_master_mock_release (struct i2c_master_mock *mock);
int i2c_master_mock_expect_tx_xfer (struct i2c_master_mock *mock, intptr_t return_val,
	uint16_t slave_addr, uint32_t reg_addr, size_t reg_addr_len, uint8_t *data, size_t len);
int i2c_master_mock_expect_rx_xfer (struct i2c_master_mock *mock, intptr_t return_val,
	const uint8_t *rx_data, size_t rx_length, uint16_t slave_addr, uint32_t reg_addr,
	size_t reg_addr_len, uint8_t *data, size_t len);
int i2c_master_mock_validate_and_release (struct i2c_master_mock *mock);


#endif /* I2C_MASTER_MOCK_H_ */
