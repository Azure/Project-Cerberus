// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include <stdint.h>
#include "i2c_master_mock.h"

static int i2c_master_mock_write (struct i2c_master_interface *i2c, uint16_t slave_addr, 
	uint8_t *data, size_t len)
{
	struct i2c_master_mock *mock = (struct i2c_master_mock*) i2c;

	if (i2c == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, i2c_master_mock_write, i2c, MOCK_ARG_CALL (slave_addr),
		MOCK_ARG_CALL (data), MOCK_ARG_CALL (len));
}

static int i2c_master_mock_write_reg (struct i2c_master_interface *i2c, uint16_t slave_addr,
	uint32_t reg_addr, size_t reg_addr_len, uint8_t *data, size_t len)
{
	struct i2c_master_mock *mock = (struct i2c_master_mock*) i2c;

	if (i2c == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, i2c_master_mock_write_reg, i2c, MOCK_ARG_CALL (slave_addr),
		MOCK_ARG_CALL (reg_addr), MOCK_ARG_CALL (reg_addr_len), MOCK_ARG_CALL (data),
		MOCK_ARG_CALL (len));
}

static int i2c_master_mock_read_reg (struct i2c_master_interface *i2c, uint16_t slave_addr,
	uint32_t reg_addr, size_t reg_addr_len, uint8_t *data, size_t len)
{
	struct i2c_master_mock *mock = (struct i2c_master_mock*) i2c;

	if (i2c == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, i2c_master_mock_read_reg, i2c, MOCK_ARG_CALL (slave_addr),
		MOCK_ARG_CALL (reg_addr), MOCK_ARG_CALL (reg_addr_len), MOCK_ARG_CALL (data),
		MOCK_ARG_CALL (len));
}

static int i2c_master_mock_func_arg_count (void *func)
{
	if (func == i2c_master_mock_write_reg) {
		return 5;
	}
	else if (func == i2c_master_mock_read_reg) {
		return 5;
	}
	else if (func == i2c_master_mock_write) {
		return 3;
	}
	else {
		return 0;
	}
}

static const char* i2c_master_mock_func_name_map (void *func)
{
	if (func == i2c_master_mock_write_reg) {
		return "write_reg";
	}
	else if (func == i2c_master_mock_read_reg) {
		return "read_reg";
	}
	else if (func == i2c_master_mock_write) {
		return "write";
	}
	else {
		return "unknown";
	}
}

static const char* i2c_master_mock_arg_name_map (void *func, int arg)
{
	if ((func == i2c_master_mock_read_reg) || (func == i2c_master_mock_write_reg)) {
		switch (arg) {
			case 0:
				return "slave_addr";

			case 1:
				return "reg_addr";

			case 2:
				return "reg_addr_len";

			case 3:
				return "data";

			case 4:
				return "len";

			default:
				return "unknown";
		}
	}
	else if (func == i2c_master_mock_write) {
		switch (arg) {
			case 0:
				return "slave_addr";

			case 1:
				return "data";

			case 2:
				return "len";

			default:
				return "unknown";
		}
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize mock interface instance
 *
 * @param mock Mock interface instance to initialize
 *
 * @return Initialization status, 0 if success or an error code.
 */
int i2c_master_mock_init (struct i2c_master_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct i2c_master_mock));

	status = mock_init (&mock->mock);

	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "i2c_master");

	mock->master.read_reg = i2c_master_mock_read_reg;
	mock->master.write_reg = i2c_master_mock_write_reg;
	mock->master.write = i2c_master_mock_write;

	mock->mock.func_arg_count = i2c_master_mock_func_arg_count;
	mock->mock.func_name_map = i2c_master_mock_func_name_map;
	mock->mock.arg_name_map = i2c_master_mock_arg_name_map;

	return 0;
}

/**
 * Release resources used by an I2C master mock instance
 *
 * @param mock Mock interface instance to release
 */
void i2c_master_mock_release (struct i2c_master_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Create a mock TX transfer expectation
 *
 * @param mock I2C master mock interface to add expectation to
 * @param return_val The return value for when transaction happens
 * @param slave_addr I2C slave device address to expect
 * @param reg_addr I2C register address to expect
 * @param reg_addr_len I2C register address length to expect
 * @param data Transaction data buffer to expect
 * @param len Transaction data length to expect
 *
 * @return 0 if expectation added or an error code.
 */
int i2c_master_mock_expect_tx_xfer (struct i2c_master_mock *mock, intptr_t return_val,
	uint16_t slave_addr, uint32_t reg_addr, size_t reg_addr_len, uint8_t *data, size_t len)
{
	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	return mock_expect (&mock->mock, i2c_master_mock_write_reg, mock, return_val,
		MOCK_ARG (slave_addr), MOCK_ARG (reg_addr), MOCK_ARG (reg_addr_len),
		MOCK_ARG_PTR_CONTAINS (data, len), MOCK_ARG (len));
}

/**
 * Create a mock RX transfer expectation
 *
 * @param mock I2C master mock interface to add expectation to
 * @param return_val The return value for when transaction happens
 * @param rx_data The data to return when the transaction happens
 * @param rx_length The transaction data length
 * @param slave_addr I2C slave device address to expect
 * @param reg_addr I2C register address to expect
 * @param reg_addr_len I2C register address length to expect
 * @param data Transaction data buffer to expect
 * @param len Transaction data length to expect
 *
 * @return 0 if expectation added or an error code.
 */
int i2c_master_mock_expect_rx_xfer (struct i2c_master_mock *mock, intptr_t return_val,
	const uint8_t *rx_data, size_t rx_length, uint16_t slave_addr, uint32_t reg_addr,
	size_t reg_addr_len, uint8_t *data, size_t len)
{
	int status;

	struct mock_expect_arg exp_data =
		(data != (void*) -1) ? MOCK_ARG (data) : MOCK_ARG_NOT_NULL;

	if ((mock == NULL) || (rx_data == NULL) || (rx_length == 0)) {
		return MOCK_INVALID_ARGUMENT;
	}

	status =  mock_expect (&mock->mock, i2c_master_mock_read_reg, mock, return_val,
		MOCK_ARG (slave_addr), MOCK_ARG (reg_addr), MOCK_ARG (reg_addr_len), exp_data,
		MOCK_ARG (len));

	if (status != 0) {
		return status;
	}

	return mock_expect_output (&mock->mock, 3, rx_data, rx_length, 4);
}

/**
 * Validate that all expectations were met then release the mock instance
 *
 * @param mock The I2C master mock interface to validate and release
 *
 * @return Validation status, 0 if expectations met or an error code.
 */
int i2c_master_mock_validate_and_release (struct i2c_master_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		i2c_master_mock_release (mock);
	}

	return status;
}
