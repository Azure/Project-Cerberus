// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <errno.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "aardvark/aardvark.h"
#include "i2c_platform.h"


/**
 * The I2C bus bit rate.
 */
#define I2C_BITRATE (100)


/**
 * I2C handle for the I2C bus event handling.
 */
static Aardvark i2c_handle;

int i2c_init (uint8_t port)
{
	uint16_t bitrate;

	i2c_handle = aa_open_ext (port, NULL);

	if (i2c_handle < 0) {
		printf ("Error open aardvark port = %d: %s\n", port, aa_status_string (i2c_handle));
		return FAILURE;
	}

	/* I2C subsystem is enabled*/
	aa_configure (i2c_handle, AA_CONFIG_SPI_I2C);

	/* Setup the bitrate */
	bitrate = aa_i2c_bitrate (i2c_handle, I2C_BITRATE);
	printf ("Bitrate set to %d kHz\n", bitrate);

	return SUCCESS;
}

int i2c_read (uint8_t cmd, int8_t addr, uint8_t *payload, int16_t length)
{
	int ret;
	uint16_t num_byte_written = 0;
	uint16_t num_byte_read = 0;

	ret = aa_i2c_write_ext (i2c_handle, addr, AA_I2C_NO_STOP, 1, &cmd, &num_byte_written);

	if (ret != AA_I2C_STATUS_OK) {
		printf ("Error send aardvark command %d: %s\n", ret, aa_status_string (ret));
		return FAILURE;
	}

	ret = aa_i2c_read_ext (i2c_handle, addr, AA_I2C_NO_FLAGS, length, payload, &num_byte_read);

	if (ret != AA_I2C_STATUS_OK) {
		printf ("Error to read aardvark data %d: %s\n", ret, aa_status_string (ret));
		return FAILURE;
	}
	return SUCCESS;
}

int i2c_write (int8_t addr, uint8_t *payload, int16_t length)
{
	int ret;
	uint16_t num_byte_written = 0;

	ret = aa_i2c_write_ext (i2c_handle, addr, AA_I2C_NO_FLAGS, length, payload, &num_byte_written);

	if (ret != AA_I2C_STATUS_OK) {
		printf ("Error to write aardvark data %d: %s\n", ret, aa_status_string (ret));
		return FAILURE;
	}

	return SUCCESS;
}
