// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "i2c_platform.h"


/**
 * I2C handle for the I2C bus event handling.
 */
static int i2c_handle;


int i2c_init (uint8_t port)
{
	char dev_name[64];

	sprintf (dev_name, "/dev/i2c-%d", port);
	i2c_handle = open (dev_name, O_RDWR);

	if (i2c_handle < 0) {
		printf ("Failed to open I2C device %s: %s\n", dev_name, strerror (errno));

		return FAILURE;
	}

	return SUCCESS;
}

int i2c_read (uint8_t cmd, int8_t addr, uint8_t *payload, int16_t length)
{
	struct i2c_msg msgs[2];
	struct i2c_rdwr_ioctl_data xfer;
	int ret = 0;

	msgs[0].addr = addr;
	msgs[0].buf = &cmd;
	msgs[0].len = 1;
	msgs[0].flags = 0;

	msgs[1].addr = addr;
	msgs[1].buf = payload;
	msgs[1].len = length + 1;
	msgs[1].flags = I2C_M_RD;

	xfer.nmsgs = 2;
	xfer.msgs = msgs;

	ret = ioctl (i2c_handle, I2C_RDWR, &xfer);
	if (ret < 0) {
		printf ("Unable to read data ioctl i2c device port: %s\n", strerror (errno));

		return FAILURE;
	}

	return SUCCESS;
}

int i2c_write (int8_t addr, uint8_t *payload, int16_t length)
{
	int ret = 0;
	struct i2c_msg msgs[2];
	struct i2c_rdwr_ioctl_data xfer;

	msgs[0].addr = addr;
	msgs[0].buf = payload;
	msgs[0].len = length + 1;
	msgs[0].flags = 0;

	xfer.nmsgs = 1;
	xfer.msgs = msgs;

	ret = ioctl (i2c_handle, I2C_RDWR, &xfer);
	if (ret < 0) {
		printf ("Unable to write data ioctl i2c device port: %s\n", strerror (errno));

		return FAILURE;
	}

	return SUCCESS;
}
