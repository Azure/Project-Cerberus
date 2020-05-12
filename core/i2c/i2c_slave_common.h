// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef I2C_SLAVE_COMMON_H_
#define I2C_SLAVE_COMMON_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"


#define	I2C_SLAVE_ERROR(code)		ROT_ERROR (ROT_MODULE_I2C_SLAVE, code)

/**
 * Error codes that can be generated by an I2C slave driver.
 */
enum {
	I2C_SLAVE_INVALID_ARGUMENT = I2C_SLAVE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	I2C_SLAVE_NO_MEMORY = I2C_SLAVE_ERROR (0x01),				/**< Memory allocation failed. */
};


#endif /* I2C_SLAVE_COMMON_H_ */
