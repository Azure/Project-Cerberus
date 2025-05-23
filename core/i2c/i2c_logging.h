// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef I2C_LOGGING_H_
#define I2C_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for I2C failures.
 */
enum {
	I2C_LOGGING_MASTER_WRITE_FAIL,			/**< Error while writing to I2C bus as master. */
	I2C_LOGGING_SLAVE_BUS_LOCKUP,			/**< I2C slave recovered from a bus lockup. */
	I2C_LOGGING_SLAVE_TX_FLUSHED_PACKET,	/**< I2C slave flushed packet from TX queue on master write */
	I2C_LOGGING_RX_QUEUE_FULL_DROP_PACKET,	/**< I2C RX queue is full, dropping packet */
};


#endif	/* I2C_LOGGING_H_ */
