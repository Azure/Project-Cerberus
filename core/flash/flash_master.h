// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_MASTER_H_
#define FLASH_MASTER_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"


/**
 * Specifies a transaction to be executed by the SPI master.
 */
struct flash_xfer {
	uint32_t address;		/**< The address for the command. */
	uint8_t *data;			/**< The buffer for the command data. */
	uint32_t length;		/**< The length of the command data. */
	uint8_t cmd;			/**< The flash command code. */
	uint8_t dummy_bytes;	/**< The number of dummy bytes in the transaction. */
	uint8_t mode_bytes;		/**< The number of mode bytes in the transaction. */
	uint16_t flags;			/**< Transaction flags. */
};

/**
 * Flags that can be set for a SPI flash transaction.
 */
enum {
	FLASH_FLAG_4BYTE_ADDRESS = 0x0001,	/**< The command contains a 4 byte address. */
	FLASH_FLAG_NO_ADDRESS = 0x0002,		/**< The command contains no address bytes. */
	FLASH_FLAG_DATA_TX = 0x0004,		/**< The transaction will send data bytes. */

	/*
	 * Dual/Quad flags are mutually exclusive.  Mixing them on a transaction will have undefined
	 * behavior.  Though, it is possible to have multiple dual or quad flags set on a transaction.
	 */

	FLASH_FLAG_DUAL_CMD = 0x0100,		/**< Command code will be sent in dual SPI mode. */
	FLASH_FLAG_DUAL_ADDR = 0x0200,		/**< Command address will be sent in dual SPI mode. */
	FLASH_FLAG_DUAL_DATA = 0x0400,		/**< Command data will be transmitted in dual SPI mode. */

	FLASH_FLAG_QUAD_CMD = 0x1000,		/**< Command code will be sent in quad SPI mode. */
	FLASH_FLAG_QUAD_ADDR = 0x2000,		/**< Command address will be sent in quad SPI mode. */
	FLASH_FLAG_QUAD_DATA = 0x4000,		/**< Command data will be transmitted in quad SPI mode. */
};

/**
 * Use DPI mode (2-2-2) for the transaction.
 */
#define FLASH_FLAG_DPI	(FLASH_FLAG_DUAL_CMD | FLASH_FLAG_DUAL_ADDR | FLASH_FLAG_DUAL_DATA)

/**
 * Use QPI mode (4-4-4) for the transaction.
 */
#define	FLASH_FLAG_QPI	(FLASH_FLAG_QUAD_CMD | FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_DATA)


/**
 * Initialize a generic flash transaction.
 */
#define	FLASH_XFER_INIT(xfer, opcode, addr, dummy, mode, buffer, len, flgs) \
	xfer.cmd = opcode; \
	xfer.address = addr; \
	xfer.dummy_bytes = dummy; \
	xfer.mode_bytes = mode; \
	xfer.data = buffer; \
	xfer.length = len; \
	xfer.flags = flgs;

/**
 * Initialize a generic flash transaction to read data.
 */
#define	FLASH_XFER_INIT_READ(xfer, cmd, addr, dummy, mode, buffer, len, flags) \
	FLASH_XFER_INIT (xfer, cmd, addr, dummy, mode, buffer, len, ((flags) & ~(FLASH_FLAG_DATA_TX)))

/**
 * Initialize a generic flash transaction to write data.
 */
#define	FLASH_XFER_INIT_WRITE(xfer, cmd, addr, dummy, buffer, len, flags) \
	FLASH_XFER_INIT (xfer, cmd, addr, dummy, 0, buffer, len, ((flags) | FLASH_FLAG_DATA_TX))

/**
 * Initialize a flash transaction that reads a register without needing an address.
 */
#define	FLASH_XFER_INIT_READ_REG(xfer, cmd, data, len, flags) \
	FLASH_XFER_INIT (xfer, cmd, 0, 0, 0, data, len, (((flags) | FLASH_FLAG_NO_ADDRESS) & ~(FLASH_FLAG_DATA_TX)))

/**
 * Initialize a flash transaction that writes a register without needing an address.
 */
#define FLASH_XFER_INIT_WRITE_REG(xfer, cmd, data, len, flags) \
	FLASH_XFER_INIT (xfer, cmd, 0, 0, 0, data, len, ((flags) | FLASH_FLAG_NO_ADDRESS | FLASH_FLAG_DATA_TX))

/**
 * Initialize a flash transaction that only sends an command code.
 */
#define	FLASH_XFER_INIT_CMD_ONLY(xfer, cmd, flags) \
	FLASH_XFER_INIT (xfer, cmd, 0, 0, 0, NULL, 0, ((flags) | FLASH_FLAG_NO_ADDRESS))

/**
 * Initialize a flash transaction that contains only a command code and address.
 */
#define	FLASH_XFER_INIT_NO_DATA(xfer, cmd, addr, flags) \
	FLASH_XFER_INIT (xfer, cmd, addr, 0, 0, NULL, 0, (flags))


/**
 * Capabilities that can reported by SPI masters.
 */
enum {
	FLASH_CAP_DUAL_2_2_2 = 0x01,		/**< Supports full DPI (2-2-2) mode. */
	FLASH_CAP_DUAL_1_2_2 = 0x02,		/**< Supports Dual address and data (1-2-2) mode. */
	FLASH_CAP_DUAL_1_1_2 = 0x04,		/**< Supports Dual data (1-1-2) mode. */

	FLASH_CAP_QUAD_4_4_4 = 0x10,		/**< Supports full QPI (4-4-4) mode. */
	FLASH_CAP_QUAD_1_4_4 = 0x20,		/**< Supports Quad address and data (1-4-4) mode. */
	FLASH_CAP_QUAD_1_1_4 = 0x40,		/**< Supports Quad data (1-1-4) mode. */

	FLASH_CAP_3BYTE_ADDR = 0x100,		/**< Commands can be sent with 3-byte addresses. */
	FLASH_CAP_4BYTE_ADDR = 0x200,		/**< Commands can be sent with 4-byte addresses. */
};


/**
 * Defines the interface to the SPI master connected to a flash device.
 */
struct flash_master {
	/**
	 * Submit a transfer to be executed by the SPI master.
	 *
	 * @param spi The SPI master to use to execute the transfer.
	 * @param xfer The transfer to execute.
	 *
	 * @return 0 if the transfer was executed successfully or an error code.
	 */
	int (*xfer) (const struct flash_master *spi, const struct flash_xfer *xfer);

	/**
	 * Get a set of capabilities supported by the SPI master.
	 *
	 * @param spi The SPI master to query.
	 *
	 * @return A capabilities bitmask for the SPI master.
	 */
	uint32_t (*capabilities) (const struct flash_master *spi);

	/**
	 * Get the current frequency used for SPI transfers.
	 *
	 * @param spi The SPI master to query.
	 *
	 * @return The SPI clock frequency, in Hz, or an error code.  Use ROT_IS_ERROR to check the
	 * return value.
	 */
	int (*get_spi_clock_frequency) (const struct flash_master *spi);

	/**
	 * Set the frequency to use for SPI transfers.
	 *
	 * It may not be possible to change the frequency while there is an active transaction, so be
	 * sure the SPI master is idle before attempting to change the clock frequency.  In cases where
	 * a single SPI master communicates with multiple devices, there must not be any activity to any
	 * of the devices to ensure that the frequency can be adjusted.
	 *
	 * Depending on the HW capabilities and configuration, it may not be possible to set exactly the
	 * frequency that is requested.  The SPI clock will use the specified frequency as a target
	 * maximum and set the clock to the nearest possible frequency without exceeding the target.
	 *
	 * @param spi The SPI master to configure.
	 * @param freq The target SPI clock frequency, in Hz.
	 *
	 * @return The SPI clock frequency that was configured, in Hz, or an error code.  Use
	 * ROT_IS_ERROR to check the return value.
	 */
	int (*set_spi_clock_frequency) (const struct flash_master *spi, uint32_t freq);
};


#define	FLASH_MASTER_ERROR(code)		ROT_ERROR (ROT_MODULE_FLASH_MASTER, code)

/**
 * Error codes that can be generated by a SPI driver for communicating with flash.
 */
enum {
	FLASH_MASTER_INVALID_ARGUMENT = FLASH_MASTER_ERROR (0x00),		/**< Input parameter is null or not valid. */
	FLASH_MASTER_NO_MEMORY = FLASH_MASTER_ERROR (0x01),				/**< Memory allocation failed. */
	FLASH_MASTER_XFER_FAILED = FLASH_MASTER_ERROR (0x02),			/**< The SPI transaction did not complete. */
	FLASH_MASTER_UNSUPPORTED_XFER = FLASH_MASTER_ERROR (0x03),		/**< The SPI transfer uses capabilities not supported by the driver. */
	FLASH_MASTER_HW_NOT_INIT = FLASH_MASTER_ERROR (0x04),			/**< The SPI hardware has not been initialized. */
	FLASH_MASTER_XFER_TIMEOUT = FLASH_MASTER_ERROR (0x05),			/**< The SPI transfer has timed out without completing. */
	FLASH_MASTER_NO_XFER_DATA = FLASH_MASTER_ERROR (0x06),			/**< No data buffer was provided for the transfer. */
	FLASH_MASTER_XFER_DMA_ERROR = FLASH_MASTER_ERROR (0x07),		/**< The was a DMA error while executing the transfer. */
	FLASH_MASTER_GET_FREQ_FAILED = FLASH_MASTER_ERROR (0x08),		/**< Failed to get the current SPI clock frequency. */
	FLASH_MASTER_SET_FREQ_FAILED = FLASH_MASTER_ERROR (0x09),		/**< Failed to set the SPI clock frequency. */
	FLASH_MASTER_SPI_FREQ_UNSUPPORTED = FLASH_MASTER_ERROR (0x0a),	/**< SPI clock operations are not supported by the driver. */
	FLASH_MASTER_FREQ_OUT_OF_RANGE = FLASH_MASTER_ERROR (0x0b),		/**< The target SPI clock frequency cannot be achieved by the hardware. */
	FLASH_MASTER_XFER_IN_PROGRESS = FLASH_MASTER_ERROR (0x0c),		/**< The operation is not possible because there is an active transfer. */
	FLASH_MASTER_RX_FIFO_OVERFLOW = FLASH_MASTER_ERROR (0x0d),		/**< The SPI HW receive FIFO overflowed and data was lost. */
	FLASH_MASTER_TX_FIFO_UNDERFLOW = FLASH_MASTER_ERROR (0x0e),		/**< The SPI HW transmit FIFO underflowed, corrupting the transfer. */
};


#endif /* FLASH_MASTER_H_ */
