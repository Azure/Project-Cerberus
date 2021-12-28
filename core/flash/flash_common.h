// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_COMMON_H_
#define FLASH_COMMON_H_

#include <stdint.h>
#include "status/rot_status.h"


/**
 * SPI flash command codes.
 */
enum {
	FLASH_CMD_NOOP = 0x00,				/**< No-op */
	FLASH_CMD_WRSR = 0x01,				/**< Write status register */
	FLASH_CMD_PP = 0x02,				/**< Page program */
	FLASH_CMD_READ = 0x03,				/**< Normal read */
	FLASH_CMD_WRDI = 0x04,				/**< Write disable */
	FLASH_CMD_RDSR = 0x05,				/**< Read status register */
	FLASH_CMD_WREN = 0x06,				/**< Write enable */
	FLASH_CMD_FAST_READ = 0x0b,			/**< Fast read */
	FLASH_CMD_4BYTE_FAST_READ = 0x0c,	/**< Fast read with 4 byte address */
	FLASH_CMD_4BYTE_PP = 0x12,			/**< Page program with 4 byte address */
	FLASH_CMD_4BYTE_READ = 0x13,		/**< Normal read with 4 byte address */
	FLASH_CMD_RDSR3 = 0x15,				/**< Read status register 3 (configuration register) */
	FLASH_CMD_4K_ERASE = 0x20,			/**< Sector erase 4kB */
	FLASH_CMD_4BYTE_4K_ERASE = 0x21,	/**< Sector erase 4kB with 4 byte address */
	FLASH_CMD_WRSR2 = 0x31,				/**< Write status register 2 */
	FLASH_CMD_RDSR2 = 0x35,				/**< Read status register 2 */
	FLASH_CMD_DUAL_READ = 0x3b,			/**< Dual output read */
	FLASH_CMD_4BYTE_DUAL_READ = 0x3c,	/**< Dual output read with 4 byte address */
	FLASH_CMD_ALT_WRSR2 = 0x3e,			/**< Alternate Write status register 2 */
	FLASH_CMD_ALT_RDSR2 = 0x3f,			/**< Alternate Read status register 2 */
	FLASH_CMD_VOLATILE_WREN = 0x50,		/**< Volatile write enable for status register 1 */
	FLASH_CMD_SFDP = 0x5a,				/**< Read SFDP registers */
	FLASH_CMD_RSTEN = 0x66,				/**< Reset enable */
	FLASH_CMD_QUAD_READ = 0x6b,			/**< Quad output read */
	FLASH_CMD_4BYTE_QUAD_READ = 0x6c,	/**< Quad output read with 4 byte address */
	FLASH_CMD_RDSR_FLAG = 0x70,			/**< Read flag status register */
	FLASH_CMD_GBULK = 0x98,				/**< Global block protection unlock */
	FLASH_CMD_RST = 0x99,				/**< Reset device */
	FLASH_CMD_RDID = 0x9f,				/**< Read identification */
	FLASH_CMD_RDP = 0xab,				/**< Release from deep power down */
	FLASH_CMD_WR_NV_CFG = 0xb1,			/**< Write non-volatile configuration register */
	FLASH_CMD_RD_NV_CFG = 0xb5,			/**< Read non-volatile configuration register */
	FLASH_CMD_EN4B = 0xb7,				/**< Enter 4-byte mode */
	FLASH_CMD_DP = 0xb9,				/**< Deep power down the device */
	FLASH_CMD_DIO_READ = 0xbb,			/**< Dual I/O read */
	FLASH_CMD_4BYTE_DIO_READ = 0xbc,	/**< Dual I/O read with 4 byte address */
	FLASH_CMD_CE = 0xc7,				/**< Chip erase */
	FLASH_CMD_64K_ERASE = 0xd8,			/**< Block erase 64kB */
	FLASH_CMD_4BYTE_64K_ERASE = 0xdc,	/**< Block erase 64kB with 4 byte address */
	FLASH_CMD_EX4B = 0xe9,				/**< Exit 4-byte mode */
	FLASH_CMD_QIO_READ = 0xeb,			/**< Quad I/O read */
	FLASH_CMD_4BYTE_QIO_READ = 0xec,	/**< Quad I/O read with 4 byte address */
	FLASH_CMD_ALT_RST = 0xf0,			/**< Alternate reset command supported by some devices. */
};

/**
 * SPI flash vendor IDs.
 */
enum {
	FLASH_ID_SPANSION = 0x01,		/**< Spansion manufacturer ID. */
	FLASH_ID_MICRON = 0x20,			/**< Micron manufacturer ID. */
	FLASH_ID_MICROCHIP = 0xbf,		/**< Microchip manufacturer ID. */
	FLASH_ID_MACRONIX = 0xc2,		/**< Macronix manufacturer ID. */
	FLASH_ID_WINBOND = 0xef			/**< Winbond manufacturer ID. */
};

/**
 * SPI flash device series IDs.
 */
enum {
	FLASH_ID_MX25L = 0x2000,		/**< Macronix MX25L flash device IDs. */
	FLASH_ID_SST26VF = 0x2600,		/**< Microchip SST26VF flash device IDs. */
	FLASH_ID_W25Q = 0x4000,			/**< Winbond W25Q flash device IDs. */
	FLASH_ID_W25Q_DTR = 0x7000,		/**< Winbond W25Q-DTR flash device IDs. */
	FLASH_ID_MT25Q = 0xba00,		/**< Micron MT25Q flash device IDs. */
};

/**
 * Extract the device series ID from the device ID.
 */
#define	FLASH_ID_DEVICE_SERIES(x)		(x & 0xff00)

/**
 * Extract the device capacity ID from the device ID.
 */
#define	FLASH_ID_DEVICE_CAPACITY(x)		(x & 0xff)


/* SPI flash status register bits */
#define	FLASH_STATUS_WIP		(1U << 0)
#define	FLASH_STATUS_WEL		(1U << 1)
#define	FLASH_STATUS_SRWD		(1U << 7)

/* SPI flash flag status register bits */
#define	FLASH_FLAG_STATUS_READY	(1U << 7)

/* SPI flash pages */
#define	FLASH_PAGE_SIZE			256
#define	FLASH_PAGE_MASK			(~(FLASH_PAGE_SIZE - 1))
#define	FLASH_PAGE_BASE(x)		(x & FLASH_PAGE_MASK)
#define	FLASH_PAGE_OFFSET(x)	(x & (FLASH_PAGE_SIZE - 1))

/* SPI flash sectors */
#define	FLASH_SECTOR_SIZE		(4 * 1024)
#define	FLASH_SECTOR_MASK		(~(FLASH_SECTOR_SIZE - 1))
#define	FLASH_SECTOR_BASE(x)	(x & FLASH_SECTOR_MASK)
#define	FLASH_SECTOR_OFFSET(x)	(x & (FLASH_SECTOR_SIZE - 1))

/* SPI flash blocks */
#define	FLASH_BLOCK_SIZE		(64 * 1024)
#define	FLASH_BLOCK_MASK		(~(FLASH_BLOCK_SIZE - 1))
#define	FLASH_BLOCK_BASE(x)		(x & FLASH_BLOCK_MASK)
#define	FLASH_BLOCK_OFFSET(x)	(x & (FLASH_BLOCK_SIZE - 1))


uint32_t flash_address_to_int (const uint8_t *buf, uint8_t addr_bytes);
int flash_int_to_address (uint32_t address, uint8_t addr_bytes, uint8_t *buf);


#define	FLASH_COMMON_ERROR(code)		ROT_ERROR (ROT_MODULE_FLASH_COMMON, code)

/**
 * Error codes that can be generated by the common flash routines.
 */
enum {
	FLASH_COMMON_INVALID_ARGUMENT = FLASH_COMMON_ERROR (0x00),	/**< Input parameter is null or not valid. */
	FLASH_COMMON_NO_MEMORY = FLASH_COMMON_ERROR (0x01),			/**< Memory allocation failed. */
};


#endif /* FLASH_COMMON_H_ */
