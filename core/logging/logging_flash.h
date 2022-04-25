// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LOGGING_FLASH_H_
#define LOGGING_FLASH_H_

#include <stdint.h>
#include <stdbool.h>
#include "logging.h"
#include "platform.h"
#include "flash/flash_common.h"
#include "flash/spi_flash.h"


/**
 * The number of flash sectors available to the log for storing entries.
 */
#define LOGGING_FLASH_AREA_LEN		FLASH_BLOCK_SIZE
#define LOGGING_FLASH_SECTORS 		(LOGGING_FLASH_AREA_LEN / FLASH_SECTOR_SIZE)


/**
 * Variable context for a log that stores entries in SPI flash.
 */
struct logging_flash_state {
	platform_mutex lock;						/**< Synchronization for log accesses. */
	uint8_t entry_buffer[FLASH_SECTOR_SIZE];	/**< Buffered entries waiting to be flushed. */
	uint8_t *next_write;						/**< The next write position in the entry buffer. */
	int write_remain;							/**< Remaining space in the entry buffer. */
	bool terminated;							/**< Entry buffer has been terminated. */
	uint32_t next_entry_id;						/**< Next ID to assign to a log entry. */
	uint32_t flash_used[LOGGING_FLASH_SECTORS];	/**< Number of valid bytes stored in each sector. */
	uint32_t next_addr;							/**< Next flash address to write to. */
	int log_start;								/**< The sector that contains the first entries. */
};

/**
 * A log that will persistently store entries in SPI flash.
 */
struct logging_flash {
	struct logging base;						/**< The base logging instance. */
	struct logging_flash_state *state;			/**< Variable context for the log instance. */
	const struct spi_flash *flash;				/**< The flash where log entries are stored. */
	uint32_t base_addr;							/**< The base address of the log data on flash. */
};


int logging_flash_init (struct logging_flash *logging, struct logging_flash_state *state,
	const struct spi_flash *flash, uint32_t base_addr);
int logging_flash_init_state (const struct logging_flash *logging);
void logging_flash_release (const struct logging_flash *logging);


#endif /* LOGGING_FLASH_H_ */
