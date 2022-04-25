// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LOGGING_FLASH_STATIC_H_
#define LOGGING_FLASH_STATIC_H_

#include "logging/logging_flash.h"


/* Internal functions declared to allow for static initialization. */
int logging_flash_create_entry (const struct logging *logging, uint8_t *entry, size_t length);
int logging_flash_flush (const struct logging *logging);
int logging_flash_clear (const struct logging *logging);
int logging_flash_get_size (const struct logging *logging);
int logging_flash_read_contents (const struct logging *logging, uint32_t offset, uint8_t *contents,
	size_t length);


/**
 * Constant initializer for the the flush operation.
 */
#ifndef LOGGING_DISABLE_FLUSH
#define	LOGGING_FLASH_FLUSH_API	.flush = logging_flash_flush,
#else
#define	LOGGING_FLASH_FLUSH_API
#endif

/**
 * Constant initializer for the logging API.
 */
#define	LOGGING_FLASH_API_INIT  { \
		.create_entry = logging_flash_create_entry, \
		LOGGING_FLASH_FLUSH_API \
		.clear = logging_flash_clear, \
		.get_size = logging_flash_get_size, \
		.read_contents = logging_flash_read_contents \
	}


/**
 * Initialize a static instance of a log that uses SPI flash.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the log.
 * @param flash_ptr The flash device where log entries are stored.
 * @param flash_base_addr The starting address for log entries.  This must be aligned to the
 * beginning of an erase block.
 */
#define	logging_flash_static_init(state_ptr, flash_ptr, flash_base_addr)	{ \
		.base = LOGGING_FLASH_API_INIT, \
		.state = state_ptr, \
		.flash = flash_ptr, \
		.base_addr = flash_base_addr \
	}


#endif /* LOGGING_FLASH_STATIC_H_ */
