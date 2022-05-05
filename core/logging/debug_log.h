// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEBUG_LOG_H_
#define DEBUG_LOG_H_

#include <stdint.h>
#include "logging.h"


/**
 * Global singleton for the debug log.
 */
#ifndef LOGGING_DEBUG_LOG_CONST_INSTANCE
extern const struct logging *debug_log;
#else
extern const struct logging *const debug_log;
#endif


/**
 * Severity levels for log entries.
 */
enum debug_log_severity {
	DEBUG_LOG_SEVERITY_ERROR = 0,				/**< Log entry documenting an error. */
	DEBUG_LOG_SEVERITY_WARNING,					/**< Log entry documenting a warning. */
	DEBUG_LOG_SEVERITY_INFO,					/**< Log entry providing information. */
	DEBUG_LOG_NUM_SEVERITY						/**< Number of valid severity levels. */
};

/**
 * IDs for components that generate log entries.
 */
enum debug_log_component {
	DEBUG_LOG_COMPONENT_INIT = 0,				/**< Log entry for initialization */
	DEBUG_LOG_COMPONENT_CMD_INTERFACE,			/**< Log entry for command interface */
	DEBUG_LOG_COMPONENT_CRYPTO,					/**< Log entry for crypto */
	DEBUG_LOG_COMPONENT_HOST_FW,				/**< Log entry for host firmware management */
	DEBUG_LOG_COMPONENT_CERBERUS_FW,			/**< Log entry for Cerberus firmware images */
	DEBUG_LOG_COMPONENT_STATE_MGR,				/**< Log entry for state management */
	DEBUG_LOG_COMPONENT_MANIFEST,				/**< Log entry for manifests */
	DEBUG_LOG_COMPONENT_SPI_FILTER,				/**< Log entry for the SPI filter */
	DEBUG_LOG_COMPONENT_I2C,					/**< Log entry for I2C failures */
	DEBUG_LOG_COMPONENT_BOOT,					/**< Log entry for the bootloader */
	DEBUG_LOG_COMPONENT_FLASH,					/**< Log entry for flash. */
	DEBUG_LOG_COMPONENT_SPI,					/**< Log entry for SPI failures */
	DEBUG_LOG_COMPONENT_RECOVERY,				/**< Log entry for recovery handling */
	DEBUG_LOG_COMPONENT_MCTP,					/**< Log entry for MCTP stack */
	DEBUG_LOG_COMPONENT_TPM,					/**< Log entry for TPM */
	DEBUG_LOG_COMPONENT_RIOT,					/**< Log entry for RIoT */
	DEBUG_LOG_COMPONENT_SYSTEM,					/**< Log entry for system management. */
	DEBUG_LOG_COMPONENT_INTRUSION,				/**< Log entry for chassis intrusion. */
	DEBUG_LOG_COMPONENT_DEVICE_SPECIFIC = 0xf0,	/**< Base component ID for device-specific messages. */
	/* Component IDs 0xf0 - 0xff are reserved for device-specific logging. */
};

#pragma pack(push, 1)

/**
 * The current format identifier for debug log entries.
 */
#define	DEBUG_LOG_ENTRY_FORMAT		1

/**
 * Format for an entry in the debug log.
 */
struct debug_log_entry_info {
	uint16_t format;			/**< Format of the log entry. */
	uint8_t severity;			/**< Severity level of the entry. */
	uint8_t component;			/**< System competent that generated the entry. */
	uint8_t msg_index;			/**< Identifier for the entry message. */
	uint32_t arg1;				/**< Message specific argument. */
	uint32_t arg2;				/**< Message specific argument. */
	uint64_t time;				/**< Elapsed time in milliseconds since boot. */
};

/**
 * Format of the debug log entry as stored in the log.
 */
struct debug_log_entry {
	struct logging_entry_header header;		/**< Standard logging header. */
	struct debug_log_entry_info entry;		/**< Information for the log entry. */
};

#pragma pack(pop)


int debug_log_create_entry (uint8_t severity, uint8_t component, uint8_t msg_index, uint32_t arg1,
	uint32_t arg2);
#ifndef LOGGING_DISABLE_FLUSH
int debug_log_flush (void);
#endif
int debug_log_clear (void);
int debug_log_get_size (void);
int debug_log_read_contents (uint32_t offset, uint8_t *contents, size_t length);


#endif /* DEBUG_LOG_H_ */
