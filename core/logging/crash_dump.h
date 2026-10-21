// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CRASH_DUMP_H_
#define CRASH_DUMP_H_

#include <stdint.h>


/**
 * Crash dump Header.
 */
struct crash_dump_packet_header {
	/**
	 * Magic number in the head of a crash dump.
	 */
	uint32_t magic;
	/**
	 * A fault code that sorts the failures fetched from resgisters to different categories.
	 */
	uint32_t fault_code;
	union {
		uint32_t version_core_type_dump_type;
		struct {
			/**
			 * Crash dump packet format version.
			 */
			uint16_t crashdump_version;
			/**
			 * Multiple cores and types, such as ARM or RISC-V, could be installed in a device.
			 * Core type is used to stand for core sequence ID.
			 */
			uint8_t core_type;
			/**
			 * Crash dump could be built and collected for different purposes, such as release,
			 * development or debugging.
			 */
			uint8_t dump_type;
		};
	};

	union {
		uint32_t crash_type_payload_size;
		struct {
			/**
			 * Crash type is used to identify the crash causes, such as exception, hanging.
			 */
			uint8_t crash_type;
			/**
			 * Reserved, must be 0.
			 */
			uint8_t reserved;
			/**
			 * Payload size, number of bytes.
			 */
			uint16_t payload_size;
		};
	};
};

/**
 * Crash Dump Dump Types
 */
enum crash_dump_dump_type {
	CRASH_DUMP_DUMP_TYPE_RELEASE = 0,	/**< Crashed FW is a release. */
	CRASH_DUMP_DUMP_TYPE_DEVELOPMENT,	/**< Crashed FW is a development version. */
};

/**
 * Crash Dump Crash Types
 */
enum crash_dump_crash_type {
	CRASH_DUMP_CRASH_TYPE_NORMAL = 0,	/**< FW was in normal operation. */
	CRASH_DUMP_CRASH_TYPE_CRASH,		/**< FW got an exception. */
	CRASH_DUMP_CRASH_TYPE_HANGING,		/**< FW stuck on somewhere. */
};


#endif	/* CRASH_DUMP_H_ */
