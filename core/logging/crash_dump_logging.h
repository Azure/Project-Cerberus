// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CRASH_DUMP_LOGGING_H_
#define CRASH_DUMP_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Error messages that can be logged for crash or exception diagnostics.
 */
enum {
	CRASH_DUMP_LOGGING_EXCEPTION = 0,		/**< An exception occurred that triggered a reboot. */
	CRASH_DUMP_LOGGING_EXCEPTION_DETAIL,	/**< Details for a device exception. */
};


/**
 * Identifiers indicating the type of information getting logged for an exception.
 */
enum {
	CRASH_DUMP_LOGGING_ARM_R0 = 0x00,		/**< The R0 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R1 = 0x01,		/**< The R1 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R2 = 0x02,		/**< The R2 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R3 = 0x03,		/**< The R3 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R12 = 0x04,		/**< The R12 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_LR = 0x05,		/**< The link register value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_PC = 0x06,		/**< The program counter from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_XPSR = 0x07,		/**< The xPSR value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_HFSR = 0x08,		/**< The HFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_MMFSR = 0x09,	/**< The MMFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_MMFAR = 0x0a,	/**< The MMFAR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_BFSR = 0x0b,		/**< The BFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_BFAR = 0x0c,		/**< The BFAR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_UFSR = 0x0d,		/**< The UFSR value for the exception. */
};


#endif	/* CRASH_DUMP_LOGGING_H_ */
