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
	CRASH_DUMP_LOGGING_HEADER,				/**< Log crash dump header information, including fault code and core ID. */
	CRASH_DUMP_LOGGING_OPAQUE_DATA,			/**< Log crash dump raw data. */
};


/**
 * Identifiers indicating the type of information getting logged for an exception.
 */
enum {
	CRASH_DUMP_LOGGING_ARM_R0 = 0x00,			/**< The R0 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R1 = 0x01,			/**< The R1 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R2 = 0x02,			/**< The R2 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R3 = 0x03,			/**< The R3 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_R12 = 0x04,			/**< The R12 value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_LR = 0x05,			/**< The link register value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_PC = 0x06,			/**< The program counter from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_XPSR = 0x07,			/**< The xPSR value from the stack frame. */
	CRASH_DUMP_LOGGING_ARM_HFSR = 0x08,			/**< The HFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_MMFSR = 0x09,		/**< The MMFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_MMFAR = 0x0a,		/**< The MMFAR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_BFSR = 0x0b,			/**< The BFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_BFAR = 0x0c,			/**< The BFAR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_UFSR = 0x0d,			/**< The UFSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_AFSR = 0x0e,			/**< The AFSR value of the BusFault Address Register. */
	CRASH_DUMP_LOGGING_ARM_CPSR = 0x0f,			/**< The CPSR value for the exception. */
	CRASH_DUMP_LOGGING_ARM_DFAR = 0x10,			/**< The data Fault Address Register value. */
	CRASH_DUMP_LOGGING_ARM_DFSR = 0x11,			/**< The data Fault status Register value. */
	CRASH_DUMP_LOGGING_ARM_IFAR = 0x12,			/**< The instruction Fault Address Register value. */
	CRASH_DUMP_LOGGING_ARM_IFSR = 0x13,			/**< The instruction Fault status Register value. */
	/* 0x14 - 0x1f enum values resverved for additional ARM registers. */
	CRASH_DUMP_LOGGING_RISCV_MEPC = 0x20,		/**< The MEPC current machine exception return pc. */
	CRASH_DUMP_LOGGING_RISCV_MSTATUS = 0x21,	/**< The MSTATUS machine status. */
	CRASH_DUMP_LOGGING_RISCV_MTVAL = 0x22,		/**< The MTVAL additional trap info. */
	CRASH_DUMP_LOGGING_RISCV_SEQ_INTR = 0x23,	/**< The SEQ_INTR number of sequential interrupts processed. */
	CRASH_DUMP_LOGGING_RISCV_RA = 0x24,			/**< The RA x1, return address. */
	CRASH_DUMP_LOGGING_RISCV_GP = 0x25,			/**< The GP global pointer. */
	CRASH_DUMP_LOGGING_RISCV_TP = 0x26,			/**< The TP x4, thread pointer. */
	CRASH_DUMP_LOGGING_RISCV_S0 = 0x27,			/**< The S0 x8/fp - saved register / frame pointer. */
};


void crash_dump_logging_save_opaque_data (uint32_t *buffer, size_t length);


#endif	/* CRASH_DUMP_LOGGING_H_ */
