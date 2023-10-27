// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "crash_dump_arm.h"
#include "logging/crash_dump_logging.h"
#include "platform_io.h"


/* Exception debugging leverages functions and information from
 * https://interrupt.memfault.com/blog/cortex-m-fault-debug */


/**
 * Save a crash dump to global memory for a processor exception.
 *
 * @param frame The stack frame captured for the current exception.
 * @param xpsr The program status register value for the exception handler.
 */
void crash_dump_arm_save (struct crash_dump_arm_stack_frame *frame, uint32_t xpsr)
{
	/* Save the exception state into the global crash dump memory defined by the platform. */
	crash->stack_ptr = frame;
	crash->handler_xpsr = xpsr;
	memcpy (&crash->frame, frame, sizeof (struct crash_dump_arm_stack_frame));
	crash->hfsr = HARD_FAULT_STATUS_REGISTER;
	crash->cfsr = CONFIGURABLE_FAULT_STATUS_REGISTER;
	crash->mmfar = MEM_MANAGE_FAULT_ADDRESS_REGISTER;
	crash->bfar = BUS_FAULT_ADDRESS_REGISTER;
}

/**
 * Print minimal crash dump details to the console.
 */
void crash_dump_arm_print_min ()
{
	platform_printf ("CRASH DUMP (0x%x):" NEWLINE, crash);
	platform_printf ("frame: 0x%x" NEWLINE, crash->stack_ptr);
	platform_printf ("\t  lr: 0x%x" NEWLINE, crash->frame.lr);
	platform_printf ("\t  pc: 0x%x" NEWLINE, crash->frame.return_address);
}

/**
 * Print full crash dump details to the console.
 */
void crash_dump_arm_print_full ()
{
	platform_printf ("CRASH DUMP (0x%x):" NEWLINE, crash);
	platform_printf (" xpsr: 0x%x" NEWLINE, crash->handler_xpsr);
	platform_printf (" hfsr: 0x%x" NEWLINE, crash->hfsr);
	platform_printf (" cfsr: 0x%x" NEWLINE, crash->cfsr);
	platform_printf ("mmfsr: 0x%x" NEWLINE, crash->mmfsr);
	platform_printf ("mmfar: 0x%x" NEWLINE, crash->mmfar);
	platform_printf (" bfsr: 0x%x" NEWLINE, crash->bfsr);
	platform_printf (" bfar: 0x%x" NEWLINE, crash->bfar);
	platform_printf (" ufsr: 0x%x" NEWLINE, crash->ufsr);
	platform_printf ("frame: 0x%x" NEWLINE, crash->stack_ptr);
	platform_printf ("\t  r0: 0x%x" NEWLINE, crash->frame.r0);
	platform_printf ("\t  r1: 0x%x" NEWLINE, crash->frame.r1);
	platform_printf ("\t  r2: 0x%x" NEWLINE, crash->frame.r2);
	platform_printf ("\t  r3: 0x%x" NEWLINE, crash->frame.r3);
	platform_printf ("\t r12: 0x%x" NEWLINE, crash->frame.r12);
	platform_printf ("\t  lr: 0x%x" NEWLINE, crash->frame.lr);
	platform_printf ("\t  pc: 0x%x" NEWLINE, crash->frame.return_address);
	platform_printf ("\txpsr: 0x%x" NEWLINE, crash->frame.xpsr);
	platform_printf (NEWLINE);
}

/**
 * Log crash dump details to the debug log.
 */
void crash_dump_arm_log ()
{
	/* Log that an exception occurred, including the exception type and stack frame pointer. */
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION, crash->handler_xpsr, (uintptr_t) crash->stack_ptr);

	/* Log the stack frame. */
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R0, crash->frame.r0);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R1, crash->frame.r1);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R2, crash->frame.r2);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R3, crash->frame.r3);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R12, crash->frame.r12);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_LR, crash->frame.lr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_PC,
		crash->frame.return_address);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_XPSR, crash->frame.xpsr);

	/* Log the fault status registers. */
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_HFSR, crash->hfsr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_MMFSR, crash->mmfsr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_MMFAR, crash->mmfar);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_BFSR, crash->bfsr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_BFAR, crash->bfar);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_UFSR, crash->ufsr);

	/* Commit the crash dump to persistent memory. */
	debug_log_flush ();
}
