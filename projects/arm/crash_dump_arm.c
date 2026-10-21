// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "crash_dump_arm.h"
#include "platform_io_api.h"
#include "logging/crash_dump_logging.h"


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
#ifdef CRASH_DUMP_ARM_HAS_AFSR
	crash->afsr = AUXILIARY_FAULT_STATUS_REGISTER;
#endif
}

/**
 * Print minimal crash dump details to the console.
 *
 * @param crash_ptr The crash context, including ARM register set.
 */
void crash_dump_arm_print_min (const struct crash_dump_arm *crash_ptr)
{
	platform_printf ("CRASH DUMP (0x%x):" NEWLINE, crash_ptr);
	platform_printf ("frame: 0x%x" NEWLINE, crash_ptr->stack_ptr);
	platform_printf ("\t  lr: 0x%x" NEWLINE, crash_ptr->frame.lr);
	platform_printf ("\t  pc: 0x%x" NEWLINE, crash_ptr->frame.return_address);
}

/**
 * Print full crash dump details to the console.
 *
 * @param crash_ptr The crash context, including ARM register set.
 */
void crash_dump_arm_print_full (const struct crash_dump_arm *crash_ptr)
{
	platform_printf ("CRASH DUMP (0x%x):" NEWLINE, crash_ptr);
	platform_printf (" xpsr: 0x%x" NEWLINE, crash_ptr->handler_xpsr);
	platform_printf (" hfsr: 0x%x" NEWLINE, crash_ptr->hfsr);
	platform_printf (" cfsr: 0x%x" NEWLINE, crash_ptr->cfsr);
	platform_printf ("mmfsr: 0x%x" NEWLINE, crash_ptr->mmfsr);
	platform_printf ("mmfar: 0x%x" NEWLINE, crash_ptr->mmfar);
	platform_printf (" bfsr: 0x%x" NEWLINE, crash_ptr->bfsr);
	platform_printf (" bfar: 0x%x" NEWLINE, crash_ptr->bfar);
	platform_printf (" ufsr: 0x%x" NEWLINE, crash_ptr->ufsr);
#ifdef CRASH_DUMP_ARM_HAS_AFSR
	platform_printf ("\afsr: 0x%x" NEWLINE, crash_ptr->afsr);
#endif
	platform_printf ("frame: 0x%x" NEWLINE, crash_ptr->stack_ptr);
	platform_printf ("\t  r0: 0x%x" NEWLINE, crash_ptr->frame.r0);
	platform_printf ("\t  r1: 0x%x" NEWLINE, crash_ptr->frame.r1);
	platform_printf ("\t  r2: 0x%x" NEWLINE, crash_ptr->frame.r2);
	platform_printf ("\t  r3: 0x%x" NEWLINE, crash_ptr->frame.r3);
	platform_printf ("\t r12: 0x%x" NEWLINE, crash_ptr->frame.r12);
	platform_printf ("\t  lr: 0x%x" NEWLINE, crash_ptr->frame.lr);
	platform_printf ("\t  pc: 0x%x" NEWLINE, crash_ptr->frame.return_address);
	platform_printf ("\txpsr: 0x%x" NEWLINE, crash_ptr->frame.xpsr);

	platform_printf (NEWLINE);
}

/**
 * Log crash dump details to the debug log.
 *
 * @param crash_ptr The crash context, including ARM register set.
 * @param log_data_registers The flag. When false, only registers that contain status or
 * pointers will be logged. When true, registers that contain data will also be logged.
 */
void crash_dump_arm_log (const struct crash_dump_arm *crash_ptr, bool log_data_registers)
{
	/* Log that an exception occurred, including the exception type and stack frame pointer. */
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION, crash_ptr->handler_xpsr, (uintptr_t) crash_ptr->stack_ptr);

	/* Log the data registers of crashdump frame. */
	if (log_data_registers) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
			CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R0, crash_ptr->frame.r0);
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
			CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R1, crash_ptr->frame.r1);
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
			CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R2, crash_ptr->frame.r2);
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
			CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R3, crash_ptr->frame.r3);
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
			CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_R12, crash_ptr->frame.r12);
	}

	/* Log the rest of crashdump frame. */
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_LR, crash_ptr->frame.lr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_PC,
		crash_ptr->frame.return_address);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_XPSR, crash_ptr->frame.xpsr);

	/* Log the fault status registers. */
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_HFSR, crash_ptr->hfsr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_MMFSR, crash_ptr->mmfsr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_MMFAR, crash_ptr->mmfar);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_BFSR, crash_ptr->bfsr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_BFAR, crash_ptr->bfar);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_UFSR, crash_ptr->ufsr);
#ifdef CRASH_DUMP_ARM_HAS_AFSR
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_ARM_AFSR, crash_ptr->afsr);
#endif

	/* Commit the crash dump to persistent memory. */
	debug_log_flush ();
}
