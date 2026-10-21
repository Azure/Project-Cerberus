// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "crash_dump_riscv.h"
#include "platform_io_api.h"
#include "logging/crash_dump_logging.h"


/**
 * Print minimal crash dump details to the console.
 *
 * @param crash_ptr The crash context, including RISCV register set.
 */
void crash_dump_riscv_print_min (const struct crash_dump_riscv *crash_ptr)
{
	platform_printf ("CRASH DUMP (0x%x):" NEWLINE, crash_ptr);
	platform_printf ("mcause:  0x%x" NEWLINE, crash_ptr->mcause);
	platform_printf ("mepc:    0x%x" NEWLINE, crash_ptr->mepc);
	platform_printf ("mtval:   0x%x" NEWLINE, crash_ptr->mtval);
}

/**
 * Print full crash dump details to the console.
 *
 * @param crash_ptr The crash context, including RISCV register set.
 */
void crash_dump_riscv_print_full (const struct crash_dump_riscv *crash_ptr)
{
	platform_printf ("CRASH DUMP (0x%x):" NEWLINE, crash_ptr);
	platform_printf ("mepc:    0x%x" NEWLINE, crash_ptr->mepc);
	platform_printf ("mstatus: 0x%x" NEWLINE, crash_ptr->mstatus);
	platform_printf ("mcause:  0x%x" NEWLINE, crash_ptr->mcause);
	platform_printf ("mtval:   0x%x" NEWLINE, crash_ptr->mtval);
	platform_printf ("seq_intr 0x%x" NEWLINE, crash_ptr->seq_intr);
	platform_printf ("ra:      0x%x" NEWLINE, crash_ptr->ra);
	platform_printf ("sp:      0x%x" NEWLINE, crash_ptr->sp);
	platform_printf ("gp:      0x%x" NEWLINE, crash_ptr->gp);
	platform_printf ("tp:      0x%x" NEWLINE, crash_ptr->tp);
	platform_printf ("s0:      0x%x" NEWLINE, crash_ptr->s0);
	platform_printf (NEWLINE);
}

/**
 * Log crash dump details to the debug log.
 *
 * @param crash_ptr The crash context, including RISC-V register set.
 */
void crash_dump_riscv_log (const struct crash_dump_riscv *crash_ptr)
{
	/* Log that an exception occurred, including the exception type and stack frame pointer. */
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION, crash_ptr->mcause, crash_ptr->sp);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_RISCV_MEPC, crash_ptr->mepc);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_RISCV_MSTATUS, crash_ptr->mstatus);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_RISCV_MTVAL, crash_ptr->mtval);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_RISCV_SEQ_INTR,
		crash_ptr->seq_intr);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_RISCV_RA, crash_ptr->ra);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_RISCV_GP, crash_ptr->gp);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_RISCV_TP, crash_ptr->tp);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CRASH_DUMP,
		CRASH_DUMP_LOGGING_EXCEPTION_DETAIL, CRASH_DUMP_LOGGING_RISCV_S0, crash_ptr->s0);

	/* Commit the crash dump to persistent memory. */
	debug_log_flush ();
}
