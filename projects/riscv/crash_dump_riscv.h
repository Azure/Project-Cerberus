// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CRASH_DUMP_RISCV_H_
#define CRASH_DUMP_RISCV_H_

#include <stdint.h>


/**
 * Structure for crash dump information from an RISC-V exception.
 */
struct crash_dump_riscv {
	uint32_t mepc;		/**< Current machine exception return pc */
	uint32_t mstatus;	/**< Machine status */
	uint32_t mcause;	/**< Trap cause */
	uint32_t mtval;		/**< Additional trap info */
	uint32_t seq_intr;	/**< Number of sequential interrupts processed */
	uint32_t ra;		/**< x1, return address */
	uint32_t sp;		/**< x2, stack pointer */
	uint32_t gp;		/**< gp, global pointer */
	uint32_t tp;		/**< x4, thread pointer  */
	uint32_t s0;		/**< x8/fp - saved register / frame pointer */
};


extern void crash_dump_riscv_print_min (const struct crash_dump_riscv *crash_ptr);
extern void crash_dump_riscv_print_full (const struct crash_dump_riscv *crash_ptr);
extern void crash_dump_riscv_log (const struct crash_dump_riscv *crash_ptr);


#endif	/* CRASH_DUMP_RISCV_H_ */
