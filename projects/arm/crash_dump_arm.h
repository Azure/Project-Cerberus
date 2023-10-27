// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CRASH_DUMP_ARM_H_
#define CRASH_DUMP_ARM_H_

#include <stdint.h>


/* NOTE: The crash dump and exception handling here is targeting ARM Cortex-M processors.  It may
 * equally apply to other ARM architectures, but is not specially attempting to present this
 * compatibility. */


/* Accessors for ARM Cortex-M fault status registers. */

/**
 * Access the HardFault Status Register.
 */
#define	HARD_FAULT_STATUS_REGISTER				*((uint32_t*) 0xe000ed2c)

/**
 * Access the Configurable Fault Status Register.  This register contains the cause for MemManage,
 * BusFault, and UsageFault exceptions.
 */
#define	CONFIGURABLE_FAULT_STATUS_REGISTER		*((uint32_t*) 0xe000ed28)

/**
 * Access the MemManage Fault Status Register.
 */
#define	MEM_MANAGE_FAULT_STATUS_REGISTER		*((uint8_t*) 0xe000ed28)

/**
 * Access the BusFault Status Register.
 */
#define	BUS_FAULT_STATUS_REGISTER				*((uint8_t*) 0xe000ed29)

/**
 * Access the UsageFault Status Register.
 */
#define	USAGE_FAULT_STATUS_REGISTER				*((uint16_t*) 0xe000ed2a)

/**
 * Access the MemManage Fault Address Register.
 */
#define	MEM_MANAGE_FAULT_ADDRESS_REGISTER		*((uint32_t*) 0xe000ed34)

/**
 * Access the MemManage Fault Address Register.
 */
#define	BUS_FAULT_ADDRESS_REGISTER				*((uint32_t*) 0xe000ed38)


/**
 * Context pushed to the stack when an exception occurs on Cortex-M architectures.
 */
struct crash_dump_arm_stack_frame {
	uint32_t r0;					/**< Value in register R0 when the exception occurred. */
	uint32_t r1;					/**< Value in register R1 when the exception occurred. */
	uint32_t r2;					/**< Value in register R2 when the exception occurred. */
	uint32_t r3;					/**< Value in register R3 when the exception occurred. */
	uint32_t r12;					/**< Value in register R12 when the exception occurred. */
	uint32_t lr;					/**< Value in the link register when the exception occurred. */
	uint32_t return_address;		/**< Return address from the exception.  This is where the exception occurred. */
	uint32_t xpsr;					/**< Value in register xPSR when the exception occurred. */
} __attribute__((__packed__));

/**
 * Structure for crash dump information from an exception.
 */
struct crash_dump_arm {
	void *stack_ptr;							/**< The address of the stack frame during exception handling. */
	uint32_t handler_xpsr;						/**< The xPSR value during exception handling.  This indicates the type of exception. */
	struct crash_dump_arm_stack_frame frame;	/**< The stack frame for the exception that was triggered. */
	uint32_t hfsr;								/**< Value of the HardFault Status Register (HFSR). */
	union {
		uint32_t cfsr;							/**< Value of the Configurable Fault Status Register (CFSR). */
		struct {
			uint8_t mmfsr;						/**< Value of the MemManage Fault Status Register (MMFSR). */
			uint8_t bfsr;						/**< Value the BusFault Status Register (BFSR). */
			uint16_t ufsr;						/**< Value of the UsageFault Status Register (UFSR). */
		};
	};
	uint32_t mmfar;								/**< Value of the MemManage Fault Address Register (MMFAR). */
	uint32_t bfar;								/**< Value of the BusFault Address Register (BFAR). */
};


/**
 * Reference to a globally accessible memory location that can be used to store crash dumps.  This
 * memory location must be preserved across device resets and not modified by any firmware other
 * than the crash dump handler.
 */
extern struct crash_dump_arm *crash;


/**
 * Handle a received exception and generate a crash dump.  This must be called directly from the
 * exception vector without any branches or stack modification prior to the call.
 */
#define	crash_dump_arm_handle_exception	\
	__asm volatile ( \
		"tst lr, #4\n" \
		"ite eq\n" \
		"mrseq r0, msp\n" \
		"mrsne r0, psp\n" \
		"mrs r1, xpsr\n" \
		"bl crash_dump_arm_save\n" \
	)

void crash_dump_arm_save (struct crash_dump_arm_stack_frame *frame, uint32_t xpsr);
void crash_dump_arm_print_min (void);
void crash_dump_arm_print_full (void);
void crash_dump_arm_log (void);


#endif /* CRASH_DUMP_ARM_H_ */
