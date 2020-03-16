// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef COUNTER_MANAGER_REGISTERS_H_
#define COUNTER_MANAGER_REGISTERS_H_

#include <stdint.h>
#include <stddef.h>
#include "platform.h"
#include "cmd_interface/cmd_device.h"
#include "counter_manager.h"


/**
 * Module that holds the registers for reset counter data.
 */
struct counter_manager_registers {
	volatile uint32_t *reg1;		/**< Register to store reset counter data */
	volatile uint32_t *reg2;		/**< Register to store reset counter data */
	platform_mutex lock;			/**< Synchronization for access/updates to counter data. */
};


int counter_manager_registers_init (struct counter_manager_registers *manager, volatile uint32_t *reg1,
	volatile uint32_t *reg2);
void counter_manager_registers_release (struct counter_manager_registers *manager);

int counter_manager_registers_increment (struct counter_manager_registers *manager, uint8_t type, uint8_t port);
int counter_manager_registers_clear (struct counter_manager_registers *manager, uint8_t type, uint8_t port);
int counter_manager_registers_get_counter (struct counter_manager_registers *manager, uint8_t type, uint8_t port);


#endif /* COUNTER_MANAGER_REGISTERS_H_ */
