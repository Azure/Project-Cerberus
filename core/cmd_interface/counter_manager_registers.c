// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "counter_manager_registers.h"
#include "cerberus_protocol_required_commands.h"


/**
 * Update reset counter to the specfied value.
 *
 * @param manager The counter manager to update.
 * @param type The reset counter type.
 * @param port The port identifier.
 * @param counter The value to use to update the reset counter.
 *
 * @return 0 if the reset counter was successfully updated or an error code.
 */
static int counter_manager_registers_set_counter (struct counter_manager_registers *manager,
	uint8_t type, uint8_t port, uint16_t counter)
{
	int status = 0;

	if (manager == NULL) {
		return COUNTER_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->lock);

	switch (type) {
		case CERBERUS_PROTOCOL_CERBERUS_RESET:
			*manager->reg1 = (*manager->reg1 & 0xffff0000) | counter; 
			break;

		case CERBERUS_PROTOCOL_COMPONENT_RESET:
			if (port == 0) {
				*manager->reg1 = (*manager->reg1 & 0x0000ffff) | (counter << 16); 
			}
			else if ((manager->reg2 != NULL) && (port == 1)) {
				*manager->reg2 = (*manager->reg2 & 0xffff0000) | counter; 
			}
			else {
				status = COUNTER_MANAGER_UNKNOWN_COUNTER;
			}
			break;

		default:
			status = COUNTER_MANAGER_UNKNOWN_COUNTER;
	}

	platform_mutex_unlock (&manager->lock);

	return status;
}

/**
 * Clear the specified reset counter.
 *
 * @param manager The counter manager to update.
 * @param type The reset counter type.
 * @param port The port identifier.
 *
 * @return 0 if the reset counter was successfully cleared or an error code.
 */
int counter_manager_registers_clear (struct counter_manager_registers *manager, uint8_t type,
	uint8_t port)
{
	return counter_manager_registers_set_counter (manager, type, port, 0);
}

/**
 * Increment the specified reset counter.
 *
 * @param manager The counter manager to update.
 * @param type The reset counter type.
 * @param port The port identifier.
 *
 * @return 0 if the reset counter was successfully incremented or an error code.
 */
int counter_manager_registers_increment (struct counter_manager_registers *manager, uint8_t type,
	uint8_t port)
{
	int counter;

	counter = counter_manager_registers_get_counter (manager, type, port);
	if (ROT_IS_ERROR (counter)) {
		return counter;
	}

	counter++;
	return counter_manager_registers_set_counter (manager, type, port, (uint16_t) counter);
}

/**
 * Retrieve the specified reset counter.
 *
 * @param manager The counter manager to update.
 * @param type The reset counter type.
 * @param port The port identifier.
 *
 * @return The reset counter value or an error code.  Use ROT_IS_ERROR to check the return value.
 */
int counter_manager_registers_get_counter (struct counter_manager_registers *manager, uint8_t type,
	uint8_t port)
{
	int status;

	if (manager == NULL) {
		return COUNTER_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->lock);

	switch (type) {
		case CERBERUS_PROTOCOL_CERBERUS_RESET:
			status = (*manager->reg1 & 0x0000ffff);
			break;

		case CERBERUS_PROTOCOL_COMPONENT_RESET:
			if (port == 0) {
				status = (*manager->reg1 >> 16) & 0x0000ffff; 
			}
			else if ((manager->reg2 != NULL) && (port == 1)) {
				status = (*manager->reg2 & 0x0000ffff);
			}
			else {
				status = COUNTER_MANAGER_UNKNOWN_COUNTER;
			}
			break;

		default:
			status = COUNTER_MANAGER_UNKNOWN_COUNTER;
	}

	platform_mutex_unlock (&manager->lock);

	return status;
}

/**
 * Initialize counter manager instance
 *
 * @param manager Counter manager instance to initialize.
 * @param reg1 Register to store reset counter data
 * @param reg2 Optional second register to store reset counter data
 *
 * @return 0 if initialized successfully or an error code.
 */
int counter_manager_registers_init (struct counter_manager_registers *manager,
	volatile uint32_t *reg1, volatile uint32_t *reg2)
{
	if ((manager == NULL) || (reg1 == NULL)) {
		return COUNTER_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct counter_manager_registers));

	manager->reg1 = reg1;
	manager->reg2 = reg2;

	return platform_mutex_init (&manager->lock);
}

/**
 * Release the resources used by the counter manager.
 *
 * @param manager The manager to release.
 */
void counter_manager_registers_release (struct counter_manager_registers *manager)
{
	if (manager) {
		platform_mutex_free (&manager->lock);
	}
}
