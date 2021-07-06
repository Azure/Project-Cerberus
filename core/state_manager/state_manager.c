// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "state_manager.h"
#include "state_logging.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"
#include "platform_io.h"


/* Bitmasks for settings in non-volatile memory. */
#define	MULTI_BYTE_STATE		(1U << 7)
#define	SINGLE_BYTE_STATE		(1U << 6)

/* Bitmasks for settings in volatile memory. */
#define	SECTOR_2_BLANK			(1U << 7)
#define	SECTOR_1_BLANK			(1U << 6)


/**
 * Initialize state stored using a single byte.
 *
 * @param manager The state manager to initialize.
 * @param state_flash The flash that contains the non-volatile state information.
 * @param store_addr The starting address for state storage.
 * @param sector_size The sector size of the flash device.
 * @param offset Output for the offset in storage where the latest state is stored.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
static int state_manager_init_single_byte_state (struct state_manager *manager,
	struct flash *state_flash, uint32_t store_addr, uint32_t sector_size, int *offset)
{
	uint8_t nv_state = 0xff;
	int status;

	/* Find the latest settings by finding the first byte that isn't blank.  If the first byte is
	 * blank, jump straight to the second sector to see if the settings are there. */
	*offset = -1;
	do {
		if (*offset == 0) {
			*offset += sector_size - 1;
		}

		do {
			manager->nv_state = 0xff00 | nv_state;
			(*offset)++;

			if (*offset < (int) (sector_size * 2)) {
				status = state_flash->read (state_flash, store_addr + *offset, &nv_state, 1);
				if (status != 0) {
					return status;
				}
			}
		} while ((nv_state != 0xff) && (*offset < (int) (sector_size * 2)));
	} while (*offset == 0);

	manager->nv_state |= MULTI_BYTE_STATE;
	return 0;
}

/**
 * Read the state information from the stored state entry.
 *
 * @param entry The stored state entry to parse.
 * @param error Optional output to indicate that there is a bit error in the entry.
 * @param refresh Optional output to indicate that there is an error that requires a state refresh.
 * This will only ever get set, never cleared.
 *
 * @return The state information.
 */
static uint16_t state_manager_read_state_bits (uint16_t *entry, bool *error, bool *refresh)
{
	int i;
	uint16_t nv_state = 0;
	uint16_t bit0;
	uint16_t bit1;
	uint16_t bit2;

	if (error) {
		*error = false;
	}

	for (i = 0; i < 16; i++) {
		bit0 = entry[0] & (1U << i);
		bit1 = entry[1] & (1U << i);
		bit2 = entry[2] & (1U << i);

		if ((bit0 == bit1) && (bit0 == bit2)) {
			nv_state |= bit0;
		}
		else {
			if (error) {
				*error = true;
			}

			/* If there is a bit error on a marker for a valid entry, always leave it cleared. */
			if ((i != 6) && (i != 7)) {
				if ((bit0 == bit1) || (bit0 == bit2)) {
					nv_state |= bit0;
				}
				else {
					nv_state |= bit1;
				}
			}
			else if ((i == 6) && refresh) {
				/* Bit errors on the entry valid marker always trigger a refresh. */
				*refresh = true;
			}
		}
	}

	/* If the last word has some data but the entry reads as blank, assume this is a valid entry
	 * with lots of bit errors. */
	if ((nv_state == 0xffff) && (entry[3] != 0xffff)) {
		nv_state &= ~SINGLE_BYTE_STATE;
		if (refresh) {
			*refresh = true;
		}
	}

	/* If both format bits are cleared, assume a multi-byte format with bit errors.  One bit always
	 * will be set, and they are mutually exclusive. */
	if (!(nv_state & (SINGLE_BYTE_STATE | MULTI_BYTE_STATE))) {
		nv_state |= MULTI_BYTE_STATE;
	}

	return nv_state;
}

/**
 * Initialize state stored using multiple bytes with redundancy.
 *
 * @param manager The state manager to initialize.
 * @param state_flash The flash that contains the non-volatile state information.
 * @param store_addr The starting address for state storage.
 * @param sector_size The sector size of the flash device.
 * @param offset Output for the offset in storage where the latest state is stored.
 * @param bit_error Output indicating if the latest state contains a bit error.
 * @param refresh_state Output indicating if there is an error requiring the state to be refreshed.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
static int state_manager_init_multi_byte_state (struct state_manager *manager,
	struct flash *state_flash, uint32_t store_addr, uint32_t sector_size, int *offset,
	bool *bit_error, bool *refresh_state)
{
	uint16_t stored[4];
	uint16_t nv_state = 0xffff;
	bool error = false;
	int status;

	/* Find the latest settings by finding the first entry that isn't blank.  If the first entry is
	 * blank, jump straight to the second sector to see if the settings are there. */
	*offset = -8;
	*refresh_state = false;
	do {
		if (*offset == 0) {
			*offset += sector_size - 8;
		}

		do {
			manager->nv_state = nv_state;
			*bit_error = error;
			(*offset) += 8;

			if (*offset < (int) (sector_size * 2)) {
				status = state_flash->read (state_flash, store_addr + *offset, (uint8_t*) stored,
					sizeof (stored));
				if (status != 0) {
					return status;
				}

				nv_state = state_manager_read_state_bits (stored, &error, refresh_state);
			}
		} while ((nv_state != 0xffff) && !(nv_state & SINGLE_BYTE_STATE) &&
			(*offset < (int) (sector_size * 2)));
	} while (*offset == 0);

	return 0;
}

/**
 * Set the write offset to have the next state stored the beginning of the unused sector.
 *
 * @param manager The state manager to update.
 * @param sector_size The flash sector size.
 */
static void state_manager_set_next_sector_write_offset (struct state_manager *manager,
	uint32_t sector_size)
{
	if (manager->store_addr < (manager->base_addr + sector_size)) {
		manager->store_addr = manager->base_addr + sector_size - 8;
	}
	else {
		manager->store_addr = manager->base_addr + (sector_size * 2) - 8;
	}
}

/**
 * Initialize the manager for state information.
 *
 * @param manager The state manager to initialize.
 * @param state_flash The flash that contains the non-volatile state information.
 * @param store_addr The starting address for state storage.  The state storage uses two contiguous
 * flash sectors.  The start address must be aligned to the start of a flash sector.
 *
 * @return 0 if the state manager was successfully initialized or an error code.
 */
int state_manager_init (struct state_manager *manager, struct flash *state_flash,
	uint32_t store_addr)
{
	int offset;
	uint32_t sector_size;
	uint16_t sector1[4];
	uint16_t state1;
	uint16_t sector2[4];
	uint16_t state2;
	bool needs_update = false;
	bool bit_error = false;
	int status;

	if ((manager == NULL) || (state_flash == NULL)) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	status = state_flash->get_sector_size (state_flash, &sector_size);
	if (status != 0) {
		return status;
	}

	if (FLASH_REGION_BASE (store_addr, sector_size) != store_addr) {
		return STATE_MANAGER_NOT_SECTOR_ALIGNED;
	}

	memset (manager, 0, sizeof (struct state_manager));

	status = state_flash->read (state_flash, store_addr, (uint8_t*) sector1, sizeof (sector1));
	if (status != 0) {
		return status;
	}

	status = state_flash->read (state_flash, store_addr + sector_size, (uint8_t*) sector2,
		sizeof (sector2));
	if (status != 0) {
		return status;
	}

	state1 = state_manager_read_state_bits (sector1, NULL, NULL);
	state2 = state_manager_read_state_bits (sector2, NULL, NULL);
	manager->nv_state = 0xffff;

	if ((state1 != 0xffff) || (state2 != 0xffff)) {
		if (!(state1 & SINGLE_BYTE_STATE) || !(state2 & SINGLE_BYTE_STATE)) {
			status = state_manager_init_multi_byte_state (manager, state_flash, store_addr,
				sector_size, &offset, &bit_error, &needs_update);
		}
		else {
			status = state_manager_init_single_byte_state (manager, state_flash, store_addr,
				sector_size, &offset);
			needs_update = true;
		}
	}
	else {
		status = flash_sector_erase_region_and_verify (state_flash, store_addr, sector_size);
		manager->volatile_state |= SECTOR_1_BLANK;
		offset = sector_size * 2;
	}

	if (status != 0) {
		return status;
	}

	manager->nv_store = state_flash;
	manager->base_addr = store_addr;
	manager->store_addr = store_addr + offset - 8;
	manager->last_nv_stored = manager->nv_state;

	if (needs_update || bit_error) {
		/* If the state is stored in the old format or the current state information has corruption,
		 * force the state to be stored on flash at the next request. */
		manager->last_nv_stored = 0xffff;

		if (needs_update) {
			/* Make sure the address is entry aligned. */
			if (offset & 0x7) {
				manager->store_addr += (8 - (offset & 0x7));
			}
			state_manager_set_next_sector_write_offset (manager, sector_size);
		}
	}

	status = platform_mutex_init (&manager->state_lock);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&manager->store_lock);
	if (status != 0) {
		platform_mutex_free (&manager->state_lock);
		return status;
	}

	return 0;
}

/**
 * Release the resources used by the host state manager.
 *
 * @param manager The state manager to release.
 */
void state_manager_release (struct state_manager *manager)
{
	if (manager != NULL) {
		platform_mutex_free (&manager->state_lock);
		platform_mutex_free (&manager->store_lock);
	}
}

/**
 * Prevent calls to store the non-volatile state from executing.  Calls will remain mutex blocked
 * until they are once again allowed.
 *
 * If there is a call to store the non-volatile state in progress, this will not return until that
 * call has completed.
 *
 * Calling this function has the same semantics as a mutex.  Meaning, calling this twice to block
 * stores without calling to block in between will cause deadlock.
 *
 * @param manager The manager whose state storage should be prevented or allowed.
 * @param block True to prevent state storage or false to allow it.
 */
void state_manager_block_non_volatile_state_storage (struct state_manager *manager, bool block)
{
	struct state_manager *state_mgr = (struct state_manager*) manager;

	if (state_mgr != NULL) {
		if (block) {
			platform_mutex_lock (&state_mgr->store_lock);
		}
		else {
			platform_mutex_unlock (&state_mgr->store_lock);
		}
	}
}

/**
 * Store the current non-volatile state to flash.
 *
 * It is expected that this function would be called in the context of a background task that will
 * periodically store the non-volatile state. This call could result in the need to erase flash, so
 * it could take an extended time for the operation to complete.
 *
 * @param manager The manager whose state should be stored.
 *
 * @return 0 if the non-volatile state was successfully stored or an error code.
 */
int state_manager_store_non_volatile_state (struct state_manager *manager)
{
	struct state_manager *state_mgr = (struct state_manager*) manager;
	int status = 0;
	int erase_status;
	uint16_t store_state;
	uint16_t nv_state[4];
	uint32_t next_addr;
	uint32_t sector_size;
	uint16_t in_flash;
	bool bit_error = false;
	bool refresh = false;

	if (state_mgr == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	status = state_mgr->nv_store->get_sector_size (state_mgr->nv_store, &sector_size);
	if (status != 0) {
		return status;
	}

	platform_mutex_lock (&state_mgr->store_lock);

	platform_mutex_lock (&state_mgr->state_lock);
	store_state = state_mgr->nv_state & ~SINGLE_BYTE_STATE;
	store_state |= MULTI_BYTE_STATE;
	platform_mutex_unlock (&state_mgr->state_lock);

	/* If our current state hasn't changed from what is on flash, verify the flash contents and
	 * refresh as necessary. */
	if (store_state == state_mgr->last_nv_stored) {
		status = state_mgr->nv_store->read (state_mgr->nv_store, state_mgr->store_addr,
			(uint8_t*) nv_state, sizeof (nv_state));

		if (status == 0) {
			in_flash = state_manager_read_state_bits (nv_state, &bit_error, &refresh);
			if ((in_flash != store_state) || bit_error) {
				/* The data in flash is bad, so force the state to be rewritten. */
				state_mgr->last_nv_stored = 0xffff;

				if (refresh) {
					state_manager_set_next_sector_write_offset (state_mgr, sector_size);
				}
			}
		}
	}

	/* If our current state is different from that stored on flash, write it to flash. */
	if (store_state != state_mgr->last_nv_stored) {
		next_addr = state_mgr->store_addr + 8;
		if (next_addr == (state_mgr->base_addr + (sector_size * 2))) {
			next_addr = state_mgr->base_addr;
		}

		nv_state[0] = store_state;
		nv_state[1] = store_state;
		nv_state[2] = store_state;
		nv_state[3] = 0;

		/* Make sure we are writing to a blank sector.
		 *
		 * If we are trying to write the last entry in the current sector, make sure the next sector
		 * is erased.  Otherwise, we will not be able to correctly determine the last state stored
		 * by looking for blank flash during initialization. */
		if ((next_addr == state_mgr->base_addr) && !(state_mgr->volatile_state & SECTOR_1_BLANK)) {
			status = STATE_MANAGER_NOT_BLANK;
		}
		else if ((next_addr == (state_mgr->base_addr + sector_size)) &&
			!(state_mgr->volatile_state & SECTOR_2_BLANK)) {
			status = STATE_MANAGER_NOT_BLANK;
		}
		else if ((next_addr == (state_mgr->base_addr + (sector_size * 2) - 8)) &&
			!(state_mgr->volatile_state & SECTOR_1_BLANK)) {
			status = STATE_MANAGER_NOT_BLANK;
		}
		else if (next_addr == (state_mgr->base_addr + sector_size - 8) &&
			!(state_mgr->volatile_state & SECTOR_2_BLANK)) {
			status = STATE_MANAGER_NOT_BLANK;
		}

		if (status == 0) {
			status = state_mgr->nv_store->write (state_mgr->nv_store, next_addr,
				(uint8_t*) nv_state, sizeof (nv_state));
			if (ROT_IS_ERROR (status)) {
				platform_mutex_unlock (&state_mgr->store_lock);
				return status;
			}

			if (status == sizeof (nv_state)) {
				status = 0;
				state_mgr->last_nv_stored = store_state;
			}
			else {
				/* We handle this scenario, but only minimally.  This is not really possible given
				 * the alignment of data. */
				status = STATE_MANAGER_INCOMPLETE_WRITE;
			}

			state_mgr->store_addr = next_addr;
		}
	}

	/* Always make sure the unused sector is erased so it is ready to be written to when needed.
	 * A failure to erase is not a reported error since the data was successfully stored. */
	if (state_mgr->store_addr < (state_mgr->base_addr + sector_size)) {
		if (state_mgr->volatile_state & SECTOR_1_BLANK) {
			state_mgr->volatile_state &= ~SECTOR_1_BLANK;
		}

		if (!(state_mgr->volatile_state & SECTOR_2_BLANK)) {
			erase_status = flash_sector_erase_region_and_verify (state_mgr->nv_store,
				state_mgr->base_addr + sector_size, sector_size);
			if (erase_status == 0) {
				state_mgr->volatile_state |= SECTOR_2_BLANK;
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_STATE_MGR,
					STATE_LOGGING_ERASE_FAIL, state_mgr->base_addr + sector_size, status);
			}
		}
	}
	else {
		if (state_mgr->volatile_state & SECTOR_2_BLANK) {
			state_mgr->volatile_state &= ~SECTOR_2_BLANK;
		}

		if (!(state_mgr->volatile_state & SECTOR_1_BLANK)) {
			erase_status = flash_sector_erase_region_and_verify (state_mgr->nv_store,
				state_mgr->base_addr, sector_size);
			if (erase_status == 0) {
				state_mgr->volatile_state |= SECTOR_1_BLANK;
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_STATE_MGR,
					STATE_LOGGING_ERASE_FAIL, state_mgr->base_addr, status);
			}
		}
	}

	platform_mutex_unlock (&state_mgr->store_lock);

	return status;
}

/**
 * Save the setting for the manifest region that contains the active manifest.
 * This setting will be stored in non-volatile memory on the next call to store state.
 *
 * @param manager The state manager to update.
 * @param active The manifest region to save as the active region.
 * @param bit The bit used to store this information.
 *
 * @return 0 if the setting was saved or an an error code if the setting was invalid.
 */
int state_manager_save_active_manifest (struct state_manager *manager, enum manifest_region active,
	uint8_t bit)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state_lock);

	switch (active) {
		case MANIFEST_REGION_1:
			manager->nv_state = manager->nv_state | bit;
			break;

		case MANIFEST_REGION_2:
			manager->nv_state = manager->nv_state & ~bit;
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->state_lock);
	return status;
}

/**
 * Get the current setting for the active manifest region.
 *
 * @param manager The state manager to query.
 * @param bit The bit used to store this information.
 *
 * @return The active manifest region.
 */
enum manifest_region state_manager_get_active_manifest (struct state_manager *manager, uint8_t bit)
{
	if (manager == NULL) {
		return MANIFEST_REGION_1;
	}

	return (manager->nv_state & bit) ? MANIFEST_REGION_1 : MANIFEST_REGION_2;
}
