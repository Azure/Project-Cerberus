// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "aes_xts.h"


/**
 * Encode a 32-bit flash address as a AES-XTS data unit identifier.
 *
 * @param address The flash address to encode.
 * @param data_unit_id Output for the encoded identifier.  If this is null, no operation will be
 * performed.
 */
void aes_xts_flash_address_to_data_unit_id (uint32_t address, uint8_t data_unit_id[16])
{
	if (data_unit_id != NULL) {
		/* This assumes the address is already represented in little endian. */
		memcpy (data_unit_id, &address, sizeof (address));

		memset (&data_unit_id[sizeof (address)], 0, 16 - sizeof (address));
	}
}
