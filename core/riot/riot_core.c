// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "riot_core.h"
#include "common/buffer_util.h"


/**
 * The serial number derivation data to use for certificate serial numbers.  Serial numbers are
 * are derived using NIST SP800-108, Counter Mode.  This data sets Label="SERIAL", Context="RIOT",
 * and L=8.
 */
const uint8_t RIOT_CORE_SERIAL_NUM_KDF_DATA[] = {
	0x00, 0x00, 0x00, 0x01, 0x53, 0x45, 0x52, 0x49, 0x41, 0x4c, 0x00, 0x52, 0x49, 0x4f, 0x54, 0x00,
	0x00, 0x00, 0x40
};

/**
 * Length of the KDF data for certificate serial numbers.
 */
const size_t RIOT_CORE_SERIAL_NUM_KDF_DATA_LENGTH = sizeof (RIOT_CORE_SERIAL_NUM_KDF_DATA);


/**
 * Clear a memory region in a way that won't be optimized out by compliers.
 *
 * @param data The data buffer to clear.
 * @param length The number of bytes to clear.
 */
void riot_core_clear (void *data, size_t length)
{
	buffer_zeroize (data, length);
}
