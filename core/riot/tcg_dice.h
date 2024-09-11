// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TCG_DICE_H_
#define TCG_DICE_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/hash.h"


/**
 * Information about the TCB for a single layer of firmware in the TCG DICE architecture.
 */
struct tcg_dice_tcbinfo {
	/**
	 * Version identifier string for the firmware.
	 */
	const char *version;

	/**
	 * Security version number of the firmware.  This is an integer value stored as a byte array.
	 * It must be stored as an unsigned, big endian integer. */
	const uint8_t *svn;
	size_t svn_length;	/**< Length of the SVN value. */

	/**
	 * The firmware ID digest for the image.
	 */
	const uint8_t *fwid;
	enum hash_type fwid_hash;	/**< The type of hash used to generate the firmware ID. */
};


#endif	/* TCG_DICE_H_ */
