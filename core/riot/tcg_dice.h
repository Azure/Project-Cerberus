// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TCG_DICE_H_
#define TCG_DICE_H_

#include <stdint.h>
#include "crypto/hash.h"


/**
 * Information about the TCB for a single layer of firmware in the TCG DICE architecture.
 */
struct tcg_dice_tcbinfo {
	const char *version;		/**< Version identifier for the firmware. */
	uint32_t svn;				/**< Security version of the firmware. */
	const uint8_t *fwid;		/**< The firmware ID digest. */
	enum hash_type fwid_hash;	/**< The type of hash used to generate the firmware ID. */
};


#endif	/* TCG_DICE_H_ */
