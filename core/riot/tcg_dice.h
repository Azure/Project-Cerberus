// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TCG_DICE_H_
#define TCG_DICE_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/hash.h"


/**
 * A single firmware measurement used for key derivation for a specific DICE layer.
 */
struct tcg_dice_fwid {
	/**
	 * A digest of firmware, initialization values, or other settings of the Target Environment.
	 */
	const uint8_t *digest;

	/**
	 * The hash algorithm used used to produce the digest value.  The algorithm will be used to
	 * determine the length of the digest.
	 */
	enum hash_type hash_alg;
};

/**
 * A single named measurement that will be reported as part of the DICE TCB.  Each measurement must
 * provide either a string or integer identifier.
 */
struct tcg_dice_integrity_register {
	/**
	 * Identifying string for the measurement
	 *
	 * This is optional and can be null if only an integer identifier should be used.
	 */
	const char *name;

	/**
	 * Integer ID for the measurement.
	 *
	 * This is optional and can be -1 if only a string identifier should be used.
	 */
	int number;

	/**
	 * A list of digests for the measurement.  There should be only one digest for each hash
	 * algorithm.
	 */
	const struct tcg_dice_fwid *digests;
	size_t digest_count;	/**< The number of digests in the list. */
};

/**
 * Information about the TCB for a single layer of firmware in the TCG DICE architecture.
 *
 * This extension defines attestation Evidence about a Target Environment that is measured by an
 * Attesting Environment that controls the Subject key.
 */
struct tcg_dice_tcbinfo {
	/**
	 * The entity that created the measurement of the Target Environment.
	 *
	 * This is optional and can be set to null if no vendor information should be included in the
	 * TcbInfo extension.
	 */
	const char *vendor;

	/**
	 * The product name associated with the measurement of the Target Environment.
	 *
	 * This is optional and can be set to null if no model information should be included in the
	 * TcbInfo extension.
	 */
	const char *model;

	/**
	 * The revision string associated with the Target Environment.
	 *
	 * This generally be the firmware version string.
	 */
	const char *version;

	/**
	 * The DICE layer associated with this measurement of the Target Environment.
	 */
	unsigned int layer;

	/**
	 * The security version number associated with the Target Environment.
	 *
	 * This is an integer value stored as a byte array. It must be stored as an unsigned, big endian
	 * integer.
	 */
	const uint8_t *svn;
	size_t svn_length;	/**< Length of the SVN value. */

	/**
	 * A list of FWID values. FWIDs are computed by the DICE layer that is the Attesting Environment
	 * and certificate Issuer. Generally, construction and evaluation of a FWID list is defined by
	 * Reference Values.
	 */
	const struct tcg_dice_fwid *fwid_list;
	size_t fwid_count;	/**< The number of FWIDs in the list. */

	/**
	 * A list of named digests.
	 *
	 * This is optional and can be set to null if there are no named measurements to report.
	 */
	const struct tcg_dice_integrity_register *ir_list;
	size_t ir_count;	/**< The number of named digests in the list. */
};


#endif	/* TCG_DICE_H_ */
