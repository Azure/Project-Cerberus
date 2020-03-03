// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_FORMAT_H_
#define MANIFEST_FORMAT_H_

#include <stdint.h>


/**
 * The magic number marker for a manifest header.
 */
#define PFM_MAGIC_NUM				0x504D
#define CFM_MAGIC_NUM				0xA592
#define PCD_MAGIC_NUM				0x8EBC


/**
 * The header information on a manifest.
 */
struct manifest_header {
	uint16_t length;				/**< The total length of the manifest. */
	uint16_t magic;					/**< The manifest magic number. */
	uint32_t id;					/**< The manifest identifier. */
	uint16_t sig_length;			/**< The length of the signature at the end of the manifest. */
	uint16_t reserved;				/**< Unused. */
};


#endif /* MANIFEST_FORMAT_H_ */
