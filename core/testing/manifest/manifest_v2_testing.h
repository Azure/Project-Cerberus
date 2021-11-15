// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_V2_TESTING_H_
#define MANIFEST_V2_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "crypto/hash.h"


/**
 * Describe a test manifest structure.
 */
struct manifest_v2_testing_data {
	const uint8_t *raw;				/**< Complete manifest data. */
	size_t length;					/**< Length of the complete data. */
	const uint8_t *hash;			/**< Hash of the manifest. */
	size_t hash_len;				/**< Length of the hash. */
	int id;							/**< Manifest ID. */
	const uint8_t *signature;		/**< Manifest signature. */
	size_t sig_len;					/**< Length of the signature. */
	uint32_t sig_offset;			/**< Offset of the signature. */
	enum hash_type sig_hash_type;	/**< Hash type used for the signature. */
	const uint8_t *toc;				/**< Manifest table of contents. */
	size_t toc_len;					/**< Length of the table of contents. */
	const uint8_t *toc_hash;		/**< Hash of the manifest table of contents. */
	size_t toc_hash_len;			/**< Hash length in the table of contents. */
	uint32_t toc_hash_offset;		/**< Offset the table of contents hash. */
	enum hash_type toc_hash_type;	/**< Hash type used for the table of contents. */
	int toc_entries;				/**< Number of table of contents entries. */
	int toc_hashes;					/**< Number of table of contents hashes. */
	const uint8_t *plat_id;			/**< Platform ID element data. */
	size_t plat_id_len;				/**< Platform ID element data length. */
	const char *plat_id_str;		/**< Platform ID string in the manifest.  Not the raw manifest data.*/
	size_t plat_id_str_len;			/**< Length of the platform ID string. */
	size_t plat_id_str_pad;			/**< Padding added to the platform ID string. */
	uint32_t plat_id_offset;		/**< Offset of the platform ID element. */
	int plat_id_entry;				/**< TOC entry for the platform ID element. */
	int plat_id_hash;				/**< TOC hash for the platform ID element. */
};


/*
 * Constant manifest sizes.
 */
#define	MANIFEST_V2_HEADER_SIZE				12
#define	MANIFEST_V2_TOC_HDR_OFFSET			MANIFEST_V2_HEADER_SIZE
#define	MANIFEST_V2_TOC_HEADER_SIZE			4
#define	MANIFEST_V2_TOC_ENTRY_OFFSET		(MANIFEST_V2_TOC_HDR_OFFSET + MANIFEST_V2_TOC_HEADER_SIZE)
#define	MANIFEST_V2_TOC_ENTRY_SIZE			8
#define	MANIFEST_V2_PLATFORM_HEADER_SIZE	4


#endif /* MANIFEST_V2_TESTING_H_ */
