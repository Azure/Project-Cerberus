// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_FORMAT_H_
#define MANIFEST_FORMAT_H_

#include <stdint.h>


/**
 * Special marker indicating a manifest type is not supported.
 */
#define	MANIFEST_NOT_SUPPORTED		0xFFFF

/**
 * The magic number marker for a manifest header.
 */
#define PFM_MAGIC_NUM				0x504D
#define	PFM_V2_MAGIC_NUM			0x706D
#define CFM_MAGIC_NUM				MANIFEST_NOT_SUPPORTED
#define	CFM_V2_MAGIC_NUM			0xA592
#define PCD_MAGIC_NUM				MANIFEST_NOT_SUPPORTED
#define	PCD_V2_MAGIC_NUM			0x1029

/**
 * Identifier for the hash algorithm used for signatures and other verification hashes in
 * manifests.
 */
enum manifest_hash_type {
	MANIFEST_HASH_SHA256 = 0,		/**< The hash or signature is generated using SHA-256. */
	MANIFEST_HASH_SHA384 = 1,		/**< The hash or signature is generated using SHA-384. */
	MANIFEST_HASH_SHA512 = 2,		/**< The hash or signature is generated using SHA-512. */
};

/**
 * Identifier for the asymmetric key type used to generate a signature.
 */
enum manifest_key_type {
	MANIFEST_KEY_RSA_2048 = 0,		/**< The signature is generated using RSA-2048. */
	MANIFEST_KEY_RSA_3072 = 0x08,	/**< The signature is generated using RSA-3072. */
	MANIFEST_KEY_RSA_4096 = 0x10,	/**< The signature is generated using RSA-4096. */
	MANIFEST_KEY_ECC_256 = 0x40,	/**< The signature is generated using ECDSA-256. */
	MANIFEST_KEY_ECC_384 = 0x48,	/**< The signature is generated using ECDSA-384. */
	MANIFEST_KEY_ECC_521 = 0x50,	/**< The signature is generated using ECDSA-521. */
};

/**
 * Get the hash type for a signature.
 *
 * @param sig_type The encoded signature type.
 */
#define	manifest_get_hash_type(sig_type)	((enum manifest_hash_type) ((sig_type) & 0x07))

/**
 * Get the key type for a signature.
 *
 * @param sig_type The encoded signature type.
 */
#define	manifest_get_key_type(sig_type)		((enum manifest_key_type) ((sig_type) & 0xf8))

#pragma pack(push, 1)
/**
 * The header information on a manifest.
 */
struct manifest_header {
	uint16_t length;				/**< The total length of the manifest. */
	uint16_t magic;					/**< The manifest magic number. */
	uint32_t id;					/**< The manifest identifier. */
	uint16_t sig_length;			/**< The length of the signature at the end of the manifest. */
	uint8_t sig_type;				/**< Type of signature used for the manifest. */
	uint8_t reserved;				/**< Unused. */
};

/**
 * Type identifiers for common manifest elements.
 */
enum manifest_element_type {
	MANIFEST_PLATFORM_ID = 0,		/**< The manifest platform identifier. */
};

/**
 * Maximum string length, including terminator, for ID strings in a manifest.
 *
 * This is also the maximum length of a string contained within an element that adds padding for
 * alignment.  A maximum length string will have one byte of padding to align to a 4 byte boundary.
 */
#define	MANIFEST_MAX_STRING			256

/**
 * Indication that a manifest element is not the child of another element.
 */
#define	MANIFEST_NO_PARENT			0xff

/**
 * Indication that an element does not have a hash value in the table of contents.
 */
#define	MANIFEST_NO_HASH			0xff

/**
 * The maximum number of entries possible in a table of contents.
 */
#define	MANIFEST_MAX_ENTRIES		0xff

/**
 * The header for a manifest table of contents.
 */
struct manifest_toc_header {
	uint8_t entry_count;			/**< The number of entries in the table of contents. */
	uint8_t hash_count;				/**< The number of element hashes in the table of contents. */
	uint8_t hash_type;				/**< The hashing algorithm used in the table of contents. */
	uint8_t reserved;				/**< Unused. */
};

/**
 * Table of contents entry for single element in the manifest.
 */
struct manifest_toc_entry {
	uint8_t type_id;				/**< Identifier for the type of manifest element. */
	uint8_t parent;					/**< Type identifier for the parent element. */
	uint8_t format;					/**< Format version of the data contained in the element. */
	uint8_t hash_id;				/**< Index of the hash entry for the element. */
	uint16_t offset;				/**< Offset from the start of the manifest where the element is located. */
	uint16_t length;				/**< Length of the element data. */
};

/**
 * Table of contents structure of the statically sized components (i.e. excludes all hashes).  This
 * is the maximum size for table of contents entries.
 */
struct manifest_toc_max_entries {
	struct manifest_toc_header header;							/**< The table of contents header. */
	struct manifest_toc_entry entries[MANIFEST_MAX_ENTRIES];	/**< List of elements contained in the manifest. */
};

/**
 * Header for the manifest platform ID element.
 */
struct manifest_platform_id {
	uint8_t id_length;				/**< Length of the platform ID string. */
	uint8_t reserved[3];			/**< Unused. */
};
#pragma pack(pop)


#endif /* MANIFEST_FORMAT_H_ */
