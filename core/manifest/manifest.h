// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_H_
#define MANIFEST_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/hash.h"
#include "crypto/signature_verification.h"
#include "status/rot_status.h"


/**
 * The base API for working with any manifest.
 */
struct manifest {
	/**
	 * Verify if the manifest is valid.
	 *
	 * @param manifest The manifest to validate.
	 * @param hash The hash engine to use for validation.
	 * @param verification Verification instance to use to verify the manifest signature.
	 * @param hash_out Optional output buffer for manifest hash calculated during verification.  A
	 * validation error does not necessarily mean the hash output is not valid.  If the manifest
	 * hash was not calculated, this buffer will be cleared.  Set this to null to not return the
	 * manifest hash.
	 * @param hash_length Length of the hash output buffer.
	 *
	 * @return 0 if the manifest is valid or an error code.
	 */
	int (*verify) (const struct manifest *manifest, const struct hash_engine *hash,
		const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length);

	/**
	 * Get the ID of the manifest.
	 *
	 * @param manifest The manifest to query.
	 * @param id The buffer to hold the manifest ID.
	 *
	 * @return 0 if the ID was successfully retrieved or an error code.
	 */
	int (*get_id) (const struct manifest *manifest, uint32_t *id);

	/**
	 * Get the string identifier of the platform for the manifest.
	 *
	 * @param manifest The manifest to query.
	 * @param id Pointer to the output buffer for the platform identifier.  The buffer pointer
	 * cannot be null, but if the buffer itself is null, the manifest instance will allocate an
	 * output buffer for the platform identifier.  When using a manifest-allocated buffer, the
	 * output must be treated as const (i.e. do not modify the contents) and must be freed by
	 * calling free_platform_id on the same instance that allocated it.
	 * @param length Length of the output buffer if the buffer is static (i.e. not null).  This
	 * argument is ignored when using manifest allocation.
	 *
	 * @return 0 if the platform ID was retrieved successfully or an error code.
	 */
	int (*get_platform_id) (const struct manifest *manifest, char **id, size_t length);

	/**
	 * Free a platform identifier allocated by a manifest instance.  Do not call this function for
	 * static buffers owned by the caller.
	 *
	 * @param manifest The manifest that allocated the platform identifier.
	 * @param id The platform identifier to free.
	 */
	void (*free_platform_id) (const struct manifest *manifest, char *id);

	/**
	 * Get the hash of the manifest data, not including the signature.  The hash returned will be
	 * calculated using the same algorithm as was used to generate the manifest signature.
	 *
	 * @param manifest The manifest to query.
	 * @param hash The hash engine to use for generating the hash.
	 * @param hash_out Output buffer for the manifest hash.
	 * @param hash_length Length of the hash output buffer.
	 *
	 * @return Length of the hash if it was calculated successfully or an error code.  Use
	 * ROT_IS_ERROR to check the return value.
	 */
	int (*get_hash) (const struct manifest *manifest, const struct hash_engine *hash,
		uint8_t *hash_out, size_t hash_length);

	/**
	 * Get the signature of the manifest.
	 *
	 * @param manifest The manifest to query.
	 * @param signature Output buffer for the manifest signature.
	 * @param length Length of the signature buffer.
	 *
	 * @return The length of the signature or an error code.  Use ROT_IS_ERROR to check the return
	 * value.
	 */
	int (*get_signature) (const struct manifest *manifest, uint8_t *signature, size_t length);

	/**
	 * Determine if the manifest is considered to be empty.  What indicates an empty manifest will
	 * depend on the specific implementation, and it doesn't necessarily mean there is no data in
	 * the manifest.
	 *
	 * @param manifest The manifest to query.
	 *
	 * @return 1 if the manifest is empty, 0 if it is not, or an error code.
	 */
	int (*is_empty) (const struct manifest *manifest);
};


#define	MANIFEST_ERROR(code)		ROT_ERROR (ROT_MODULE_MANIFEST, code)

/**
 * Error codes that can be generated by a manifest.
 *
 * Note: Commented error codes have been deprecated.
 */
enum {
	MANIFEST_INVALID_ARGUMENT = MANIFEST_ERROR (0x00),			/**< Input parameter is null or not valid. */
	MANIFEST_NO_MEMORY = MANIFEST_ERROR (0x01),					/**< Memory allocation failed. */
	MANIFEST_VERIFY_FAILED = MANIFEST_ERROR (0x02),				/**< A verify failure unrelated to authentication. */
	MANIFEST_GET_ID_FAILED = MANIFEST_ERROR (0x03),				/**< The ID was not retrieved. */
	MANIFEST_BAD_MAGIC_NUMBER = MANIFEST_ERROR (0x04),			/**< The manifest magic number was not valid. */
	MANIFEST_BAD_LENGTH = MANIFEST_ERROR (0x05),				/**< The manifest length is bad. */
	MANIFEST_MALFORMED = MANIFEST_ERROR (0x06),					/**< The manifest is not formatted correctly. */
//	MANIFEST_BAD_RESERVED_BYTE = MANIFEST_ERROR (0x07),			/**< The manifest has data in reserved bytes. */
	MANIFEST_GET_HASH_FAILED = MANIFEST_ERROR (0x08),			/**< The hash could not be calculated. */
	MANIFEST_GET_SIGNATURE_FAILED = MANIFEST_ERROR (0x09),		/**< The signature could not be retrieved. */
	MANIFEST_HASH_BUFFER_TOO_SMALL = MANIFEST_ERROR (0x0a),		/**< A buffer for hash output was too small. */
	MANIFEST_SIG_BUFFER_TOO_SMALL = MANIFEST_ERROR (0x0b),		/**< A buffer for signature output was too small. */
	MANIFEST_STORAGE_NOT_ALIGNED = MANIFEST_ERROR (0x0c),		/**< The manifest storage is not aligned correctly. */
	MANIFEST_GET_PLATFORM_ID_FAILED = MANIFEST_ERROR (0x0d),	/**< The platform ID was not retrieved. */
	MANIFEST_SIG_UNKNOWN_HASH_TYPE = MANIFEST_ERROR (0x0e),		/**< The manifest signature uses an unknown hash type. */
	MANIFEST_TOC_UNKNOWN_HASH_TYPE = MANIFEST_ERROR (0x0f),		/**< The manifest table of contents uses an unknown hash type. */
	MANIFEST_NO_PLATFORM_ID = MANIFEST_ERROR (0x10),			/**< The manifest does not contain a platform ID entry. */
	MANIFEST_PLAT_ID_BUFFER_TOO_SMALL = MANIFEST_ERROR (0x11),	/**< A buffer for the platform ID was too small. */
	MANIFEST_NO_MANIFEST = MANIFEST_ERROR (0x12),				/**< A manifest has not been successfully validated. */
	MANIFEST_ELEMENT_NOT_FOUND = MANIFEST_ERROR (0x13),			/**< The specified element was not found in the manifest. */
	MANIFEST_TOC_INVALID = MANIFEST_ERROR (0x14),				/**< The table of contents failed validation. */
	MANIFEST_ELEMENT_INVALID = MANIFEST_ERROR (0x15),			/**< A manifest element failed validation. */
	MANIFEST_WRONG_PARENT = MANIFEST_ERROR (0x16),				/**< Parent element is not of the correct type. */
	MANIFEST_CHILD_NOT_FOUND = MANIFEST_ERROR (0x17),			/**< A child element was not found in the manifest. */
	MANIFEST_CHECK_EMPTY_FAILED = MANIFEST_ERROR (0x18),		/**< Failed to determine if the manifest was empty. */
};


#endif	/* MANIFEST_H_ */
