// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEY_MANIFEST_H_
#define KEY_MANIFEST_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "crypto/rsa.h"
#include "crypto/ecc.h"
#include "crypto/ecc_der_util.h"
#include "crypto/hash.h"


/**
 * The types of public keys that can be contained in a key manifest.
 */
enum key_manifest_key_type {
	KEY_MANIFEST_RSA_KEY,			/**< An RSA public key. */
	KEY_MANIFEST_ECC_KEY,			/**< An ECc public key. */
};

/**
 * Public key format exposed from the key manifest.
 */
struct key_manifest_public_key {
	enum key_manifest_key_type type;		/**< The type of public key. */
	union {
		struct rsa_public_key rsa;			/**< RSA public key data. */
		struct ecc_point_public_key ecc;	/**< ECC public key data. */
	} key;									/**< The public key. */
};

/**
 * A platform-independent API for accessing the key manifest.
 */
struct key_manifest {
	/**
	 * Verify that the key manifest is valid.  A valid manifest is one that has a good signature
	 * with a validated key.
	 *
	 * It is not required that verification of the manifest check for revocation, though some
	 * implementations may also check this condition if needed to satisy other requirements of a
	 * particular device.  Full verification of a manifest includes a call to both
	 * key_manifest.verify and key_manifest.is_allowed.
	 *
	 * Verification of the key manifest is not guaranteed to be reentrant.
	 *
	 * @param manifest The manifest to validate.
	 * @param hash The hash engine to use for validation.
	 *
	 * @return 0 if the manifest is valid or an error code.
	 */
	int (*verify) (const struct key_manifest *manifest, struct hash_engine *hash);

	/**
	 * Check if the key manifest is allowed to be used on this device.  An allowed manifest is one
	 * that has not been revoked.
	 *
	 * Some implementations may also restrict key manifests whose revocation ID is too high relative
	 * to the current device state.  This prevents a single image from invalidating all revocation
	 * bits and to keeps the scope of allowed images as narrow as possible.
	 *
	 * This call does not check that the manifest is valid, simply that it has not been revoked.  A
	 * call to key_manifest.verify is required to ensure validity of the key manifest.
	 *
	 * @param manifest The manifest to check for permission.
	 *
	 * @return 1 if the manifest is allowed to be used, 0 if it is not, or an error code.
	 */
	int (*is_allowed) (const struct key_manifest *manifest);

	/**
	 * Check if the key manifest is configured to revoke any previous manifest.
	 *
	 * This make no indication about whether the revocation is valid or not.  It is simply a check
	 * of the manifest revocation ID against the current device state.  A call to
	 * key_manifest.is_allowed will determine if the manifest (and therefore the revocation) is
	 * allowed by the device.
	 *
	 * @param manifest The manifest to check for updated revocation information.
	 *
	 * @return 1 if the manifest updates the revocation information, 0 if it does not, or an error
	 * code.
	 */
	int (*revokes_old_manifest) (const struct key_manifest *manifest);

	/**
	 * Update the device revocation information from the manifest.
	 *
	 * It is not a requirement for this call to enforce checking for valid manifest revocations.  It
	 * is expected that calling code would validate the manifest and revocation prior to calling
	 * this function.  However, implementations may choose to enforce additional checks here, as
	 * appropriate.
	 *
	 * @param manifest The manifest to use for updating the revocation information.
	 *
	 * @return 0 if the revocation information was successfully updated or an error code.
	 */
	int (*update_revocation) (const struct key_manifest *manifest);

	/**
	 * Get the public key used to verify the key manifest.
	 *
	 * A key returned by this function doesn't necessarily mean it is trusted.  This can only be
	 * guaranteed after successful verification of the manifest, which is a separate operation.
	 *
	 * @param manifest The manifest to get the key from.
	 *
	 * @return The root public key or null if there is an error.  The memory for this key is
	 * managed by the manifest instance.
	 */
	const struct key_manifest_public_key* (*get_root_key) (const struct key_manifest *manifest);

	/**
	 * Get the public key used to verify application images.
	 *
	 * A key returned by this function doesn't necessarily mean it is trusted.  This can only be
	 * guaranteed after successful verification of the manifest, which is a separate operation.
	 *
	 * @param manifest The manifest to get the key from.
	 *
	 * @return The application public key or null if there is an error.  The memory for this key is
	 * managed by the manifest instance.
	 */
	const struct key_manifest_public_key* (*get_app_key) (const struct key_manifest *manifest);

	/**
	 * Get the public key used to verify FW manifests.
	 *
	 * A key returned by this function doesn't necessarily mean it is trusted.  This can only be
	 * guaranteed after successful verification of the manifest, which is a separate operation.
	 *
	 * @param manifest The manifest to get the key from.
	 *
	 * @return The manifest public key or null if there is an error.  The memory for this key is
	 * managed by the manifest instance.
	 */
	const struct key_manifest_public_key* (*get_manifest_key) (const struct key_manifest *manifest);
};


#define	KEY_MANIFEST_ERROR(code)		ROT_ERROR (ROT_MODULE_KEY_MANIFEST, code)

/**
 * Error codes that can be generated by a key manifest.
 */
enum {
	KEY_MANIFEST_INVALID_ARGUMENT = KEY_MANIFEST_ERROR (0x00),		/**< Input parameter is null or not valid. */
	KEY_MANIFEST_NO_MEMORY = KEY_MANIFEST_ERROR (0x01),				/**< Memory allocation failed. */
	KEY_MANIFEST_VERIFY_FAILED = KEY_MANIFEST_ERROR (0x02),			/**< Verification of the key manifest failed. */
	KEY_MANIFEST_IS_ALLOWED_FAILED = KEY_MANIFEST_ERROR (0x03),		/**< Unable to determine if the manifest is revoked. */
	KEY_MANIFEST_REVOKE_CHECK_FAILED = KEY_MANIFEST_ERROR (0x04),	/**< Unable to determine if the manifest revokes an old manifest. */
	KEY_MANIFEST_REVOKE_UPDATE_FAILED = KEY_MANIFEST_ERROR (0x05),	/**< Revocation was not updated. */
	KEY_MANIFEST_BAD_ROOT_KEY = KEY_MANIFEST_ERROR (0x06),			/**< The root key in the manifest is not valid. */
	KEY_MANIFEST_INVALID_FORMAT = KEY_MANIFEST_ERROR (0x07),		/**< The manifest is not formatted correctly. */
	KEY_MANIFEST_UNSUPPORTED_KEY = KEY_MANIFEST_ERROR (0x08),		/**< A key in the manifest is not supported. */
	KEY_MANIFEST_UNSUPPORTED_CERT = KEY_MANIFEST_ERROR (0x09),		/**< A certificate in the manifest is not supported. */
	KEY_MANIFEST_WEAK_KEY = KEY_MANIFEST_ERROR (0x0a),				/**< A key in the manifest does not meet security requirements. */
	KEY_MANIFEST_UNTRUSTED_ROOT_KEY = KEY_MANIFEST_ERROR (0x0b),	/**< A valid root key is not trusted (e.g. revoked by hardware). */
	KEY_MANIFEST_REVOKED = KEY_MANIFEST_ERROR (0x0c),				/**< The key manifest has been revoked. */
	KEY_MANIFEST_ID_TOO_HIGH = KEY_MANIFEST_ERROR (0x0d),			/**< The key manifest is reporting an ID too much greater than the current state. */
};


#endif /* KEY_MANIFEST_H_ */
