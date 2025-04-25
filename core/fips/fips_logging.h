// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIPS_LOGGING_H_
#define FIPS_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for FIPS handling.
 */
enum {
	FIPS_LOGGING_DRBG_KAT_FAILED,					/**< Failed during execution of a DRBG KAT. */
	FIPS_LOGGING_AES_CBC_ENCRYPT_KAT_FAILED,		/**< Failed during execution of an AES-CBC encrypt KAT. */
	FIPS_LOGGING_AES_CBC_DECRYPT_KAT_FAILED,		/**< Failed during execution of an AES-CBC decrypt KAT. */
	FIPS_LOGGING_AES_ECB_ENCRYPT_KAT_FAILED,		/**< Failed during execution of an AES-ECB encrypt KAT. */
	FIPS_LOGGING_AES_ECB_DECRYPT_KAT_FAILED,		/**< Failed during execution of an AES-ECB decrypt KAT. */
	FIPS_LOGGING_AES_GCM_ENCRYPT_KAT_FAILED,		/**< Failed during execution of an AES-GCM encrypt KAT. */
	FIPS_LOGGING_AES_GCM_DECRYPT_KAT_FAILED,		/**< Failed during execution of an AES-GCM decrypt KAT. */
	FIPS_LOGGING_AES_XTS_ENCRYPT_KAT_FAILED,		/**< Failed during execution of an AES-XTS encrypt KAT. */
	FIPS_LOGGING_AES_XTS_DECRYPT_KAT_FAILED,		/**< Failed during execution of an AES-XTS decrypt KAT. */
	FIPS_LOGGING_AES_KEY_WRAP_KAT_FAILED,			/**< Failed during execution of an AES key wrap KAT. */
	FIPS_LOGGING_AES_KEY_UNWRAP_KAT_FAILED,			/**< Failed during execution of an AES key unwrap KAT. */
	FIPS_LOGGING_AES_KEY_WRAP_PADDING_KAT_FAILED,	/**< Failed during execution of an AES key wrap with padding KAT. */
	FIPS_LOGGING_AES_KEY_UNWRAP_PADDING_KAT_FAILED,	/**< Failed during execution of an AES key unwrap with padding KAT. */
	FIPS_LOGGING_SHA_KAT_FAILED,					/**< Failed during execution of a SHA KAT. */
	FIPS_LOGGING_HMAC_KAT_FAILED,					/**< Failed during execution of a HMAC KAT. */
	FIPS_LOGGING_KBKDF_KAT_FAILED,					/**< Failed during execution of a KBKDF KAT. */
	FIPS_LOGGING_HKDF_KAT_FAILED,					/**< Failed during execution of a HKDF KAT. */
	FIPS_LOGGING_ECDSA_SIGN_KAT_FAILED,				/**< Failed during execution of an ECDSA sign KAT. */
	FIPS_LOGGING_ECDSA_VERIFY_KAT_FAILED,			/**< Failed during execution of an ECDSA verify KAT. */
	FIPS_LOGGING_ECDH_KAT_FAILED,					/**< Failed during execution of an ECDH KAT. */
};


#endif	/* FIPS_LOGGING_H_ */
