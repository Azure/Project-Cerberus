// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSASSA_H_
#define RSASSA_H_

#include "status/rot_status.h"


#define	RSASSA_ERROR(code)		ROT_ERROR (ROT_MODULE_RSASSA, code)

/**
 * Error codes that can be generated during RSASSA processing.
 */
enum {
	RSASSA_INVALID_ARGUMENT = RSASSA_ERROR (0x00),				/**< Input parameter is null or not valid. */
	RSASSA_NO_MEMORY = RSASSA_ERROR (0x01),						/**< Memory allocation failed. */
	RSASSA_2K_SIGN_SELF_TEST_FAILED = RSASSA_ERROR (0x02),		/**< Failed a self-test for RSASSA sign with a 2048-bit key. */
	RSASSA_3K_SIGN_SELF_TEST_FAILED = RSASSA_ERROR (0x03),		/**< Failed a self-test for RSASSA sign with a 3072-bit key. */
	RSASSA_4K_SIGN_SELF_TEST_FAILED = RSASSA_ERROR (0x04),		/**< Failed a self-test for RSASSA sign with a 4096-bit key. */
	RSASSA_2K_VERIFY_SELF_TEST_FAILED = RSASSA_ERROR (0x05),	/**< Failed a self-test for RSASSA verify with a 2048-bit key. */
	RSASSA_3K_VERIFY_SELF_TEST_FAILED = RSASSA_ERROR (0x06),	/**< Failed a self-test for RSASSA verify with a 3072-bit key. */
	RSASSA_4K_VERIFY_SELF_TEST_FAILED = RSASSA_ERROR (0x07),	/**< Failed a self-test for RSASSA verify with a 4096-bit key. */
	RSASSA_UNSUPPORTED_SELF_TEST = RSASSA_ERROR (0x08),			/**< The key length or hash algorithm is not supported. */
};


#endif	/* RSASSA_H_ */
