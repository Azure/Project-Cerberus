// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_LOGGING_H_
#define ACVP_LOGGING_H_

#include "logging/debug_log.h"


/**
 * ACVP algorithm logging identifier.
 */
enum acvp_algorithm {
	ACVP_ALGORITHM_UNSPECIFIED = 0x0,	/**< ACVP algorithm not specified. */
	ACVP_ALGORITHM_SHA = 0x1,			/**< ACVP SHA algorithm. */
	ACVP_ALGORITHM_AEAD = 0x2,			/**< ACVP AEAD algorithm. */
	ACVP_ALGORITHM_RSA = 0x3,			/**< ACVP RSA algorithm. */
	ACVP_ALGORITHM_ECDSA = 0x4,			/**< ACVP ECDSA algorithm. */
	ACVP_ALGORITHM_HKDF = 0x5,			/**< ACVP HKDF algorithm. */
	ACVP_ALGORITHM_SYM = 0x6,			/**< ACVP symmetric cipher algorithm. */
	ACVP_ALGORITHM_HMAC = 0x7,			/**< ACVP HMAC algorithm. */
	ACVP_ALGORITHM_ECDH = 0x8,			/**< ACVP ECDH algorithm. */
	ACVP_NUM_ALGORITHMS,				/**< Number of ACVP algorithms. */
};


/**
 * ACVP log messages.
 */
enum {
	ACVP_LOGGING_TEST_FAILURE,	/**< Failure during ACVP test execution. */
};


#endif	/* ACVP_LOGGING_H_ */
