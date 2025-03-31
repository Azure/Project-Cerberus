// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MBEDTLS_COMPAT_H_
#define MBEDTLS_COMPAT_H_

#include "mbedtls/version.h"


/**
 * Indicate if the mbedTLS library is version 3.x.x
 */
#define	MBEDTLS_IS_VERSION_3	(MBEDTLS_VERSION_MAJOR == 3)

/* mbedTLS version 3 introduces a macro to mark certain fields as private.  Define this macro for
 * compatibility with version 2 when private fields need to be accessed.
 *
 * In general, accessing private fields should be avoided, but there are some scenarios where there
 * are no public APIs for accessing the associated information or doing so incurrs unnecessary
 * memory overhead.  In these case, the private fields are still accessed. */
#if !MBEDTLS_IS_VERSION_3
#define	MBEDTLS_PRIVATE(x)			x
#endif


#endif	/* MBEDTLS_COMPAT_H_ */
