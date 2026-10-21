// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef OPENSSL_CHECK_H_
#define OPENSSL_CHECK_H_

#include <openssl/opensslv.h>


/**
 * Indicate if the OpenSSL library is version 3.x.x
 */
#define	OPENSSL_IS_VERSION_3	(OPENSSL_VERSION_MAJOR == 3)


#endif /* OPENSSL_CHECK_H_ */
