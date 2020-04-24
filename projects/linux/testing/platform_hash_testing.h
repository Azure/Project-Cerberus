// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_HASH_TESTING_H_
#define PLATFORM_HASH_TESTING_H_


//#define	HASH_TESTING_USE_OPENSSL


#ifdef HASH_TESTING_USE_OPENSSL
/* Configure the hash testing to use the OpenSSL. */
#include "crypto/hash_openssl.h"
#define	HASH_TESTING_ENGINE_NAME	openssl
#endif


#endif /* PLATFORM_HASH_TESTING_H_ */
