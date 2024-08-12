// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_AES_TESTING_H_
#define PLATFORM_AES_TESTING_H_


//#define	AES_TESTING_USE_OPENSSL
//#define	AES_XTS_TESTING_USE_OPENSSL


#ifdef AES_TESTING_USE_OPENSSL
/* Configure the AES-GCM testing engine to use OpenSSL. */
#include "crypto/aes_openssl.h"
#define	AES_TESTING_ENGINE_NAME	openssl
#endif

#ifdef AES_XTS_TESTING_USE_OPENSSL
/* Configure the AES-XTS testing engine to use OpenSSL. */
#include "crypto/aes_openssl.h"
#define	AES_XTS_TESTING_ENGINE_NAME	openssl
#endif


#endif /* PLATFORM_AES_TESTING_H_ */
