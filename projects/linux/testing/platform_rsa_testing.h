// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_RSA_TESTING_H_
#define PLATFORM_RSA_TESTING_H_


//#define	RSA_TESTING_USE_OPENSSL


#ifdef RSA_TESTING_USE_OPENSSL
/* Configure the RSA testing to use the OpenSSL. */
#include "crypto/rsa_openssl.h"
#define	RSA_TESTING_ENGINE_NAME	openssl
#endif


#endif /* PLATFORM_RSA_TESTING_H_ */
