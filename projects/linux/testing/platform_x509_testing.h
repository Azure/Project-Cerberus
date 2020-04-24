// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_X509_TESTING_H_
#define PLATFORM_X509_TESTING_H_


//#define	X509_TESTING_USE_OPENSSL


#ifdef X509_TESTING_USE_OPENSSL
/* Configure the X.509 testing to use the OpenSSL. */
#include "crypto/x509_openssl.h"
#define	X509_TESTING_ENGINE_NAME	openssl
#endif


#endif /* PLATFORM_X509_TESTING_H_ */
