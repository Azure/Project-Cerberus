// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_TESTING_ENGINE_H_
#define X509_TESTING_ENGINE_H_

#include "testing/platform_x509_testing.h"


#ifndef	X509_TESTING_ENGINE_NAME
#include "asn1/x509_mbedtls.h"
#define	X509_TESTING_ENGINE_NAME	mbedtls
#endif


#define	X509_TESTING_ENGINE_STRUCT_DEF(name)	struct x509_engine_ ## name
#define	X509_TESTING_ENGINE_STRUCT(name)		X509_TESTING_ENGINE_STRUCT_DEF(name)
#define	X509_TESTING_ENGINE						X509_TESTING_ENGINE_STRUCT(X509_TESTING_ENGINE_NAME)

#define	X509_TESTING_ENGINE_INIT_FUNC_DEF(name)	x509_ ## name ## _init
#define	X509_TESTING_ENGINE_INIT_FUNC(name)		X509_TESTING_ENGINE_INIT_FUNC_DEF(name)
#define	X509_TESTING_ENGINE_INIT                    \
		X509_TESTING_ENGINE_INIT_FUNC(X509_TESTING_ENGINE_NAME)

#define	X509_TESTING_ENGINE_RELEASE_FUNC_DEF(name)	x509_ ## name ## _release
#define	X509_TESTING_ENGINE_RELEASE_FUNC(name)		X509_TESTING_ENGINE_RELEASE_FUNC_DEF(name)
#define	X509_TESTING_ENGINE_RELEASE                 \
		X509_TESTING_ENGINE_RELEASE_FUNC(X509_TESTING_ENGINE_NAME)


#endif	/* X509_TESTING_ENGINE_H_ */
