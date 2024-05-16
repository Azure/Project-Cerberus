// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_TESTING_ENGINE_H_
#define BASE64_TESTING_ENGINE_H_

#include "testing/platform_base64_testing.h"


#ifndef	BASE64_TESTING_ENGINE_NAME
#include "asn1/base64_mbedtls.h"
#define	BASE64_TESTING_ENGINE_NAME	mbedtls
#endif


#define	BASE64_TESTING_ENGINE_STRUCT_DEF(name)		struct base64_engine_ ## name
#define	BASE64_TESTING_ENGINE_STRUCT(name)			BASE64_TESTING_ENGINE_STRUCT_DEF(name)
#define	BASE64_TESTING_ENGINE                       \
		BASE64_TESTING_ENGINE_STRUCT(BASE64_TESTING_ENGINE_NAME)

#define	BASE64_TESTING_ENGINE_INIT_FUNC_DEF(name)	base64_ ## name ## _init
#define	BASE64_TESTING_ENGINE_INIT_FUNC(name)		BASE64_TESTING_ENGINE_INIT_FUNC_DEF(name)
#define	BASE64_TESTING_ENGINE_INIT                  \
		BASE64_TESTING_ENGINE_INIT_FUNC(BASE64_TESTING_ENGINE_NAME)

#define	BASE64_TESTING_ENGINE_RELEASE_FUNC_DEF(name)	base64_ ## name ## _release
#define	BASE64_TESTING_ENGINE_RELEASE_FUNC(name)		BASE64_TESTING_ENGINE_RELEASE_FUNC_DEF(name)
#define	BASE64_TESTING_ENGINE_RELEASE                   \
		BASE64_TESTING_ENGINE_RELEASE_FUNC(BASE64_TESTING_ENGINE_NAME)


#endif	/* BASE64_TESTING_ENGINE_H_ */
