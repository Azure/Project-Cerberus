// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_TESTING_ENGINE_H_
#define AES_TESTING_ENGINE_H_

#include "testing/platform_aes_testing.h"


#ifndef	AES_TESTING_ENGINE_NAME
#include "crypto/aes_mbedtls.h"
#define	AES_TESTING_ENGINE_NAME	mbedtls
#endif


#define	AES_TESTING_ENGINE_STRUCT_DEF(name)		struct aes_engine_ ## name
#define	AES_TESTING_ENGINE_STRUCT(name)			AES_TESTING_ENGINE_STRUCT_DEF(name)
#define	AES_TESTING_ENGINE						AES_TESTING_ENGINE_STRUCT(AES_TESTING_ENGINE_NAME)

#define	AES_TESTING_ENGINE_INIT_FUNC_DEF(name)	aes_ ## name ## _init
#define	AES_TESTING_ENGINE_INIT_FUNC(name)		AES_TESTING_ENGINE_INIT_FUNC_DEF(name)
#define	AES_TESTING_ENGINE_INIT					AES_TESTING_ENGINE_INIT_FUNC(AES_TESTING_ENGINE_NAME)

#define	AES_TESTING_ENGINE_RELEASE_FUNC_DEF(name)	aes_ ## name ## _release
#define	AES_TESTING_ENGINE_RELEASE_FUNC(name)		AES_TESTING_ENGINE_RELEASE_FUNC_DEF(name)
#define	AES_TESTING_ENGINE_RELEASE					AES_TESTING_ENGINE_RELEASE_FUNC(AES_TESTING_ENGINE_NAME)


#endif /* AES_TESTING_ENGINE_H_ */
