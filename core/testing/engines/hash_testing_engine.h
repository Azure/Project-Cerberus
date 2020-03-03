// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_TESTING_ENGINE_H_
#define HASH_TESTING_ENGINE_H_

#include "testing/platform_hash_testing.h"


#ifndef	HASH_TESTING_ENGINE_NAME
#include "crypto/hash_mbedtls.h"
#define	HASH_TESTING_ENGINE_NAME	mbedtls
#endif


#define	HASH_TESTING_ENGINE_STRUCT_DEF(name)	struct hash_engine_ ## name
#define	HASH_TESTING_ENGINE_STRUCT(name)		HASH_TESTING_ENGINE_STRUCT_DEF(name)
#define	HASH_TESTING_ENGINE						HASH_TESTING_ENGINE_STRUCT(HASH_TESTING_ENGINE_NAME)

#define	HASH_TESTING_ENGINE_INIT_FUNC_DEF(name)	hash_ ## name ## _init
#define	HASH_TESTING_ENGINE_INIT_FUNC(name)		HASH_TESTING_ENGINE_INIT_FUNC_DEF(name)
#define	HASH_TESTING_ENGINE_INIT				HASH_TESTING_ENGINE_INIT_FUNC(HASH_TESTING_ENGINE_NAME)

#define	HASH_TESTING_ENGINE_RELEASE_FUNC_DEF(name)	hash_ ## name ## _release
#define	HASH_TESTING_ENGINE_RELEASE_FUNC(name)		HASH_TESTING_ENGINE_RELEASE_FUNC_DEF(name)
#define	HASH_TESTING_ENGINE_RELEASE					HASH_TESTING_ENGINE_RELEASE_FUNC(HASH_TESTING_ENGINE_NAME)


#endif /* HASH_TESTING_ENGINE_H_ */
