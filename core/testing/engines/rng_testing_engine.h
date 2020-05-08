// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_TESTING_ENGINE_H_
#define RNG_TESTING_ENGINE_H_

#include "testing/platform_rng_testing.h"


#ifndef	RNG_TESTING_ENGINE_NAME
#include "crypto/rng_mbedtls.h"
#define	RNG_TESTING_ENGINE_NAME	mbedtls
#endif


#define	RNG_TESTING_ENGINE_STRUCT_DEF(name)	struct rng_engine_ ## name
#define	RNG_TESTING_ENGINE_STRUCT(name)		RNG_TESTING_ENGINE_STRUCT_DEF(name)
#define	RNG_TESTING_ENGINE					RNG_TESTING_ENGINE_STRUCT(RNG_TESTING_ENGINE_NAME)

#define	RNG_TESTING_ENGINE_INIT_FUNC_DEF(name)	rng_ ## name ## _init
#define	RNG_TESTING_ENGINE_INIT_FUNC(name)		RNG_TESTING_ENGINE_INIT_FUNC_DEF(name)
#define	RNG_TESTING_ENGINE_INIT					RNG_TESTING_ENGINE_INIT_FUNC(RNG_TESTING_ENGINE_NAME)

#define	RNG_TESTING_ENGINE_RELEASE_FUNC_DEF(name)	rng_ ## name ## _release
#define	RNG_TESTING_ENGINE_RELEASE_FUNC(name)		RNG_TESTING_ENGINE_RELEASE_FUNC_DEF(name)
#define	RNG_TESTING_ENGINE_RELEASE					RNG_TESTING_ENGINE_RELEASE_FUNC(RNG_TESTING_ENGINE_NAME)


#endif /* RNG_TESTING_ENGINE_H_ */
