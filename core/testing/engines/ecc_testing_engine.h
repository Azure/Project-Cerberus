// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_TESTING_ENGINE_H_
#define ECC_TESTING_ENGINE_H_

#include "testing/platform_ecc_testing.h"


#ifndef	ECC_TESTING_ENGINE_NAME
#include "crypto/ecc_mbedtls.h"
#define	ECC_TESTING_ENGINE_NAME	mbedtls
#endif


#define	ECC_TESTING_ENGINE_STRUCT_DEF(name)		struct ecc_engine_ ## name
#define	ECC_TESTING_ENGINE_STRUCT(name)			ECC_TESTING_ENGINE_STRUCT_DEF(name)
#define	ECC_TESTING_ENGINE						ECC_TESTING_ENGINE_STRUCT(ECC_TESTING_ENGINE_NAME)

#define	ECC_TESTING_ENGINE_INIT_FUNC_DEF(name)	ecc_ ## name ## _init
#define	ECC_TESTING_ENGINE_INIT_FUNC(name)		ECC_TESTING_ENGINE_INIT_FUNC_DEF(name)
#define	ECC_TESTING_ENGINE_INIT					ECC_TESTING_ENGINE_INIT_FUNC(ECC_TESTING_ENGINE_NAME)

#define	ECC_TESTING_ENGINE_RELEASE_FUNC_DEF(name)	ecc_ ## name ## _release
#define	ECC_TESTING_ENGINE_RELEASE_FUNC(name)		ECC_TESTING_ENGINE_RELEASE_FUNC_DEF(name)
#define	ECC_TESTING_ENGINE_RELEASE					ECC_TESTING_ENGINE_RELEASE_FUNC(ECC_TESTING_ENGINE_NAME)


#endif /* ECC_TESTING_ENGINE_H_ */
