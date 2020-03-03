// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_TESTING_ENGINE_H_
#define RSA_TESTING_ENGINE_H_

#include <stdint.h>
#include <stddef.h>
#include "testing/platform_rsa_testing.h"


#ifndef	RSA_TESTING_ENGINE_NAME
#include "crypto/rsa_mbedtls.h"
#define	RSA_TESTING_ENGINE_NAME	mbedtls
#endif


#define	RSA_TESTING_ENGINE_STRUCT_DEF(name)		struct rsa_engine_ ## name
#define	RSA_TESTING_ENGINE_STRUCT(name)			RSA_TESTING_ENGINE_STRUCT_DEF(name)
#define	RSA_TESTING_ENGINE						RSA_TESTING_ENGINE_STRUCT(RSA_TESTING_ENGINE_NAME)

#define	RSA_TESTING_ENGINE_INIT_FUNC_DEF(name)	rsa_ ## name ## _init
#define	RSA_TESTING_ENGINE_INIT_FUNC(name)		RSA_TESTING_ENGINE_INIT_FUNC_DEF(name)
#define	RSA_TESTING_ENGINE_INIT					RSA_TESTING_ENGINE_INIT_FUNC(RSA_TESTING_ENGINE_NAME)

#define	RSA_TESTING_ENGINE_RELEASE_FUNC_DEF(name)	rsa_ ## name ## _release
#define	RSA_TESTING_ENGINE_RELEASE_FUNC(name)		RSA_TESTING_ENGINE_RELEASE_FUNC_DEF(name)
#define	RSA_TESTING_ENGINE_RELEASE					RSA_TESTING_ENGINE_RELEASE_FUNC(RSA_TESTING_ENGINE_NAME)

#define	RSA_TESTING_ENGINE_SIGN_FUNC_DEF(name)	rsa_ ## name ## _testing_sign_data
#define	RSA_TESTING_ENGINE_SIGN_FUNC(name)		RSA_TESTING_ENGINE_SIGN_FUNC_DEF(name)
#define	RSA_TESTING_ENGINE_SIGN					RSA_TESTING_ENGINE_SIGN_FUNC(RSA_TESTING_ENGINE_NAME)

int RSA_TESTING_ENGINE_SIGN (const uint8_t *data, size_t length, const uint8_t *key,
	size_t key_length, uint8_t *signature, size_t sig_length);


#endif /* RSA_TESTING_ENGINE_H_ */
