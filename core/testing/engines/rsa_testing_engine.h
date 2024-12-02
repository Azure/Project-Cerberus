// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_TESTING_ENGINE_H_
#define RSA_TESTING_ENGINE_H_

#include <stddef.h>
#include <stdint.h>
#include "testing/platform_rsa_testing.h"


#ifndef	RSA_TESTING_ENGINE_NAME
#include "crypto/rsa_mbedtls.h"
#define	RSA_TESTING_ENGINE_NAME	mbedtls
#endif


/* The testing engine provides unit tests a way to abstract the specific engine being used
 * for RSA operations in the test environment.  The following macros are defined for test usage:
 *
 * RSA_TESTING_ENGINE(var) - Define a single instance of the testing engine as a variable or struct
 * field.
 * 		ex:  RSA_TESTING_ENGINE (rsa);
 *
 * RSA_TESTING_ENGINE_ARRAY(var, count) - Define an array of instances of the testing engine.
 * 		ex:  RSA_TESTING_ENGINE (rsa_array, 5);
 *
 * RSA_TESTING_ENGINE_PARAM(var) - Include a test RSA engine as a parameter in a function
 * definition.
 * 		ex:  int foo (RSA_TESTING_ENGINE (*rsa));
 *
 * RSA_TESTING_ENGINE_ARG(var) - Pass a test RSA engine as an argument to a function call.
 * 		ex:  foo (RSA_TESTING_ENGINE_ARG (&rsa));
 *
 * RSA_TESTING_ENGINE_ARRAY_ARG(var, index) - Pass a test RSA engine from an array as an argument
 * to a function call.
 * 		ex:  foo (RSA_TESTING_ENGINE_ARRAY_ARG (&rsa_array, 2));
 *
 * RSA_TESTING_ENGINE_INIT(var) - Initialize a test RSA engine instance defined with
 * RSA_TESTING_ENGINE.
 * 		ex:  RSA_TESTING_ENGINE_INIT (&rsa);
 *
 * RSA_TESTING_ENGINE_INIT_ARRAY(var, index) - Initialize a test RSA engine instance defined with
 * RSA_TESTING_ENGINE_ARRAY.
 * 		ex:  RSA_TESTING_ENGINE_INIT_ARRAY (&rsa_array, 3);
 *
 * RSA_TESTING_ENGINE_RELEASE(var) - Release a test RSA engine instance.  It doesn't matter how it
 * was defined.
 * 		ex:  RSA_TESTING_ENGINE_RELEASE (&rsa);
 * 		ex:  RSA_TESTING_ENGINE_RELEASE (&rsa_array[1]); */


#ifndef RSA_TESTING_ENGINE_HAS_STATE

/* The selected rsa engine does not have any variable state. */
#define	RSA_TESTING_ENGINE_STRUCT_DEF(name, var)	struct rsa_engine_ ## name var
#define	RSA_TESTING_ENGINE_STRUCT(name, var)		RSA_TESTING_ENGINE_STRUCT_DEF(name, var)
#define	RSA_TESTING_ENGINE(var)                     \
	RSA_TESTING_ENGINE_STRUCT(RSA_TESTING_ENGINE_NAME, var)

#define	RSA_TESTING_ENGINE_ARRAY(var, count)		RSA_TESTING_ENGINE (var)[count]

#define	RSA_TESTING_ENGINE_PARAM(var)				RSA_TESTING_ENGINE (var)

#define	RSA_TESTING_ENGINE_ARG(var)					var

#define	RSA_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index]

#else

/* The selected rsa engine requires a variable state instance. */
#define	RSA_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)	struct rsa_engine_ ## name ## _state var
#define	RSA_TESTING_ENGINE_STATE_STRUCT(name, var)      \
	RSA_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)
#define	RSA_TESTING_ENGINE_STATE(var)                   \
	RSA_TESTING_ENGINE_STATE_STRUCT(RSA_TESTING_ENGINE_NAME, var)

#define	RSA_TESTING_ENGINE_INST_STRUCT_DEF(name, var)	struct rsa_engine_ ## name var
#define	RSA_TESTING_ENGINE_INST_STRUCT(name, var)       \
	RSA_TESTING_ENGINE_INST_STRUCT_DEF(name, var)
#define	RSA_TESTING_ENGINE_INST(var)                    \
	RSA_TESTING_ENGINE_INST_STRUCT(RSA_TESTING_ENGINE_NAME, var)

#define	RSA_TESTING_ENGINE(var)                     \
	RSA_TESTING_ENGINE_STATE (var ## _state); RSA_TESTING_ENGINE_INST (var)

#define	RSA_TESTING_ENGINE_ARRAY(var, count)        \
	RSA_TESTING_ENGINE_STATE (var ## _state)[count]; RSA_TESTING_ENGINE_INST (var)[count]

#define	RSA_TESTING_ENGINE_PARAM(var)               \
	RSA_TESTING_ENGINE_INST (var), RSA_TESTING_ENGINE_STATE (var ## _state)

#define	RSA_TESTING_ENGINE_ARG(var)					var, var ## _state

#define	RSA_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index], var ## _state[index]

#endif

#define	RSA_TESTING_ENGINE_INIT_FUNC_DEF(name, var)    \
	rsa_ ## name ## _init (RSA_TESTING_ENGINE_ARG (var))
#define	RSA_TESTING_ENGINE_INIT_FUNC(name, var)        \
	RSA_TESTING_ENGINE_INIT_FUNC_DEF(name, var)
#define	RSA_TESTING_ENGINE_INIT(var)                   \
	RSA_TESTING_ENGINE_INIT_FUNC(RSA_TESTING_ENGINE_NAME, var)

#define	RSA_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)   \
	rsa_ ## name ## _init (RSA_TESTING_ENGINE_ARRAY_ARG (var, index))
#define	RSA_TESTING_ENGINE_INIT_ARRAY_FUNC(name, var, index)       \
	RSA_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)
#define	RSA_TESTING_ENGINE_INIT_ARRAY(var, index)                  \
	RSA_TESTING_ENGINE_INIT_ARRAY_FUNC(RSA_TESTING_ENGINE_NAME, var, index)

#define	RSA_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)	rsa_ ## name ## _release (var)
#define	RSA_TESTING_ENGINE_RELEASE_FUNC(name, var)      \
	RSA_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)
#define	RSA_TESTING_ENGINE_RELEASE(var)                 \
	RSA_TESTING_ENGINE_RELEASE_FUNC(RSA_TESTING_ENGINE_NAME, var)

#define	RSA_TESTING_ENGINE_SIGN_FUNC_DEF(name)	rsa_ ## name ## _testing_sign_data
#define	RSA_TESTING_ENGINE_SIGN_FUNC(name)		RSA_TESTING_ENGINE_SIGN_FUNC_DEF(name)
#define	RSA_TESTING_ENGINE_SIGN                 \
		RSA_TESTING_ENGINE_SIGN_FUNC(RSA_TESTING_ENGINE_NAME)

/**
 * Sign data with an RSA private key using SHA-256
 *
 * @param data The data to sign.
 * @param length The length of the data.
 * @param key The private key to use to sign the data.
 * @param key_length The length of the key.
 * @param signature Output buffer for the signature.
 * @param sig_length The length of the signature buffer.
 *
 * @return 0 if the signature was successfully generated or an error code.
 */
int RSA_TESTING_ENGINE_SIGN (const uint8_t *data, size_t length, const uint8_t *key,
	size_t key_length, uint8_t *signature, size_t sig_length);


#endif	/* RSA_TESTING_ENGINE_H_ */
