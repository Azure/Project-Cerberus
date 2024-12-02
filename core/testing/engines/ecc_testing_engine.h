// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_TESTING_ENGINE_H_
#define ECC_TESTING_ENGINE_H_

#include "testing/platform_ecc_testing.h"


#ifndef	ECC_TESTING_ENGINE_NAME
#include "crypto/ecc_mbedtls.h"
#define	ECC_TESTING_ENGINE_NAME	mbedtls
#endif


/* The testing engine provides unit tests a way to abstract the specific engine being used
 * for ECC operations in the test environment.  The following macros are defined for test usage:
 *
 * ECC_TESTING_ENGINE(var) - Define a single instance of the testing engine as a variable or struct
 * field.
 * 		ex:  ECC_TESTING_ENGINE (ecc);
 *
 * ECC_TESTING_ENGINE_ARRAY(var, count) - Define an array of instances of the testing engine.
 * 		ex:  ECC_TESTING_ENGINE (ecc_array, 5);
 *
 * ECC_TESTING_ENGINE_PARAM(var) - Include a test ECC engine as a parameter in a function
 * definition.
 * 		ex:  int foo (ECC_TESTING_ENGINE (*ecc));
 *
 * ECC_TESTING_ENGINE_ARG(var) - Pass a test ECC engine as an argument to a function call.
 * 		ex:  foo (ECC_TESTING_ENGINE_ARG (&ecc));
 *
 * ECC_TESTING_ENGINE_ARRAY_ARG(var, index) - Pass a test ECC engine from an array as an argument
 * to a function call.
 * 		ex:  foo (ECC_TESTING_ENGINE_ARRAY_ARG (&ecc_array, 2));
 *
 * ECC_TESTING_ENGINE_INIT(var) - Initialize a test ECC engine instance defined with
 * ECC_TESTING_ENGINE.
 * 		ex:  ECC_TESTING_ENGINE_INIT (&ecc);
 *
 * ECC_TESTING_ENGINE_INIT_ARRAY(var, index) - Initialize a test ECC engine instance defined with
 * ECC_TESTING_ENGINE_ARRAY.
 * 		ex:  ECC_TESTING_ENGINE_INIT_ARRAY (&ecc_array, 3);
 *
 * ECC_TESTING_ENGINE_RELEASE(var) - Release a test ECC engine instance.  It doesn't matter how it
 * was defined.
 * 		ex:  ECC_TESTING_ENGINE_RELEASE (&ecc);
 * 		ex:  ECC_TESTING_ENGINE_RELEASE (&ecc_array[1]); */


#ifndef ECC_TESTING_ENGINE_HAS_STATE

/* The selected ecc engine does not have any variable state. */
#define	ECC_TESTING_ENGINE_STRUCT_DEF(name, var)	struct ecc_engine_ ## name var
#define	ECC_TESTING_ENGINE_STRUCT(name, var)		ECC_TESTING_ENGINE_STRUCT_DEF(name, var)
#define	ECC_TESTING_ENGINE(var)                     \
	ECC_TESTING_ENGINE_STRUCT(ECC_TESTING_ENGINE_NAME, var)

#define	ECC_TESTING_ENGINE_ARRAY(var, count)		ECC_TESTING_ENGINE (var)[count]

#define	ECC_TESTING_ENGINE_PARAM(var)				ECC_TESTING_ENGINE (var)

#define	ECC_TESTING_ENGINE_ARG(var)					var

#define	ECC_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index]

#else

/* The selected ecc engine requires a variable state instance. */
#define	ECC_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)	struct ecc_engine_ ## name ## _state var
#define	ECC_TESTING_ENGINE_STATE_STRUCT(name, var)      \
	ECC_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)
#define	ECC_TESTING_ENGINE_STATE(var)                   \
	ECC_TESTING_ENGINE_STATE_STRUCT(ECC_TESTING_ENGINE_NAME, var)

#define	ECC_TESTING_ENGINE_INST_STRUCT_DEF(name, var)	struct ecc_engine_ ## name var
#define	ECC_TESTING_ENGINE_INST_STRUCT(name, var)       \
	ECC_TESTING_ENGINE_INST_STRUCT_DEF(name, var)
#define	ECC_TESTING_ENGINE_INST(var)                    \
	ECC_TESTING_ENGINE_INST_STRUCT(ECC_TESTING_ENGINE_NAME, var)

#define	ECC_TESTING_ENGINE(var)                     \
	ECC_TESTING_ENGINE_STATE (var ## _state); ECC_TESTING_ENGINE_INST (var)

#define	ECC_TESTING_ENGINE_ARRAY(var, count)        \
	ECC_TESTING_ENGINE_STATE (var ## _state)[count]; ECC_TESTING_ENGINE_INST (var)[count]

#define	ECC_TESTING_ENGINE_PARAM(var)               \
	ECC_TESTING_ENGINE_INST (var), ECC_TESTING_ENGINE_STATE (var ## _state)

#define	ECC_TESTING_ENGINE_ARG(var)					var, var ## _state

#define	ECC_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index], var ## _state[index]

#endif

#define	ECC_TESTING_ENGINE_INIT_FUNC_DEF(name, var)    \
	ecc_ ## name ## _init (ECC_TESTING_ENGINE_ARG (var))
#define	ECC_TESTING_ENGINE_INIT_FUNC(name, var)        \
	ECC_TESTING_ENGINE_INIT_FUNC_DEF(name, var)
#define	ECC_TESTING_ENGINE_INIT(var)                   \
	ECC_TESTING_ENGINE_INIT_FUNC(ECC_TESTING_ENGINE_NAME, var)

#define	ECC_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)   \
	ecc_ ## name ## _init (ECC_TESTING_ENGINE_ARRAY_ARG (var, index))
#define	ECC_TESTING_ENGINE_INIT_ARRAY_FUNC(name, var, index)       \
	ECC_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)
#define	ECC_TESTING_ENGINE_INIT_ARRAY(var, index)                  \
	ECC_TESTING_ENGINE_INIT_ARRAY_FUNC(ECC_TESTING_ENGINE_NAME, var, index)

#define	ECC_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)	ecc_ ## name ## _release (var)
#define	ECC_TESTING_ENGINE_RELEASE_FUNC(name, var)      \
	ECC_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)
#define	ECC_TESTING_ENGINE_RELEASE(var)                 \
	ECC_TESTING_ENGINE_RELEASE_FUNC(ECC_TESTING_ENGINE_NAME, var)


#endif	/* ECC_TESTING_ENGINE_H_ */
