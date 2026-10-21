// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_TESTING_ENGINE_H_
#define RNG_TESTING_ENGINE_H_

#include "testing/platform_rng_testing.h"


#ifndef	RNG_TESTING_ENGINE_NAME
#include "crypto/rng_mbedtls.h"
#define	RNG_TESTING_ENGINE_NAME	mbedtls
#define	RNG_TESTING_ENGINE_HAS_STATE
#endif


/* The testing engine provides unit tests a way to abstract the specific engine being used
 * for RNG operations in the test environment.  The following macros are defined for test usage:
 *
 * RNG_TESTING_ENGINE(var) - Define a single instance of the testing engine as a variable or struct
 * field.
 * 		ex:  RNG_TESTING_ENGINE (rng);
 *
 * RNG_TESTING_ENGINE_ARRAY(var, count) - Define an array of instances of the testing engine.
 * 		ex:  RNG_TESTING_ENGINE (rng_array, 5);
 *
 * RNG_TESTING_ENGINE_PARAM(var) - Include a test RNG engine as a parameter in a function
 * definition.
 * 		ex:  int foo (RNG_TESTING_ENGINE (*rng));
 *
 * RNG_TESTING_ENGINE_ARG(var) - Pass a test RNG engine as an argument to a function call.
 * 		ex:  foo (RNG_TESTING_ENGINE_ARG (&rng));
 *
 * RNG_TESTING_ENGINE_ARRAY_ARG(var, index) - Pass a test RNG engine from an array as an argument
 * to a function call.
 * 		ex:  foo (RNG_TESTING_ENGINE_ARRAY_ARG (&rng_array, 2));
 *
 * RNG_TESTING_ENGINE_INIT(var) - Initialize a test RNG engine instance defined with
 * RNG_TESTING_ENGINE.
 * 		ex:  RNG_TESTING_ENGINE_INIT (&rng);
 *
 * RNG_TESTING_ENGINE_INIT_ARRAY(var, index) - Initialize a test RNG engine instance defined with
 * RNG_TESTING_ENGINE_ARRAY.
 * 		ex:  RNG_TESTING_ENGINE_INIT_ARRAY (&rng_array, 3);
 *
 * RNG_TESTING_ENGINE_RELEASE(var) - Release a test RNG engine instance.  It doesn't matter how it
 * was defined.
 * 		ex:  RNG_TESTING_ENGINE_RELEASE (&rng);
 * 		ex:  RNG_TESTING_ENGINE_RELEASE (&rng_array[1]); */


#ifndef RNG_TESTING_ENGINE_HAS_STATE

/* The selected rng engine does not have any variable state. */
#define	RNG_TESTING_ENGINE_STRUCT_DEF(name, var)	struct rng_engine_ ## name var
#define	RNG_TESTING_ENGINE_STRUCT(name, var)		RNG_TESTING_ENGINE_STRUCT_DEF(name, var)
#define	RNG_TESTING_ENGINE(var)                     \
	RNG_TESTING_ENGINE_STRUCT(RNG_TESTING_ENGINE_NAME, var)

#define	RNG_TESTING_ENGINE_ARRAY(var, count)		RNG_TESTING_ENGINE (var)[count]

#define	RNG_TESTING_ENGINE_PARAM(var)				RNG_TESTING_ENGINE (var)

#define	RNG_TESTING_ENGINE_ARG(var)					var

#define	RNG_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index]

#else

/* The selected rng engine requires a variable state instance. */
#define	RNG_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)	struct rng_engine_ ## name ## _state var
#define	RNG_TESTING_ENGINE_STATE_STRUCT(name, var)      \
	RNG_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)
#define	RNG_TESTING_ENGINE_STATE(var)                   \
	RNG_TESTING_ENGINE_STATE_STRUCT(RNG_TESTING_ENGINE_NAME, var)

#define	RNG_TESTING_ENGINE_INST_STRUCT_DEF(name, var)	struct rng_engine_ ## name var
#define	RNG_TESTING_ENGINE_INST_STRUCT(name, var)       \
	RNG_TESTING_ENGINE_INST_STRUCT_DEF(name, var)
#define	RNG_TESTING_ENGINE_INST(var)                    \
	RNG_TESTING_ENGINE_INST_STRUCT(RNG_TESTING_ENGINE_NAME, var)

#define	RNG_TESTING_ENGINE(var)                     \
	RNG_TESTING_ENGINE_STATE (var ## _state); RNG_TESTING_ENGINE_INST (var)

#define	RNG_TESTING_ENGINE_ARRAY(var, count)        \
	RNG_TESTING_ENGINE_STATE (var ## _state)[count]; RNG_TESTING_ENGINE_INST (var)[count]

#define	RNG_TESTING_ENGINE_PARAM(var)               \
	RNG_TESTING_ENGINE_INST (var), RNG_TESTING_ENGINE_STATE (var ## _state)

#define	RNG_TESTING_ENGINE_ARG(var)					var, var ## _state

#define	RNG_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index], var ## _state[index]

#endif

#define	RNG_TESTING_ENGINE_INIT_FUNC_DEF(name, var)    \
	rng_ ## name ## _init (RNG_TESTING_ENGINE_ARG (var))
#define	RNG_TESTING_ENGINE_INIT_FUNC(name, var)        \
	RNG_TESTING_ENGINE_INIT_FUNC_DEF(name, var)
#define	RNG_TESTING_ENGINE_INIT(var)                   \
	RNG_TESTING_ENGINE_INIT_FUNC(RNG_TESTING_ENGINE_NAME, var)

#define	RNG_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)   \
	rng_ ## name ## _init (RNG_TESTING_ENGINE_ARRAY_ARG (var, index))
#define	RNG_TESTING_ENGINE_INIT_ARRAY_FUNC(name, var, index)       \
	RNG_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)
#define	RNG_TESTING_ENGINE_INIT_ARRAY(var, index)                  \
	RNG_TESTING_ENGINE_INIT_ARRAY_FUNC(RNG_TESTING_ENGINE_NAME, var, index)

#define	RNG_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)	rng_ ## name ## _release (var)
#define	RNG_TESTING_ENGINE_RELEASE_FUNC(name, var)      \
	RNG_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)
#define	RNG_TESTING_ENGINE_RELEASE(var)                 \
	RNG_TESTING_ENGINE_RELEASE_FUNC(RNG_TESTING_ENGINE_NAME, var)


#endif	/* RNG_TESTING_ENGINE_H_ */
