// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_TESTING_ENGINE_H_
#define HASH_TESTING_ENGINE_H_

#include "testing/platform_hash_testing.h"


#ifndef	HASH_TESTING_ENGINE_NAME
#include "crypto/hash_mbedtls.h"
#define	HASH_TESTING_ENGINE_NAME		mbedtls
#define	HASH_TESTING_ENGINE_HAS_STATE
#endif


/* The testing engine provides unit tests a way to abstract the specific engine being used
 * for hash operations in the test environment.  The following macros are defined for test usage:
 *
 * HASH_TESTING_ENGINE(var) - Define a single instance of the testing engine as a variable or struct
 * field.
 * 		ex:  HASH_TESTING_ENGINE (hash);
 *
 * HASH_TESTING_ENGINE_ARRAY(var, count) - Define an array of instances of the testing engine.
 * 		ex:  HASH_TESTING_ENGINE (hash_array, 5);
 *
 * HASH_TESTING_ENGINE_PARAM(var) - Include a test hash engine as a parameter in a function
 * definition.
 * 		ex:  int foo (HASH_TESTING_ENGINE (*hash));
 *
 * HASH_TESTING_ENGINE_ARG(var) - Pass a test hash engine as an argument to a function call.
 * 		ex:  foo (HASH_TESTING_ENGINE_ARG (&hash));
 *
 * HASH_TESTING_ENGINE_ARRAY_ARG(var, index) - Pass a test hash engine from an array as an argument
 * to a function call.
 * 		ex:  foo (HASH_TESTING_ENGINE_ARRAY_ARG (&hash_array, 2));
 *
 * HASH_TESTING_ENGINE_INIT(var) - Initialize a test hash engine instance defined with
 * HASH_TESTING_ENGINE.
 * 		ex:  HASH_TESTING_ENGINE_INIT (&hash);
 *
 * HASH_TESTING_ENGINE_INIT_ARRAY(var, index) - Initialize a test hash engine instance defined with
 * HASH_TESTING_ENGINE_ARRAY.
 * 		ex:  HASH_TESTING_ENGINE_INIT_ARRAY (&hash_array, 3);
 *
 * HASH_TESTING_ENGINE_RELEASE(var) - Release a test hash engine instance.  It doesn't matter how it
 * was defined.
 * 		ex:  HASH_TESTING_ENGINE_RELEASE (&hash);
 * 		ex:  HASH_TESTING_ENGINE_RELEASE (&hash_array[1]); */


#ifndef HASH_TESTING_ENGINE_HAS_STATE

/* The selected hash engine does not have any variable state. */
#define	HASH_TESTING_ENGINE_STRUCT_DEF(name, var)	struct hash_engine_ ## name var
#define	HASH_TESTING_ENGINE_STRUCT(name, var)		HASH_TESTING_ENGINE_STRUCT_DEF(name, var)
#define	HASH_TESTING_ENGINE(var)                    \
	HASH_TESTING_ENGINE_STRUCT(HASH_TESTING_ENGINE_NAME, var)

#define	HASH_TESTING_ENGINE_ARRAY(var, count)		HASH_TESTING_ENGINE (var)[count]

#define	HASH_TESTING_ENGINE_PARAM(var)				HASH_TESTING_ENGINE (var)

#define	HASH_TESTING_ENGINE_ARG(var)				var

#define	HASH_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index]

#else

/* The selected hash engine requires a variable state instance. */
#define	HASH_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)	struct hash_engine_ ## name ## _state var
#define	HASH_TESTING_ENGINE_STATE_STRUCT(name, var)     \
	HASH_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)
#define	HASH_TESTING_ENGINE_STATE(var)                  \
	HASH_TESTING_ENGINE_STATE_STRUCT(HASH_TESTING_ENGINE_NAME, var)

#define	HASH_TESTING_ENGINE_INST_STRUCT_DEF(name, var)	struct hash_engine_ ## name var
#define	HASH_TESTING_ENGINE_INST_STRUCT(name, var)      \
	HASH_TESTING_ENGINE_INST_STRUCT_DEF(name, var)
#define	HASH_TESTING_ENGINE_INST(var)                   \
	HASH_TESTING_ENGINE_INST_STRUCT(HASH_TESTING_ENGINE_NAME, var)

#define	HASH_TESTING_ENGINE(var)                    \
	HASH_TESTING_ENGINE_STATE (var ## _state); HASH_TESTING_ENGINE_INST (var)

#define	HASH_TESTING_ENGINE_ARRAY(var, count)       \
	HASH_TESTING_ENGINE_STATE (var ## _state)[count]; HASH_TESTING_ENGINE_INST (var)[count]

#define	HASH_TESTING_ENGINE_PARAM(var)              \
	HASH_TESTING_ENGINE_INST (var), HASH_TESTING_ENGINE_STATE (var ## _state)

#define	HASH_TESTING_ENGINE_ARG(var)				var, var ## _state

#define	HASH_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index], var ## _state[index]

#endif

#define	HASH_TESTING_ENGINE_INIT_FUNC_DEF(name, var)    \
	hash_ ## name ## _init (HASH_TESTING_ENGINE_ARG (var))
#define	HASH_TESTING_ENGINE_INIT_FUNC(name, var)        \
	HASH_TESTING_ENGINE_INIT_FUNC_DEF(name, var)
#define	HASH_TESTING_ENGINE_INIT(var)                   \
	HASH_TESTING_ENGINE_INIT_FUNC(HASH_TESTING_ENGINE_NAME, var)

#define	HASH_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)   \
	hash_ ## name ## _init (HASH_TESTING_ENGINE_ARRAY_ARG (var, index))
#define	HASH_TESTING_ENGINE_INIT_ARRAY_FUNC(name, var, index)       \
	HASH_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)
#define	HASH_TESTING_ENGINE_INIT_ARRAY(var, index)                  \
	HASH_TESTING_ENGINE_INIT_ARRAY_FUNC(HASH_TESTING_ENGINE_NAME, var, index)

#define	HASH_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)	hash_ ## name ## _release (var)
#define	HASH_TESTING_ENGINE_RELEASE_FUNC(name, var)     \
	HASH_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)
#define	HASH_TESTING_ENGINE_RELEASE(var)                \
	HASH_TESTING_ENGINE_RELEASE_FUNC(HASH_TESTING_ENGINE_NAME, var)


#endif	/* HASH_TESTING_ENGINE_H_ */
