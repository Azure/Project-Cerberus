// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_TESTING_ENGINE_H_
#define BASE64_TESTING_ENGINE_H_

#include "testing/platform_base64_testing.h"


#ifndef	BASE64_TESTING_ENGINE_NAME
#include "asn1/base64_mbedtls.h"
#define	BASE64_TESTING_ENGINE_NAME	mbedtls
#endif


/* The testing engine provides unit tests a way to abstract the specific engine being used
 * for base64 operations in the test environment.  The following macros are defined for test usage:
 *
 * BASE64_TESTING_ENGINE(var) - Define a single instance of the testing engine as a variable or
 * struct field.
 * 		ex:  BASE64_TESTING_ENGINE (base64);
 *
 * BASE64_TESTING_ENGINE_ARRAY(var, count) - Define an array of instances of the testing engine.
 * 		ex:  BASE64_TESTING_ENGINE (base64_array, 5);
 *
 * BASE64_TESTING_ENGINE_PARAM(var) - Include a test base64 engine as a parameter in a function
 * definition.
 * 		ex:  int foo (BASE64_TESTING_ENGINE (*base64));
 *
 * BASE64_TESTING_ENGINE_ARG(var) - Pass a test base64 engine as an argument to a function call.
 * 		ex:  foo (BASE64_TESTING_ENGINE_ARG (&base64));
 *
 * BASE64_TESTING_ENGINE_ARRAY_ARG(var, index) - Pass a test base64 engine from an array as an
 * argument to a function call.
 * 		ex:  foo (BASE64_TESTING_ENGINE_ARRAY_ARG (&base64_array, 2));
 *
 * BASE64_TESTING_ENGINE_INIT(var) - Initialize a test base64 engine instance defined with
 * BASE64_TESTING_ENGINE.
 * 		ex:  BASE64_TESTING_ENGINE_INIT (&base64);
 *
 * BASE64_TESTING_ENGINE_INIT_ARRAY(var, index) - Initialize a test base64 engine instance defined
 * with BASE64_TESTING_ENGINE_ARRAY.
 * 		ex:  BASE64_TESTING_ENGINE_INIT_ARRAY (&base64_array, 3);
 *
 * BASE64_TESTING_ENGINE_RELEASE(var) - Release a test base64 engine instance.  It doesn't matter
 * how it was defined.
 * 		ex:  BASE64_TESTING_ENGINE_RELEASE (&base64);
 * 		ex:  BASE64_TESTING_ENGINE_RELEASE (&base64_array[1]); */


#ifndef BASE64_TESTING_ENGINE_HAS_STATE

/* The selected base64 engine does not have any variable state. */
#define	BASE64_TESTING_ENGINE_STRUCT_DEF(name, var)	struct base64_engine_ ## name var
#define	BASE64_TESTING_ENGINE_STRUCT(name, var)		BASE64_TESTING_ENGINE_STRUCT_DEF(name, var)
#define	BASE64_TESTING_ENGINE(var)                    \
	BASE64_TESTING_ENGINE_STRUCT(BASE64_TESTING_ENGINE_NAME, var)

#define	BASE64_TESTING_ENGINE_ARRAY(var, count)		BASE64_TESTING_ENGINE (var)[count]

#define	BASE64_TESTING_ENGINE_PARAM(var)				BASE64_TESTING_ENGINE (var)

#define	BASE64_TESTING_ENGINE_ARG(var)				var

#define	BASE64_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index]

#else

/* The selected base64 engine requires a variable state instance. */
#define	BASE64_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)   \
	struct base64_engine_ ## name ## _state var
#define	BASE64_TESTING_ENGINE_STATE_STRUCT(name, var)       \
	BASE64_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)
#define	BASE64_TESTING_ENGINE_STATE(var)                    \
	BASE64_TESTING_ENGINE_STATE_STRUCT(BASE64_TESTING_ENGINE_NAME, var)

#define	BASE64_TESTING_ENGINE_INST_STRUCT_DEF(name, var)	struct base64_engine_ ## name var
#define	BASE64_TESTING_ENGINE_INST_STRUCT(name, var)        \
	BASE64_TESTING_ENGINE_INST_STRUCT_DEF(name, var)
#define	BASE64_TESTING_ENGINE_INST(var)                     \
	BASE64_TESTING_ENGINE_INST_STRUCT(BASE64_TESTING_ENGINE_NAME, var)

#define	BASE64_TESTING_ENGINE(var)                  \
	BASE64_TESTING_ENGINE_STATE (var ## _state); BASE64_TESTING_ENGINE_INST (var)

#define	BASE64_TESTING_ENGINE_ARRAY(var, count)     \
	BASE64_TESTING_ENGINE_STATE (var ## _state)[count]; BASE64_TESTING_ENGINE_INST (var)[count]

#define	BASE64_TESTING_ENGINE_PARAM(var)            \
	BASE64_TESTING_ENGINE_INST (var), BASE64_TESTING_ENGINE_STATE (var ## _state)

#define	BASE64_TESTING_ENGINE_ARG(var)				var, var ## _state

#define	BASE64_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index], var ## _state[index]

#endif

#define	BASE64_TESTING_ENGINE_INIT_FUNC_DEF(name, var)    \
	base64_ ## name ## _init (BASE64_TESTING_ENGINE_ARG (var))
#define	BASE64_TESTING_ENGINE_INIT_FUNC(name, var)        \
	BASE64_TESTING_ENGINE_INIT_FUNC_DEF(name, var)
#define	BASE64_TESTING_ENGINE_INIT(var)                   \
	BASE64_TESTING_ENGINE_INIT_FUNC(BASE64_TESTING_ENGINE_NAME, var)

#define	BASE64_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)   \
	base64_ ## name ## _init (BASE64_TESTING_ENGINE_ARRAY_ARG (var, index))
#define	BASE64_TESTING_ENGINE_INIT_ARRAY_FUNC(name, var, index)       \
	BASE64_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)
#define	BASE64_TESTING_ENGINE_INIT_ARRAY(var, index)                  \
	BASE64_TESTING_ENGINE_INIT_ARRAY_FUNC(BASE64_TESTING_ENGINE_NAME, var, index)

#define	BASE64_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)	base64_ ## name ## _release (var)
#define	BASE64_TESTING_ENGINE_RELEASE_FUNC(name, var)       \
	BASE64_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)
#define	BASE64_TESTING_ENGINE_RELEASE(var)                  \
	BASE64_TESTING_ENGINE_RELEASE_FUNC(BASE64_TESTING_ENGINE_NAME, var)


#endif	/* BASE64_TESTING_ENGINE_H_ */
