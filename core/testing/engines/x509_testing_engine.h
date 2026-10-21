// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_TESTING_ENGINE_H_
#define X509_TESTING_ENGINE_H_

#include "testing/platform_x509_testing.h"


#ifndef	X509_TESTING_ENGINE_NAME
#include "asn1/x509_mbedtls.h"
#define	X509_TESTING_ENGINE_NAME	mbedtls
#define	X509_TESTING_ENGINE_HAS_STATE
#endif


/* The testing engine provides unit tests a way to abstract the specific engine being used
 * for X.509 operations in the test environment.  The following macros are defined for test usage:
 *
 * X509_TESTING_ENGINE(var) - Define a single instance of the testing engine as a variable or struct
 * field.
 * 		ex:  X509_TESTING_ENGINE (x509);
 *
 * X509_TESTING_ENGINE_ARRAY(var, count) - Define an array of instances of the testing engine.
 * 		ex:  X509_TESTING_ENGINE (x509_array, 5);
 *
 * X509_TESTING_ENGINE_PARAM(var) - Include a test X.509 engine as a parameter in a function
 * definition.
 * 		ex:  int foo (X509_TESTING_ENGINE (*x509));
 *
 * X509_TESTING_ENGINE_ARG(var) - Pass a test X.509 engine as an argument to a function call.
 * 		ex:  foo (X509_TESTING_ENGINE_ARG (&x509));
 *
 * X509_TESTING_ENGINE_ARRAY_ARG(var, index) - Pass a test X.509 engine from an array as an argument
 * to a function call.
 * 		ex:  foo (X509_TESTING_ENGINE_ARRAY_ARG (&x509_array, 2));
 *
 * X509_TESTING_ENGINE_INIT(var) - Initialize a test X.509 engine instance defined with
 * X509_TESTING_ENGINE.
 * 		ex:  X509_TESTING_ENGINE_INIT (&x509);
 *
 * X509_TESTING_ENGINE_INIT_ARRAY(var, index) - Initialize a test X.509 engine instance defined with
 * X509_TESTING_ENGINE_ARRAY.
 * 		ex:  X509_TESTING_ENGINE_INIT_ARRAY (&x509_array, 3);
 *
 * X509_TESTING_ENGINE_RELEASE(var) - Release a test X.509 engine instance.  It doesn't matter how
 * it was defined.
 * 		ex:  X509_TESTING_ENGINE_RELEASE (&x509);
 * 		ex:  X509_TESTING_ENGINE_RELEASE (&x509_array[1]); */


#ifndef X509_TESTING_ENGINE_HAS_STATE

/* The selected x509 engine does not have any variable state. */
#define	X509_TESTING_ENGINE_STRUCT_DEF(name, var)	struct x509_engine_ ## name var
#define	X509_TESTING_ENGINE_STRUCT(name, var)		X509_TESTING_ENGINE_STRUCT_DEF(name, var)
#define	X509_TESTING_ENGINE(var)                    \
	X509_TESTING_ENGINE_STRUCT(X509_TESTING_ENGINE_NAME, var)

#define	X509_TESTING_ENGINE_ARRAY(var, count)		X509_TESTING_ENGINE (var)[count]

#define	X509_TESTING_ENGINE_PARAM(var)				X509_TESTING_ENGINE (var)

#define	X509_TESTING_ENGINE_ARG(var)				var

#define	X509_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index]

#else

/* The selected x509 engine requires a variable state instance. */
#define	X509_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)	struct x509_engine_ ## name ## _state var
#define	X509_TESTING_ENGINE_STATE_STRUCT(name, var)     \
	X509_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)
#define	X509_TESTING_ENGINE_STATE(var)                  \
	X509_TESTING_ENGINE_STATE_STRUCT(X509_TESTING_ENGINE_NAME, var)

#define	X509_TESTING_ENGINE_INST_STRUCT_DEF(name, var)	struct x509_engine_ ## name var
#define	X509_TESTING_ENGINE_INST_STRUCT(name, var)      \
	X509_TESTING_ENGINE_INST_STRUCT_DEF(name, var)
#define	X509_TESTING_ENGINE_INST(var)                   \
	X509_TESTING_ENGINE_INST_STRUCT(X509_TESTING_ENGINE_NAME, var)

#define	X509_TESTING_ENGINE(var)                    \
	X509_TESTING_ENGINE_STATE (var ## _state); X509_TESTING_ENGINE_INST (var)

#define	X509_TESTING_ENGINE_ARRAY(var, count)       \
	X509_TESTING_ENGINE_STATE (var ## _state)[count]; X509_TESTING_ENGINE_INST (var)[count]

#define	X509_TESTING_ENGINE_PARAM(var)              \
	X509_TESTING_ENGINE_INST (var), X509_TESTING_ENGINE_STATE (var ## _state)

#define	X509_TESTING_ENGINE_ARG(var)				var, var ## _state

#define	X509_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index], var ## _state[index]

#endif

#define	X509_TESTING_ENGINE_INIT_FUNC_DEF(name, var)    \
	x509_ ## name ## _init (X509_TESTING_ENGINE_ARG (var))
#define	X509_TESTING_ENGINE_INIT_FUNC(name, var)        \
	X509_TESTING_ENGINE_INIT_FUNC_DEF(name, var)
#define	X509_TESTING_ENGINE_INIT(var)                   \
	X509_TESTING_ENGINE_INIT_FUNC(X509_TESTING_ENGINE_NAME, var)

#define	X509_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)   \
	x509_ ## name ## _init (X509_TESTING_ENGINE_ARRAY_ARG (var, index))
#define	X509_TESTING_ENGINE_INIT_ARRAY_FUNC(name, var, index)       \
	X509_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)
#define	X509_TESTING_ENGINE_INIT_ARRAY(var, index)                  \
	X509_TESTING_ENGINE_INIT_ARRAY_FUNC(X509_TESTING_ENGINE_NAME, var, index)

#define	X509_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)	x509_ ## name ## _release (var)
#define	X509_TESTING_ENGINE_RELEASE_FUNC(name, var)     \
	X509_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)
#define	X509_TESTING_ENGINE_RELEASE(var)                \
	X509_TESTING_ENGINE_RELEASE_FUNC(X509_TESTING_ENGINE_NAME, var)


#endif	/* X509_TESTING_ENGINE_H_ */
