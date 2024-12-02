// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_TESTING_ENGINE_H_
#define AES_TESTING_ENGINE_H_

#include "testing/platform_aes_testing.h"


/* AES-GCM engine */
#ifndef	AES_GCM_TESTING_ENGINE_NAME
#include "crypto/aes_gcm_mbedtls.h"
#define	AES_GCM_TESTING_ENGINE_NAME	mbedtls
#define	AES_GCM_TESTING_ENGINE_HAS_STATE
#endif


/* The testing engine provides unit tests a way to abstract the specific engine being used
 * for AES-GCM operations in the test environment.  The following macros are defined for test usage:
 *
 * AES_GCM_TESTING_ENGINE(var) - Define a single instance of the testing engine as a variable or
 * struct field.
 * 		ex:  AES_GCM_TESTING_ENGINE (aes_gcm);
 *
 * AES_GCM_TESTING_ENGINE_ARRAY(var, count) - Define an array of instances of the testing engine.
 * 		ex:  AES_GCM_TESTING_ENGINE (aes_gcm_array, 5);
 *
 * AES_GCM_TESTING_ENGINE_PARAM(var) - Include a test AES-GCM engine as a parameter in a function
 * definition.
 * 		ex:  int foo (AES_GCM_TESTING_ENGINE (*aes_gcm));
 *
 * AES_GCM_TESTING_ENGINE_ARG(var) - Pass a test AES-GCM engine as an argument to a function call.
 * 		ex:  foo (AES_GCM_TESTING_ENGINE_ARG (&aes_gcm));
 *
 * AES_GCM_TESTING_ENGINE_ARRAY_ARG(var, index) - Pass a test AES-GCM engine from an array as an
 * argument to a function call.
 * 		ex:  foo (AES_GCM_TESTING_ENGINE_ARRAY_ARG (&aes_gcm_array, 2));
 *
 * AES_GCM_TESTING_ENGINE_INIT(var) - Initialize a test AES-GCM engine instance defined with
 * AES_GCM_TESTING_ENGINE.
 * 		ex:  AES_GCM_TESTING_ENGINE_INIT (&aes_gcm);
 *
 * AES_GCM_TESTING_ENGINE_INIT_ARRAY(var, index) - Initialize a test AES-GCM engine instance defined
 * with AES_GCM_TESTING_ENGINE_ARRAY.
 * 		ex:  AES_GCM_TESTING_ENGINE_INIT_ARRAY (&aes_gcm_array, 3);
 *
 * AES_GCM_TESTING_ENGINE_RELEASE(var) - Release a test AES-GCM engine instance.  It doesn't matter
 * how it was defined.
 * 		ex:  AES_GCM_TESTING_ENGINE_RELEASE (&aes_gcm);
 * 		ex:  AES_GCM_TESTING_ENGINE_RELEASE (&aes_gcm_array[1]); */


#ifndef AES_GCM_TESTING_ENGINE_HAS_STATE

/* The selected aes_gcm engine does not have any variable state. */
#define	AES_GCM_TESTING_ENGINE_STRUCT_DEF(name, var)	struct aes_gcm_engine_ ## name var
#define	AES_GCM_TESTING_ENGINE_STRUCT(name, var)		AES_GCM_TESTING_ENGINE_STRUCT_DEF(name, var)
#define	AES_GCM_TESTING_ENGINE(var)                     \
	AES_GCM_TESTING_ENGINE_STRUCT(AES_GCM_TESTING_ENGINE_NAME, var)

#define	AES_GCM_TESTING_ENGINE_ARRAY(var, count)		AES_GCM_TESTING_ENGINE (var)[count]

#define	AES_GCM_TESTING_ENGINE_PARAM(var)				AES_GCM_TESTING_ENGINE (var)

#define	AES_GCM_TESTING_ENGINE_ARG(var)					var

#define	AES_GCM_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index]

#else

/* The selected aes_gcm engine requires a variable state instance. */
#define	AES_GCM_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)  \
	struct aes_gcm_engine_ ## name ## _state var
#define	AES_GCM_TESTING_ENGINE_STATE_STRUCT(name, var)      \
	AES_GCM_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)
#define	AES_GCM_TESTING_ENGINE_STATE(var)                   \
	AES_GCM_TESTING_ENGINE_STATE_STRUCT(AES_GCM_TESTING_ENGINE_NAME, var)

#define	AES_GCM_TESTING_ENGINE_INST_STRUCT_DEF(name, var)	struct aes_gcm_engine_ ## name var
#define	AES_GCM_TESTING_ENGINE_INST_STRUCT(name, var)       \
	AES_GCM_TESTING_ENGINE_INST_STRUCT_DEF(name, var)
#define	AES_GCM_TESTING_ENGINE_INST(var)                    \
	AES_GCM_TESTING_ENGINE_INST_STRUCT(AES_GCM_TESTING_ENGINE_NAME, var)

#define	AES_GCM_TESTING_ENGINE(var)                     \
	AES_GCM_TESTING_ENGINE_STATE (var ## _state); AES_GCM_TESTING_ENGINE_INST (var)

#define	AES_GCM_TESTING_ENGINE_ARRAY(var, count)        \
	AES_GCM_TESTING_ENGINE_STATE (var ## _state)[count]; AES_GCM_TESTING_ENGINE_INST (var)[count]

#define	AES_GCM_TESTING_ENGINE_PARAM(var)               \
	AES_GCM_TESTING_ENGINE_INST (var), AES_GCM_TESTING_ENGINE_STATE (var ## _state)

#define	AES_GCM_TESTING_ENGINE_ARG(var)					var, var ## _state

#define	AES_GCM_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index], var ## _state[index]

#endif

#define	AES_GCM_TESTING_ENGINE_INIT_FUNC_DEF(name, var)    \
	aes_gcm_ ## name ## _init (AES_GCM_TESTING_ENGINE_ARG (var))
#define	AES_GCM_TESTING_ENGINE_INIT_FUNC(name, var)        \
	AES_GCM_TESTING_ENGINE_INIT_FUNC_DEF(name, var)
#define	AES_GCM_TESTING_ENGINE_INIT(var)                   \
	AES_GCM_TESTING_ENGINE_INIT_FUNC(AES_GCM_TESTING_ENGINE_NAME, var)

#define	AES_GCM_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)   \
	aes_gcm_ ## name ## _init (AES_GCM_TESTING_ENGINE_ARRAY_ARG (var, index))
#define	AES_GCM_TESTING_ENGINE_INIT_ARRAY_FUNC(name, var, index)       \
	AES_GCM_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)
#define	AES_GCM_TESTING_ENGINE_INIT_ARRAY(var, index)                  \
	AES_GCM_TESTING_ENGINE_INIT_ARRAY_FUNC(AES_GCM_TESTING_ENGINE_NAME, var, index)

#define	AES_GCM_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)	aes_gcm_ ## name ## _release (var)
#define	AES_GCM_TESTING_ENGINE_RELEASE_FUNC(name, var)      \
	AES_GCM_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)
#define	AES_GCM_TESTING_ENGINE_RELEASE(var)                 \
	AES_GCM_TESTING_ENGINE_RELEASE_FUNC(AES_GCM_TESTING_ENGINE_NAME, var)


/* AES-XTS engine */
#ifndef	AES_XTS_TESTING_ENGINE_NAME
#include "crypto/aes_xts_mbedtls.h"
#define	AES_XTS_TESTING_ENGINE_NAME	mbedtls
#define	AES_XTS_TESTING_ENGINE_HAS_STATE
#endif


/* The testing engine provides unit tests a way to abstract the specific engine being used
 * for AES-XTS operations in the test environment.  The following macros are defined for test usage:
 *
 * AES_XTS_TESTING_ENGINE(var) - Define a single instance of the testing engine as a variable or
 * struct field.
 * 		ex:  AES_XTS_TESTING_ENGINE (aes_xts);
 *
 * AES_XTS_TESTING_ENGINE_ARRAY(var, count) - Define an array of instances of the testing engine.
 * 		ex:  AES_XTS_TESTING_ENGINE (aes_xts_array, 5);
 *
 * AES_XTS_TESTING_ENGINE_PARAM(var) - Include a test AES-XTS engine as a parameter in a function
 * definition.
 * 		ex:  int foo (AES_XTS_TESTING_ENGINE (*aes_xts));
 *
 * AES_XTS_TESTING_ENGINE_ARG(var) - Pass a test AES-XTS engine as an argument to a function call.
 * 		ex:  foo (AES_XTS_TESTING_ENGINE_ARG (&aes_xts));
 *
 * AES_XTS_TESTING_ENGINE_ARRAY_ARG(var, index) - Pass a test AES-XTS engine from an array as an
 * argument to a function call.
 * 		ex:  foo (AES_XTS_TESTING_ENGINE_ARRAY_ARG (&aes_xts_array, 2));
 *
 * AES_XTS_TESTING_ENGINE_INIT(var) - Initialize a test AES-XTS engine instance defined with
 * AES_XTS_TESTING_ENGINE.
 * 		ex:  AES_XTS_TESTING_ENGINE_INIT (&aes_xts);
 *
 * AES_XTS_TESTING_ENGINE_INIT_ARRAY(var, index) - Initialize a test AES-XTS engine instance defined
 * with AES_XTS_TESTING_ENGINE_ARRAY.
 * 		ex:  AES_XTS_TESTING_ENGINE_INIT_ARRAY (&aes_xts_array, 3);
 *
 * AES_XTS_TESTING_ENGINE_RELEASE(var) - Release a test AES-XTS engine instance.  It doesn't matter
 * how it was defined.
 * 		ex:  AES_XTS_TESTING_ENGINE_RELEASE (&aes_xts);
 * 		ex:  AES_XTS_TESTING_ENGINE_RELEASE (&aes_xts_array[1]); */


#ifndef AES_XTS_TESTING_ENGINE_HAS_STATE

/* The selected aes_xts engine does not have any variable state. */
#define	AES_XTS_TESTING_ENGINE_STRUCT_DEF(name, var)	struct aes_xts_engine_ ## name var
#define	AES_XTS_TESTING_ENGINE_STRUCT(name, var)		AES_XTS_TESTING_ENGINE_STRUCT_DEF(name, var)
#define	AES_XTS_TESTING_ENGINE(var)                     \
	AES_XTS_TESTING_ENGINE_STRUCT(AES_XTS_TESTING_ENGINE_NAME, var)

#define	AES_XTS_TESTING_ENGINE_ARRAY(var, count)		AES_XTS_TESTING_ENGINE (var)[count]

#define	AES_XTS_TESTING_ENGINE_PARAM(var)				AES_XTS_TESTING_ENGINE (var)

#define	AES_XTS_TESTING_ENGINE_ARG(var)					var

#define	AES_XTS_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index]

#else

/* The selected aes_xts engine requires a variable state instance. */
#define	AES_XTS_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)  \
	struct aes_xts_engine_ ## name ## _state var
#define	AES_XTS_TESTING_ENGINE_STATE_STRUCT(name, var)      \
	AES_XTS_TESTING_ENGINE_STATE_STRUCT_DEF(name, var)
#define	AES_XTS_TESTING_ENGINE_STATE(var)                   \
	AES_XTS_TESTING_ENGINE_STATE_STRUCT(AES_XTS_TESTING_ENGINE_NAME, var)

#define	AES_XTS_TESTING_ENGINE_INST_STRUCT_DEF(name, var)	struct aes_xts_engine_ ## name var
#define	AES_XTS_TESTING_ENGINE_INST_STRUCT(name, var)       \
	AES_XTS_TESTING_ENGINE_INST_STRUCT_DEF(name, var)
#define	AES_XTS_TESTING_ENGINE_INST(var)                    \
	AES_XTS_TESTING_ENGINE_INST_STRUCT(AES_XTS_TESTING_ENGINE_NAME, var)

#define	AES_XTS_TESTING_ENGINE(var)                     \
	AES_XTS_TESTING_ENGINE_STATE (var ## _state); AES_XTS_TESTING_ENGINE_INST (var)

#define	AES_XTS_TESTING_ENGINE_ARRAY(var, count)        \
	AES_XTS_TESTING_ENGINE_STATE (var ## _state)[count]; AES_XTS_TESTING_ENGINE_INST (var)[count]

#define	AES_XTS_TESTING_ENGINE_PARAM(var)               \
	AES_XTS_TESTING_ENGINE_INST (var), AES_XTS_TESTING_ENGINE_STATE (var ## _state)

#define	AES_XTS_TESTING_ENGINE_ARG(var)					var, var ## _state

#define	AES_XTS_TESTING_ENGINE_ARRAY_ARG(var, index)	var[index], var ## _state[index]

#endif

#define	AES_XTS_TESTING_ENGINE_INIT_FUNC_DEF(name, var)    \
	aes_xts_ ## name ## _init (AES_XTS_TESTING_ENGINE_ARG (var))
#define	AES_XTS_TESTING_ENGINE_INIT_FUNC(name, var)        \
	AES_XTS_TESTING_ENGINE_INIT_FUNC_DEF(name, var)
#define	AES_XTS_TESTING_ENGINE_INIT(var)                   \
	AES_XTS_TESTING_ENGINE_INIT_FUNC(AES_XTS_TESTING_ENGINE_NAME, var)

#define	AES_XTS_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)   \
	aes_xts_ ## name ## _init (AES_XTS_TESTING_ENGINE_ARRAY_ARG (var, index))
#define	AES_XTS_TESTING_ENGINE_INIT_ARRAY_FUNC(name, var, index)       \
	AES_XTS_TESTING_ENGINE_INIT_ARRAY_FUNC_DEF(name, var, index)
#define	AES_XTS_TESTING_ENGINE_INIT_ARRAY(var, index)                  \
	AES_XTS_TESTING_ENGINE_INIT_ARRAY_FUNC(AES_XTS_TESTING_ENGINE_NAME, var, index)

#define	AES_XTS_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)	aes_xts_ ## name ## _release (var)
#define	AES_XTS_TESTING_ENGINE_RELEASE_FUNC(name, var)      \
	AES_XTS_TESTING_ENGINE_RELEASE_FUNC_DEF(name, var)
#define	AES_XTS_TESTING_ENGINE_RELEASE(var)                 \
	AES_XTS_TESTING_ENGINE_RELEASE_FUNC(AES_XTS_TESTING_ENGINE_NAME, var)


#endif	/* AES_TESTING_ENGINE_H_ */
