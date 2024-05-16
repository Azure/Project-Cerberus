// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_CORE_H_
#define BASE64_CORE_H_

#include "asn1/base64.h"


/**
 * Generic implementation for base64 encoding.  This implementation does not rely on any external
 * dependencies.
 */
struct base64_engine_core {
	struct base64_engine base;	/**< The base base64 engine. */
};


int base64_core_init (struct base64_engine_core *engine);
void base64_core_release (struct base64_engine_core *engine);


#endif	/* BASE64_CORE_H_ */
