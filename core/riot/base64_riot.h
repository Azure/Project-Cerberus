// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BASE64_RIOT_H_
#define BASE64_RIOT_H_

#include "crypto/base64.h"


/**
 * RIoT implementation for base64 encoding.
 */
struct base64_engine_riot {
	struct base64_engine base;		/**< The base base64 engine. */
};


int base64_riot_init (struct base64_engine_riot *engine);
void base64_riot_release (struct base64_engine_riot *engine);


#endif /* BASE64_RIOT_H_ */
