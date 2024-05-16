// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_NULL_H_
#define KEYSTORE_NULL_H_

#include "keystore.h"


/**
 * Defines a null keystore that will never contain any keys.  Save operations will succeed but not
 * store any data.  Load operations will always report that there is no key present for any key ID.
 */
struct keystore_null {
	struct keystore base;	/**< Base keystore API. */
};


int keystore_null_init (struct keystore_null *store);
void keystore_null_release (const struct keystore_null *store);


#endif	/* KEYSTORE_NULL_H_ */
