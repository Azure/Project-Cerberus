// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_DATA_WITH_AAD_H_
#define AUTHORIZED_DATA_WITH_AAD_H_

#include "authorized_data.h"
#include "authorizing_signature.h"


/**
 * Authorized data parser for payloads that can contain either a token, authenticated data, or both.
 *
 * A single instance can be used to parse any number of authorized payloads.
 */
struct authorized_data_with_aad {
	struct authorized_data base_data;		/**< Base API for authorized data handling. */
	struct authorizing_signature base_sig;	/**< Base API for authorizing signature handling. */
};


int authorized_data_with_aad_init (struct authorized_data_with_aad *auth);
void authorized_data_with_aad_release (const struct authorized_data_with_aad *auth);


#endif	/* AUTHORIZED_DATA_WITH_AAD_H_ */
