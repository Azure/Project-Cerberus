// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_DATA_TOKEN_ONLY_H_
#define AUTHORIZED_DATA_TOKEN_ONLY_H_

#include "authorized_data.h"


/**
 * Authorized data parser for payloads that only contain a signed authorization token.
 *
 * A single instance can be used to parse any number of authorized payloads.
 */
struct authorized_data_token_only {
	struct authorized_data base;	/**< Base API for authorized data handling. */
};


int authorized_data_token_only_init (struct authorized_data_token_only *auth);
void authorized_data_token_only_release (const struct authorized_data_token_only *auth);


#endif	/* AUTHORIZED_DATA_TOKEN_ONLY_H_ */
