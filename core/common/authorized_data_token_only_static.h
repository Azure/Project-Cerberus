// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_DATA_TOKEN_ONLY_STATIC_H_
#define AUTHORIZED_DATA_TOKEN_ONLY_STATIC_H_

#include "authorized_data_token_only.h"


/* Internal functions declared to allow for static initialization. */
int authorized_data_token_only_get_token_offset (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *token_offset);
int authorized_data_token_only_get_authenticated_data (const struct authorized_data *auth,
	const uint8_t *data, size_t length, const uint8_t **aad, size_t *aad_length);
int authorized_data_token_only_get_authenticated_data_length (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *aad_length);


/**
 * Constant initializer for the authorized data API.
 */
#define	AUTHORIZED_DATA_TOKEN_ONLY_API_INIT  { \
		.get_token_offset = authorized_data_token_only_get_token_offset, \
		.get_authenticated_data = authorized_data_token_only_get_authenticated_data, \
		.get_authenticated_data_length = authorized_data_token_only_get_authenticated_data_length, \
	}


/**
 * Initialize a static authorized data parser for payloads that only contain a signed authorization
 * token.
 */
#define	authorized_data_token_only_static_init() { \
		.base = AUTHORIZED_DATA_TOKEN_ONLY_API_INIT, \
	}


#endif	/* AUTHORIZED_DATA_TOKEN_ONLY_STATIC_H_ */
