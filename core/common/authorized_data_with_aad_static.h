// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_DATA_WITH_AAD_STATIC_H_
#define AUTHORIZED_DATA_WITH_AAD_STATIC_H_

#include "authorized_data_with_aad.h"


/* Internal functions declared to allow for static initialization. */
int authorized_data_with_aad_get_token_offset (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *token_offset);
int authorized_data_with_aad_get_authenticated_data (const struct authorized_data *auth,
	const uint8_t *data, size_t length, const uint8_t **aad, size_t *aad_length);
int authorized_data_with_aad_get_authenticated_data_length (const struct authorized_data *auth,
	const uint8_t *data, size_t length, size_t *aad_length);

int authorized_data_with_aad_get_signature (const struct authorizing_signature *auth,
	const uint8_t *data, size_t length, const uint8_t **signature, size_t *sig_length);
int authorized_data_with_aad_get_signature_length (const struct authorizing_signature *auth,
	const uint8_t *data, size_t length, size_t *sig_length);


/**
 * Constant initializer for the authorized data API.
 */
#define	AUTHORIZED_DATA_WITH_AAD_DATA_API_INIT  { \
		.get_token_offset = authorized_data_with_aad_get_token_offset, \
		.get_authenticated_data = authorized_data_with_aad_get_authenticated_data, \
		.get_authenticated_data_length = authorized_data_with_aad_get_authenticated_data_length, \
	}

/**
 * Constant initializer for the authorizing signature API.
 */
#define	AUTHORIZED_DATA_WITH_AAD_SIG_API_INIT  { \
		.get_signature = authorized_data_with_aad_get_signature, \
		.get_signature_length = authorized_data_with_aad_get_signature_length, \
	}


/**
 * Initialize a static authorized data parser for payloads that can contain either an authorization
 * token, authenticated data, or both.
 */
#define	authorized_data_with_aad_static_init() { \
		.base_data = AUTHORIZED_DATA_WITH_AAD_DATA_API_INIT, \
		.base_sig = AUTHORIZED_DATA_WITH_AAD_SIG_API_INIT, \
	}


#endif	/* AUTHORIZED_DATA_WITH_AAD_STATIC_H_ */
