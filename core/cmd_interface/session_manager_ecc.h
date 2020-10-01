// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SESSION_MANAGER_ECC_H_
#define SESSION_MANAGER_ECC_H_


#include <stdint.h>
#include "crypto/ecc.h"
#include "keystore/keystore.h"
#include "session_manager.h"


/**
 * Module which holds engines needed for session manager operation and caches session keys
 */
struct session_manager_ecc {
	struct session_manager base;						/**< Base session manager. */
	struct ecc_engine *ecc;								/**< ECC engine used to generate AES shared key. */
};


int session_manager_ecc_init (struct session_manager_ecc *session, struct aes_engine *aes, 
	struct ecc_engine *ecc, struct hash_engine *hash, struct rng_engine *rng, 
	struct riot_key_manager *riot, struct session_manager_entry *sessions_table, 
	size_t num_sessions, const uint8_t *pairing_eids, size_t num_pairing_eids, 
	struct keystore *store);
void session_manager_ecc_release (struct session_manager_ecc *session);


#endif // SESSION_MANAGER_ECC_H_
