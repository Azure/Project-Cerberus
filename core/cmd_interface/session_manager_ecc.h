// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SESSION_MANAGER_ECC_H_
#define SESSION_MANAGER_ECC_H_


#include <stdint.h>
#include "crypto/ecc.h"
#include "session_manager.h"


/**
 * Entry in table holding session information and cached keys.  
 */
struct session_manager_ecc_entry {
	struct session_manager_entry entry;					/**< Common session manager entry */
	uint8_t pub_key[ECC_MAX_PUBKEY_DER_LEN]; 			/**< Device ECC public key used during session establishment */
	uint32_t pub_key_len;								/**< Length of device public key used during session establishment */
};

/**
 * Module which holds engines needed for session manager operation and caches session keys
 */
struct session_manager_ecc {
	struct session_manager base;						/**< Base session manager. */
	struct ecc_engine *ecc;								/**< ECC engine used to generate AES shared key. */
};


int session_manager_ecc_init (struct session_manager_ecc *session, struct aes_engine *aes, 
	struct ecc_engine *ecc, struct hash_engine *hash, struct rng_engine *rng, 
	struct riot_key_manager *riot, size_t num_sessions);
int session_manager_ecc_init_table_preallocated (struct session_manager_ecc *session, 
	struct aes_engine *aes, struct ecc_engine *ecc, struct hash_engine *hash, 
	struct rng_engine *rng, struct riot_key_manager *riot, 
	struct session_manager_ecc_entry *sessions_table, size_t num_sessions);
void session_manager_ecc_release (struct session_manager_ecc *session);


#endif // SESSION_MANAGER_ECC_H_
