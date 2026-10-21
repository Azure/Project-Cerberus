// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_CERT_CHAIN_VERIFIER_STATIC_H_
#define SPDM_CERT_CHAIN_VERIFIER_STATIC_H_

#include "spdm/spdm_cert_chain_verifier.h"


/* Internal functions declared to allow for static initialization. */
int spdm_cert_chain_verifier_start (const struct cert_chain_verifier *base);
int spdm_cert_chain_verifier_process (const struct cert_chain_verifier *base, const uint8_t *cert,
	size_t length);
int spdm_cert_chain_verifier_finalize (const struct cert_chain_verifier *base,
	struct cert_chain_verifier_result *result);


/**
 * Constant initializer for the certificate chain verifier API.
 */
#define	SPDM_CERT_CHAIN_VERIFIER_API_INIT  { \
		.start_verification = spdm_cert_chain_verifier_start, \
		.process_cert = spdm_cert_chain_verifier_process, \
		.finalize_verification = spdm_cert_chain_verifier_finalize, \
	}


/**
 * Initialize a static instance of an x509-backed streaming SPDM certificate chain verifier.
 *
 * There is no validation done on the arguments.
 *
 * The variable per-chain context lives in the caller-provided state structure; call
 * spdm_cert_chain_verifier_init_state before first use to initialize it.
 *
 * @param state_ptr Variable (per-chain) context for the verifier.  Must be RAM-resident.
 * @param x509_ptr X.509 engine used for chain validation and leaf key extraction.
 */
#define	spdm_cert_chain_verifier_static_init(state_ptr, x509_ptr)	{ \
		.base = SPDM_CERT_CHAIN_VERIFIER_API_INIT, \
		.x509 = x509_ptr, \
		.state = state_ptr, \
	}


#endif	/* SPDM_CERT_CHAIN_VERIFIER_STATIC_H_ */
