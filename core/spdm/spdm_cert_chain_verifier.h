// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_CERT_CHAIN_VERIFIER_H_
#define SPDM_CERT_CHAIN_VERIFIER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "asn1/x509.h"
#include "spdm/cert_chain_verifier_interface.h"


/**
 * Variable (per-chain) context for an x509-backed streaming certificate chain verifier.  This must
 * be placed in RAM; the containing struct spdm_cert_chain_verifier can be const/ROM-resident.  The
 * state tracks only the active verification; a successful finalize transfers the root and leaf key
 * buffers to the caller's result and returns the state to idle.
 */
struct spdm_cert_chain_verifier_state {
	uint8_t *pending_cert;		/**< Owned DER of the last accepted certificate: promoted to a trusted CA
											 * if a successor arrives, otherwise parsed as the leaf at finalize. */
	size_t pending_cert_len;	/**< Length of pending_cert in bytes. */
	uint8_t *root_cert;			/**< Owned root DER; ownership transfers to the result at successful finalize. */
	size_t root_len;			/**< Length of the copied root certificate. */
	uint32_t cert_count;		/**< Number of certificates processed so far. */
	bool started;				/**< True between start_verification and finalize_verification. */
};

/**
 * An x509-backed streaming implementation of the certificate chain verifier.  All fields are
 * immutable after initialization, so a single instance may be declared const and placed in ROM;
 * the mutable per-chain context lives in the separate, RAM-resident state structure.  Root DER is
 * dynamically allocated and limited to UINT16_MAX bytes by the SPDM chain length field.
 */
struct spdm_cert_chain_verifier {
	struct cert_chain_verifier base;				/**< Base certificate chain verifier interface. */
	const struct x509_engine *x509;					/**< X.509 engine for chain validation and key extraction. */
	struct spdm_cert_chain_verifier_state *state;	/**< Variable context for the verifier. */
};


int spdm_cert_chain_verifier_init (struct spdm_cert_chain_verifier *verifier,
	struct spdm_cert_chain_verifier_state *state, const struct x509_engine *x509);

int spdm_cert_chain_verifier_init_state (const struct spdm_cert_chain_verifier *verifier);

void spdm_cert_chain_verifier_release (const struct spdm_cert_chain_verifier *verifier);


#endif	/* SPDM_CERT_CHAIN_VERIFIER_H_ */
