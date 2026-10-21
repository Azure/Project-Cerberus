// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "spdm_cert_chain_verifier.h"
#include "common/type_cast.h"
#include "status/rot_status.h"


/**
 * Release all per-chain resources and return the verifier to an idle state.  Buffers whose
 * ownership has already been transferred to a result must be detached (set to NULL) by the caller
 * beforehand so they are not freed here.
 *
 * @param verifier The certificate chain verifier to reset.
 */
static void spdm_cert_chain_verifier_reset (const struct spdm_cert_chain_verifier *verifier)
{
	struct spdm_cert_chain_verifier_state *state = verifier->state;

	platform_free (state->pending_cert);
	platform_free (state->root_cert);
	memset (state, 0, sizeof (*state));
}

/**
 * Initialize a trust store anchored at the most recently accepted certificate: the pending CA if
 * one exists, otherwise the root.  The caller releases the store on success.
 *
 * @param verifier The certificate chain verifier.
 * @param store The store to initialize.  It is left uninitialized on failure.
 *
 * @return 0 if the store was initialized successfully or an error code.
 */
static int spdm_cert_chain_verifier_init_anchor_store (
	const struct spdm_cert_chain_verifier *verifier, struct x509_ca_certs *store)
{
	const struct spdm_cert_chain_verifier_state *state = verifier->state;
	int status;

	status = verifier->x509->init_ca_cert_store (verifier->x509, store);
	if (status != 0) {
		return status;
	}

	if (state->pending_cert != NULL) {
		/* A successor has already proven this certificate is not the leaf. */
		status = verifier->x509->add_trusted_ca (verifier->x509, store, state->pending_cert,
			state->pending_cert_len);
	}
	else if (state->root_cert != NULL) {
		status = verifier->x509->add_root_ca (verifier->x509, store, state->root_cert,
			state->root_len);
	}
	else {
		status = CERT_CHAIN_VERIFIER_NO_TRUST_ANCHOR;
	}

	if (status != 0) {
		verifier->x509->release_ca_cert_store (verifier->x509, store);
	}

	return status;
}

int spdm_cert_chain_verifier_start (const struct cert_chain_verifier *base)
{
	const struct spdm_cert_chain_verifier *verifier =
		TO_DERIVED_TYPE (base, const struct spdm_cert_chain_verifier, base);

	if (base == NULL) {
		return CERT_CHAIN_VERIFIER_INVALID_ARGUMENT;
	}

	spdm_cert_chain_verifier_reset (verifier);
	verifier->state->started = true;

	return 0;
}

int spdm_cert_chain_verifier_process (const struct cert_chain_verifier *base, const uint8_t *cert,
	size_t length)
{
	const struct spdm_cert_chain_verifier *verifier =
		TO_DERIVED_TYPE (base, const struct spdm_cert_chain_verifier, base);
	struct spdm_cert_chain_verifier_state *state;
	struct x509_ca_certs store;
	struct x509_certificate new_cert;
	int status;

	if ((base == NULL) || (cert == NULL) || (length == 0)) {
		return CERT_CHAIN_VERIFIER_INVALID_ARGUMENT;
	}
	state = verifier->state;
	if (!state->started) {
		return CERT_CHAIN_VERIFIER_NOT_STARTED;
	}

	if (state->cert_count == 0) {
		/* Root: copy into RoT-private memory and confirm it is a valid self-signed CA. */
		if (length > UINT16_MAX) {
			return CERT_CHAIN_VERIFIER_ROOT_TOO_LARGE;
		}
		state->root_cert = platform_malloc (length);
		if (state->root_cert == NULL) {
			status = CERT_CHAIN_VERIFIER_NO_MEMORY;
			goto reset;
		}
		memcpy (state->root_cert, cert, length);
		state->root_len = length;

		status = spdm_cert_chain_verifier_init_anchor_store (verifier, &store);
		if (status != 0) {
			goto reset;
		}
		verifier->x509->release_ca_cert_store (verifier->x509, &store);

		state->cert_count = 1;

		return 0;
	}

	/* Parse the incoming certificate before building the anchor store; this needs no store, so a
	 * malformed certificate fails fast. */
	status = verifier->x509->load_certificate (verifier->x509, &new_cert, cert, length);
	if (status != 0) {
		status = CERT_CHAIN_VERIFIER_CHAIN_INVALID;
		goto reset;
	}

	status = spdm_cert_chain_verifier_init_anchor_store (verifier, &store);
	if (status != 0) {
		verifier->x509->release_certificate (verifier->x509, &new_cert);
		goto reset;
	}

	/* The store keeps its own copy of the anchor, so the pending DER can be released now. */
	platform_free (state->pending_cert);
	state->pending_cert = NULL;
	state->pending_cert_len = 0;

	status = verifier->x509->authenticate (verifier->x509, &new_cert, &store);
	verifier->x509->release_certificate (verifier->x509, &new_cert);
	verifier->x509->release_ca_cert_store (verifier->x509, &store);
	if (status != 0) {
		status = CERT_CHAIN_VERIFIER_CHAIN_INVALID;
		goto reset;
	}

	state->pending_cert = platform_malloc (length);
	if (state->pending_cert == NULL) {
		status = CERT_CHAIN_VERIFIER_NO_MEMORY;
		goto reset;
	}
	memcpy (state->pending_cert, cert, length);
	state->pending_cert_len = length;

	state->cert_count++;

	return 0;

reset:
	spdm_cert_chain_verifier_reset (verifier);

	return status;
}

int spdm_cert_chain_verifier_finalize (const struct cert_chain_verifier *base,
	struct cert_chain_verifier_result *result)
{
	const struct spdm_cert_chain_verifier *verifier =
		TO_DERIVED_TYPE (base, const struct spdm_cert_chain_verifier, base);
	struct spdm_cert_chain_verifier_state *state;
	struct x509_certificate leaf_cert;
	uint8_t *leaf_key = NULL;
	size_t leaf_key_len = 0;
	int key_type;
	int status;

	if ((base == NULL) || (result == NULL)) {
		return CERT_CHAIN_VERIFIER_INVALID_ARGUMENT;
	}
	state = verifier->state;
	if (!state->started) {
		return CERT_CHAIN_VERIFIER_NOT_STARTED;
	}

	/* pending_cert holds the last non-root certificate; without one there is no leaf to key, so a
	 * chain of only a root CA (or an empty chain) is incomplete. */
	if (state->pending_cert == NULL) {
		spdm_cert_chain_verifier_reset (verifier);

		return CERT_CHAIN_VERIFIER_INCOMPLETE_CHAIN;
	}

	status = verifier->x509->load_certificate (verifier->x509, &leaf_cert, state->pending_cert,
		state->pending_cert_len);
	if (status != 0) {
		spdm_cert_chain_verifier_reset (verifier);

		return CERT_CHAIN_VERIFIER_NO_KEY;
	}

	key_type = verifier->x509->get_public_key_type (verifier->x509, &leaf_cert);
	if (ROT_IS_ERROR (key_type)) {
		status = CERT_CHAIN_VERIFIER_NO_KEY;
	}
	else if (verifier->x509->get_public_key (verifier->x509, &leaf_cert, &leaf_key,
		&leaf_key_len) != 0) {
		status = CERT_CHAIN_VERIFIER_NO_KEY;
	}
	verifier->x509->release_certificate (verifier->x509, &leaf_cert);

	if (status != 0) {
		spdm_cert_chain_verifier_reset (verifier);

		return status;
	}

	result->key_type = key_type;
	result->alias_key = leaf_key;
	result->alias_key_length = leaf_key_len;
	result->root_cert.cert = state->root_cert;
	result->root_cert.length = state->root_len;

	/* Ownership of the root and key buffers now belongs to result; detach them so reset does not
	 * free them. */
	state->root_cert = NULL;
	state->root_len = 0;

	spdm_cert_chain_verifier_reset (verifier);

	return 0;
}

/**
 * Initialize an x509-backed streaming SPDM certificate chain verifier.
 *
 * @param verifier The verifier instance to initialize.
 * @param state The variable (per-chain) context for the verifier.  Must be RAM-resident.
 * @param x509 X.509 engine used for chain validation and leaf key extraction.
 *
 * @return 0 if the verifier was initialized successfully or an error code.
 */
int spdm_cert_chain_verifier_init (struct spdm_cert_chain_verifier *verifier,
	struct spdm_cert_chain_verifier_state *state, const struct x509_engine *x509)
{
	if ((verifier == NULL) || (state == NULL) || (x509 == NULL)) {
		return CERT_CHAIN_VERIFIER_INVALID_ARGUMENT;
	}

	memset (verifier, 0, sizeof (struct spdm_cert_chain_verifier));

	verifier->base.start_verification = spdm_cert_chain_verifier_start;
	verifier->base.process_cert = spdm_cert_chain_verifier_process;
	verifier->base.finalize_verification = spdm_cert_chain_verifier_finalize;
	verifier->x509 = x509;
	verifier->state = state;

	return spdm_cert_chain_verifier_init_state (verifier);
}

/**
 * Initialize only the variable (per-chain) state of an SPDM certificate chain verifier.  The rest
 * of the instance is expected to have been initialized, e.g. via static initialization.
 *
 * @param verifier The verifier instance whose state should be initialized.
 *
 * @return 0 if the state was initialized successfully or an error code.
 */
int spdm_cert_chain_verifier_init_state (const struct spdm_cert_chain_verifier *verifier)
{
	if ((verifier == NULL) || (verifier->state == NULL) || (verifier->x509 == NULL)) {
		return CERT_CHAIN_VERIFIER_INVALID_ARGUMENT;
	}

	memset (verifier->state, 0, sizeof (struct spdm_cert_chain_verifier_state));

	return 0;
}

/**
 * Release resources held by an initialized certificate chain verifier, including an unfinished
 * chain and the root DER retained after successful finalize.  Caller-owned state and engine
 * instances are not freed.  Repeated release calls are safe.
 *
 * @param verifier The verifier to release.  This can be null.
 */
void spdm_cert_chain_verifier_release (const struct spdm_cert_chain_verifier *verifier)
{
	if (verifier != NULL) {
		spdm_cert_chain_verifier_reset (verifier);
	}
}
