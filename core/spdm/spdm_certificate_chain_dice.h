// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_CERTIFICATE_CHAIN_DICE_H_
#define SPDM_CERTIFICATE_CHAIN_DICE_H_

#include "spdm_certificate_chain.h"
#include "riot/riot_key_manager.h"


/**
 * Manage the device DICE certificate chain via SPDM.
 */
struct spdm_certificate_chain_dice {
	struct spdm_certificate_chain base;		/**< Base certificate chain API. */
	const struct riot_key_manager *certs;	/**< Manager for the DICE certificates. */
};


int spdm_certificate_chain_dice_init (struct spdm_certificate_chain_dice *chain,
	const struct riot_key_manager *dice_certs);
void spdm_certificate_chain_dice_release (const struct spdm_certificate_chain_dice *chain);


#endif	/* SPDM_CERTIFICATE_CHAIN_DICE_H_ */
