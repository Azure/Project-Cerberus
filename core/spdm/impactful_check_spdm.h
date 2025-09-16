// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_CHECK_SPDM_H_
#define IMPACTFUL_CHECK_SPDM_H_

#include "spdm_secure_session_manager.h"
#include "firmware/impactful_check.h"


/**
 * Interface to check SPDM policy to determine whether a firmware update is impactful.
 */
struct impactful_check_spdm {
	struct impactful_check base;					/**< Base notification interface. */
	const struct spdm_secure_session_manager *spdm;	/**< SPDM secure session manager interface. */
};


int impactful_check_spdm_init (struct impactful_check_spdm *impactful,
	const struct spdm_secure_session_manager *spdm);
void impactful_check_spdm_release (
	const struct impactful_check_spdm *impactful);


#endif	/* IMPACTFUL_CHECK_SPDM_H_ */
