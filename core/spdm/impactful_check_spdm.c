// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "impactful_check_spdm.h"
#include "common/type_cast.h"
#include "common/unused.h"


int impactful_check_spdm_is_not_impactful (const struct impactful_check *impactful)
{
	const struct impactful_check_spdm *spdm_impactful = TO_DERIVED_TYPE (impactful,
		const struct impactful_check_spdm, base);

	if (impactful == NULL) {
		return IMPACTFUL_CHECK_INVALID_ARGUMENT;
	}

	return spdm_impactful->spdm->is_termination_policy_set (spdm_impactful->spdm);
}

int impactful_check_spdm_is_authorization_allowed (const struct impactful_check *impactful)
{
	/* Never block impactful updates. */
	UNUSED (impactful);

	return 0;
}

/**
 * Initialize an impactful check used to determine whether a firmware update is impactful based on
 * SPDM policy.
 *
 * @param impactful The impactful check to initialize.
 * @param spdm The SPDM secure session manager interface that should be used to determine if an
 * update is impactful.
 *
 * @return 0 if the impactful check was initialized successfully or an error code.
 */
int impactful_check_spdm_init (struct impactful_check_spdm *impactful,
	const struct spdm_secure_session_manager *spdm)
{
	if ((impactful == NULL) || (spdm == NULL)) {
		return IMPACTFUL_CHECK_INVALID_ARGUMENT;
	}

	memset (impactful, 0, sizeof (*impactful));

	impactful->base.is_not_impactful = impactful_check_spdm_is_not_impactful;
	impactful->base.is_authorization_allowed = impactful_check_spdm_is_authorization_allowed;

	impactful->spdm = spdm;

	return 0;
}

/**
 * Release the resources used for an SPDM impactful check.
 *
 * @param impactful The impactful check to release.
 */
void impactful_check_spdm_release (
	const struct impactful_check_spdm *impactful)
{
	UNUSED (impactful);
}
