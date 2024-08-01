// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_CHECK_H_
#define IMPACTFUL_CHECK_H_

#include "status/rot_status.h"


/**
 * Interface to check a condition managed by the device to determine if a firmware update in this
 * context would be impactful (i.e. requires more than a device self-reset or would have some other
 * adverse impact to the system).
 */
struct impactful_check {
	/**
	 * Check the device context to determine if an update would be impactful or not.  If the update
	 * would be impactful, it should not be allowed without additional authorization.
	 *
	 * @param impactful The device context to query.
	 *
	 * @return 0 if the update would not be impactful or an error code.
	 */
	int (*is_not_impactful) (const struct impactful_check *impactful);

	/**
	 * Determine if an impactful update can be authorized for this context.  If an impactful update
	 * cannot be authorized, it should always be blocked from being applied.
	 *
	 * @param impactful The device context to query.
	 *
	 * @return 0 if the impactful update can be authorized for use or an error code.
	 */
	int (*is_authorization_allowed) (const struct impactful_check *impactful);
};


#define	IMPACTFUL_CHECK_ERROR(code)		ROT_ERROR (ROT_MODULE_IMPACTFUL_CHECK, code)

/**
 * Error codes that can be generated during an impactful update check.
 */
enum {
	IMPACTFUL_CHECK_INVALID_ARGUMENT = IMPACTFUL_CHECK_ERROR (0x00),		/**< Input parameter is null or not valid. */
	IMPACTFUL_CHECK_NO_MEMORY = IMPACTFUL_CHECK_ERROR (0x01),				/**< Memory allocation failed. */
	IMPACTFUL_CHECK_NOT_IMPACTFUL_FAILED = IMPACTFUL_CHECK_ERROR (0x02),	/**< Failed to determine if an update is impactful. */
	IMPACTFUL_CHECK_AUTH_ALLOWED_FAILED = IMPACTFUL_CHECK_ERROR (0x03),		/**< Failed to determine if an impactful update can be authorized. */
	IMPACTFUL_CHECK_IMPACTFUL_UPDATE = IMPACTFUL_CHECK_ERROR (0x04),		/**< An update in the current context would be impactful. */
	IMPACTFUL_CHECK_AUTH_NOT_ALLOWED = IMPACTFUL_CHECK_ERROR (0x05),		/**< Authorization is not allowed for an impactful update. */
};


#endif	/* IMPACTFUL_CHECK_H_ */
