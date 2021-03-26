// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_LOGGING_H_
#define MANIFEST_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for manifests.
 */
enum {
	MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL,		/**< Failed to record manifest measurement in PCR store. */
	MANIFEST_LOGGING_GET_MEASUREMENT_FAIL,			/**< Failed to get a manifest measurement. */
	MANIFEST_LOGGING_PFM_VERIFIED_EVENT_FAIL,		/**< Failed PFM verification notification. */
	MANIFEST_LOGGING_PFM_ACTIVATED_EVENT_FAIL,		/**< Failed PFM activation notification. */
	MANIFEST_LOGGING_CFM_VERIFIED_EVENT_FAIL,		/**< Failed CFM verification notification. */
	MANIFEST_LOGGING_CFM_ACTIVATED_EVENT_FAIL,		/**< Failed CFM activation notification. */
	MANIFEST_LOGGING_PENDING_RESET_FAIL,			/**< Failed to set reset for a pending PFM. */
	MANIFEST_LOGGING_PFM_RECORD_INVALID,			/**< Invalid call to force PFM measurements. */
	MANIFEST_LOGGING_CFM_RECORD_INVALID,			/**< Invalid call to force CFM measurements. */
	MANIFEST_LOGGING_KEY_REVOCATION_FAIL,			/**< Failure while running manifest key revocation. */
	MANIFEST_LOGGING_ERASE_FAIL,					/**< Failed to erase pending manifest region. */
	MANIFEST_LOGGING_WRITE_FAIL,					/**< Failed to write manifest data. */
	MANIFEST_LOGGING_VERIFY_FAIL,					/**< Failed to verify new manifest. */
	MANIFEST_LOGGING_NOTIFICATION_ERROR,			/**< Unknown task action specified. */
	MANIFEST_LOGGING_ACTIVATION_FLASH_ERROR,		/**< Critical failure during activation. */
	MANIFEST_LOGGING_ACTIVATION_FAIL,				/**< Failed to activate manifest. */
	MANIFEST_LOGGING_PCD_VERIFIED_EVENT_FAIL,		/**< Failed PCD verification notification. */
	MANIFEST_LOGGING_PCD_ACTIVATED_EVENT_FAIL,		/**< Failed PCD activation notification. */
	MANIFEST_LOGGING_PCD_RECORD_INVALID,			/**< Invalid call to force PCD measurements. */
	MANIFEST_LOGGING_EMPTY_PFM,						/**< An empty PFM caused manifests to be cleared. */
	MANIFEST_LOGGING_GET_ID_FAIL,					/**< Failed to get manifest ID for measurement. */
	MANIFEST_LOGGING_GET_PLATFORM_ID_FAIL,			/**< Failed to get manifest platform ID for measurement. */
	MANIFEST_LOGGING_EMPTY_PCD,						/**< An empty PCD caused manifests to be cleared. */
	MANIFEST_LOGGING_EMPTY_CFM,						/**< An empty CFM caused manifests to be cleared. */
	MANIFEST_LOGGING_PFM_CLEAR_ACTIVE_EVENT_FAIL,	/**< Failed clear active PFM notification. */
	MANIFEST_LOGGING_CFM_CLEAR_ACTIVE_EVENT_FAIL,	/**< Failed clear active CFM notification. */
	MANIFEST_LOGGING_PCD_CLEAR_ACTIVE_EVENT_FAIL,	/**< Failed clear active PCD notification. */
	MANIFEST_LOGGING_PCD_UPDATE,					/**< Received a PCD update. */
};


#endif /* MANIFEST_LOGGING_H_ */
