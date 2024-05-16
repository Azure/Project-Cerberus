// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CONFIG_RESET_H_
#define CONFIG_RESET_H_

#include <stddef.h>
#include <stdint.h>
#include "attestation/aux_attestation.h"
#include "intrusion/intrusion_manager.h"
#include "keystore/keystore.h"
#include "manifest/manifest_manager.h"
#include "recovery/recovery_image_manager.h"
#include "riot/riot_key_manager.h"
#include "state_manager/state_manager.h"
#include "status/rot_status.h"


/**
 * Status codes for configuration reset operations.
 */
enum config_reset_status {
	CONFIG_RESET_STATUS_SUCCESS = 0,				/**< Successful operation. */
	CONFIG_RESET_STATUS_STARTING,					/**< A configuration reset operation has started. */
	CONFIG_RESET_STATUS_REQUEST_BLOCKED,			/**< A request has been made before the previous one finished. */
	CONFIG_RESET_STATUS_RESTORE_BYPASS,				/**< Configuration is being reset to restore bypass mode. */
	CONFIG_RESET_STATUS_BYPASS_FAILED,				/**< Failed to restore bypass mode. */
	CONFIG_RESET_STATUS_RESTORE_DEFAULTS,			/**< All configuration and state are being erased. */
	CONFIG_RESET_STATUS_DEFAULTS_FAILED,			/**< Failed to restore default configuration. */
	CONFIG_RESET_STATUS_NONE_STARTED,				/**< No configuration reset operation has been started. */
	CONFIG_RESET_STATUS_TASK_NOT_RUNNING,			/**< The task servicing reset operations is not running. */
	CONFIG_RESET_STATUS_INTERNAL_ERROR,				/**< An unspecified, internal error occurred. */
	CONFIG_RESET_STATUS_UNKNOWN,					/**< The configuration reset status could not be determined. */
	CONFIG_RESET_STATUS_CLEAR_PLATFORM_CONFIG,		/**< Platform configuration is being cleared. */
	CONFIG_RESET_STATUS_PLATFORM_CONFIG_FAILED,		/**< Failed to clear platform configuration. */
	CONFIG_RESET_STATUS_RESET_INTRUSION,			/**< Intrusion state is being reset. */
	CONFIG_RESET_STATUS_INTRUSION_FAILED,			/**< Failed to reset intrusion state. */
	CONFIG_RESET_STATUS_CLEAR_COMPONENT_MANIFESTS,	/**< Component manifests are being cleared. */
	CONFIG_RESET_STATUS_COMPONENT_MANIFESTS_FAILED,	/**< Failed to clear component manifests. */
};

/**
 * Handler to reset configuration back to the initial state.
 */
struct config_reset {
	const struct manifest_manager **bypass;					/**< List of configuration files to clear for bypass mode. */
	size_t bypass_count;									/**< Number of bypass configuration managers. */
	const struct manifest_manager **config;					/**< List of configuration files to clear for defaults. */
	size_t config_count;									/**< Number of default configuration managers. */
	const struct manifest_manager **component_manifests;	/**< List of component manifests to disable attesting external component. */
	size_t component_manifests_count;						/**< Number of component manifest managers. */
	struct state_manager **state;							/**< List of state information to reset. */
	size_t state_count;										/**< Number of state managers. */
	struct riot_key_manager *riot;							/**< Manager for RIoT keys. */
	struct aux_attestation *aux;							/**< Manager for attestation keys. */
	struct recovery_image_manager *recovery;				/**< Manager for host recovery images. */
	const struct keystore **keystores;						/**< Array of keystores to clear keys of. */
	size_t keystore_count;									/**< Number of keystores in the keystores array. */
	struct intrusion_manager *intrusion;					/**< Intrusion manager to reset intrusion. */
};


int config_reset_init (struct config_reset *reset, const struct manifest_manager **bypass_config,
	size_t bypass_count, const struct manifest_manager **platform_config, size_t platform_count,
	const struct manifest_manager **component_manifests, size_t component_manifests_count,
	struct state_manager **state, size_t state_count, struct riot_key_manager *riot,
	struct aux_attestation *aux, struct recovery_image_manager *recovery,
	const struct keystore **keystores, size_t keystore_count, struct intrusion_manager *intrusion);
void config_reset_release (struct config_reset *reset);

int config_reset_restore_bypass (struct config_reset *reset);
int config_reset_restore_defaults (struct config_reset *reset);
int config_reset_restore_platform_config (struct config_reset *reset);
int config_reset_reset_intrusion (struct config_reset *reset);
int config_reset_clear_component_manifests (struct config_reset *reset);


#define	CONFIG_RESET_ERROR(code)		ROT_ERROR (ROT_MODULE_CONFIG_RESET, code)

/**
 * Error codes that can be generated by a configuration reset manager.
 */
enum {
	CONFIG_RESET_INVALID_ARGUMENT = CONFIG_RESET_ERROR (0x00),	/**< Input parameter is null or not valid. */
	CONFIG_RESET_NO_MEMORY = CONFIG_RESET_ERROR (0x01),			/**< Memory allocation failed. */
	CONFIG_RESET_NO_MANIFESTS = CONFIG_RESET_ERROR (0x02),		/**< No manifest are available. */
};


#endif	/* CONFIG_RESET_H_ */
