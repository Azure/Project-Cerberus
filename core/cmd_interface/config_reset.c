// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "config_reset.h"


/**
 * Initialize a manager for erasing all configuration from the device.
 *
 * @param reset The configuration reset manager to initialize.
 * @param bypass_config A list of managers for the configuration to clear for bypass mode.
 * @param bypass_count The number of managers in the bypass configuration list.
 * @param platform_config A list of managers for the configuration to clear for restoring platform
 * configuration.
 * @param platform_count The number of managers in the platform configuration list.
 * @param state A list of managers for state information to reset.
 * @param state_count The number of managers in the state list.
 * @param riot Manager RIoT keys to be cleared.
 * @param aux Attestation handler for keys to be cleared.
 * @param recovery Manager for recovery images to be cleared.
 * @param keystores Array of keystores to clear keys of.
 * @param keystore_count Number of keystores in the keystores array.
 * @param intrusion The intrusion manager to reset intrusion.
 *
 * @return 0 if the manager was initialized successfully or an error code.
 */
int config_reset_init (struct config_reset *reset, struct manifest_manager **bypass_config,
	size_t bypass_count, struct manifest_manager **platform_config, size_t platform_count,
	struct state_manager **state, size_t state_count, struct riot_key_manager *riot,
	struct aux_attestation *aux, struct recovery_image_manager *recovery,
	struct keystore **keystores, size_t keystore_count, struct intrusion_manager *intrusion)
{
	if ((reset == NULL) || (bypass_count && (bypass_config == NULL)) ||
		(platform_count && (platform_config == NULL)) || (state_count && (state == NULL)) ||
		(keystore_count && (keystores == NULL))) {
		return CONFIG_RESET_INVALID_ARGUMENT;
	}

	if (state_count && !platform_count && !bypass_count) {
		return CONFIG_RESET_NO_MANIFESTS;
	}

	memset (reset, 0, sizeof (struct config_reset));

	reset->bypass = bypass_config;
	reset->bypass_count = bypass_count;
	reset->config = platform_config;
	reset->config_count = platform_count;
	reset->state = state;
	reset->state_count = state_count;
	reset->riot = riot;
	reset->aux = aux;
	reset->recovery = recovery;
	reset->keystores = keystores;
	reset->keystore_count = keystore_count;
	reset->intrusion = intrusion;

	return 0;
}

/**
 * Release the resources used for managing configuration resets.
 *
 * @param reset The configuration reset manager to release.
 */
void config_reset_release (struct config_reset *reset)
{

}

/**
 * Erase all configuration files necessary to revert back to bypass mode.  State information will
 * remain unchanged.  This protects against switching back to a flash that contains an old or
 * non-bootable image.
 *
 * Only configuration files specified to restore bypass mode will be cleared.
 *
 * @param reset The configuration that should be erased.
 *
 * @return 0 if the configuration was erased or an error code.
 */
int config_reset_restore_bypass (struct config_reset *reset)
{
	size_t i;
	int status;

	if (reset == NULL) {
		return CONFIG_RESET_INVALID_ARGUMENT;
	}

	if (!reset->bypass_count) {
		return CONFIG_RESET_NO_MANIFESTS;
	}

	for (i = 0; i < reset->bypass_count; i++) {
		status = (reset->bypass[i])->clear_all_manifests (reset->bypass[i]);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Erase all managed configuration files and restore internal state to default values.
 *
 * @param reset The configuration that should be reset.
 *
 * @return 0 if defaults were restored or an error code.
 */
int config_reset_restore_defaults (struct config_reset *reset)
{
	size_t i;
	int status = 0;

	if (reset == NULL) {
		return CONFIG_RESET_INVALID_ARGUMENT;
	}

	for (i = 0; i < reset->bypass_count; i++) {
		status = reset->bypass[i]->clear_all_manifests (reset->bypass[i]);
		if (status != 0) {
			return status;
		}
	}

	for (i = 0; i < reset->config_count; i++) {
		status = (reset->config[i])->clear_all_manifests (reset->config[i]);
		if (status != 0) {
			return status;
		}
	}

	for (i = 0; i < reset->state_count; i++) {
		(reset->state[i])->restore_default_state (reset->state[i]);
	}

	if (reset->riot) {
		status = riot_key_manager_erase_all_certificates (reset->riot);
		if (status != 0) {
			return status;
		}
	}

	if (reset->aux) {
		status = aux_attestation_erase_key (reset->aux);
		if (status != 0) {
			return status;
		}
	}

	if (reset->recovery) {
		status = reset->recovery->erase_all_recovery_regions (reset->recovery);
		if (status != 0) {
			return status;
		}
	}

	for (i = 0; i < reset->keystore_count; ++i) {
		status = reset->keystores[i]->erase_all_keys (reset->keystores[i]);
		if (status != 0) {
			return status;
		}
	}

	if (reset->intrusion) {
		/* The default state for intrusion detection is "intruded". */
		status = reset->intrusion->handle_intrusion (reset->intrusion);
	}

	return status;
}

/**
 * Erase all managed configuration for platform-specific properties.
 *
 * @param reset The configuration that should be reset.
 *
 * @return 0 if defaults were restored or an error code.
 */
int config_reset_restore_platform_config (struct config_reset *reset)
{
	size_t i;
	int status;

	if (reset == NULL) {
		return CONFIG_RESET_INVALID_ARGUMENT;
	}

	if (!reset->config_count) {
		return CONFIG_RESET_NO_MANIFESTS;
	}

	for (i = 0; i < reset->config_count; i++) {
		status = (reset->config[i])->clear_all_manifests (reset->config[i]);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Reset the system intrusion detection to report that no intrusion has taken place.
 *
 * @param reset The configuration that should be reset.
 *
 * @return 0 if intrusion was reset or an error code.
 */
int config_reset_reset_intrusion (struct config_reset *reset)
{
	if (reset == NULL) {
		return CONFIG_RESET_INVALID_ARGUMENT;
	}

	if (reset->intrusion) {
		return reset->intrusion->reset_intrusion (reset->intrusion);
	}
	else {
		return 0;
	}
}
