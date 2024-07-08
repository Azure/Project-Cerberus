// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CONFIG_RESET_STATIC_H_
#define CONFIG_RESET_STATIC_H_

#include "config_reset.h"


/**
 * Initialize a static manager for erasing all configuration from the device.
 *
 * There is no validation done on the arguments.
 *
 * @param bypass_config_ptr A list of managers for the configuration to clear for bypass mode.
 * @param bypass_count_arg The number of managers in the bypass configuration list.
 * @param platform_config_ptr A list of managers for the configuration to clear for restoring
 * platform configuration.
 * @param platform_count_arg The number of managers in the platform configuration list.
 * @param component_manifests_ptr A list of managers for the configuration to clear for restoring
 * 	component manifests to defaults.
 * @param component_manifests_count_arg The number of managers in the component manifests list.
 * @param state_ptr A list of managers for state information to reset.
 * @param state_count_arg The number of managers in the state list.
 * @param riot_ptr Manager RIoT keys to be cleared.
 * @param aux_ptr Attestation handler for keys to be cleared.
 * @param recovery_ptr Manager for recovery images to be cleared.
 * @param keystores_ptr Array of keystores to clear keys of.
 * @param keystore_count_arg Number of keystores in the keystores array.
 */
#define	config_reset_static_init(bypass_config_ptr, bypass_count_arg, platform_config_ptr, \
	platform_count_arg, component_manifests_ptr, component_manifests_count_arg, state_ptr, \
	state_count_arg, riot_ptr, aux_ptr, recovery_ptr, keystores_ptr, keystore_count_arg) { \
		.bypass = bypass_config_ptr, \
		.bypass_count = bypass_count_arg, \
		.config = platform_config_ptr, \
		.config_count = platform_count_arg, \
		.component_manifests = component_manifests_ptr, \
		.component_manifests_count = component_manifests_count_arg, \
		.state = state_ptr, \
		.state_count = state_count_arg, \
		.riot = riot_ptr, \
		.aux = aux_ptr, \
		.recovery = recovery_ptr, \
		.keystores = keystores_ptr, \
		.keystore_count = keystore_count_arg, \
	}


#endif	/* CONFIG_RESET_STATIC_H_ */
