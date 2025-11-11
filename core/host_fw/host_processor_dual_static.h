// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_DUAL_STATIC_H_
#define HOST_PROCESSOR_DUAL_STATIC_H_

#include "host_processor_dual.h"


/* Internal functions declared to allow for static initialization. */
int host_processor_dual_power_on_reset (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa);
int host_processor_dual_soft_reset (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa);
int host_processor_dual_run_time_verification (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa);
int host_processor_dual_flash_rollback (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, bool disable_bypass,
	bool no_reset);
int host_processor_dual_recover_active_read_write_data (const struct host_processor *host);
int host_processor_dual_bypass_mode (const struct host_processor *host, bool swap_flash);

int host_processor_dual_full_read_write_flash (const struct host_processor_filtered *host);


/**
 * Constant initializer for the host processor API.
 */
#define	HOST_PROCESSOR_DUAL_API_INIT    \
	.power_on_reset = host_processor_dual_power_on_reset, \
	.soft_reset = host_processor_dual_soft_reset, \
	.run_time_verification = host_processor_dual_run_time_verification, \
	.flash_rollback = host_processor_dual_flash_rollback, \
	.recover_active_read_write_data = host_processor_dual_recover_active_read_write_data, \
	.get_next_reset_verification_actions = \
		host_processor_filtered_get_next_reset_verification_actions, \
	.needs_config_recovery = host_processor_filtered_needs_config_recovery, \
	.apply_recovery_image = host_processor_filtered_apply_recovery_image, \
	.bypass_mode = host_processor_dual_bypass_mode,

/**
 * Constant initializer for internal APIs.
 */
#define	HOST_PROCESSOR_DUAL_INTERNAL_API_INIT	{ \
		.enable_bypass_mode = host_processor_dual_full_read_write_flash, \
	}

/**
 * Internal initializer for a static instance for executing host processor actions using two flash
 * devices.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash devices for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 * @param pulse_width_arg The width of the reset pulse, in milliseconds.  If set to 0, the reset
 * will be held instead of being pulsed.
 * @param reset_flash_arg Flag to indicate if flash should reset on host soft resets.
 * @param internal_api Initializer for the internal APIs.
 */
#define	host_processor_dual_static_init_internal(state_ptr, control_ptr, flash_ptr, \
	host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg, reset_flash_arg, \
	internal_api)	{ \
		.base = { \
			HOST_PROCESSOR_DUAL_API_INIT \
			.state = &(state_ptr)->base, \
		}, \
		.state = state_ptr, \
		.control = control_ptr, \
		.flash = &(flash_ptr)->base, \
		.host_state = host_state_ptr, \
		.filter = filter_ptr, \
		.pfm = pfm_ptr, \
		.recovery = recovery_ptr, \
		.reset_pulse = pulse_width_arg, \
		.reset_flash = reset_flash_arg, \
		.internal = internal_api, \
	}


/**
 * Initialize a static instance of the interface for executing host processor actions using two
 * flash devices.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash devices for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 */
#define	host_processor_dual_static_init(state_ptr, control_ptr, flash_ptr, host_state_ptr, \
	filter_ptr, pfm_ptr, recovery_ptr)  \
		host_processor_dual_static_init_internal (state_ptr, control_ptr, flash_ptr, \
			host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, 0, false, \
			HOST_PROCESSOR_DUAL_INTERNAL_API_INIT)

/**
 * Initialize a static instance of the interface for executing host processor actions using two
 * flash devices.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash devices for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 * @param pulse_width_arg The width of the reset pulse, in milliseconds.  If set to 0, the reset
 * will be held instead of being pulsed.
 */
#define	host_processor_dual_static_init_pulse_reset(state_ptr, control_ptr, flash_ptr, \
	host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg) \
		host_processor_dual_static_init_internal (state_ptr, control_ptr, flash_ptr, \
			host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg, false, \
			HOST_PROCESSOR_DUAL_INTERNAL_API_INIT)

/**
 * Initialize a static instance of the interface for executing host processor actions using two
 * flash devices.
 *
 * The host flash devices will be reset on host resets.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash devices for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 */
#define	host_processor_dual_static_init_reset_flash(state_ptr, control_ptr, flash_ptr, \
	host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr)  \
		host_processor_dual_static_init_internal (state_ptr, control_ptr, flash_ptr, \
			host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, 0, true, \
			HOST_PROCESSOR_DUAL_INTERNAL_API_INIT)

/**
 * Initialize a static instance of the interface for executing host processor actions using two
 * flash devices.
 *
 * While host flash is being accessed, the host processor will not be held in reset.  After the host
 * flash accesses have been completed, the host processor reset will be pulsed.
 *
 * The host flash devices will be reset on host resets.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host processor handling.
 * @param control_ptr The interface for controlling the host processor.
 * @param flash_ptr The manager for the flash devices for the host processor.
 * @param host_state_ptr The state information for the host.
 * @param filter_ptr The SPI filter controlling flash access for the host processor.
 * @param pfm_ptr The manager for PFMs for the host processor.
 * @param recovery_ptr The manager for recovery of the host processor.
 * @param pulse_width_arg The width of the reset pulse, in milliseconds.  If set to 0, the reset
 * will be held instead of being pulsed.
 */
#define	host_processor_dual_static_init_reset_flash_pulse_reset(state_ptr, control_ptr, flash_ptr, \
	host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg) \
		host_processor_dual_static_init_internal (state_ptr, control_ptr, flash_ptr, \
			host_state_ptr, filter_ptr, pfm_ptr, recovery_ptr, pulse_width_arg, true, \
			HOST_PROCESSOR_DUAL_INTERNAL_API_INIT)


#endif	/* HOST_PROCESSOR_DUAL_STATIC_H_ */
