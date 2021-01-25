// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_H_
#define HOST_PROCESSOR_H_

#include <stdbool.h>
#include "status/rot_status.h"
#include "host_fw_util.h"
#include "crypto/hash.h"
#include "crypto/rsa.h"
#include "flash/flash_util.h"
#include "common/observable.h"
#include "host_processor_observer.h"


/**
 * Boolean macro to determine if a status code represents a validation failure of flash.
 */
#define	IS_VALIDATION_FAILURE(x)	((x == RSA_ENGINE_BAD_SIGNATURE) || (x == HOST_FW_UTIL_BAD_IMAGE_HASH) || (x == FLASH_UTIL_UNEXPECTED_VALUE) || (x == HOST_FW_UTIL_UNSUPPORTED_VERSION))


/**
 * Verification actions that can be taken on reset of the host processor.
 */
enum host_processor_reset_actions {
	HOST_PROCESSOR_ACTION_NONE = 0,						/**< No action is pending on host reset. */
	HOST_PROCESSOR_ACTION_VERIFY_PFM,					/**< A pending PFM will be verified. */
	HOST_PROCESSOR_ACTION_VERIFY_UPDATE,				/**< A host FW update will be verified. */
	HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE,		/**< A pending PFM and host FW update will be verified. */
	HOST_PROCESSOR_ACTION_ACTIVATE_UPDATE,				/**< A prevalidated host FW update will be made active. */
	HOST_PROCESSOR_ACTION_ACTIVATE_PFM_AND_UPDATE,		/**< A prevalidated pending PFM and host FW update will both be made active. */
	HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH,			/**< A PFM will be used to verify flash, which is being accessed in bypass mode. */
};

/**
 * Defines the core interface for protecting the firmware of a single host processor.
 */
struct host_processor {
	/**
	 * Execute power-on reset firmware verification for the host processor.
	 *
	 * Management of host reset control is not handled here.  Prior to starting POR verification,
	 * it is expected the host processor will be in reset.  Reset should be released upon successful
	 * return from this call.
	 *
	 * In the case of an error, POR processing must leave the system in a state such that repeated
	 * calls to this function or calls to other host processor functions behave correctly.
	 *
	 * @param host The instance for the processor that has triggered power-on reset.
	 * @param hash The hash engine to use for firmware validation.
	 * @param rsa The RSA engine to use for signature verification.
	 *
	 * @return 0 if all power-on reset tasks were completed successfully or an error code.
	 */
	int (*power_on_reset) (struct host_processor *host, struct hash_engine *hash,
		struct rsa_engine *rsa);

	/**
	 * Execute soft reset firmware verification for the host processor.
	 *
	 * @param host The instance for the processor that has triggered a soft reset.
	 * @param hash The hash engine to use for firmware validation.
	 * @param rsa The RSA engine to use for signature verification.
	 *
	 * @return 0 if all soft reset tasks were completed successfully or an error code.
	 */
	int (*soft_reset) (struct host_processor *host, struct hash_engine *hash,
		struct rsa_engine *rsa);

	/**
	 * Execute run-time firmware verification for the host processor.
	 *
	 * The host is left running during this verification, but will not have access to flash.  The
	 * host is responsible for suspending flash accesses during this verification process.
	 *
	 * No host resets will be triggered before or after verification.  New host firmware will not be
	 * applied until the host resets itself.  PFMs for the active FW will be applied without a host
	 * reset.
	 *
	 * @param host The instance for the processor requesting run-time firmware verification.
	 * @param hash The hash engine to use for firmware validation.
	 * @param rsa The RSA engine to use for signature verification.
	 *
	 * @return 0 if firmware verification was completed successfully or an error code.
	 */
	int (*run_time_verification) (struct host_processor *host, struct hash_engine *hash,
		struct rsa_engine *rsa);

	/**
	 * Attempt to rollback to a previously valid image.  Rollback will only be allowed to an image
	 * that can be authenticated.
	 *
	 * @param host The instance for the processor that is attempting a rollback.
	 * @param hash The hash engine to use for firmware validation.
	 * @param rsa The RSA engine to use for signature verification.
	 * @param disable_bypass Disable rollback when there is no PFM, if the implementation supports
	 * this flow.  If the implementation does not support rollback in bypass mode, this argument has
	 * no effect.
	 * @param no_reset Flag to disable host reset control during rollback operations.
	 *
	 * @return 0 if the rollback was successful or an error code.
	 */
	int (*flash_rollback) (struct host_processor *host, struct hash_engine *hash,
		struct rsa_engine *rsa, bool disable_bypass, bool no_reset);

	/**
	 * Recover read/write data for the active image.
	 *
	 * @param host The instance for the host processor that will execute recovery.
	 *
	 * @return 0 if read/write recovery was successful or an error code.
	 */
	int (*recover_active_read_write_data) (struct host_processor *host);

	/**
	 * Determine the verification actions that will be performed on the next host reset.
	 *
	 * @param host Host processor to query.
	 *
	 * @return A status code indicating what verification is pending or an error code.  The
	 * verification status will be one of {@link enum host_processor_reset_actions}.  Use
	 * ROT_IS_ERROR to determine if the call failed.
	 */
	int (*get_next_reset_verification_actions) (struct host_processor *host);

	/**
	 * Determine if the system is in a state that requires recovery steps to restore an operational
	 * configuration.
	 *
	 * @param host The host processor instance to query.
	 *
	 * @return 0 if the system configuration is good, 1 if it is not, or an error code.
	 */
	int (*needs_config_recovery) (struct host_processor *host);

	/**
	 * Apply to host flash a valid recovery image and release the host reset line.
	 *
	 * @param host The instance for host processor needing a recovery image.
	 * @param no_reset Flag to disable host reset control during recovery operations.
	 *
	 * @return 0 if the host recovery image application was successful or an error code.
	 */
	int (*apply_recovery_image) (struct host_processor *host, bool no_reset);

	/**
	 * Boot the host in bypass mode regardless of the PFM state.  The host will be bypassed to the
	 * read-only flash device.
	 *
	 * No control of host reset is provided as part of this handler.
	 *
	 * @param host The instance for the host processor to boot in bypass mode.
	 * @param swap_flash Flag indicating if the read-only and read/write devices should be swapped
	 * before configuring for bypass mode.  If there is only one flash device for the host, this
	 * argument has no effect.
	 *
	 * @return 0 if bypass mode was configured successfully or an error code.
	 */
	int (*bypass_mode) (struct host_processor *host, bool swap_flash);

	int port;								/**< The port identifier of the host. */
	struct observable observable;			/**< Observer manager for the port handler. */
};


void host_processor_set_port (struct host_processor *host, int port);
int host_processor_get_port (struct host_processor *host);

int host_processor_add_observer (struct host_processor *host,
	struct host_processor_observer *observer);
int host_processor_remove_observer (struct host_processor *host,
	struct host_processor_observer *observer);

/* Internal functions for use by derived types. */
int host_processor_init (struct host_processor *host);
void host_processor_release (struct host_processor *host);


#define	HOST_PROCESSOR_ERROR(code)		ROT_ERROR (ROT_MODULE_HOST_PROCESSOR, code)

/**
 * Error codes that can be generated by a host processor.
 */
enum {
	HOST_PROCESSOR_INVALID_ARGUMENT = HOST_PROCESSOR_ERROR (0x00),			/**< Input parameter is null or not valid. */
	HOST_PROCESSOR_NO_MEMORY = HOST_PROCESSOR_ERROR (0x01),					/**< Memory allocation failed. */
	HOST_PROCESSOR_POR_FAILED = HOST_PROCESSOR_ERROR (0x02),				/**< POR validation and configuration was not completed */
	HOST_PROCESSOR_SOFT_RESET_FAILED = HOST_PROCESSOR_ERROR (0x03),			/**< Soft reset operations were not completed. */
	HOST_PROCESSOR_ROLLBACK_FAILED = HOST_PROCESSOR_ERROR (0x04),			/**< Flash rollback was not completed. */
	HOST_PROCESSOR_NO_ROLLBACK = HOST_PROCESSOR_ERROR (0x05),				/**< Flash rollback is not possible. */
	HOST_PROCESSOR_ROLLBACK_DIRTY = HOST_PROCESSOR_ERROR (0x06),			/**< The rollback flash has been changed. */
	HOST_PROCESSOR_RW_SKIPPED = HOST_PROCESSOR_ERROR (0x07),				/**< Validation of read/write flash was skipped. */
	HOST_PROCESSOR_RUN_TIME_FAILED = HOST_PROCESSOR_ERROR (0x08),			/**< Run-time validation was not completed. */
	HOST_PROCESSOR_NOTHING_TO_VERIFY = HOST_PROCESSOR_ERROR (0x09),			/**< No update requiring verification has occurred. */
	HOST_PROCESSOR_NEXT_ACTIONS_FAILED = HOST_PROCESSOR_ERROR (0x0a),		/**< Failed to determine the pending verification actions. */
	HOST_PROCESSOR_NEEDS_RECOVERY_FAILED = HOST_PROCESSOR_ERROR (0x0b),		/**< Failed to determine if the host needs recovery. */
	HOST_PROCESSOR_RECOVERY_IMG_FAILED = HOST_PROCESSOR_ERROR (0x0c),		/**< Applying recovery image was not completed. */
	HOST_PROCESSOR_RECOVERY_UNSUPPORTED = HOST_PROCESSOR_ERROR (0x0d),		/**< Host recovery is not supported. */
	HOST_PROCESSOR_NO_RECOVERY_IMAGE = HOST_PROCESSOR_ERROR (0x0e),			/**< There is no valid recovery image. */
	HOST_PROCESSOR_BYPASS_FAILED = HOST_PROCESSOR_ERROR (0x0f),				/**< Failed to configure bypass mode. */
	HOST_PROCESSOR_FLASH_NOT_SUPPORTED = HOST_PROCESSOR_ERROR (0x10),		/**< The flash configuration is not supported. */
	HOST_PROCESSOR_RW_RECOVERY_FAILED = HOST_PROCESSOR_ERROR (0x11),		/**< Failed to recover active read/write data. */
	HOST_PROCESSOR_RW_RECOVERY_UNSUPPORTED = HOST_PROCESSOR_ERROR (0x12),	/**< Recovery of active read/write data is not supported. */
	HOST_PROCESSOR_NO_ACTIVE_RW_DATA = HOST_PROCESSOR_ERROR (0x13),			/**< There is no active image for read/write recovery. */
};


#endif /* HOST_PROCESSOR_H_ */
