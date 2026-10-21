// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_PFM_VERIFY_H_
#define FIRMWARE_PFM_VERIFY_H_

#include <stddef.h>
#include <stdint.h>
#include "attestation/pcr_store.h"
#include "crypto/hash.h"
#include "crypto/signature_verification.h"
#include "flash/flash.h"
#include "manifest/pfm/pfm.h"
#include "status/module_id.h"


/**
 * Variable context for device firmware verification with a PFM.
 */
struct firmware_pfm_verify_state {
	int32_t result;	/**< Result of the firmware verification. */
};

/**
 * Handler for device firmware that will be verified using a PFM.  Loading the firmware would
 * happen as a separate step by some other component, so there would still need to some additional
 * type of verification on the images during the load process to prevent time-of-check/time-of-use
 * issues.  Using a PFM in this way mainly provides a mechanism for measurement and attestation that
 * is similar to host firmware flows that use PFMs.
 *
 * There is no PFM management provided.  It's expected that the PFM will be updated and managed as
 * part of the firmware image.  Since the PFM is directly bundled and managed by the firmware that
 * it's verifying, there some limitations to PFM construction to fit this model:
 *
 *   1. Only a single version of firmware can be present in the PFM.  This single entry will always
 *      be used for verification without any kind of version string matching that is used in the
 *      host firmware flows.
 *   2. Only a single firmware component can be present in the PFM.  The verification flow is
 *      intended to support one and only one firmware image on flash, which is incompatible with the
 *      concept of multiple independent firmware components sharing a flash.
 *   3. Only images marked to be always validated will be verified.  Other regions of flash will be
 *      ignored.
 *   4. Only v2 PFMs are supported since there is no ability to provide an RSA engine as part of
 *      verification.  PFMv1 use is generally discouraged due to the better security and easier
 *      manageability of PFMv2.
 */
struct firmware_pfm_verify {
	struct firmware_pfm_verify_state *state;			/**< Variable context for firmware verification. */
	const struct flash *flash;							/**< Flash device containing the firmware image. */
	const struct pfm *pfm;								/**< PFM to use for firmware verification. */
	const struct hash_engine *hash;						/**< Hash engine to use for verification. */
	const struct signature_verification *sig_verify;	/**< Engine for PFM verification. */
	struct pcr_store *pcr;								/**< PCR manager for verification measurements. */
	char *version;										/**< Buffer for the firmware version. */
	size_t max_version;									/**< Length of the firmware version buffer. */
	uint16_t measurement_result;						/**< Measurement ID for the verification result. */
	uint16_t measurement_version;						/**< Measurement ID for the firmware version string. */
	uint16_t measurement_pfm;							/**< Measurement ID for the PFM digest. */
	uint16_t measurement_pfm_id;						/**< Measurement ID for the PFM ID. */
	uint16_t measurement_platform_id;					/**< Measurement ID for the PFM platform ID. */
};


int firmware_pfm_verify_init (struct firmware_pfm_verify *fw_verify,
	struct firmware_pfm_verify_state *state, const struct flash *flash, const struct pfm *pfm,
	const struct hash_engine *hash, const struct signature_verification *sig_verify,
	struct pcr_store *pcr, char *version_buffer, size_t max_version_length,
	uint16_t measurement_result, uint16_t measurement_version, uint16_t measurement_pfm,
	uint16_t measurement_pfm_id, uint16_t measurement_platform_id);
int firmware_pfm_verify_init_state (const struct firmware_pfm_verify *fw_verify);
void firmware_pfm_verify_release (const struct firmware_pfm_verify *fw_verify);

int firmware_pfm_verify_run_verification (const struct firmware_pfm_verify *fw_verify,
	uint32_t *expected_id);

int firmware_pfm_verify_get_fw_version_measured_data (const struct firmware_pfm_verify *fw_verify,
	size_t offset, uint8_t *buffer, size_t length, uint32_t *total_len);
int firmware_pfm_verify_hash_fw_version_measured_data (const struct firmware_pfm_verify *fw_verify,
	const struct hash_engine *hash);

int firmware_pfm_verify_get_pfm_digest_measured_data (const struct firmware_pfm_verify *fw_verify,
	size_t offset, uint8_t *buffer, size_t length, uint32_t *total_len);
int firmware_pfm_verify_hash_pfm_digest_measured_data (const struct firmware_pfm_verify *fw_verify,
	const struct hash_engine *hash);

int firmware_pfm_verify_get_pfm_id_measured_data (const struct firmware_pfm_verify *fw_verify,
	size_t offset, uint8_t *buffer, size_t length, uint32_t *total_len);
int firmware_pfm_verify_hash_pfm_id_measured_data (const struct firmware_pfm_verify *fw_verify,
	const struct hash_engine *hash);

int firmware_pfm_verify_get_pfm_platform_id_measured_data (
	const struct firmware_pfm_verify *fw_verify, size_t offset, uint8_t *buffer, size_t length,
	uint32_t *total_len);
int firmware_pfm_verify_hash_pfm_platform_id_measured_data (
	const struct firmware_pfm_verify *fw_verify, const struct hash_engine *hash);

/* Initializers for accessing the measured data of the verification. */

/**
 * Statically initialize a pcr_measured_data structure for the verification result measurement.
 *
 * @param fw_verify_state The variable context for the firmware verification handler generating the
 * measurement.
 */
#define	firmware_pfm_verify_result_measured_data_init(fw_verify_state)	{ \
		.type = PCR_DATA_TYPE_MEMORY, \
		.data = { \
			.memory = { \
				.buffer = (uint8_t*) (&(fw_verify_state)->result), \
				.length = sizeof (int32_t) \
			}, \
		}, \
	}

/**
 * Statically initialize a pcr_measured_data structure for the verified firmware version
 * measurement.
 *
 * @param fw_verify The verification handler that is generating the measurement.
 */
#define	firmware_pfm_verify_fw_version_measured_data_init(fw_verify)	{ \
		.type = PCR_DATA_TYPE_CALLBACK, \
		.data = { \
			.callback = { \
				.get_data = \
					(pcr_data_get_measured_data) firmware_pfm_verify_get_fw_version_measured_data, \
				.hash_data = (pcr_data_hash_measured_data) \
					firmware_pfm_verify_hash_fw_version_measured_data, \
				.context = (void*) (fw_verify), \
			}, \
		}, \
	}

/**
 * Statically initialize a pcr_measured_data structure for the verified firmware version
 * measurement.
 *
 * The callback to retrieve the data hash will not be set.
 *
 * @param fw_verify The verification handler that is generating the measurement.
 */
#define	firmware_pfm_verify_fw_version_measured_data_init_no_hash(fw_verify)	{ \
		.type = PCR_DATA_TYPE_CALLBACK, \
		.data = { \
			.callback = { \
				.get_data = \
					(pcr_data_get_measured_data) firmware_pfm_verify_get_fw_version_measured_data, \
				.hash_data = NULL, \
				.context = (void*) (fw_verify), \
			}, \
		}, \
	}

/**
 * Statically initialize a pcr_measured_data structure for the PFM digest measurement.
 *
 * @param fw_verify The verification handler that is generating the measurement.
 */
#define	firmware_pfm_verify_pfm_digest_measured_data_init(fw_verify)	{ \
		.type = PCR_DATA_TYPE_CALLBACK, \
		.data = { \
			.callback = { \
				.get_data = \
					(pcr_data_get_measured_data) firmware_pfm_verify_get_pfm_digest_measured_data, \
				.hash_data = (pcr_data_hash_measured_data) \
					firmware_pfm_verify_hash_pfm_digest_measured_data, \
				.context = (void*) (fw_verify), \
			}, \
		}, \
	}

/**
 * Statically initialize a pcr_measured_data structure for the PFM digest measurement.
 *
 * The callback to retrieve the data hash will not be set.
 *
 * @param fw_verify The verification handler that is generating the measurement.
 */
#define	firmware_pfm_verify_pfm_digest_measured_data_init_no_hash(fw_verify)	{ \
		.type = PCR_DATA_TYPE_CALLBACK, \
		.data = { \
			.callback = { \
				.get_data = \
					(pcr_data_get_measured_data) firmware_pfm_verify_get_pfm_digest_measured_data, \
				.hash_data = NULL, \
				.context = (void*) (fw_verify), \
			}, \
		}, \
	}

/**
 * Statically initialize a pcr_measured_data structure for the PFM ID measurement.
 *
 * @param fw_verify The verification handler that is generating the measurement.
 */
#define	firmware_pfm_verify_pfm_id_measured_data_init(fw_verify)	{ \
		.type = PCR_DATA_TYPE_CALLBACK, \
		.data = { \
			.callback = { \
				.get_data = \
					(pcr_data_get_measured_data) firmware_pfm_verify_get_pfm_id_measured_data, \
				.hash_data = \
					(pcr_data_hash_measured_data) firmware_pfm_verify_hash_pfm_id_measured_data, \
				.context = (void*) (fw_verify), \
			}, \
		}, \
	}

/**
 * Statically initialize a pcr_measured_data structure for the PFM ID measurement.
 *
 * The callback to retrieve the data hash will not be set.
 *
 * @param fw_verify The verification handler that is generating the measurement.
 */
#define	firmware_pfm_verify_pfm_id_measured_data_init_no_hash(fw_verify)	{ \
		.type = PCR_DATA_TYPE_CALLBACK, \
		.data = { \
			.callback = { \
				.get_data = \
					(pcr_data_get_measured_data) firmware_pfm_verify_get_pfm_id_measured_data, \
				.hash_data = NULL, \
				.context = (void*) (fw_verify), \
			}, \
		}, \
	}

/**
 * Statically initialize a pcr_measured_data structure for the PFM platform ID measurement.
 *
 * @param fw_verify The verification handler that is generating the measurement.
 */
#define	firmware_pfm_verify_pfm_platform_id_measured_data_init(fw_verify)	{ \
		.type = PCR_DATA_TYPE_CALLBACK, \
		.data = { \
			.callback = { \
				.get_data = (pcr_data_get_measured_data) \
					firmware_pfm_verify_get_pfm_platform_id_measured_data, \
				.hash_data = (pcr_data_hash_measured_data) \
					firmware_pfm_verify_hash_pfm_platform_id_measured_data, \
				.context = (void*) (fw_verify), \
			}, \
		}, \
	}

/**
 * Statically initialize a pcr_measured_data structure for the PFM platform ID measurement.
 *
 * The callback to retrieve the data hash will not be set.
 *
 * @param fw_verify The verification handler that is generating the measurement.
 */
#define	firmware_pfm_verify_pfm_platform_id_measured_data_init_no_hash(fw_verify)	{ \
		.type = PCR_DATA_TYPE_CALLBACK, \
		.data = { \
			.callback = { \
				.get_data = (pcr_data_get_measured_data) \
					firmware_pfm_verify_get_pfm_platform_id_measured_data, \
				.hash_data = NULL, \
				.context = (void*) (fw_verify), \
			}, \
		}, \
	}


#define	FIRMWARE_PFM_VERIFY_ERROR(code)		ROT_ERROR (ROT_MODULE_FIRMWARE_PFM_VERIFY, code)

/**
 * Error codes that can be generated by firmware image verification with a PFM.
 */
enum {
	FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT = FIRMWARE_PFM_VERIFY_ERROR (0x00),	/**< Input parameter is null or not valid. */
	FIRMWARE_PFM_VERIFY_NO_MEMORY = FIRMWARE_PFM_VERIFY_ERROR (0x01),			/**< Memory allocation failed. */
	FIRMWARE_PFM_VERIFY_NOT_VERIFIED = FIRMWARE_PFM_VERIFY_ERROR (0x02),		/**< Firmware verification has not been run. */
	FIRMWARE_PFM_VERIFY_PFM_MULTI_FW = FIRMWARE_PFM_VERIFY_ERROR (0x03),		/**< The PFM contains multiple FW components. */
	FIRMWARE_PFM_VERIFY_EMPTY_PFM = FIRMWARE_PFM_VERIFY_ERROR (0x04),			/**< The PFM contains no firmware information. */
	FIRMWARE_PFM_VERIFY_PFM_MULTI_VERSION = FIRMWARE_PFM_VERIFY_ERROR (0x05),	/**< The PFM contains multiple firmware versions. */
	FIRMWARE_PFM_VERIFY_PFM_NO_VERSION = FIRMWARE_PFM_VERIFY_ERROR (0x06),		/**< The PFM contains no firmware version. */
	FIRMWARE_PFM_VERIFY_PFM_NO_IMAGE = FIRMWARE_PFM_VERIFY_ERROR (0x07),		/**< The PFM contains no firmware image information. */
	FIRMWARE_PFM_VERIFY_UNSUPPORTED_ID = FIRMWARE_PFM_VERIFY_ERROR (0x08),		/**< The PFM contains an unsupported ID. */
};


#endif	/* FIRMWARE_PFM_VERIFY_H_ */
