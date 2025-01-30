// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_pfm_verify.h"
#include "common/buffer_util.h"
#include "common/unused.h"
#include "host_fw/host_fw_util.h"
#include "manifest/manifest_logging.h"
#include "manifest/manifest_manager.h"
#include "manifest/manifest_pcr.h"


/**
 * Update the measurements associated with the verification handler.
 *
 * @param fw_verify The handler whose measurements should be updated.
 *
 * @return 0 if all measurements were updated successfully or an error code.
 */
static int firmware_pfm_verify_update_measurements (const struct firmware_pfm_verify *fw_verify)
{
	const struct manifest *active;
	int status;

	/* If the verification result is successful, measure the PFM.  If not, report no PFM and clear
	 * any data in the version buffer. */
	if (fw_verify->state->result == 0) {
		active = &fw_verify->pfm->base;
	}
	else {
		active = NULL;
		memset (fw_verify->version, 0, fw_verify->max_version);
	}

	status = pcr_store_update_versioned_buffer (fw_verify->pcr, fw_verify->hash,
		fw_verify->measurement_result, (uint8_t*) &fw_verify->state->result,
		sizeof (fw_verify->state->result), true, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, fw_verify->measurement_result, status);

		return status;
	}

	status = pcr_store_update_versioned_buffer (fw_verify->pcr, fw_verify->hash,
		fw_verify->measurement_version, (uint8_t*) fw_verify->version,
		strlen (fw_verify->version) + 1, true, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, fw_verify->measurement_version, status);

		return status;
	}

	return manifest_pcr_measure_manifest (active, fw_verify->hash, fw_verify->pcr,
		fw_verify->measurement_pfm, fw_verify->measurement_pfm_id,
		fw_verify->measurement_platform_id);
}

/**
 * Initialize a handler for device firmware that leverages a PFM for providing verification and
 * measurement of the image.
 *
 * @param fw_verify The verification handler to initialize.
 * @param state Variable context for firmware verification.  This must be uninitialized.
 * @param flash Flash device that contains the firmware image that will be verified.
 * @param pfm The PFM to use for firmware verification and measurement.
 * @param hash Hash engine to use for firmware image verification.
 * @param sig_verify Engine to use for PFM verification.
 * @param pcr Manager for PCRs to use for storing verification measurements.
 * @param version_buffer Buffer that will be used to store the firmware version string from the PFM.
 * @param max_version_length Length of the firmware version buffer, including the NULL terminator.
 * @param measurement_result PCR measurement index to update with the result of PFM verification.
 * @param measurement_version PCR measurement index to update with the firmware version string from
 * the PFM.
 * @param measurement_pfm PCR measurement index to update with the PFM digest.
 * @param measurement_pfm_id PCR measurement index to update with the PFM ID.
 * @param measurement_platform_id PCR measurement index to update with the PFM platform ID.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int firmware_pfm_verify_init (struct firmware_pfm_verify *fw_verify,
	struct firmware_pfm_verify_state *state, const struct flash *flash, const struct pfm *pfm,
	const struct hash_engine *hash, const struct signature_verification *sig_verify,
	struct pcr_store *pcr, char *version_buffer, size_t max_version_length,
	uint16_t measurement_result, uint16_t measurement_version, uint16_t measurement_pfm,
	uint16_t measurement_pfm_id, uint16_t measurement_platform_id)
{
	if (fw_verify == NULL) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	memset (fw_verify, 0, sizeof (*fw_verify));

	fw_verify->state = state;
	fw_verify->flash = flash;
	fw_verify->pfm = pfm;
	fw_verify->hash = hash;
	fw_verify->sig_verify = sig_verify;
	fw_verify->pcr = pcr;
	fw_verify->version = version_buffer;
	fw_verify->max_version = max_version_length;
	fw_verify->measurement_result = measurement_result;
	fw_verify->measurement_version = measurement_version;
	fw_verify->measurement_pfm = measurement_pfm;
	fw_verify->measurement_pfm_id = measurement_pfm_id;
	fw_verify->measurement_platform_id = measurement_platform_id;

	return firmware_pfm_verify_init_state (fw_verify);
}

/**
 * Initialize only the variable state for the firmware verification handler.  The rest of the
 * instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param fw_verify The firmware verification instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int firmware_pfm_verify_init_state (const struct firmware_pfm_verify *fw_verify)
{
	if ((fw_verify == NULL) || (fw_verify->state == NULL) || (fw_verify->flash == NULL) ||
		(fw_verify->pfm == NULL) || (fw_verify->hash == NULL) || (fw_verify->sig_verify == NULL) ||
		(fw_verify->pcr == NULL) || (fw_verify->version == NULL) || (fw_verify->max_version == 0)) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	fw_verify->state->result = FIRMWARE_PFM_VERIFY_NOT_VERIFIED;

	return firmware_pfm_verify_update_measurements (fw_verify);
}

/**
 * Release the resources used for firmware verification with a PFM.
 *
 * @param fw_verify The verification handler to release.
 */
void firmware_pfm_verify_release (const struct firmware_pfm_verify *fw_verify)
{
	UNUSED (fw_verify);
}

/**
 * Run verification of the firmware image using the PFM included with the image.  Measurements will
 * be updated whether verification is successful or not.
 *
 * @param fw_verify The handler to use for image verification.
 * @param expected_id Address of an expected PFM ID value. If NULL check will be bypassed.
 *
 * @return 0 if verification was completed successfully or an error code.  Failure to update PCRs
 * will generate log messages but will not report a verification failure.
 */
int firmware_pfm_verify_run_verification (const struct firmware_pfm_verify *fw_verify,
	uint32_t *expected_id)
{
	struct pfm_firmware fw_list;
	struct pfm_firmware_versions version_list;
	struct pfm_image_list img_list;
	uint32_t pfm_id;
	int status;

	if (fw_verify == NULL) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	/* Verify that the PFM is authentic and constructed correctly.  Meaning, it's not empty and has
	 * only one firmware component. */
	status = fw_verify->pfm->base.verify (&fw_verify->pfm->base, fw_verify->hash,
		fw_verify->sig_verify, NULL, 0);
	if (status != 0) {
		goto measure;
	}

	/* Optionally enforce PFM ID against an expected ID. */
	if (expected_id != NULL) {
		status = fw_verify->pfm->base.get_id (&fw_verify->pfm->base, &pfm_id);
		if (status != 0) {
			goto measure;
		}

		if (pfm_id != *expected_id) {
			status = FIRMWARE_PFM_VERIFY_UNSUPPORTED_ID;
			goto measure;
		}
	}

	status = fw_verify->pfm->base.is_empty (&fw_verify->pfm->base);
	if (status != 0) {
		if (status == 1) {
			status = FIRMWARE_PFM_VERIFY_EMPTY_PFM;
		}

		goto measure;
	}

	status = fw_verify->pfm->get_firmware (fw_verify->pfm, &fw_list);
	if (status == 0) {
		if (fw_list.count > 1) {
			status = FIRMWARE_PFM_VERIFY_PFM_MULTI_FW;
		}

		fw_verify->pfm->free_firmware (fw_verify->pfm, &fw_list);
	}

	if (status != 0) {
		goto measure;
	}

	/* Get the firmware image details for the verification.  There can only be one version listed
	 * in the PFM. */
	status = fw_verify->pfm->get_supported_versions (fw_verify->pfm, NULL, &version_list);
	if (status == 0) {
		if (version_list.count == 0) {
			status = FIRMWARE_PFM_VERIFY_PFM_NO_VERSION;
		}
		else if (version_list.count > 1) {
			status = FIRMWARE_PFM_VERIFY_PFM_MULTI_VERSION;
		}

		if (status != 0) {
			goto free_versions;
		}
	}
	else {
		goto measure;
	}

	status = fw_verify->pfm->get_firmware_images (fw_verify->pfm, NULL,
		version_list.versions[0].fw_version_id, &img_list);
	if (status != 0) {
		goto free_versions;
	}

	/* Verify the flash contents based on the image details from the PFM. */
	if (img_list.count == 0) {
		status = FIRMWARE_PFM_VERIFY_PFM_NO_IMAGE;
	}

	if (status == 0) {
		status = host_fw_verify_images (fw_verify->flash, &img_list, fw_verify->hash, NULL);
	}

	fw_verify->pfm->free_firmware_images (fw_verify->pfm, &img_list);

free_versions:
	if (status == 0) {
		/* Copy only the amount of the version string that fits in the provided buffer.  This may
		 * mean that the measured value doesn't completely match the one used for verification, but
		 * it's better than failing verification just because of a measurement issue. */
		strncpy (fw_verify->version, version_list.versions[0].fw_version_id,
			fw_verify->max_version);
		fw_verify->version[fw_verify->max_version - 1] = '\0';
	}

	fw_verify->pfm->free_fw_versions (fw_verify->pfm, &version_list);

measure:
	fw_verify->state->result = status;

	firmware_pfm_verify_update_measurements (fw_verify);

	return status;
}

/**
 * Get the firmware version string that was measured during the last verification.  If there has not
 * been any successful verification, this will be an empty string.
 *
 * @param fw_verify The verification handler to query.
 * @param offset The offset to read data from.
 * @param buffer The output buffer to be filled with measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer with total length of version string measurement. This will always
 * contain the total length of the data, even if it's only partially returned.
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int firmware_pfm_verify_get_fw_version_measured_data (const struct firmware_pfm_verify *fw_verify,
	size_t offset, uint8_t *buffer, size_t length, uint32_t *total_len)
{
	if ((fw_verify == NULL) || (buffer == NULL) || (total_len == NULL)) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	*total_len = strlen (fw_verify->version) + 1;

	return buffer_copy ((uint8_t*) fw_verify->version, *total_len, &offset, &length, buffer);
}

/**
 * Update a hash context with the data used for the firmware version string measurement.
 *
 * @param fw_verify The verification handler to query.
 * @param hash Hash engine to update.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int firmware_pfm_verify_hash_fw_version_measured_data (const struct firmware_pfm_verify *fw_verify,
	const struct hash_engine *hash)
{
	if ((fw_verify == NULL) || (hash == NULL)) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	return hash->update (hash, (uint8_t*) fw_verify->version, strlen (fw_verify->version) + 1);
}

/**
 * Get the digest of the PFM that was measured with the last verification.  If there has not been
 * any successful verification, this will be all zeros.
 *
 * @param fw_verify The verification handler to query.
 * @param offset The offset to read data from.
 * @param buffer The output buffer to be filled with measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer with total length of PFM digest. This will always contain the
 * total length of the data even, if it's only partially returned.
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int firmware_pfm_verify_get_pfm_digest_measured_data (const struct firmware_pfm_verify *fw_verify,
	size_t offset, uint8_t *buffer, size_t length, uint32_t *total_len)
{
	if (fw_verify == NULL) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	if (fw_verify->state->result == 0) {
		return manifest_manager_get_manifest_digest_measured_data (&fw_verify->pfm->base,
			fw_verify->hash, offset, buffer, length, total_len);
	}
	else {
		return manifest_manager_get_manifest_digest_measured_data (NULL, fw_verify->hash, offset,
			buffer, length, total_len);
	}
}

/**
 * Update a hash context with the digest of the PFM that was last measured.
 *
 * NOTE:  This cannot be passed the same hash engine instance that has been assigned to the
 * verification handler.
 *
 * @param fw_verify The verification handler to query.
 * @param hash Hash engine to update.  This must be different than the hash engine used by the
 * verification handler.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int firmware_pfm_verify_hash_pfm_digest_measured_data (const struct firmware_pfm_verify *fw_verify,
	const struct hash_engine *hash)
{
	if (fw_verify == NULL) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	if (fw_verify->state->result == 0) {
		return manifest_manager_hash_manifest_digest_measured_data (&fw_verify->pfm->base,
			fw_verify->hash, hash);
	}
	else {
		return manifest_manager_hash_manifest_digest_measured_data (NULL, fw_verify->hash, hash);
	}
}

/**
 * Get the measurement data of the PFM ID that was measured with the last verification.  If there
 * has not  been any successful verification, this will be all zeros.
 *
 * @param fw_verify The verification handler to query.
 * @param offset The offset to read data from.
 * @param buffer The output buffer to be filled with measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer with total length of PFM ID. This will always contain the total
 * length of the data even, if it's only partially returned.
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int firmware_pfm_verify_get_pfm_id_measured_data (const struct firmware_pfm_verify *fw_verify,
	size_t offset, uint8_t *buffer, size_t length, uint32_t *total_len)
{
	if (fw_verify == NULL) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	if (fw_verify->state->result == 0) {
		return manifest_manager_get_id_measured_data (&fw_verify->pfm->base, offset, buffer, length,
			total_len);
	}
	else {
		return manifest_manager_get_id_measured_data (NULL, offset, buffer, length, total_len);
	}
}

/**
 * Update a hash context with the ID of the PFM that was last measured.
 *
 * @param fw_verify The verification handler to query.
 * @param hash Hash engine to update.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int firmware_pfm_verify_hash_pfm_id_measured_data (const struct firmware_pfm_verify *fw_verify,
	const struct hash_engine *hash)
{
	if (fw_verify == NULL) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	if (fw_verify->state->result == 0) {
		return manifest_manager_hash_id_measured_data (&fw_verify->pfm->base, hash);
	}
	else {
		return manifest_manager_hash_id_measured_data (NULL, hash);
	}
}

/**
 * Get the PFM platform ID that was measured with the last verification.  If there has not been any
 * successful verification, this will be an empty string.
 *
 * @param fw_verify The verification handler to query.
 * @param offset The offset to read data from.
 * @param buffer The output buffer to be filled with measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer with total length of PFM platform ID. This will always contain the
 * total length of the data even, if it's only partially returned.
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int firmware_pfm_verify_get_pfm_platform_id_measured_data (
	const struct firmware_pfm_verify *fw_verify, size_t offset, uint8_t *buffer, size_t length,
	uint32_t *total_len)
{
	if (fw_verify == NULL) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	if (fw_verify->state->result == 0) {
		return manifest_manager_get_platform_id_measured_data (&fw_verify->pfm->base, offset,
			buffer, length, total_len);
	}
	else {
		return manifest_manager_get_platform_id_measured_data (NULL, offset, buffer, length,
			total_len);
	}
}

/**
 * Update a hash context with the platform ID of the PFM that was last measured.
 *
 * @param fw_verify The verification handler to query.
 * @param hash Hash engine to update.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int firmware_pfm_verify_hash_pfm_platform_id_measured_data (
	const struct firmware_pfm_verify *fw_verify, const struct hash_engine *hash)
{
	if (fw_verify == NULL) {
		return FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT;
	}

	if (fw_verify->state->result == 0) {
		return manifest_manager_hash_platform_id_measured_data (&fw_verify->pfm->base, hash);
	}
	else {
		return manifest_manager_hash_platform_id_measured_data (NULL, hash);
	}
}
