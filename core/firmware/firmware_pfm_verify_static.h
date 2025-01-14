// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_PFM_VERIFY_STATIC_H_
#define FIRMWARE_PFM_VERIFY_STATIC_H_

#include "firmware_pfm_verify.h"


/**
 * Initialize a static instance of a handler for device firmware that leverages a PFM for providing
 * verification and measurement of the image.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for firmware verification.
 * @param flash_ptr Flash device that contains the firmware image that will be verified.
 * @param pfm_ptr The PFM to use for firmware verification and measurement.
 * @param hash_ptr Hash engine to use for firmware image verification.
 * @param sig_verify_ptr Engine to use for PFM verification.
 * @param pcr_ptr Manager for PCRs to use for storing verification measurements.
 * @param version_buffer_ptr Buffer that will be used to store the firmware version string from the
 * PFM.
 * @param max_version_length_arg Length of the firmware version buffer, including the NULL
 * terminator.
 * @param measurement_result PCR measurement index to update with the result of PFM verification.
 * @param measurement_version PCR measurement index to update with the firmware version string from
 * the PFM.
 * @param measurement_pfm PCR measurement index to update with the PFM digest.
 * @param measurement_pfm_id PCR measurement index to update with the PFM ID.
 * @param measurement_platform_id PCR measurement index to update with the PFM platform ID.
 */
#define	firmware_pfm_verify_static_init(state_ptr, flash_ptr, pfm_ptr, hash_ptr, sig_verify_ptr, \
	pcr_ptr, version_buffer_ptr, max_version_length_arg, measurement_result_arg, \
	measurement_version_arg, measurement_pfm_arg, measurement_pfm_id_arg, \
	measurement_platform_id_arg)	{ \
		.state = state_ptr, \
		.flash = flash_ptr, \
		.pfm = pfm_ptr, \
		.hash = hash_ptr, \
		.sig_verify = sig_verify_ptr, \
		.pcr = pcr_ptr, \
		.version = version_buffer_ptr, \
		.max_version = max_version_length_arg, \
		.measurement_result = measurement_result_arg, \
		.measurement_version = measurement_version_arg, \
		.measurement_pfm = measurement_pfm_arg, \
		.measurement_pfm_id = measurement_pfm_id_arg, \
		.measurement_platform_id = measurement_platform_id_arg, \
	}


#endif	/* FIRMWARE_PFM_VERIFY_STATIC_H_ */
