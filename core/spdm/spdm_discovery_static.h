// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_DISCOVERY_STATIC_H_
#define SPDM_DISCOVERY_STATIC_H_

#include "spdm_discovery.h"


/**
 * Initialize a static instance of measurement data for reporting information about the device type.
 * This information is used during the discovery phase of attestation.
 *
 * @param vendor_id_arg The vendor ID to assign to the discovery measurement.
 * @param device_id_arg The device type identifier to assign to the discovery measurement.
 * @param subsystem_vid_arg The subsystem vendor ID to assign to the discovery measurement.
 * @param subsystem_id_arg The subsystem device type identifier to assign to the discovery
 * measurement.
 */
#define	spdm_discovery_device_id_static_init(vendor_id_arg, device_id_arg, subsystem_vid_arg, \
	subsystem_id_arg)	{ \
		.header = { \
			.completion_code = 0, \
			.device_id_len = sizeof (struct spdm_discovery_pci_id_descriptor) * 4, \
			.descriptor_count = 4, \
		}, \
		.descriptor = { \
			{ \
				.descriptor_type = SPDM_DISCOVERY_DEVICE_ID_PCI_VID, \
				.descriptor_len = 2, \
				.descriptor_data = vendor_id_arg, \
			}, \
			{ \
				.descriptor_type = SPDM_DISCOVERY_DEVICE_ID_PCI_DEVICE_ID, \
				.descriptor_len = 2, \
				.descriptor_data = device_id_arg, \
			}, \
			{ \
				.descriptor_type = SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_VID, \
				.descriptor_len = 2, \
				.descriptor_data = subsystem_vid_arg, \
			}, \
			{ \
				.descriptor_type = SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_ID, \
				.descriptor_len = 2, \
				.descriptor_data = subsystem_id_arg, \
			}, \
		}, \
	}


#endif	/* SPDM_DISCOVERY_STATIC_H_ */
