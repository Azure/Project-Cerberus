// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include "spdm_discovery.h"
#include "common/array_size.h"


/**
 * Initialize measurement data for reporting information about the device type. This informaiton is
 * used during the discovery phase of attestation.
 *
 * @param discovery The discovery measurement data to initialize.
 * @param vendor_id The vendor ID to assign to the discovery measurement.
 * @param device_id The device type identifier to assign to the discovery measurement.
 * @param subsystem_vid The subsystem vendor ID to assign to the discovery measurement.
 * @param subsystem_id The subsystem device type identifier to assign to the discovery measurement.
 */
void spdm_discovery_device_id_init (struct spdm_discovery_device_id *discovery, uint16_t vendor_id,
	uint16_t device_id, uint16_t subsystem_vid, uint16_t subsystem_id)
{
	if (discovery == NULL) {
		return;
	}

	discovery->header.completion_code = SPDM_DISCOVERY_DEVICE_ID_BLOCK_CC_SUCCESS;
	discovery->header.device_id_len = sizeof (discovery->descriptor);
	discovery->header.descriptor_count = ARRAY_SIZE (discovery->descriptor);

	discovery->descriptor[0].descriptor_type = SPDM_DISCOVERY_DEVICE_ID_PCI_VID;
	discovery->descriptor[0].descriptor_len = sizeof (discovery->descriptor[0].descriptor_data);
	discovery->descriptor[0].descriptor_data = vendor_id;

	discovery->descriptor[1].descriptor_type = SPDM_DISCOVERY_DEVICE_ID_PCI_DEVICE_ID;
	discovery->descriptor[1].descriptor_len = sizeof (discovery->descriptor[1].descriptor_data);
	discovery->descriptor[1].descriptor_data = device_id;

	discovery->descriptor[2].descriptor_type = SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_VID;
	discovery->descriptor[2].descriptor_len = sizeof (discovery->descriptor[2].descriptor_data);
	discovery->descriptor[2].descriptor_data = subsystem_vid;

	discovery->descriptor[3].descriptor_type = SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_ID;
	discovery->descriptor[3].descriptor_len = sizeof (discovery->descriptor[3].descriptor_data);
	discovery->descriptor[3].descriptor_data = subsystem_id;
}
