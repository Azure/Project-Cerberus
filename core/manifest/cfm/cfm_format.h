// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_FORMAT_H_
#define CFM_FORMAT_H_

#include <stdint.h>
#include "manifest/manifest_format.h"


/**
 * The CFM is a variable length structure that has the following format:
 *
 * struct {
 * 		struct manifest_header
 * 		struct cfm_components_header
 * 		<components>[cfm_components_header.components_count]
 * 		uint8_t signature[manifest_header.sig_length]
 * }
 *
 *
 * Each component is defined with a descriptor that is a variable length structure with the
 * following format:
 *
 * struct {
 * 		struct cfm_component_header
 * 		<firmware_imgs>[cfm_component_header.fw_count]
 * }
 *
 *
 * Each firmware is defined with a descriptor that is a variable length structure with the
 * following format:
 *
 * struct {
 * 		struct cfm_fw_header
 * 		uint8_t version[cfm_img_header.version_length]
 * 		uint8_t alignment[0..3]
 * 		<signed_imgs>[cfm_fw_header.imgs_count]
 * }
 *
 * Each signed image is defined with a descriptor that is a variable length structure with the
 * following format:
 *
 * struct {
 * 		struct cfm_img_header
 * 		uint8_t digest[cfm_img_header.digest_length]
 * }
 */


/**
 * The header information for the CFM components list.
 */
struct cfm_components_header {
	uint16_t length;						/**< The total length of the CFM components list. */
	uint8_t components_count;				/**< The number of components contained in the CFM. */
	uint8_t reserved;						/**< Unused. */
};

/**
 * The information on each component in the CFM.
 */
struct cfm_component_header {
	uint16_t length;						/**< The total length of the component descriptor. */
	uint8_t fw_count;						/**< Then number of firmware images supported by this component. */
	uint8_t reserved;						/**< Unused. */
	uint32_t component_id;					/**< Component device identifier */
};

/**
 * The information on each component firmware in the CFM.
 */
struct cfm_fw_header {
	uint16_t length;						/**< The total length of the firmware descriptor. */
	uint8_t img_count;						/**< Then number of signed images part of this component firmware. */
	uint8_t reserved;						/**< Unused. */
	uint16_t version_length;				/**< The length of the firmware version identifier */
	uint16_t reserved2;						/**< Unused. */
};

/**
 * The information on each component firmware signed image in the CFM.
 */
struct cfm_img_header {
	uint16_t length;						/**< The total length of the image descriptor. */
	uint16_t digest_length;					/**< The length of the image digest. */
	uint16_t flags;							/**< Signed image flags. */
	uint16_t reserved;						/**< Unused. */
};

/**
 * The two LSB in the flags field in cfm_img_header correspond to failure actions defined below.
 */
enum cfm_failure_actions {
	CFM_FAILURE_PLATFORM_DEFINED = 0,		/**< Action platform defined. */
	CFM_FAILURE_REPORT_ONLY,				/**< Only report component failure. */
	CFM_FAILURE_AUTORECOVERY,				/**< Perform auto recovery of component. */
	CFM_FAILURE_POWEROFF					/**< Power off component. */
};

#define CFM_FLAGS_FAILURE_ACTIONS_SHIFT	 	0
#define CFM_FLAGS_FAILURE_ACTIONS_MASK		(3U << CFM_FLAGS_FAILURE_ACTIONS_SHIFT)


#endif /* CFM_FORMAT_H_ */
