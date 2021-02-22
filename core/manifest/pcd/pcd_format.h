// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_FORMAT_H_
#define PCD_FORMAT_H_

#include <stdint.h>
#include "manifest/manifest_format.h"


#define PCD_ROT_HDR_IS_PA_ROT_SHIFT						0
#define PCD_ROT_HDR_IS_PA_ROT_SET_MASK					(1U << PCD_ROT_HDR_IS_PA_ROT_SHIFT)
#define PCD_ROT_HDR_IS_PA_ROT_CLR_MASK					(~PCD_ROT_HDR_IS_PA_ROT_SET_MASK)

#define PCD_COMPONENT_HDR_I2C_MODE_SHIFT				0
#define PCD_COMPONENT_HDR_I2C_MODE_SET_MASK				(1U << PCD_COMPONENT_HDR_I2C_MODE_SHIFT)
#define PCD_COMPONENT_HDR_I2C_MODE_CLR_MASK				(~PCD_COMPONENT_HDR_I2C_MODE_SET_MASK)


/**
 * The PCD is a variable length structure that has the following format:
 *
 * struct {
 * 		struct manifest_header
 * 		struct pcd_header
 * 		struct pcd_rot_header
 * 		<struct pcd_port_header> [pcd_rot_header.num_ports]
 * 		struct pcd_components_header
 * 		<components> [pcd_components_header.num_components]
 * 		struct pcd_platform_header
 * 		char platform_id[pcd_platform_header.id_len]
 * 		uint8_t signature[manifest_header.sig_length]
 * }
 *
 * Each component is a variable length structure that has the following format:
 *
 * struct {
 * 		struct pcd_component_header
 * 		<struct pcd_mux_header> [pcd_component_header.num_muxes]
 * }
 */

/**
 * The header information for the PCD.
 */
struct pcd_header {
	uint16_t length;						/**< Total length of PCD without manifest header and signature. */
	uint16_t header_len;					/**< PCD header length. */
	uint8_t format_id;						/**< PCD format ID. */
	uint8_t reserved1;						/**< Reserved. */
	uint8_t reserved2;						/**< Reserved. */
	uint8_t reserved3;						/**< Reserved. */
};

/**
 * The header information for the PCD RoT.
 */
struct pcd_rot_header {
	uint16_t length;						/**< Total length of PCD RoT section including header. */
	uint16_t header_len;					/**< Length of PCD RoT header. */
	uint8_t format_id;						/**< PCD RoT format ID. */
	uint8_t num_ports;						/**< Number of ports in RoT. */
	uint8_t addr;							/**< I2C slave address */
	uint8_t bmc_i2c_addr;					/**< BMC I2C address */
	uint8_t cpld_addr;						/**< CPLD I2C slave address */
	uint8_t cpld_channel;					/**< CPLD I2C bus channel */
	uint8_t active;						   	/**< Policy active */
	uint8_t default_failure_action;		   	/**< Default action on attestation failure */
	uint8_t flags;							/**< Field for flags */
	uint8_t reserved1;						/**< Reserved. */
	uint8_t reserved2;						/**< Reserved. */
	uint8_t reserved3;						/**< Reserved. */
};

/**
 * The header information for a RoT port section.
 */
struct pcd_port_header {
	uint16_t length;						/**< Total length of RoT ports section. */
	uint16_t header_len;					/**< Length of PCD port header. */
	uint8_t format_id;						/**< RoT ports format ID. */
	uint8_t id;								/**< Port ID */
	uint8_t reserverd1;						/**< Reserved. */
	uint8_t reserverd2;						/**< Reserved. */
	uint32_t frequency;						/**< Bus frequency */
};

/**
 * The header information for the PCD components section.
 */
struct pcd_components_header {
	uint16_t length;						/**< Total length of PCD components section. */
	uint16_t header_len;					/**< Length of PCD components header. */
	uint8_t format_id;						/**< PCD components format ID. */
	uint8_t num_components;					/**< Number of components in PCD. */
	uint8_t reserved1;						/**< Reserved. */
	uint8_t reserved2;						/**< Reserved. */
};

/**
 * The header information for a PCD component.
 */
struct pcd_component_header {
	uint16_t length;						/**< Total length of PCD component. */
	uint16_t header_len;					/**< Length of PCD component header. */
	uint8_t format_id;						/**< PCD component format ID. */
	uint8_t num_muxes;						/**< Number of muxes in component. */
	uint8_t addr;							/**< I2C slave address */
	uint8_t channel;						/**< I2C bus channel */
	uint8_t flags;							/**< Field for flags */
	uint8_t eid;							/**< MCTP EID */
	uint8_t power_ctrl_reg;					/**< Power control register */
	uint8_t power_ctrl_mask; 				/**< Power control bitmask */
	uint32_t id; 							/**< Component ID. */
};

/**
 * The header information for a mux section.
 */
struct pcd_mux_header {
	uint16_t length;						/**< Total length of component mux section. */
	uint16_t header_len;					/**< Length of PCD mux header */
	uint8_t format_id;						/**< Component mux format ID. */
	uint8_t addr;							/**< I2C slave address */
	uint8_t channel;						/**< I2C bus channel */
	uint8_t mux_level;						/**< Mux level */
};

/**
 * The header information for the platform information.
 */
struct pcd_platform_header {
	uint16_t length;						/**< The total length of the platform descriptor. */
	uint16_t header_len;					/**< Length of PCD platform header. */
	uint8_t format_id;						/**< PCD platform header format ID. */
	uint8_t id_len;							/**< Platform ID length. */
	uint8_t reserved1;						/**< Reserved. */
	uint8_t reserved2;						/**< Reserved. */
};


#endif /* PCD_FORMAT_H_ */
