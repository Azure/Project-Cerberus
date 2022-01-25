// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_FORMAT_H_
#define PCD_FORMAT_H_

#include <stdint.h>
#include "manifest/manifest_format.h"
#include "manifest/pcd/pcd.h"


/**
 * Type identifiers for PCD v2 elements.
 */
enum pcd_element_type {
	PCD_ROT = 0x40,												/**< Information about the RoT configuration. */
	PCD_SPI_FLASH_PORT = 0x41,									/**< Information about protected firmware stored on SPI flash. */
	PCD_POWER_CONTROLLER = 0x42,								/**< Information about power controller utilized by RoT. */
	PCD_COMPONENT_DIRECT = 0x43,								/**< A single component connected directly to RoT. */
	PCD_COMPONENT_MCTP_BRIDGE = 0x44,							/**< A components connected to RoT through an MCTP bridge. */
};

/**
 * Flags for policy failure action.
 */
enum pcd_policy_failure_action {
	PCD_POLICY_FAILURE_ACTION_PASSIVE = 0x0,					/**< Report policy failure through attestation. */
	PCD_POLICY_FAILURE_ACTION_ACTIVE = 0x1,						/**< Prevent failed device from booting. */
};


#pragma pack(push, 1)
struct pcd_rot_element {
	uint8_t rot_flags;											/**< Flags pertaining to RoT configuration. */
	uint8_t port_count;											/**< The number of ports protected by RoT. */
	uint8_t components_count;									/**< The number of components attested by RoT. */
	uint8_t rot_address;										/**< RoT slave address to utilize. */
	uint8_t rot_eid;											/**< Default RoT MCTP EID to utilize. */
	uint8_t bridge_address;										/**< MCTP bridge slave address. */
	uint8_t bridge_eid;											/**< MCTP bridge EID. */
	uint8_t reserved;											/**< Unused. */
};

#define PCD_ROT_FLAGS_ROT_TYPE_SHIFT							0
#define PCD_ROT_FLAGS_ROT_TYPE_SET_MASK							(1 << PCD_ROT_FLAGS_ROT_TYPE_SHIFT)

/**
 * Flags for RoT configuration.
 */
enum pcd_rot_type_flags {
	PCD_ROT_TYPE_PA_ROT = 0x0,									/**< PA-ROT. */
	PCD_ROT_TYPE_AC_ROT = 0x1,									/**< AC-ROT. */
};

/**
 * Get RoT type.
 *
 * @param rot Pointer to a pcd_rot element.
 */
#define	pcd_get_rot_type(rot)	(enum pcd_rot_type_flags) (((rot)->rot_flags) & \
	PCD_ROT_FLAGS_ROT_TYPE_SET_MASK)

/**
 * A port section defined in PCD as part of RoT element.
 */
struct pcd_port_element {
	uint8_t port_id;											/**< Port ID. */
	uint8_t port_flags;											/**< Flags with port configuration. */
	uint8_t policy;												/**< Port attestation policy. */
	uint8_t pulse_interval;										/**< Pulse interval if port is to pulse reset. */
	uint32_t spi_frequency_hz;									/**< Flash SPI frequency in Hz. */
};

#define PCD_PORT_FLAGS_WATCHDOG_MONITORING_SHIFT				5
#define PCD_PORT_FLAGS_WATCHDOG_MONITORING_SET_MASK				(1 << PCD_PORT_FLAGS_WATCHDOG_MONITORING_SHIFT)

#define PCD_PORT_FLAGS_RUNTIME_VERIFICATION_SHIFT				4
#define PCD_PORT_FLAGS_RUNTIME_VERIFICATION_SET_MASK			(1 << PCD_PORT_FLAGS_RUNTIME_VERIFICATION_SHIFT)

#define PCD_PORT_FLAGS_FLASH_MODE_SHIFT							2
#define PCD_PORT_FLAGS_FLASH_MODE_SET_MASK						(3 << PCD_PORT_FLAGS_FLASH_MODE_SHIFT)

#define PCD_PORT_FLAGS_RESET_CTRL_SHIFT							0
#define PCD_PORT_FLAGS_RESET_CTRL_SET_MASK						(3 << PCD_PORT_FLAGS_RESET_CTRL_SHIFT)

/**
 * Get port watchdog monitoring setting.
 *
 * @param port Pointer to a pcd_port element.
 */
#define	pcd_get_port_watchdog_monitoring(port)	(enum pcd_port_watchdog_monitoring) ((((port)->port_flags) & \
	PCD_PORT_FLAGS_WATCHDOG_MONITORING_SET_MASK) >> PCD_PORT_FLAGS_WATCHDOG_MONITORING_SHIFT)

/**
 * Get port runtime verification setting.
 *
 * @param port Pointer to a pcd_port element.
 */
#define	pcd_get_port_runtime_verification(port)	(enum pcd_port_runtime_verification) ((((port)->port_flags) & \
	PCD_PORT_FLAGS_RUNTIME_VERIFICATION_SET_MASK) >> PCD_PORT_FLAGS_RUNTIME_VERIFICATION_SHIFT)

/**
 * Get port flash mode.
 *
 * @param port Pointer to a pcd_port element.
 */
#define	pcd_get_port_flash_mode(port)	(enum pcd_port_flash_mode) ((((port)->port_flags) & \
	PCD_PORT_FLAGS_FLASH_MODE_SET_MASK) >> PCD_PORT_FLAGS_FLASH_MODE_SHIFT)

/**
 * Get port reset control setting.
 *
 * @param port Pointer to a pcd_port element.
 */
#define	pcd_get_port_reset_control(port)	(enum pcd_port_reset_control) (((port)->port_flags) & \
	PCD_PORT_FLAGS_RESET_CTRL_SET_MASK)

/**
 * A single I2C mux section.
 */
struct pcd_mux {
	uint8_t mux_address;										/**< I2C slave address of mux. */
	uint8_t mux_channel;										/**< Channel to activate on mux. */
	uint16_t reserved;											/**< Unused. */
};

/**
 * Container for fields common to I2C interface sections in elements.
 */
struct pcd_i2c_interface {
	uint8_t mux_count:4;										/**< Number of muxes in I2C path from RoT to device. */
	uint8_t i2c_flags:4;										/**< Flags with I2C configuration. */
	uint8_t bus;												/**< I2C bus device is on. */
	uint8_t address;											/**< Device I2C slave address. */
	uint8_t eid;												/**< Device MCTP EID, 0x00 if not utilizing MCTP. */
};

#define PCD_I2C_FLAGS_I2C_MODE_SHIFT							0
#define PCD_I2C_FLAGS_I2C_MODE_SET_MASK							(3 << PCD_I2C_FLAGS_I2C_MODE_SHIFT)

/**
 * Get i2c mode for i2c interface.
 *
 * @param i2c Pointer to a pcd_i2c_interface element.
 */
#define	pcd_get_i2c_interface_i2c_mode(i2c)	(enum pcd_i2c_mode) (((i2c)->i2c_flags) & \
	PCD_I2C_FLAGS_I2C_MODE_SET_MASK)

/**
 * An I2C power controller element.
 */
struct pcd_power_controller_element {
	struct pcd_i2c_interface i2c;								/**< Power controller I2C interface. */
};

/**
 * Container for fields common to component elements.
 */
struct pcd_component_common {
	uint8_t policy;												/**< Component attestation policy. */
	uint8_t power_ctrl_reg;										/**< Power control register. */
	uint8_t power_ctrl_mask;									/**< Power control mask. */
	uint8_t type_len;											/**< Component type length. */
	uint8_t type[MANIFEST_MAX_STRING];							/**< Component type. */
};

/**
 * Element for a component with direct I2C connection to RoT.
 */
struct pcd_direct_i2c_component_element {
	struct pcd_component_common component;						/**< Common component configuration. */
	struct pcd_i2c_interface i2c;								/**< Component I2C interface. */
};

/**
 * Container for connection information for a component with connection to RoT through MCTP bridge.
 */
struct pcd_mctp_bridge_component_connection {
	uint16_t device_id;											/**< Device ID. */
	uint16_t vendor_id;											/**< Vendor ID. */
	uint16_t subsystem_device_id;								/**< Subsystem device ID. */
	uint16_t subsystem_vendor_id;								/**< Subsystem vendor ID. */
	uint8_t components_count;									/**< Number of identical components this element describes. */
	uint8_t eid;												/**< Default EID to use if cannot retrieve EID table from MCTP bridge. */
	uint16_t reserved;											/**< Unused. */
};

/**
 * Element for a component with connection to RoT through MCTP bridge.
 */
struct pcd_mctp_bridge_component_element {
	struct pcd_component_common component;						/**< Common component configuration. */
	struct pcd_mctp_bridge_component_connection connection;		/**< Component connection information. */
};

/**
 * Get component connection portion from a MCTP bridge component element container.
 *
 * @param component Pointer to a buffer containing a pcd_mctp_bridge_component_element element.
 * @param len Length of buffer
 */
#define	pcd_get_mctp_bridge_component_connection(component, len) ((struct pcd_mctp_bridge_component_connection*) \
	((component) + len - sizeof (struct pcd_mctp_bridge_component_connection)))
#pragma pack(pop)


#endif /* PCD_FORMAT_H_ */
