// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_H_
#define PCD_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "cmd_interface/device_manager.h"
#include "manifest/manifest.h"


/**
 * Container for RoT info.
 */
struct pcd_rot_info {
	bool is_pa_rot;													/**< Flag indicating if RoT is a PA-RoT */
	uint8_t port_count;												/**< Number of ports directly protected by RoT */
	uint8_t components_count;										/**< Number of components attested by RoT */
	uint8_t i2c_slave_addr;											/**< I2C slave address */
	uint8_t eid;													/**< MCTP EID */
	uint8_t bridge_i2c_addr;										/**< MCTP bridge I2C address */
	uint8_t bridge_eid;												/**< MCTP bridge EID */
};

/**
 * Flags for port watchdog monitoring setting.
 */
enum pcd_port_watchdog_monitoring {
	PCD_PORT_WATCHDOG_MONITORING_DISABLED = 0x0,					/**< Watchdog monitoring disabled. */
	PCD_PORT_WATCHDOG_MONITORING_ENABLED = 0x1,						/**< Watchdog monitoring enabled. */
};

/**
 * Flags for port runtime verification setting.
 */
enum pcd_port_runtime_verification {
	PCD_PORT_RUNTIME_VERIFICATION_DISABLED = 0x0,					/**< Runtime verification disabled. */
	PCD_PORT_RUNTIME_VERIFICATION_ENABLED = 0x1,					/**< Runtime verification enabled. */
};

/**
 * Flags for port flash mode.
 */
enum pcd_port_flash_mode {
	PCD_PORT_FLASH_MODE_DUAL = 0x0,									/**< Dual flash mode. */
	PCD_PORT_FLASH_MODE_SINGLE = 0x1,								/**< Single flash mode. */
	PCD_PORT_FLASH_MODE_DUAL_FILTERED_BYPASS = 0x2,					/**< Dual flash mode with filtered bypass. */
	PCD_PORT_FLASH_MODE_SINGLE_FILTERED_BYPASS = 0x3,				/**< Single flash mode with filtered bypass. */
	PCD_PORT_FLASH_MODE_RESERVED,									/**< Reserved value. */
};

/**
 * Flags for port reset control.
 */
enum pcd_port_reset_control {
	PCD_PORT_RESET_CTRL_NOTIFY = 0x0,								/**< Notify when port reset pin toggled. */
	PCD_PORT_RESET_CTRL_RESET = 0x1,								/**< Reset port when port reset pin toggled. */
	PCD_PORT_RESET_CTRL_PULSE = 0x2,								/**< Reset is pulsed after validation. */
	PCD_PORT_RESET_CTRL_RESERVED,									/**< Reserved value. */
};

/**
 * Container for RoT port info.
 */
struct pcd_port_info {
	uint32_t spi_freq;												/**< Port SPI frequency */
	enum pcd_port_flash_mode flash_mode;							/**< Port flash mode */
	enum pcd_port_reset_control reset_ctrl;							/**< Port reset control */
	uint8_t policy;													/**< Port attestation policy */
	enum pcd_port_runtime_verification runtime_verification;		/**< Runtime verification setting */
	enum pcd_port_watchdog_monitoring watchdog_monitoring;			/**< Watchdog monitoring setting */
	uint8_t pulse_interval;											/**< Pulse interval in multiples of 10ms */
};

/**
 * Flags for I2C mode.
 */
enum pcd_i2c_mode {
	PCD_I2C_MODE_MULTIMASTER = 0x0,									/**< MultiMaster I2C communication scheme. */
	PCD_I2C_MODE_MASTER_SLAVE = 0x1,								/**< Master/Slave I2C communication scheme. */
	PCD_I2C_MODE_RESERVED,											/**< Reserved value. */
};

/**
 * Container for power controller info.
 */
struct pcd_power_controller_info {
	uint8_t mux_count;												/**< Number of muxes to reach power controller */
	enum pcd_i2c_mode i2c_mode;										/**< Power controller I2C mode */
	uint8_t bus;													/**< Bus power controller is on */
	uint8_t address;												/**< Power controller address */
	uint8_t eid;													/**< MCTP EID used by power controller if any */
};

/**
 *	Container for mux info.
 */
struct pcd_mux_info {
	uint8_t address;												/**< Mux address */
	uint8_t channel;												/**< Mux channel to utilize */
};

/**
 * Container for MCTP bridge components info.
 */
struct pcd_mctp_bridge_components_info {
	void *context;												/**< Implementation context. */
	uint8_t component_type[SHA256_HASH_LENGTH];					/**< Digest of component type key in PCD and CFM */
	uint16_t pci_vid;											/**< PCI Vendor ID */
	uint16_t pci_device_id;										/**< PCI Device ID */
	uint16_t pci_subsystem_vid;									/**< PCI Subsystem Vendor ID */
	uint16_t pci_subsystem_id;									/**< PCI Subsystem ID */
	uint8_t components_count;									/**< Number of identical components this element describes. */
};

/**
 * The API for interfacing with a PCD file.
 */
struct pcd {
	struct manifest base;											/**< Manifest interface */

	/**
	 * Get next MCTP bridge component from PCD.
	 *
	 * @param pcd The PCD to query.
	 * @param component A container to be updated with the component information.  If first is not
	 * 	true, then same container that was passed previously needs to be passed in.  Instances never
	 * 	passed to this function need to have first set to true.
	 * @param first Fetch first MCTP bridge component from PCD, or next MCTP component since last
	 * 	call.
	 *
	 * @return 0 if a component was found or an error code.
	 */
	int (*get_next_mctp_bridge_component) (struct pcd *pcd,
		struct pcd_mctp_bridge_components_info *component, bool first);

	/* TODO Implement a similar function to get_next_mctp_bridge_component for direct connection
		components */

	/**
	 * Get RoT info.
	 *
	 * @param pcd The PCD to query.
	 * @param info Container with RoT info.
	 *
	 * @return 0 if the RoT info was retrieved successfully or an error code.
	 */
	int (*get_rot_info) (struct pcd *pcd, struct pcd_rot_info *info);

	/**
	 * Get RoT port info.
	 *
	 * @param pcd The PCD to query.
	 * @param port_id ID of requested port.
	 * @param info Info for requested port.
	 *
	 * @return 0 if the port info was retrieved successfully or an error code.
	 */
	int (*get_port_info) (struct pcd *pcd, uint8_t port_id, struct pcd_port_info *info);

	/**
	 * Get power controller info.
	 *
	 * @param pcd The PCD to query.
	 * @param info Container with power controller info.
	 *
	 * @return 0 if the power controller info was retrieved successfully or an error code.
	 */
	int (*get_power_controller_info) (struct pcd *pcd, struct pcd_power_controller_info *info);
};


#define	PCD_ERROR(code)		ROT_ERROR (ROT_MODULE_PCD, code)

/**
 * Error codes that can be generated by a PCD.
 */
enum {
	PCD_INVALID_ARGUMENT = PCD_ERROR (0x00),						/**< Input parameter is null or not valid. */
	PCD_NO_MEMORY = PCD_ERROR (0x01),								/**< Memory allocation failed. */
	PCD_INVALID_PORT = PCD_ERROR (0x02),							/**< Port not found in PCD. */
	PCD_UNKNOWN_COMPONENT = PCD_ERROR (0x03),						/**< The component identifier is not present in the PCD. */
	PCD_MALFORMED_ROT_ELEMENT = PCD_ERROR (0x04),					/**< PCD RoT element too short. */
	PCD_MALFORMED_DIRECT_I2C_COMPONENT_ELEMENT = PCD_ERROR (0x05),	/**< PCD direct i2c component element too short. */
	PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT = PCD_ERROR (0x06),		/**< PCD bridge component element too short. */
	PCD_MALFORMED_PORT_ELEMENT = PCD_ERROR (0x07),					/**< PCD port element too short. */
};


#endif /* PCD_H_ */
