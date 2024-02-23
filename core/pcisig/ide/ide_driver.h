// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IDE_DRIVER_H_
#define IDE_DRIVER_H_

#include "ide_protocol.h"


/**
 * IDE driver interface.
 */
struct ide_driver {
	/**
	 * Get the IDE bus, device/function, and segment information.
	 *
	 * @param ide_driver The IDE driver interface to query.
	 * @param port_index The port index to query.
	 * @param bus_num The bus number to fill.
	 * @param device_func_num The device function number to fill.
	 * @param segment The segment number to fill.
	 * @param max_port_index The maximum port index to fill.
	 *
	 * @return 0 if the information was successfully filled or an error code.
	 */
	int (*get_bus_device_segment_info) (const struct ide_driver *ide_driver,
		uint8_t port_index, uint8_t *bus_num, uint8_t *device_func_num, uint8_t *segment,
		uint8_t *max_port_index);

	/**
	 * Get the IDE capability register.
	 *
	 * @param ide_driver The IDE driver interface to query.
	 * @param port_index The port index to query.
	 * @param capability_register The capability register to fill.
	 *
	 * @return 0 if the capability register was successfully filled or an error code.
	 */
	int (*get_capability_register) (const struct ide_driver *ide_driver,
		uint8_t port_index, struct ide_capability_register *capability_register);

	/**
	 * Get the IDE control register.
	 *
	 * @param ide_driver The IDE driver interface to query.
	 * @param port_index The port index to query.
	 * @param control_register The control register to fill.
	 *
	 * @return 0 if the control register was successfully filled or an error code.
	 */
	int (*get_control_register) (const struct ide_driver *ide_driver, uint8_t port_index,
		struct ide_control_register *control_register);

	/**
	 * Get the Link IDE register block.
	 *
	 * @param ide_driver The IDE driver interface to query.
	 * @param port_index The port index to query.
	 * @param block_idx The index of the register block to fill.
	 * @param register_block The register block to fill.
	 *
	 * @return 0 if the register block was successfully filled or an error code.
	 */
	 int (*get_link_ide_register_block) (const struct ide_driver *ide_driver,
	 	uint8_t port_index, uint8_t block_idx, struct ide_link_ide_stream_register_block *register_block);

	/**
	 * Get the Selective IDE register block.
	 *
	 * @param ide_driver The IDE driver interface to query.
	 * @param port_index The port index to query.
	 * @param block_idx The index of the register block to fill.
	 * @param register_block The register block to fill.
	 *
	 * @return 0 if the register block was successfully filled or an error code.
	 */
	int (*get_selective_ide_stream_register_block) (const struct ide_driver *ide_driver,
		uint8_t port_index, uint8_t block_idx,
		struct ide_selective_ide_stream_register_block *register_block);

	/**
	 * Stash the IDE host key information.
	 *
	 * @param ide_driver The IDE driver interface to query.
	 * @param port_index The port index to stash the key for.
	 * @param stream_id The stream ID to stash the key for.
	 * @param key_set Key Set to use.
	 * @param tx_key Flag indicating if the key is for TX.
	 * @param key_substream The key substream.
	 * @param key The key to stash.
	 * @param key_size The size of the key.
	 * @param iv The IV to stash.
	 * @param iv_size The size of the IV.
	 *
	 * @return 0 if the key was successfully stashed or an error code.
	 */
	int (*key_prog) (const struct ide_driver *ide_driver,
		uint8_t port_index, uint8_t stream_id, uint8_t key_set, bool tx_key, uint8_t key_substream,
		const uint32_t* key, uint32_t key_size, const uint32_t* iv, uint32_t iv_size);

	/**
	 * Set the IDE host key stashed in the driver via the key_prog function.
	 *
	 * @param ide_driver The IDE driver interface to query.
	 * @param port_index The port index to set the key for.
	 * @param stream_id The stream ID to set the key for.
	 * @param key_set Key Set to use.
	 * @param tx_key Flag indicating if the key is for TX.
	 * @param key_substream The key substream.
	 *
	 * @return 0 if the key was successfully set or an error code.
	 */
	int (*key_set_go) (const struct ide_driver *ide_driver, uint8_t port_index, uint8_t stream_id,
		uint8_t key_set, bool tx_key, uint8_t key_substream);

	/**
	 * Stop using an IDE Key Set.
	 *
	 * @param ide_driver The IDE driver interface to query.
	 * @param port_index The port index to stop the stream for.
	 * @param stream_id The stream ID to stop.
	 * @param key_set Key Set to use.
	 * @param tx_key Flag indicating if the key is for TX.
	 * @param key_substream The key substream.
	 *
	 * @return 0 if the stream was successfully stopped or an error code.
	 */
	int (*key_set_stop) (const struct ide_driver *ide_driver, uint8_t port_index, uint8_t stream_id,
		uint8_t key_set, bool tx_key, uint8_t key_substream);
};


#define	IDE_DRIVER_ERROR(code)	ROT_ERROR (ROT_MODULE_IDE_DRIVER, code)

/**
 * Error codes that can be generated by the IDE driver interface.
 */
enum {
	IDE_DRIVER_INVALID_ARGUMENT = IDE_DRIVER_ERROR (0x00),						/**< Input parameter is null or not valid. */
	IDE_DRIVER_NO_MEMORY = IDE_DRIVER_ERROR (0x01),								/**< Memory allocation failed. */
	IDE_DRIVER_GET_CAPABILITY_REGISTER_FAILED = IDE_DRIVER_ERROR (0x02),		/**< The driver failed to get the capability register. */
	IDE_DRIVER_GET_CONTROL_REGISTER_FAILED = IDE_DRIVER_ERROR (0x03),			/**< The driver failed to get the control register. */
	IDE_DRIVER_GET_LINK_IDE_REGISTER_BLOCK_FAILED = IDE_DRIVER_ERROR (0x04),	/**< The driver failed to get the link IDE register block. */
	IDE_DRIVER_GET_SELECTIVE_IDE_STREAM_REGISTER_BLOCK_FAILED = IDE_DRIVER_ERROR (0x05),	/**< The driver failed to get the selective IDE stream register block. */
	IDE_DRIVER_KEY_PROG_FAILED = IDE_DRIVER_ERROR (0x06),						/**< The driver failed to stash the IDE host key information. */
	IDE_DRIVER_KEY_SET_GO_FAILED = IDE_DRIVER_ERROR (0x07),						/**< The driver failed to set the IDE host key. */
	IDE_DRIVER_KEY_SET_STOP_FAILED = IDE_DRIVER_ERROR (0x08),					/**< The driver failed to stop using the IDE host key. */
	IDE_DRIVER_GET_BUS_DEVICE_SEGMENT_INFO_FAILED = IDE_DRIVER_ERROR (0x09),	/**< The driver failed to get the bus, device/function, and segment information. */
};


#endif /* IDE_DRIVER_H_ */