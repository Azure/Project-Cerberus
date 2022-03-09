// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef OCP_RECOVERY_H_
#define OCP_RECOVERY_H_

#include <stdint.h>


/* The contents of this file and the protocol handlers that use it are meant to implement the OCP
 * Security Recovery specification, which can be found at
 * https://www.opencompute.org/wiki/Security. */


/**
 * The 7-bit SMBus address that a device should use for OCP Recovery commands if SMBus ARP is not
 * supported.
 */
#define	OCP_RECOVERY_FIXED_SMBUS_ADDRESS		(0xd2 >> 1)

/**
 * OCP Recovery command set.
 */
enum {
	OCP_RECOVERY_CMD_MIN_VALID = 0x22,			/**< Minimum valid command code for OCP recovery. */
	OCP_RECOVERY_CMD_PROT_CAP = 0x22,			/**< Recovery Capabilities command */
	OCP_RECOVERY_CMD_DEVICE_ID = 0x23,			/**< Recovery Device Identifier command */
	OCP_RECOVERY_CMD_DEVICE_STATUS = 0x24,		/**< Device Status command */
	OCP_RECOVERY_CMD_RESET = 0x25,				/**< Reset Control command */
	OCP_RECOVERY_CMD_RECOVERY_CTRL = 0x26,		/**< Recovery Configuration and Control command */
	OCP_RECOVERY_CMD_RECOVERY_STATUS = 0x27,	/**< Recovery Status command */
	OCP_RECOVERY_CMD_HW_STATUS = 0x28,			/**< Hardware Status command */
	OCP_RECOVERY_CMD_INDIRECT_CTRL = 0x29,		/**< Indirect Memory Access Configuration command */
	OCP_RECOVERY_CMD_INDIRECT_STATUS = 0x2a,	/**< Indirect Memory Access Status command */
	OCP_RECOVERY_CMD_INDIRECT_DATA = 0x2b,		/**< Indirect Memory Access command */
	OCP_RECOVERY_CMD_VENDOR = 0x2c,				/**< Vendor Defined command */
	OCP_RECOVERY_CMD_MAX_VALID = 0x2c			/**< Maximum valid command code for OCP recovery. */
};


/* A note on naming.  Enum values are named to directly be associated with the OCP Recovery command
 * for which they are valid.  Some enum types are named to allow them to be used by dependent code.
 * In these cases, the enum name follows the field name in the OCP Recovery spec, which leads to a
 * difference between the naming of the enum type and values. */

#pragma pack(push, 1)
/**
 * Magic string that is returned during capabilities requests.
 */
#define	OCP_RECOVERY_PROT_CAP_MAGIC_STRING		"OCP RECV"

/**
 * OCP Recovery protocol version.
 */
#define	OCP_RECOVERY_PROT_CAP_MAJOR_VERSION		1
#define	OCP_RECOVERY_PROT_CAP_MINOR_VERSION		0

/**
 * Capability bits that can be reported by a device in the PROT_CAP command.
 */
enum {
	OCP_RECOVERY_PROT_CAP_SUPPORTS_IDENTIFICATION = (1U << 0),		/**< Supports the DEVICE_ID command. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_FORCED_RECOVERY = (1U << 1),		/**< Supports the forced recovery option in the RESET command. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_MGMT_RESET = (1U << 2),			/**< Supports a management-only reset option in the RESET command. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_DEVICE_RESET = (1U << 3),		/**< Supports a full device reset option in the RESET command. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_DEVICE_STATUS = (1U << 4),		/**< Supports the DEVICE_STATUS command. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_MEMORY_ACCESS = (1U << 5),		/**< Supports INDIRECT commands to access device memory. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_LOCAL_IMAGE = (1U << 6),			/**< Supports a locally stored for recovery. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_PUSH_IMAGE = (1U << 7),			/**< Supports pushing an image over the recovery interface. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_INTF_ISOLATION = (1U << 8),		/**< Supports control over bus mastering of the recovery interface. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_HW_STATUS = (1U << 9),			/**< Supports the HW_STATUS command. */
	OCP_RECOVERY_PROT_CAP_SUPPORTS_VENDOR_COMMAND = (1U << 10),		/**< Supports the VENDOR command. */
};

/**
 * The maximum device response time, in microseconds.
 */
#define	OCP_RECOVERY_PROT_CAP_RESPONSE_TIME_US(x)	(1U << (x))

/**
 * The heartbeat period for the device, in microseconds.
 */
#define	OCP_RECOVERY_PROT_CAP_HEARTBEAT_US(x)		(((x) == 0) ? 0 : (1U << (x)))

/**
 * OCP Recovery Capabilities (PROT_CAP) command format.
 */
struct ocp_recovery_prot_cap {
	uint8_t magic_string[8];			/**< Magic value indicating an OCP recovery structure. */
	uint8_t major_version;				/**< Major version number of the recovery protocol. */
	uint8_t minor_version;				/**< Minor version number of the recovery protocol. */
	uint16_t capabilities;				/**< Bitmask of device capabilities. */
	uint8_t cms_regions;				/**< Total number CMS regions supported by the device. */
	uint8_t max_response_time;			/**< Maximum time it takes the device to generate a response. */
	uint8_t heartbeat_period;			/**< Period between heartbeat status updates. */
};


/**
 * Identifier specifying the type of ID reported by the device.
 */
enum {
	OCP_RECOVERY_DEVICE_ID_PCI_VENDOR = 0x0,	/**< The device reports a PCI vendor/device ID. */
	OCP_RECOVERY_DEVICE_ID_IANA = 0x1,			/**< The device reports an IANA vendor/product ID. */
	OCP_RECOVERY_DEVICE_ID_UUID = 0x2,			/**< The device reports a UUID. */
	OCP_RECOVERY_DEVICE_ID_PNP_VENDOR = 0x3,	/**< The device reports a PnP vendor/product ID. */
	OCP_RECOVERY_DEVICE_ID_ACPI_VENDOR = 0x4,	/**< The device reports an ACPI vendor/product ID. */
	OCP_RECOVERY_DEVICE_ID_NVME_MI = 0xf,		/**< The device reports NVMe vendor ID. */
};

/**
 * OCP Recovery Device Identifier (DEVICE_ID) command format.
 */
struct ocp_recovery_device_id {
	struct {
		uint8_t id_type;						/**< Type of ID used by the device. */
		uint8_t vendor_length;					/**< Length of the vendor-specific string. */
		union {
			/**
			 * PCI vendor/device ID format.
			 */
			struct ocp_recovery_device_id_pci {
				uint16_t vendor_id;				/**< PCI vendor ID. */
				uint16_t device_id;				/**< PCI device ID. */
				uint16_t subsystem_vendor_id;	/**< PCI subsystem vender ID. */
				uint16_t subsystem_device_id;	/**< PCI subsystem device ID. */
				uint8_t revsion_id;				/**< PCI revision ID. */
				uint8_t pad[13];				/**< Zero padding. */
			} pci;

			/**
			 * IANA vender/product ID format.
			 */
			struct ocp_recovery_device_id_iana {
				uint8_t enterprise_id[4];		/**< IANA enterprise ID. */
				uint8_t product_id[12];			/**< ACPI product ID. */
				uint8_t pad[6];					/**< Zero padding. */
			} iana;

			/**
			 * Device UUID format.
			 */
			struct ocp_recovery_device_id_uuid {
				uint8_t uuid[16];				/**< Device UUID. */
				uint8_t pad[6];					/**< Zero padding. */
			} uuid;

			/**
			 * PnP vendor/product ID format.
			 */
			struct ocp_recovery_device_id_pnp {
				uint8_t vendor_id[3];			/**< PnP vendor ID. */
				uint8_t product_id[4];			/**< PnP product ID. */
				uint8_t pad[15];				/**< Zero padding. */
			} pnp;

			/**
			 * ACPI vendor/product ID format.
			 */
			struct ocp_recovery_device_id_acpi {
				uint8_t vendor_id[4];			/**< ACPI vendor ID. */
				uint8_t product_id[3];			/**< ACPI product ID. */
				uint8_t pad[15];				/**< Zero padding. */
			} acpi;

			/**
			 * NVMe-MI vendor ID format.
			 */
			struct ocp_recovery_device_id_nvme_mi {
				uint16_t vendor_id;				/**< NVMe vendor ID. */
				uint8_t serial_num[20];			/**< Device serial number. */
			} nvme;
		};
	} base;										/**< The minimum required portion of the ID_CAP command. */
	uint8_t vendor_string[231];					/**< Vendor-specific ID string. */
};


/**
 * Status codes for the device reported by the DEVICE_STATUS command.
 */
enum ocp_recovery_device_status_code {
	OCP_RECOVERY_DEVICE_STATUS_PENDING = 0x00,			/**< Device is booting and does not yet have a status. */
	OCP_RECOVERY_DEVICE_STATUS_HEALTHY = 0x01,			/**< Device is running and healthy. */
	OCP_RECOVERY_DEVICE_STATUS_DEVICE_ERROR = 0x02,		/**< Non-fatal or some other "soft" error state. */
	OCP_RECOVERY_DEVICE_STATUS_RECOVERY_MODE = 0x03,	/**< Ready to accept an recovery image. */
	OCP_RECOVERY_DEVICE_STATUS_RECOVERY_PENDING = 0x04,	/**< Waiting for a device reset to apply a recovery image. */
	OCP_RECOVERY_DEVICE_STATUS_RUNNING_RECOVERY = 0x05,	/**< The device recovery image is executing. */
	OCP_RECOVERY_DEVICE_STATUS_BOOT_FAILURE = 0x0e,		/**< Device boot has halted due to some error condition. */
	OCP_RECOVERY_DEVICE_STATUS_FATAL_ERROR = 0x0f,		/**< The device has encountered a fatal error. */
};

/**
 * Status codes for recovery protocol errors that can be reported.
 */
enum {
	OCP_RECOVERY_DEVICE_STATUS_PROTO_NO_ERROR = 0x00,			/**< No error has been encountered. */
	OCP_RECOVERY_DEVICE_STATUS_PROTO_UNSUPPORTED_CMD = 0x01,	/**< A unsupported command was sent to the device. */
	OCP_RECOVERY_DEVICE_STATUS_PROTO_UNSUPPORTED_PARAM = 0x02,	/**< A command received an unsupported parameter. */
	OCP_RECOVERY_DEVICE_STATUS_PROTO_LENGTH_ERROR = 0x03,		/**< A write command contained an invalid number of bytes. */
	OCP_RECOVERY_DEVICE_STATUS_PROTO_CRC_ERROR = 0x04,			/**< The physical layer detected a CRC error. */
};

/**
 * Reason codes for why the device has entered recovery mode.
 */
enum ocp_recovery_recovery_reason_code {
	OCP_RECOVERY_DEVICE_STATUS_REC_NO_FAILURE = 0x00,			/**< No boot failure. */
	OCP_RECOVERY_DEVICE_STATUS_REC_HW_ERROR = 0x01,				/**< A generic HW error occurred. */
	OCP_RECOVERY_DEVICE_STATUS_REC_SOFT_HW_ERROR = 0x02,		/**< A generic soft HW error occurred. */
	OCP_RECOVERY_DEVICE_STATUS_REC_BIST_FAILURE = 0x03,			/**< A self-test failure (e.g. crypto KAT). */
	OCP_RECOVERY_DEVICE_STATUS_REC_NO_CRITICAL_DATA = 0x04,		/**< Data critical for device function was not found or was corrupt. */
	OCP_RECOVERY_DEVICE_STATUS_REC_NO_KEY_MANIFEST = 0x05,		/**< The FW key manifest was not found or was corrupt. */
	OCP_RECOVERY_DEVICE_STATUS_REC_MAIFEST_AUTH_FAIL = 0x06,	/**< The FW key manifest failed authentication. */
	OCP_RECOVERY_DEVICE_STATUS_REC_MANIFEST_REVOKED = 0x07,		/**< The FW key manifest failed anti-rollback checks. */
	OCP_RECOVERY_DEVICE_STATUS_REC_NO_BOOT_LOADER = 0x08,		/**< The FW boot loader was not found or was corrupt. */
	OCP_RECOVERY_DEVICE_STATUS_REC_BOOT_AUTH_FAIL = 0x09,		/**< The FW boot loader failed authentication. */
	OCP_RECOVERY_DEVICE_STATUS_REC_BOOT_REVOKED = 0x0a,			/**< The FW boot loader failed anti-rollback checks. */
	OCP_RECOVERY_DEVICE_STATUS_REC_NO_FW_IMAGE  = 0x0b,			/**< The main FW image was not found or was corrupt. */
	OCP_RECOVERY_DEVICE_STATUS_REC_FW_AUTH_FAIL = 0x0c,			/**< The main FW image failed authentication. */
	OCP_RECOVERY_DEVICE_STATUS_REC_FW_REVOKED = 0x0d,			/**< The main FW image failed anti-rollback checks. */
	OCP_RECOVERY_DEVICE_STATUS_REC_NO_RECOVERY_FW = 0x0e,		/**< The recovery FW was not found or was corrupt. */
	OCP_RECOVERY_DEVICE_STATUS_REC_RECOVERY_AUTH_FAIL = 0x0f,	/**< The recovery FW failed authentication. */
	OCP_RECOVERY_DEVICE_STATUS_REC_RECOVERY_REVOKED = 0x10,		/**< The recovery FW failed anti-rollback checks. */
	OCP_RECOVERY_DEVICE_STATUS_REC_FORCED_RECOVERY = 0x11,		/**< The device was forced into recovery mode. */
};

/**
 * OCP Recovery Device Status (DEVICE_STATUS) command format.
 */
struct ocp_recovery_device_status {
	struct {
		uint8_t status;				/**< Overall device status. */
		uint8_t protocol_status;	/**< Status of the last recovery protocol message received. */
		uint16_t recovery_reason;	/**< Status code indicating why the device is in recovery mode. */
		uint16_t heartbeat;			/**< Counter indicating device activity. */
		uint8_t vendor_length;		/**< Length of the vendor-defined status. */
	} base;							/**< The minimum required portion of the DEVICE_STATUS command. */
	uint8_t vendor_status[248];		/**< Vendor-defined status information. */
};


/**
 * Types of device reset that can be performed.
 */
enum {
	OCP_RECOVERY_RESET_NO_RESET = 0x00,			/**< Do not reset the device. */
	OCP_RECOVERY_RESET_DEVICE_RESET = 0x01,		/**< Full device reset.  Likely disruptive to any bus activity. */
	OCP_RECOVERY_RESET_MGMT_RESET = 0x02,		/**< Only reset the management subsystem.  This must not impact any bus activity. */
};

/**
 * Control indicator for forcing the device into recovery mode.
 */
enum {
	OCP_RECOVERY_RESET_NO_FORCED_RECOVERY = 0x00,	/**< Recovery mode is not forced on the next device reset. */
	OCP_RECOVERY_RESET_FORCED_RECOVERY = 0x0f,		/**< Force the device into recovery mode on the next device reset. */
};

/**
 * Control for interface mastering.
 */
enum {
	OCP_RECOVERY_RESET_INTF_DISABLE_MASTERING = 0x00,	/**< The interface must not master the physical bus. */
	OCP_RECOVERY_RESET_INTF_ENABLE_MASTERING = 0x01,	/**< The interface may master the physical bus. */
};

/**
 * OCP Recovery Reset (RESET) command format.
 */
struct ocp_recovery_reset {
	uint8_t reset_ctrl;				/**< Control resets triggered through the recovery interface. */
	uint8_t forced_recovery;		/**< Control recovery mode execution on the next reset. */
	uint8_t intf_control;			/**< Control for interface bus mastering. */
};


/**
 * Types of recovery image that can be used with the device.
 */
enum {
	OCP_RECOVERY_RECOVERY_CTRL_IMAGE_NONE = 0x00,		/**< No recovery image should be used. */
	OCP_RECOVERY_RECOVERY_CTRL_IMAGE_FROM_CMS = 0x01,	/**< Use a recovery image from a memory region. */
	OCP_RECOVERY_RECOVERY_CTRL_IMAGE_IN_DEVICE = 0x02,	/**< Use a recovery image stored in the device. */
};

/**
 * Control indicator for executing a recovery image.
 */
enum {
	OCP_RECOVERY_RECOVERY_CTRL_ACTIVATE_NONE = 0x00,	/**< Do not activate the recovery image. */
	OCP_RECOVERY_RECOVERY_CTRL_ACTIVATE_IMAGE = 0x0f,	/**< Activate the recovery image. */
};

/**
 * OCP Recovery Control (RECOVERY_CTRL) command format.
 */
struct ocp_recovery_recovery_ctrl {
	uint8_t cms;					/**< Memory region to use for loading a recovery image. */
	uint8_t recovery_image;			/**< The type of recovery image to use. */
	uint8_t activate;				/**< Control recovery image activation. */
};


/**
 * Status codes for the device recovery image reported by RECOVERY_STATUS.
 */
enum {
	OCP_RECOVERY_RECOVERY_STATUS_NOT_RECOVERY_MODE = 0x00,		/**< Device is not in recovery mode .*/
	OCP_RECOVERY_RECOVERY_STATUS_WAITING_FOR_IMAGE = 0x01,		/**< Device is waiting to receive a recovery image .*/
	OCP_RECOVERY_RECOVERY_STATUS_BOOTING_IMAGE = 0x02,			/**< A recovery image is being loaded. */
	OCP_RECOVERY_RECOVERY_STATUS_SUCCESSFUL = 0x03,				/**< The recovery image is current running. */
	OCP_RECOVERY_RECOVERY_STATUS_FAILED = 0x0c,					/**< Failed to execute the recovery image. */
	OCP_RECOVERY_RECOVERY_STATUS_AUTH_FAILURE = 0x0d,			/**< The recovery image failed authentication. */
	OCP_RECOVERY_RECOVERY_STATUS_ENTER_RECOVERY_FAIL = 0x0e,	/**< There was an error while trying to enter recovery mode. */
	OCP_RECOVERY_RECOVERY_STATUS_INVALID_CMS = 0x0f,			/**< An invalid CMS was specified for the recovery image. */
};

/**
 * OCP Recovery Status (RECOVERY_STATUS) command format.
 */
struct ocp_recovery_recovery_status {
	uint8_t status;					/**< Status of the most recent recovery operation. */
	uint8_t vendor_status;			/**< Vendor-defined status code. */
};


/**
 * Error bits for HW failures.
 */
enum {
	OCP_RECOVERY_HW_STATUS_TEMP_ERROR = (1U << 0),			/**< The device temperature is critical. */
	OCP_RECOVERY_HW_STATUS_SOFT_ERROR = (1U << 1),			/**< A non-fatal error, which may need a reset to clear. */
	OCP_RECOVERY_HW_STATUS_FATAL_ERROR = (1U << 2),			/**< A fatal HW error. */
};

/**
 * OCP Recovery HW Status (HW_STATUS) command format.
 */
struct ocp_recovery_hw_status {
	struct {
		uint8_t status;				/**< Current error state of the device HW. */
		uint8_t vendor_status;		/**< Vendor-defined HW status. */
		uint16_t temperature;		/**< Current temperature of the device. */
		uint8_t vendor_length;		/**< Length of the vendor-specific status. */
	} base;							/**< The minimum required portion of the HW_STATUS command. */
	uint8_t vendor_hw_status[250];	/**< Extra vendor-specific HW status. */
};


/**
 * OCP Recovery Indirect Control (INDIRECT_CTRL) command format.
 */
struct ocp_recovery_indirect_ctrl {
	uint8_t cms;					/**< Index for the memory region to access. */
	uint8_t reserved;				/**< Unused. */
	uint32_t offset;				/**< The offset within the memory region to start accessing data from. */
};


/**
 * Status bits for indirect memory accesses to a memory region.
 */
enum {
	OCP_RECOVERY_INDIRECT_STATUS_OVERLFLOW = (1U << 0),		/**< The region access as overflowed the bounds and wrapped to the beginning. */
	OCP_RECOVERY_INDIRECT_STATUS_READ_ONLY = (1U << 1),		/**< A write was attempted to a read only region. */
	OCP_RECOVERY_INDIRECT_STATUS_POLLING_ACK = (1U << 2),	/**< ACK from the device for polling memory regions. */
};

/**
 * Identifier for the region type that is exposed for indirect access.
 */
enum ocp_recovery_region_type {
	OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE = 0x00,			/**< A R/W region for storing a recovery image. */
	OCP_RECOVERY_INDIRECT_STATUS_REGION_LOG = 0x01,						/**< A RO region that stores log information in the standard format. */
	OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW = 0x05,				/**< A vendor-defined R/W region. */
	OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RO = 0x06,				/**< A vendor-defined RO region. */
	OCP_RECOVERY_INDIRECT_STATUS_REGION_UNSUPPORTED = 0x07,				/**< The region is not supported by the device. */
	OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE_POLLING = 0x08,	/**< A R/W region for storing a recovery image. */
	OCP_RECOVERY_INDIRECT_STATUS_REGION_LOG_POLLING = 0x09,				/**< A RO region that stores log information in the standard format. */
	OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW_POLLING = 0x0d,		/**< A vendor-defined R/W region. */
	OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RO_POLLING = 0x0e,		/**< A vendor-defined RO region. */
};

/**
 * Flag on the region type that indicates that accesses require polling the ACK bit before issuing
 * additional indirect commands.
 */
#define	OCP_RECOVERY_INDIRECT_STATUS_REGION_POLLING_FLAG	(1U << 3)

/**
 * OCP Recovery Indirect Status (INDIRECT_STATUS) command format.
 */
struct ocp_recovery_indirect_status {
	uint8_t status;					/**< Status of the last indirect operation. */
	uint8_t type;					/**< The type of region currently being accessed. */
	uint32_t size;					/**< Total size of the memory region, in 4-byte units. */
};


/**
 * OCP Recovery Indirect Data (INDIRECT_DATA) command format.
 */
struct ocp_recovery_indirect_data {
	uint8_t data[255];				/**< Data to or from the active memory region at the current offset. */
};


/**
 * OCP Recovery Vendor (VENDOR) command format.
 */
struct ocp_recovery_vendor {
	uint8_t vendor[255];			/**< Vendor-defined data. */
};
#pragma pack(pop)


#endif /* OCP_RECOVERY_H_ */
