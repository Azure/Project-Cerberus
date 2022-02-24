// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEVICE_MANAGER_
#define DEVICE_MANAGER_

#include <stdint.h>
#include "status/rot_status.h"
#include "manifest/manifest_format.h"
#include "common/certificate.h"
#include "crypto/hash.h"


/**
 * Number in device table reserved for self
 */
#define DEVICE_MANAGER_SELF_DEVICE_NUM					0

/**
 * Number in device table reserved for MCTP bridge
 */
#define DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM			1


/**
 * Device states
 */
enum {
	DEVICE_MANAGER_NOT_READY = 0,						/**< Communication with device not established */
	DEVICE_MANAGER_AVAILABLE,							/**< Device ready for communication, but unauthenticated */
	DEVICE_MANAGER_AUTHENTICATED,						/**< Authenticated state */
	NUM_DEVICE_MANAGER_STATES							/**< Number of device states */
};

/**
 * Device hierarchy roles as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_AC_ROT_MODE = 0,						/**< Device acting as AC-RoT */
	DEVICE_MANAGER_PA_ROT_MODE,							/**< Device acting as PA-RoT */
	NUM_BUS_HIERACHY_ROLES								/**< Number of hierarchy roles */
};

/**
 * Roles a device supports on the I2C bus as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_UNKNOWN_BUS_ROLE = 0,				/**< Unknown bus role */
	DEVICE_MANAGER_MASTER_BUS_ROLE,						/**< Device acting as bus master */
	DEVICE_MANAGER_SLAVE_BUS_ROLE,						/**< Device acting as bus slave */
	DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE,			/**< Device acting as both master and slave on bus */
	NUM_BUS_ROLES										/**< Number of bus roles */
};

/**
 * Channel security capabilities of the device as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_SECURITY_NONE = 0,					/**< No channel security. */
	DEVICE_MANAGER_SECURITY_HASH_KDF = 1,				/**< Channel supports using hash/KDF. */
	DEVICE_MANAGER_SECURITY_AUTHENTICATION = 2,			/**< Channel support certificate authentication. */
	DEVICE_MANAGER_SECURITY_CONFIDENTIALITY = 4			/**< Channel support AES encryption. */
};

/**
 * Supported ECC key strength as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_ECC_KEY_NONE = 0,					/**< No ECC key support. */
	DEVICE_MANAGER_ECC_KEY_160 = 1,						/**< Supports ECC-160. */
	DEVICE_MANAGER_ECC_KEY_256 = 2,						/**< Supports ECC-256. */
	DEVICE_MANAGER_ECC_KEY_RESERVED = 4					/**< Unused. */
};

/**
 * Supported RSA key strength as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MAANGER_RSA_KEY_NONE = 0,					/**< No RSA key support. */
	DEVICE_MANAGER_RSA_KEY_2048 = 1,					/**< Supports RSA-2048. */
	DEVICE_MANAGER_RSA_KEY_3072 = 2,					/**< Supports RSA-3072. */
	DEVICE_MANAGER_RSA_KEY_4096 = 4						/**< Supports RSA-4096. */
};

/**
 * Supported AES key strength as defined in the Cerberus protocol.
 */
enum {
	DEVICE_MANAGER_AES_KEY_NONE = 0,					/**< No AES key support. */
	DEVICE_MANAGER_AES_KEY_128 = 1,						/**< Supports AES-128. */
	DEVICE_MANAGER_AES_KEY_256 = 2,						/**< Supports AES-256. */
	DEVICE_MANAGER_AES_KEY_384 = 4						/**< Supports AES-384. */
};

#pragma pack(push, 1)
/**
 * Container for a device's capabilities.  This matches the Cerberus protocol request format.
 */
struct device_manager_capabilities {
	uint16_t max_message_size;							/**< Maximum message payload the device can accept */
	uint16_t max_packet_size;							/**< Maximum packet payload the device can accept */
	uint8_t security_mode:3;							/**< Security mode */
	uint8_t reserved1:1;								/**< Reserved */
	uint8_t bus_role:2;									/**< Master/Slave role enabled */
	uint8_t hierarchy_role:2;							/**< AC-RoT or PA-RoT */
	uint8_t reserved2:5;								/**< Reserved */
	uint8_t fw_protection:1;							/**< FW protection enabled */
	uint8_t policy_support:1;							/**< Policy support enabled */
	uint8_t pfm_support:1;								/**< PFM support enabled */
	uint8_t rsa_key_strength:3;							/**< RSA key strength */
	uint8_t ecc_key_strength:3;							/**< ECC key strength */
	uint8_t ecdsa:1;									/**< ECDSA capable */
	uint8_t rsa:1;										/**< RSA capable */
	uint8_t aes_enc_key_strength:3;						/**< AES encryption key strength */
	uint8_t reserved3:4;								/**< Reserved */
	uint8_t ecc:1;										/**< ECC encryption capable */
};

/**
 * Container for all of a device's capabilities.  This matches the Cerberus protocol response
 * format.
 */
struct device_manager_full_capabilities {
	struct device_manager_capabilities request;			/**< Capabilities request information. */
	uint8_t max_timeout;								/**< Maximum timeout in 10ms multiples. */
	uint8_t max_sig;									/**< Maximum cryptographic response delay in 100ms multiples. */
};
#pragma pack(pop)

/**
 * Container for Cerberus device info and capabilities
 */
struct device_manager_info {
	uint8_t eid;											/**< Endpoint ID */
	uint8_t smbus_addr;										/**< SMBUS address */
	struct device_manager_full_capabilities capabilities;	/**< Device capabilities */
};

/**
 * Certificate chain
 */
struct device_manager_cert_chain {
	struct der_cert *cert;								/**< Certificate. */
	uint8_t num_cert;									/**< Number of certificates in chain. */
};

/**
 * Entry type on a device manager table
 */
struct device_manager_entry {
	struct device_manager_info info;					/**< Device info and capabilities*/
	struct device_manager_cert_chain cert_chain;		/**< Device certificate chain */
	uint8_t state;										/**< Device state */
	uint8_t component_type[SHA256_HASH_LENGTH];			/**< Digest of component type key in PCD and CFM */
};

/**
 * Module which holds a table of all devices Cerberus expects to communicate with and itself,
 * to be populated from PCD
 */
struct device_manager {
	struct device_manager_entry *entries;				/**< Device table entries */
	uint8_t num_devices;								/**< Number of device table entries */
};


int device_manager_init (struct device_manager *mgr, int num_devices, uint8_t hierarchy,
	uint8_t bus_role);
void device_manager_release (struct device_manager *mgr);

int device_manager_resize_entries_table (struct device_manager *mgr, int num_devices);

int device_manager_get_device_num (struct device_manager *mgr, uint8_t eid);
int device_manager_get_device_addr (struct device_manager *mgr, int device_num);
int device_manager_get_device_eid (struct device_manager *mgr, int device_num);
int device_manager_update_device_eid (struct device_manager *mgr, int device_num, uint8_t eid);
int device_manager_update_device_entry (struct device_manager *mgr, int device_num, uint8_t eid,
	uint8_t smbus_addr);

int device_manager_get_device_capabilities (struct device_manager *mgr, int device_num,
	struct device_manager_full_capabilities *capabilities);
int device_manager_update_device_capabilities (struct device_manager *mgr, int device_num,
	struct device_manager_full_capabilities *capabilities);

int device_manager_get_device_capabilities_request (struct device_manager *mgr,
	struct device_manager_capabilities *capabilites);
int device_manager_update_device_capabilities_request (struct device_manager *mgr, int device_num,
	struct device_manager_capabilities *capabilities);

size_t device_manager_get_max_message_len (struct device_manager *mgr, int device_num);
size_t device_manager_get_max_message_len_by_eid (struct device_manager *mgr, uint8_t eid);

size_t device_manager_get_max_transmission_unit (struct device_manager *mgr, int device_num);
size_t device_manager_get_max_transmission_unit_by_eid (struct device_manager *mgr, uint8_t eid);

uint32_t device_manager_get_reponse_timeout (struct device_manager *mgr, int device_num);
uint32_t device_manager_get_reponse_timeout_by_eid (struct device_manager *mgr, uint8_t eid);

uint32_t device_manager_get_crypto_timeout (struct device_manager *mgr, int device_num);
uint32_t device_manager_get_crypto_timeout_by_eid (struct device_manager *mgr, uint8_t eid);

int device_manager_init_cert_chain (struct device_manager *mgr, int device_num, uint8_t num_cert);
int device_manager_update_cert (struct device_manager *mgr, int device_num, uint8_t cert_num,
	const uint8_t *buf, int buf_len);
int device_manager_get_device_cert_chain (struct device_manager *mgr, int device_num,
	struct device_manager_cert_chain *chain);

int device_manager_get_device_state (struct device_manager *mgr, int device_num);
int device_manager_update_device_state (struct device_manager *mgr, int device_num, int state);

const uint8_t* device_manager_get_component_type (struct device_manager *mgr, uint8_t eid);
int device_manager_update_component_type (struct device_manager *mgr, struct hash_engine *hash,
	uint8_t eid, const char* component_type);


#define	DEVICE_MGR_ERROR(code)		ROT_ERROR (ROT_MODULE_DEVICE_MANAGER, code)

/**
 * Error codes that can be generated by the device manager.
 */
enum {
	DEVICE_MGR_INVALID_ARGUMENT = DEVICE_MGR_ERROR (0x00),	/**< Input parameter is null or not valid. */
	DEVICE_MGR_NO_MEMORY = DEVICE_MGR_ERROR (0x01),			/**< Memory allocation failed. */
	DEVICE_MGR_UNKNOWN_DEVICE = DEVICE_MGR_ERROR (0x02),	/**< Invalid device number. */
	DEVICE_MGR_INVALID_CERT_NUM = DEVICE_MGR_ERROR (0x03),	/**< Invalid certificate number. */
};


#endif // DEVICE_MANAGER_
