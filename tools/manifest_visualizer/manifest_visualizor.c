// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "manifest/manifest_format.h"
#include "manifest/pfm/pfm_format.h"
#include "manifest/cfm/cfm_format.h"
#include "manifest/pcd/pcd_format.h"
#include "manifest/pcd/pcd.h"
#include "crypto/hash.h"


uint8_t *element_types = NULL;
int entry_count = 0;


enum {
	MANIFEST_TYPE_PFM = 0,
	MANIFEST_TYPE_CFM,
	MANIFEST_TYPE_PCD,
};


int32_t visualize_pfm_v1 (uint8_t *pfm)
{
	struct pfm_allowable_firmware_header *allowable_fw_header =
		(struct pfm_allowable_firmware_header*) pfm;
	uint8_t* pointer = ((uint8_t*)allowable_fw_header) +
		sizeof (struct pfm_allowable_firmware_header);

	printf ("pfm_allowable_firmware_header\n");
	printf ("{");
	printf ("\tlength: %i\n", allowable_fw_header->length);
	printf ("\tfw_count: %i\n", allowable_fw_header->fw_count);
	printf ("\treserved: %i\n", allowable_fw_header->reserved);
	printf ("}\n");

	printf ("Allowable Firmware\n");
	printf ("[\n");

	for (int i = 0; i < allowable_fw_header->fw_count; ++i)
	{
		struct pfm_firmware_header *fw_header = (struct pfm_firmware_header*) pointer;
		char *version_id = (char*)malloc (fw_header->version_length + 1);
		if(version_id == NULL)
		{
			printf ("Failed to allocate version id buffer.\n");
			return -1;
		}

		strncpy(version_id, (char*)((uint8_t*)fw_header + sizeof (struct pfm_firmware_header)),
            fw_header->version_length);
		version_id[fw_header->version_length] = '\0';
		int alignment = fw_header->version_length % 4;
		alignment = (alignment == 0) ? 0 : (4 - alignment);
		pointer = (uint8_t*)fw_header + sizeof (struct pfm_firmware_header) +
			fw_header->version_length + alignment;

		printf ("\t{\n");
		printf ("\t\tpfm_firmware_header\n");
		printf ("\t\t{\n");
		printf ("\t\t\tlength: %i\n", fw_header->length);
		printf ("\t\t\tversion_length: %i\n", fw_header->version_length);
		printf ("\t\t\tblank_byte: 0x%02x\n", fw_header->blank_byte);
		printf ("\t\t\tversion_addr: 0x%x\n", fw_header->version_addr);
		printf ("\t\t\timg_count: %i\n", fw_header->img_count);
		printf ("\t\t\trw_count: %i\n", fw_header->rw_count);
		printf ("\t\t\treserved: %i\n", fw_header->reserved);
		printf ("\t\t}\n");
		printf ("\t\tversion_id: %s\n", version_id);

		free (version_id);
		printf ("\t\tRW Regions\n");
		printf ("\t\t[\n");

		for (int j = 0; j < fw_header->rw_count; ++j)
		{
			uint32_t start_addr = *((uint32_t*) pointer);
			uint32_t end_addr = *((uint32_t*) pointer + 1);
			pointer = (uint8_t*)((uint32_t*) pointer + 2);

			printf ("\t\t\t{\n");
			printf ("\t\t\t\tpfm_flash_region\n");
			printf ("\t\t\t\t{\n");
			printf ("\t\t\t\t\tstart_addr: 0x%x\n", start_addr);
			printf ("\t\t\t\t\tend_addr: 0x%x\n", end_addr);
			printf ("\t\t\t\t}\n");
			printf ("\t\t\t}\n");
		}

		printf ("\t\t]\n");

		for (int j = 0; j < fw_header->img_count; ++j)
		{
			struct pfm_image_header *img_header = (struct pfm_image_header*) pointer;
			uint8_t *sig = malloc (img_header->sig_length);
			if(sig == NULL)
			{
				printf ("Failed to allocate signature buffer.\n");
				return -1;
			}

			memcpy(sig, img_header + 1, img_header->sig_length);
			pointer = (uint8_t*)img_header + sizeof (struct pfm_image_header) +
				img_header->sig_length;

			printf ("\t\tpfm_image_header\n");
			printf ("\t\t{\n");
			printf ("\t\t\tlength: %i\n", img_header->length);
			printf ("\t\t\tflags: %i\n", img_header->flags);
			printf ("\t\t\tkey_id: %i\n", img_header->key_id);
			printf ("\t\t\tregion_count: %i\n", img_header->region_count);
			printf ("\t\t\tsig_length: %i\n", img_header->sig_length);
			printf ("\t\t}\n");
			printf ("\t\tSignature:");
			for (int k = 0; k < img_header->sig_length; ++k)
			{
				if ((k % 32) == 0)
				{
					printf ("\n\t\t\t");
				}
				printf ("%02x", sig[k]);
			}
			printf ("\n");

			free (sig);
			printf ("\t\tRO Regions\n");
			printf ("\t\t[\n");

			for (int k = 0; k < img_header->region_count; ++k)
			{
				printf ("\t\t\t{\n");
				uint32_t start_addr = *((uint32_t*) pointer);
				uint32_t end_addr = *((uint32_t*) pointer + 1);
				pointer = (uint8_t*)((uint32_t*) pointer + 2);
				printf ("\t\t\t\tpfm_flash_region\n");
				printf ("\t\t\t\t{\n");
				printf ("\t\t\t\t\tstart_addr: 0x%x\n", start_addr);
				printf ("\t\t\t\t\tend_addr: 0x%x\n", end_addr);
				printf ("\t\t\t\t}\n");
				printf ("\t\t\t}\n");
			}

			printf ("\t\t]\n");
		}

		printf ("\t}\n");
	}

	printf ("]\n");

	struct pfm_key_manifest_header *key_manifest_header = (struct pfm_key_manifest_header *) pointer;
	pointer = (uint8_t*) pointer + sizeof (struct pfm_key_manifest_header);

	printf ("pfm_key_manifest_header\n");
	printf ("{\n");
	printf ("\tlength: %i\n", key_manifest_header->length);
	printf ("\tkey_count: %i\n", key_manifest_header->key_count);
	printf ("\treserved: %i\n", key_manifest_header->reserved);
	printf ("}\n");
	printf ("Keys\n");
	printf ("[\n");

	for (int i = 0; i < key_manifest_header->key_count; ++i)
	{
		struct pfm_public_key_header *key_header = (struct pfm_public_key_header*) pointer;

		printf ("\t{\n");
		printf ("\t\tpfm_key_manifest_header\n");
		printf ("\t\tlength: %i\n", key_header->length);
		printf ("\t\tkey_length: %i\n", key_header->key_length);
		printf ("\t\tkey_exponent: 0x%x\n", key_header->key_exponent);
		printf ("\t\tid: %i\n", key_header->id);
		printf ("\t\treserved[0]: %i\n", key_header->reserved[0]);
		printf ("\t\treserved[1]: %i\n", key_header->reserved[1]);
		printf ("\t\treserved[2]: %i\n", key_header->reserved[2]);

		uint8_t *modulus = (uint8_t*)malloc (key_header->key_length);
		if(modulus == NULL)
		{
			printf ("Failed to allocate modulus buffer.\n");
			return -1;
		}

		memcpy(modulus, key_header + 1, key_header->key_length);
		pointer = (uint8_t*)key_header + sizeof (struct pfm_public_key_header) +
			key_header->key_length;

		printf ("\t\tmodulus:");
		for (int j = 0; j < key_header->key_length; ++j)
		{
			if ((j % 32) == 0)
			{
				printf ("\n\t\t\t");
			}
			printf ("%02x", modulus[j]);
		}
		printf ("\n");

		free (modulus);
		printf ("\n");
		printf ("\t}\n");
	}

	printf ("]\n");

	struct pfm_platform_header *platform_header = (struct pfm_platform_header *) pointer;
	pointer = (uint8_t*) pointer + sizeof (struct pfm_platform_header);

	printf ("pfm_platform_header\n");
	printf ("{\n");
	printf ("\tlength: %i\n", platform_header->length);
	printf ("\tid_length: %i\n", platform_header->id_length);
	printf ("\treserved: %i\n", platform_header->reserved);
	printf ("}\n");

	char *platform_id = malloc (platform_header->id_length + 1);
	if(platform_id == NULL)
	{
		printf ("Failed to allocate platform id buffer.\n");
		return -1;
	}

	memcpy(platform_id, pointer, platform_header->id_length);
	platform_id[platform_header->id_length] = '\0';
	int alignment = platform_header->id_length % 4;
	alignment = (alignment == 0) ? 0 : (4 - alignment);
	pointer += platform_header->id_length + alignment;

	printf ("platform_id: %s\n", platform_id);

	free (platform_id);

	return (pointer - pfm);
}

int32_t visualize_toc (uint8_t *start)
{
	struct manifest_toc_header *toc_header = (struct manifest_toc_header*) start;
	uint8_t* pointer = start + sizeof (struct manifest_toc_header);
	int hash_len;

	printf ("manifest_toc_header\n");
	printf ("{\n");
	printf ("\tentry_count: %i\n", toc_header->entry_count);
	printf ("\thash_count: %i\n", toc_header->hash_count);
	printf ("\thash_type: %i\n", toc_header->hash_type);
	printf ("\treserved: %i\n", toc_header->reserved);

	entry_count = toc_header->entry_count;
	element_types = malloc (sizeof (uint8_t) * entry_count);

	switch (toc_header->hash_type) {
		case MANIFEST_HASH_SHA256:
			hash_len = SHA256_HASH_LENGTH;
			break;
		case MANIFEST_HASH_SHA384:
			hash_len = SHA384_HASH_LENGTH;
			break;
		case MANIFEST_HASH_SHA512:
			hash_len = SHA512_HASH_LENGTH;
			break;
		default:
			printf ("Unsupported hash type selected: %i\n", toc_header->hash_type);
			return -1;
	}

	printf ("\tEntries\n");
	printf ("\t[\n");

	for (int i = 0; i < toc_header->entry_count; ++i) {
		struct manifest_toc_entry *entry = (struct manifest_toc_entry*) pointer;
		pointer += sizeof (struct manifest_toc_entry);

		element_types[i] = entry->type_id;

		printf ("\t\tmanifest_toc_entry\n");
		printf ("\t\t{\n");
		printf ("\t\t\ttype_id: 0x%x\n", entry->type_id);
		printf ("\t\t\tparent: 0x%x\n", entry->parent);
		printf ("\t\t\tformat: %i\n", entry->format);
		printf ("\t\t\thash_id: %i\n", entry->hash_id);
		printf ("\t\t\toffset: 0x%x\n", entry->offset);
		printf ("\t\t\tlength: 0x%x\n", entry->length);
		printf ("\t\t}\n");
	}

	printf ("\t]\n");

	printf ("\tHash\n");
	printf ("\t[\n");

	for (int i = 0; i < toc_header->hash_count; ++i) {
		printf ("\t\tHash %i\n", i);
		printf ("\t\t{");
		for (int j = 0; j < hash_len; ++j, ++pointer)
		{
			if ((j % 32) == 0)
			{
				printf ("\n\t\t\t");
			}

			printf ("%02x", *pointer);
		}
		printf ("\n");
		printf ("\t\t}\n");
	}

	printf ("\t\tTable Hash\n");
	printf ("\t\t{");
	for (int i = 0; i < hash_len; ++i, ++pointer) {
		if ((i % 32) == 0) {
			printf ("\n\t\t\t");
		}

		printf ("%02x", *pointer);
	}
	printf ("\n");
	printf ("\t\t}\n");

	printf ("\t]\n");

	printf ("}\n");

	return (pointer - start);
}

int32_t visualize_pcd_rot_element (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct pcd_rot_element *rot = (struct pcd_rot_element*) pointer;

	pointer += sizeof (struct pcd_rot_element);

	printf ("%spcd_rot_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\trot_flags: 0x%x\n", prefix, rot->rot_flags);
	printf ("%s\tport_count: %i\n", prefix, rot->port_count);
	printf ("%s\tcomponents_count: %i\n", prefix, rot->components_count);
	printf ("%s\trot_address: 0x%x\n", prefix, rot->rot_address);
	printf ("%s\trot_eid: 0x%x\n", prefix, rot->rot_eid);
	printf ("%s\tbridge_address: 0x%x\n", prefix, rot->bridge_address);
	printf ("%s\tbridge_eid: 0x%x\n", prefix, rot->bridge_eid);
	printf ("%s\treserved: %i\n", prefix, rot->reserved);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_pcd_port_element (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct pcd_port_element *port = (struct pcd_port_element*) pointer;

	pointer += sizeof (struct pcd_port_element);

	printf ("%spcd_port_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tport_id: %i\n", prefix, port->port_id);
	printf ("%s\tport_flags: 0x%x\n", prefix, port->port_flags);
	printf ("%s\tpolicy: 0x%x\n", prefix, port->policy);
	printf ("%s\tpulse_interval: %i\n", prefix, port->pulse_interval);
	printf ("%s\tspi_frequency_hz: %i\n", prefix, port->spi_frequency_hz);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_pcd_power_controller_element (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct pcd_power_controller_element *power_controller =
		(struct pcd_power_controller_element*) pointer;

	pointer += sizeof (struct pcd_power_controller_element);

	printf ("%spcd_power_controller_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tmux_count: %i\n", prefix, power_controller->i2c.mux_count);
	printf ("%s\ti2c_flags: 0x%x\n", prefix, power_controller->i2c.i2c_flags);
	printf ("%s\tbus: %i\n", prefix, power_controller->i2c.bus);
	printf ("%s\taddress: 0x%x\n", prefix, power_controller->i2c.address);
	printf ("%s\teid: 0x%x\n", prefix, power_controller->i2c.eid);

	printf ("%s\tMuxes\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < power_controller->i2c.mux_count; ++i) {
		struct pcd_mux *mux = (struct pcd_mux*) pointer;
		pointer += sizeof (struct pcd_mux);

		printf ("%s\t\tpcd_mux\n", prefix);
		printf ("%s\t\t{\n", prefix);
		printf ("%s\t\t\tmux_address: 0x%x\n", prefix, mux->mux_address);
		printf ("%s\t\t\tmux_channel: %i\n", prefix, mux->mux_channel);
		printf ("%s\t\t\treserved: %i\n", prefix, mux->reserved);
		printf ("%s\t\t}\n", prefix);
	}

	printf ("%s\t]\n", prefix);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_pcd_direct_i2c_component_element (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct pcd_component_common *component = (struct pcd_component_common*) pointer;
	struct pcd_i2c_interface *interface;
	char* type;
	size_t type_len;

	pointer += (sizeof (struct pcd_component_common) - MANIFEST_MAX_STRING);

	printf ("%spcd_direct_i2c_component_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tpolicy: 0x%x\n", prefix, component->policy);
	printf ("%s\tpower_ctrl_reg: 0x%x\n", prefix, component->power_ctrl_reg);
	printf ("%s\tpower_ctrl_mask: 0x%x\n", prefix, component->power_ctrl_mask);
	printf ("%s\ttype_len: %i\n", prefix, component->type_len);

	type = malloc ((size_t) component->type_len + 1);
	if (type == NULL) {
		printf ("Failed to allocate type buffer.\n");
		return -1;
	}

	memcpy (type, pointer, component->type_len);
	type[component->type_len] = '\0';

	printf ("%s\tType: %s\n", prefix, type);
	free (type);

	type_len = (((size_t) component->type_len + 3) & ~((size_t) 3));
	pointer += type_len;

	interface = (struct pcd_i2c_interface*) pointer;
	pointer += sizeof (struct pcd_i2c_interface);

	printf ("%s\tmux_count: %i\n", prefix, interface->mux_count);
	printf ("%s\ti2c_flags: 0x%x\n", prefix, interface->i2c_flags);
	printf ("%s\tbus: %i\n", prefix, interface->bus);
	printf ("%s\taddress: 0x%x\n", prefix, interface->address);
	printf ("%s\teid: 0x%x\n", prefix, interface->eid);

	printf ("%s\tMuxes\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < interface->mux_count; ++i) {
		struct pcd_mux *mux = (struct pcd_mux*) pointer;
		pointer += sizeof (struct pcd_mux);

		printf ("%s\t\tpcd_mux\n", prefix);
		printf ("%s\t\t{\n", prefix);
		printf ("%s\t\t\tmux_address: 0x%x\n", prefix, mux->mux_address);
		printf ("%s\t\t\tmux_channel: %i\n", prefix, mux->mux_channel);
		printf ("%s\t\t\treserved: %i\n", prefix, mux->reserved);
		printf ("%s\t\t}\n", prefix);
	}

	printf ("%s\t]\n", prefix);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_pcd_mctp_bridge_component_element (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct pcd_component_common *component = (struct pcd_component_common*) pointer;
	char* type;
	size_t type_len;

	pointer += (sizeof (struct pcd_component_common) - MANIFEST_MAX_STRING);

	printf ("%spcd_mctp_bridge_component_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tpolicy: 0x%x\n", prefix, component->policy);
	printf ("%s\tpower_ctrl_reg: 0x%x\n", prefix, component->power_ctrl_reg);
	printf ("%s\tpower_ctrl_mask: 0x%x\n", prefix, component->power_ctrl_mask);
	printf ("%s\ttype_len: %i\n", prefix, component->type_len);

	type = malloc ((size_t) component->type_len + 1);
	if (type == NULL) {
		printf ("Failed to allocate type buffer.\n");
		return -1;
	}

	memcpy (type, pointer, component->type_len);
	type[component->type_len] = '\0';

	printf ("%s\tType: %s\n", prefix, type);
	free (type);

	type_len = (((size_t) component->type_len + 3) & ~((size_t) 3));
	pointer += type_len;

	printf ("%s\tdevice_id: 0x%x\n", prefix, *((uint16_t*) pointer));
	pointer += 2;
	printf ("%s\tvendor_id: 0x%x\n", prefix, *((uint16_t*) pointer));
	pointer += 2;
	printf ("%s\tsubsystem_device_id: 0x%x\n", prefix, *((uint16_t*) pointer));
	pointer += 2;
	printf ("%s\tsubsystem_vendor_id: 0x%x\n", prefix, *((uint16_t*) pointer));
	pointer += 2;
	printf ("%s\tcomponents_count: %i\n", prefix, *((uint8_t*) pointer++));
	printf ("%s\teid: 0x%x\n", prefix, *((uint8_t*) pointer++));
	printf ("%s\treserved: %i\n", prefix, *((uint16_t*) pointer));
	pointer += 2;

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_platform_id (uint8_t *start, const char *prefix)
{
	uint8_t *pointer = start;
	struct manifest_platform_id *platform_id = (struct manifest_platform_id*) pointer;
	uint8_t *id;
	size_t id_len;

	pointer += sizeof (struct manifest_platform_id);

	printf ("%smanifest_platform_id\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tid_length: %i\n", prefix, platform_id->id_length);
	printf ("%s\treserved1: %i\n", prefix, platform_id->reserved[0]);
	printf ("%s\treserved2: %i\n", prefix, platform_id->reserved[1]);
	printf ("%s\treserved3: %i\n", prefix, platform_id->reserved[2]);

	id = malloc (platform_id->id_length + 1);
	if (id == NULL) {
		printf ("Failed to allocate platform ID buffer.\n");
		return -1;
	}

	memcpy (id, pointer, platform_id->id_length);
	id[platform_id->id_length] = '\0';

	printf ("%s\tPlatform ID: %s\n", prefix, id);
	free (id);

	id_len = ((platform_id->id_length + 3) & ~((size_t) 3));
	pointer += id_len;

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_common_element (uint8_t type, uint8_t *pointer, const char *prefix)
{
	switch (type) {
		case MANIFEST_PLATFORM_ID:
			return visualize_platform_id (pointer, prefix);
		default:
			printf ("Unsupported element type: 0x%x\n", type);
			return -1;
	}
}

int32_t visualize_pfm_flash_device_element (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct pfm_flash_device_element *flash_device = (struct pfm_flash_device_element*) pointer;

	pointer += sizeof (struct pfm_flash_device_element);

	printf ("%spfm_flash_device_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tblank_byte: 0x%x\n", prefix, flash_device->blank_byte);
	printf ("%s\tfw_count: %i\n", prefix, flash_device->fw_count);
	printf ("%s\treserved: %i\n", prefix, flash_device->reserved);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_pfm_fw_element (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct pfm_firmware_element *fw = (struct pfm_firmware_element*) pointer;
	uint8_t *fw_id;
	size_t fw_id_len;

	pointer += (sizeof (struct pfm_firmware_element) - MANIFEST_MAX_STRING);

	printf ("%spfm_firmware_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tversion_count: %i\n", prefix, fw->version_count);
	printf ("%s\tid_length: %i\n", prefix, fw->id_length);
	printf ("%s\tflags: 0x%x\n", prefix, fw->flags);
	printf ("%s\treserved: %i\n", prefix, fw->reserved);

	fw_id = malloc ((size_t) fw->id_length + 1);
	if (fw_id == NULL) {
		printf ("Failed to allocate FW ID buffer.\n");
		return -1;
	}

	memcpy (fw_id, pointer, fw->id_length);
	fw_id[fw->id_length] = '\0';

	printf ("%s\tFW ID: %s\n", prefix, fw_id);
	free (fw_id);

	fw_id_len = (((size_t) fw->id_length + 3) & ~((size_t) 3));
	pointer += fw_id_len;

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_pfm_fw_version_element (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct pfm_firmware_version_element *version = (struct pfm_firmware_version_element*) pointer;
	uint8_t *version_str;
	size_t version_str_len;

	pointer += (sizeof (struct pfm_firmware_version_element) - MANIFEST_MAX_STRING);

	printf ("%spfm_firmware_version_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\timg_count: %i\n", prefix, version->img_count);
	printf ("%s\trw_count: %i\n", prefix, version->rw_count);
	printf ("%s\tversion_length: %i\n", prefix, version->version_length);
	printf ("%s\treserved: %i\n", prefix, version->reserved);
	printf ("%s\tversion_addr: 0x%x\n", prefix, version->version_addr);

	version_str = malloc ((size_t) version->version_length + 1);
	if (version_str == NULL) {
		printf ("Failed to allocate Version buffer.\n");
		return -1;
	}

	memcpy (version_str, pointer, version->version_length);
	version_str[version->version_length] = '\0';

	printf ("%s\tVersion: %s\n", prefix, version_str);
	free (version_str);

	version_str_len = (((size_t) version->version_length + 3) & ~((size_t) 3));
	pointer += version_str_len;

	printf ("%s\tRW Regions\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < version->rw_count; ++i) {
		struct pfm_fw_version_element_rw_region *rw =
			(struct pfm_fw_version_element_rw_region*) pointer;
		pointer += (sizeof (struct pfm_fw_version_element_rw_region) -
			sizeof (struct pfm_flash_region));
		struct pfm_flash_region *region = (struct pfm_flash_region*) pointer;
		pointer += sizeof (struct pfm_flash_region);

		printf ("%s\t\tpfm_fw_version_element_rw_region\n", prefix);
		printf ("%s\t\t{\n", prefix);
		printf ("%s\t\t\tflags: 0x%x\n", prefix, rw->flags);
		printf ("%s\t\t\treserved_0: %i\n", prefix, rw->reserved[0]);
		printf ("%s\t\t\treserved_1: %i\n", prefix, rw->reserved[1]);
		printf ("%s\t\t\treserved_2: %i\n", prefix, rw->reserved[2]);
		printf ("%s\t\t\tpfm_flash_region\n", prefix);
		printf ("%s\t\t\t{\n", prefix);
		printf ("%s\t\t\t\tstart_addr: 0x%x\n", prefix, region->start_addr);
		printf ("%s\t\t\t\tend_addr: 0x%x\n", prefix, region->end_addr);
		printf ("%s\t\t\t}\n", prefix);
		printf ("%s\t\t}\n", prefix);
	}

	printf ("%s\t]\n", prefix);

	printf ("%s\tImages\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < version->img_count; ++i) {
		struct pfm_fw_version_element_image *img = (struct pfm_fw_version_element_image*) pointer;
		int hash_len;
		pointer += sizeof (struct pfm_fw_version_element_image);

		printf ("%s\t\tpfm_fw_version_element_image\n", prefix);
		printf ("%s\t\t{\n", prefix);
		printf ("%s\t\t\thash_type: %i\n", prefix, img->hash_type);
		printf ("%s\t\t\tregion_count: %i\n", prefix, img->region_count);
		printf ("%s\t\t\tflags: 0x%x\n", prefix, img->flags);
		printf ("%s\t\t\treserved: %i\n", prefix, img->reserved);

		switch (img->hash_type) {
		case MANIFEST_HASH_SHA256:
			hash_len = SHA256_HASH_LENGTH;
			break;
		case MANIFEST_HASH_SHA384:
			hash_len = SHA384_HASH_LENGTH;
			break;
		case MANIFEST_HASH_SHA512:
			hash_len = SHA512_HASH_LENGTH;
			break;
		default:
			printf ("Unsupported hash type selected: %i\n", img->hash_type);
			return -1;
		}

		printf ("%s\t\t\tHash:\n", prefix);
		printf ("%s\t\t\t{", prefix);
		for (int j = 0; j < hash_len; ++j, ++pointer)
		{
			if ((j % 32) == 0)
			{
				printf ("%s\n\t\t\t\t", prefix);
			}

			printf ("%02x", *pointer);
		}
		printf ("\n");
		printf ("%s\t\t\t}\n", prefix);

		printf ("%s\t\t\tRegions:\n", prefix);
		printf ("%s\t\t\t[\n", prefix);
		for (int j = 0; j < img->region_count; ++j)
		{
			uint32_t *address = (uint32_t*) pointer;
			pointer += sizeof (uint32_t);
			printf ("%s\t\t\t\tRegion %i\n", prefix, j);
			printf ("%s\t\t\t\t{\n", prefix);
			printf ("%s\t\t\t\t\tImage Start Address: 0x%x\n", prefix, *address);

			address = (uint32_t*) pointer;
			pointer += sizeof (uint32_t);

			printf ("%s\t\t\t\t\tImage End Address: 0x%x\n", prefix, *address);
			printf ("%s\t\t\t\t}\n", prefix);
		}
		printf ("\n");
		printf ("%s\t\t\t]\n", prefix);
		printf ("%s\t\t}\n", prefix);
	}

	printf ("%s\t]\n", prefix);

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_component_device (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_component_device_element *device = (struct cfm_component_device_element*) pointer;
	char* type;
	size_t type_len;

	pointer += (sizeof (struct cfm_component_device_element) - MANIFEST_MAX_STRING);

	printf ("%scfm_component_device_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tcert_slot: %i\n", prefix, device->cert_slot);
	printf ("%s\tattestation_protocol: %i\n", prefix, device->attestation_protocol);
	printf ("%s\treserved: %i\n", prefix, device->reserved);
	printf ("%s\ttype_len: %i\n", prefix, device->type_len);

	type = malloc ((size_t) device->type_len + 1);
	if (type == NULL) {
		printf ("Failed to allocate type buffer.\n");
		return -1;
	}

	memcpy (type, pointer, device->type_len);
	type[device->type_len] = '\0';

	printf ("%s\tType: %s\n", prefix, type);
	free (type);

	type_len = (((size_t) device->type_len + 3) & ~((size_t) 3));
	pointer += type_len;

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_pmr_digest (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_pmr_digest_element *pmr_digest = (struct cfm_pmr_digest_element*) pointer;
	int hash_len;

	pointer += sizeof (struct cfm_pmr_digest_element);

	printf ("%scfm_pmr_digest_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tpmr_id: %i\n", prefix, pmr_digest->pmr_id);
	printf ("%s\treserved: %i\n", prefix, pmr_digest->reserved);
	printf ("%s\tpmr_hash_type: %i\n", prefix, pmr_digest->pmr_hash_type);
	printf ("%s\tdigest_count: %i\n", prefix, pmr_digest->digest_count);
	printf ("%s\treserved2: %i\n", prefix, pmr_digest->reserved2);

	switch (pmr_digest->pmr_hash_type) {
	case MANIFEST_HASH_SHA256:
		hash_len = SHA256_HASH_LENGTH;
		break;
	case MANIFEST_HASH_SHA384:
		hash_len = SHA384_HASH_LENGTH;
		break;
	case MANIFEST_HASH_SHA512:
		hash_len = SHA512_HASH_LENGTH;
		break;
	default:
		printf ("Unsupported hash type selected: %i\n", pmr_digest->pmr_hash_type);
		return -1;
	}

	printf ("%s\tHashes:\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < pmr_digest->digest_count; ++i) {
		printf ("%s\t\t{", prefix);

		for (int j = 0; j < hash_len; ++j, ++pointer)
		{
			if ((j % 32) == 0)
			{
				printf ("%s\n\t\t\t", prefix);
			}

			printf ("%02x", *pointer);
		}
		printf ("%s\n\t\t}\n", prefix);
	}

	printf ("%s\t]\n", prefix);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_measurement (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_measurement_element *measurement = (struct cfm_measurement_element*) pointer;
	int hash_len;

	pointer += sizeof (struct cfm_measurement_element);

	printf ("%scfm_measurement_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tpmr_id: %i\n", prefix, measurement->pmr_id);
	printf ("%s\tmeasurement_id: %i\n", prefix, measurement->measurement_id);
	printf ("%s\treserved: %i\n", prefix, measurement->reserved);
	printf ("%s\thash_type: %i\n", prefix, measurement->hash_type);
	printf ("%s\tdigest_count: %i\n", prefix, measurement->digest_count);

	switch (measurement->hash_type) {
	case MANIFEST_HASH_SHA256:
		hash_len = SHA256_HASH_LENGTH;
		break;
	case MANIFEST_HASH_SHA384:
		hash_len = SHA384_HASH_LENGTH;
		break;
	case MANIFEST_HASH_SHA512:
		hash_len = SHA512_HASH_LENGTH;
		break;
	default:
		printf ("Unsupported hash type selected: %i\n", measurement->hash_type);
		return -1;
	}

	printf ("%s\tHashes:\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < measurement->digest_count; ++i) {
		printf ("%s\t\t{", prefix);

		for (int j = 0; j < hash_len; ++j, ++pointer)
		{
			if ((j % 32) == 0)
			{
				printf ("%s\n\t\t\t", prefix);
			}

			printf ("%02x", *pointer);
		}
		printf ("%s\n\t\t}\n", prefix);
	}

	printf ("%s\t]\n", prefix);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_measurement_data (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_measurement_data_element *measurement_data =
		(struct cfm_measurement_data_element*) pointer;

	pointer += sizeof (struct cfm_measurement_data_element);

	printf ("%scfm_measurement_data_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tpmr_id: %i\n", prefix, measurement_data->pmr_id);
	printf ("%s\tmeasurement_id: %i\n", prefix, measurement_data->measurement_id);
	printf ("%s\treserved: %i\n", prefix, measurement_data->reserved);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_allowable_data (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_allowable_data_element *allowable_data =
		(struct cfm_allowable_data_element*) pointer;
	int total_data_len = 0;

	pointer += sizeof (struct cfm_allowable_data_element);

	printf ("%scfm_allowable_data_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\treserved: %i\n", prefix, allowable_data->reserved);
	printf ("%s\tbitmask_presence: %i\n", prefix, allowable_data->bitmask_presence);
	printf ("%s\tcheck: %i\n", prefix, allowable_data->check);
	printf ("%s\tnum_data: %i\n", prefix, allowable_data->num_data);
	printf ("%s\tdata_len: %i\n", prefix, allowable_data->data_len);
	printf ("%s\treserved2[0]: %i\n", prefix, allowable_data->reserved2[0]);
	printf ("%s\treserved2[1]: %i\n", prefix, allowable_data->reserved2[1]);
	printf ("%s\treserved2[2]: %i\n", prefix, allowable_data->reserved2[2]);

	if (allowable_data->bitmask_presence) {
		printf ("%s\tBitmask:\n", prefix);
		printf ("%s\t{", prefix);

		for (int i = 0; i < allowable_data->data_len; ++i, ++pointer)
		{
			if ((i % 32) == 0)
			{
				printf ("%s\n\t\t", prefix);
			}

			printf ("%02x", *pointer);
		}

		pointer += ((((size_t) allowable_data->data_len + 3) &
			~((size_t) 3)) - allowable_data->data_len);

		printf ("\n\t}\n");
	}

	printf ("%s\tData:\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < allowable_data->num_data; ++i) {
		printf ("%s\t\t{", prefix);

		for (int j = 0; j < allowable_data->data_len; ++j, ++pointer, ++total_data_len)
		{
			if ((j % 32) == 0)
			{
				printf ("%s\n\t\t\t", prefix);
			}

			printf ("%02x", *pointer);
		}

		printf ("\n\t\t}\n");
	}

	pointer += ((((size_t) total_data_len + 3) & ~((size_t) 3)) - total_data_len);

	printf ("%s\t]\n", prefix);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_allowable_manifest (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_allowable_manifest *allowable_manifest = (struct cfm_allowable_manifest*) pointer;
	uint8_t *platform_id;
	size_t platform_id_len;

	pointer += (sizeof (struct cfm_allowable_manifest) - MANIFEST_MAX_STRING);

	printf ("%scfm_allowable_manifest:\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tplatform_id_len: %i\n", prefix, allowable_manifest->platform_id_len);

	platform_id = malloc ((size_t) allowable_manifest->platform_id_len + 1);
	if (platform_id == NULL) {
		printf ("Failed to allocate platform ID buffer.\n");
		return -1;
	}

	memcpy (platform_id, pointer, allowable_manifest->platform_id_len);
	platform_id[allowable_manifest->platform_id_len] = '\0';

	printf ("%s\tplatform_id: %s\n", prefix, platform_id);
	free (platform_id);

	platform_id_len = (((size_t) allowable_manifest->platform_id_len + 3) & ~((size_t) 3));
	pointer += platform_id_len;

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_allowable_pfm (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_allowable_pfm_element *pfm = (struct cfm_allowable_pfm_element*) pointer;

	pointer += (sizeof (struct cfm_allowable_pfm_element) - sizeof (struct cfm_allowable_manifest));

	printf ("%scfm_allowable_pfm_element:\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tport_id: %i\n", prefix, pfm->port_id);

	pointer += visualize_cfm_allowable_manifest (pointer, "\t");;

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_allowable_cfm (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_allowable_cfm_element *cfm = (struct cfm_allowable_cfm_element*) pointer;

	pointer += (sizeof (struct cfm_allowable_cfm_element) - sizeof (struct cfm_allowable_manifest));

	printf ("%scfm_allowable_cfm_element:\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tindex: %i\n", prefix, cfm->index);

	pointer += visualize_cfm_allowable_manifest (pointer, "\t");;

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_allowable_pcd (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_allowable_pcd_element *pcd = (struct cfm_allowable_pcd_element*) pointer;

	pointer += (sizeof (struct cfm_allowable_pcd_element) - sizeof (struct cfm_allowable_manifest));

	printf ("%scfm_allowable_pcd_element:\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\treserved: %i\n", prefix, pcd->reserved);

	pointer += visualize_cfm_allowable_manifest (pointer, "\t");;

	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_allowable_id (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	uint32_t *id;
	struct cfm_allowable_id_element *allowable_id = (struct cfm_allowable_id_element*) pointer;

	pointer += sizeof (struct cfm_allowable_id_element);

	printf ("%scfm_allowable_id_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tcheck: %i\n", prefix, allowable_id->check);
	printf ("%s\tnum_id: %i\n", prefix, allowable_id->num_id);
	printf ("%s\treserved: %i\n", prefix, allowable_id->reserved);

	printf ("%s\tIDs:\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < allowable_id->num_id; ++i, pointer += sizeof (uint32_t)) {
		id = (uint32_t*) pointer;
		printf ("\t\t0x%08x\n", *id);
	}

	printf ("%s\t]\n", prefix);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_root_ca_digests (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_root_ca_digests_element *root_ca_digests =
		(struct cfm_root_ca_digests_element*) pointer;
	int hash_len;

	pointer += sizeof (struct cfm_root_ca_digests_element);

	printf ("%scfm_root_ca_digests_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\treserved: %i\n", prefix, root_ca_digests->reserved);
	printf ("%s\thash_type: %i\n", prefix, root_ca_digests->hash_type);
	printf ("%s\tca_count: %i\n", prefix, root_ca_digests->ca_count);
	printf ("%s\treserved2: %i\n", prefix, root_ca_digests->reserved2);

	switch (root_ca_digests->hash_type) {
	case MANIFEST_HASH_SHA256:
		hash_len = SHA256_HASH_LENGTH;
		break;
	case MANIFEST_HASH_SHA384:
		hash_len = SHA384_HASH_LENGTH;
		break;
	case MANIFEST_HASH_SHA512:
		hash_len = SHA512_HASH_LENGTH;
		break;
	default:
		printf ("Unsupported hash type selected: %i\n", root_ca_digests->hash_type);
		return -1;
	}

	printf ("%s\tHashes:\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < root_ca_digests->ca_count; ++i) {
		printf ("%s\t\t{", prefix);

		for (int j = 0; j < hash_len; ++j, ++pointer)
		{
			if ((j % 32) == 0)
			{
				printf ("%s\n\t\t\t", prefix);
			}

			printf ("%02x", *pointer);
		}
		printf ("%s\n\t\t}\n", prefix);
	}

	printf ("%s\t]\n", prefix);
	printf ("%s}\n", prefix);

	return (pointer - start);
}

int32_t visualize_cfm_pmr (uint8_t *start, const char* prefix)
{
	uint8_t *pointer = start;
	struct cfm_pmr_element *pmr = (struct cfm_pmr_element*) pointer;
	int hash_len;

	pointer += (sizeof (struct cfm_pmr_element) - sizeof (pmr->initial_value));

	printf ("%scfm_pmr_element\n", prefix);
	printf ("%s{\n", prefix);
	printf ("%s\tpmr_id: %i\n", prefix, pmr->pmr_id);
	printf ("%s\treserved: %i\n", prefix, pmr->reserved);
	printf ("%s\thash_type: %i\n", prefix, pmr->hash_type);
	printf ("%s\treserved2: %i\n", prefix, pmr->reserved2);

	switch (pmr->hash_type) {
		case MANIFEST_HASH_SHA256:
			hash_len = SHA256_HASH_LENGTH;
			break;
		case MANIFEST_HASH_SHA384:
			hash_len = SHA384_HASH_LENGTH;
			break;
		case MANIFEST_HASH_SHA512:
			hash_len = SHA512_HASH_LENGTH;
			break;
		default:
			printf ("Unsupported hash type selected: %i\n", pmr->hash_type);
			return -1;
	}

	printf ("%s\tInitial Value:\n", prefix);
	printf ("%s\t{", prefix);

	for (int j = 0; j < hash_len; ++j, ++pointer)
	{
		if ((j % 32) == 0)
		{
			printf ("%s\n\t\t", prefix);
		}

		printf ("%02x", *pointer);
	}
	printf ("%s\n\t}\n", prefix);
	printf ("%s\n}\n", prefix);

	return (pointer - start);
}

int32_t visualize_pfm (uint8_t *start)
{
	uint8_t *pointer = start;
	int32_t offset;

	offset = visualize_toc (pointer);
	if (offset == -1) {
		return offset;
	}

	pointer += offset;

	for (int i = 0; i < entry_count; ++i) {
		switch (element_types[i]) {
			case PFM_FLASH_DEVICE:
				offset = visualize_pfm_flash_device_element (pointer, "");
				break;
			case PFM_FIRMWARE:
				offset = visualize_pfm_fw_element (pointer, "");
				break;
			case PFM_FIRMWARE_VERSION:
				offset = visualize_pfm_fw_version_element (pointer, "");
				break;
			default:
				offset = visualize_common_element (element_types[i], pointer, "");
				break;
		}

		if (offset == -1) {
			return -1;
		}

		pointer += offset;
	}

	return (pointer - start);
}

int32_t visualize_cfm (uint8_t *start)
{
	uint8_t *pointer = start;
	int32_t offset;

	offset = visualize_toc (pointer);
	if (offset == -1) {
		return offset;
	}

	pointer += offset;

	for (int i = 0; i < entry_count; ++i) {
		switch (element_types[i]) {
			case CFM_COMPONENT_DEVICE:
				offset = visualize_cfm_component_device (pointer, "");
				break;

			case CFM_PMR_DIGEST:
				offset = visualize_cfm_pmr_digest (pointer, "");
				break;

			case CFM_MEASUREMENT:
				offset = visualize_cfm_measurement (pointer, "");
				break;

			case CFM_MEASUREMENT_DATA:
				offset = visualize_cfm_measurement_data (pointer, "");
				break;

			case CFM_ALLOWABLE_DATA:
				offset = visualize_cfm_allowable_data (pointer, "");
				break;

			case CFM_ALLOWABLE_PFM:
				offset = visualize_cfm_allowable_pfm (pointer, "");
				break;

			case CFM_ALLOWABLE_CFM:
				offset = visualize_cfm_allowable_cfm (pointer, "");
				break;

			case CFM_ALLOWABLE_PCD:
				offset = visualize_cfm_allowable_pcd (pointer, "");
				break;

			case CFM_ALLOWABLE_ID:
				offset = visualize_cfm_allowable_id (pointer, "");
				break;

			case CFM_ROOT_CA:
				offset = visualize_cfm_root_ca_digests (pointer, "");
				break;

			case CFM_PMR:
				offset = visualize_cfm_pmr (pointer, "");
				break;

			default:
				offset = visualize_common_element (element_types[i], pointer, "");
				break;
		}

		if (offset == -1) {
			return -1;
		}

		pointer += offset;
	}

	return (pointer - start);
}

int32_t visualize_pcd (uint8_t *start)
{
	uint8_t *pointer = start;
	int32_t offset;

	offset = visualize_toc (pointer);
	if (offset == -1) {
		return offset;
	}

	pointer += offset;

	for (int i = 0; i < entry_count; ++i) {
		switch (element_types[i]) {
			case PCD_ROT:
				offset = visualize_pcd_rot_element (pointer, "");
				break;
			case PCD_SPI_FLASH_PORT:
				offset = visualize_pcd_port_element (pointer, "");
				break;
			case PCD_POWER_CONTROLLER:
				offset = visualize_pcd_power_controller_element (pointer, "");
				break;
			case PCD_COMPONENT_DIRECT:
				offset = visualize_pcd_direct_i2c_component_element (pointer, "");
				break;
			case PCD_COMPONENT_MCTP_BRIDGE:
				offset = visualize_pcd_mctp_bridge_component_element (pointer, "");
				break;
			default:
				offset = visualize_common_element (element_types[i], pointer, "");
				break;
		}

		if (offset == -1) {
			return -1;
		}

		pointer += offset;
	}

	return (pointer - start);
}

int main (int argc, char** argv)
{
	FILE *fp;
	int32_t offset;
	uint8_t *pointer;
	uint8_t *manifest;
	unsigned long fileLen;

	if (argc < 1 || argv == NULL) {
		printf ("No manifest file passed in.\n");
		return -1;
	}

	fp = fopen (argv[1], "rb");
	if (fp == NULL) {
		printf ("Failed to open manifest file.\n");
		return -1;
	}

	fseek (fp, 0, SEEK_END);
	fileLen = ftell (fp);
	fseek (fp, 0, SEEK_SET);

	manifest = (uint8_t*) malloc (fileLen + 1);
	if (manifest == NULL) {
		printf ("Failed to allocate manifest buffer.\n");
		return -1;
	}

	fread ((void*) manifest, sizeof (uint8_t), fileLen, fp);
	fclose (fp);

	struct manifest_header *header = (struct manifest_header *) manifest;
	printf ("manifest_header\n");
	printf ("{");
	printf ("\tlength: %i\n", header->length);
	printf ("\tmagic: 0x%x\n", header->magic);
	printf ("\tid: %i\n", header->id);
	printf ("\tsig_length: %i\n", header->sig_length);
	printf ("\tsig_type: %i\n", header->sig_type);
	printf ("\treserved: %i\n", header->reserved);
	printf ("}\n");

	switch (header->magic)
	{
		case PFM_MAGIC_NUM:
			offset = visualize_pfm_v1 (manifest + sizeof (struct manifest_header));
			break;
		case PFM_V2_MAGIC_NUM:
			offset = visualize_pfm (manifest + sizeof (struct manifest_header));
			break;
		case CFM_V2_MAGIC_NUM:
			offset = visualize_cfm (manifest + sizeof (struct manifest_header));
			break;
		case PCD_V2_MAGIC_NUM:
			offset = visualize_pcd (manifest + sizeof (struct manifest_header));
			break;
		default:
			goto exit;
	}

	if (offset == -1) {
		goto exit;
	}

	pointer = manifest + offset + sizeof (struct manifest_header);

	printf ("Signature:");
	for (int k = 0; k < header->sig_length; ++k)
	{
		if ((k % 32) == 0)
		{
			printf ("\n\t");
		}
		printf ("%02x", pointer[k]);
	}
	printf ("\n");

exit:
	if (manifest != NULL) {
		free (manifest);
	}

	if (element_types != NULL) {
		free (element_types);
	}
}
