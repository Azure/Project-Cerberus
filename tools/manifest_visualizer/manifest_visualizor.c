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


int32_t visualize_pfm (uint8_t *pfm) 
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

int32_t visualize_cfm (uint8_t *cfm) 
{
	struct cfm_components_header *components_header = (struct cfm_components_header*)cfm;
	uint8_t* pointer = ((uint8_t*)components_header) + sizeof (struct cfm_components_header);

	printf ("cfm_components_header\n");
	printf ("{");
	printf ("\tlength: %i\n", components_header->length);
	printf ("\tcomponents_count: %i\n", components_header->components_count);
	printf ("\treserved: %i\n", components_header->reserved);
	printf ("}\n");

	printf ("Components\n");
	printf ("[\n");

	for (int i = 0; i < components_header->components_count; ++i)
	{
		struct cfm_component_header *component_header = (struct cfm_component_header*) pointer;
		printf ("\t{\n");
		printf ("\t\tcfm_component_header\n");
		printf ("\t\t{\n");
		printf ("\t\t\tlength: %i\n", component_header->length);
		printf ("\t\t\tfw_count: %i\n", component_header->fw_count);
		printf ("\t\t\treserved: %i\n", component_header->reserved);
		printf ("\t\t\tcomponent_id: 0x%x\n", component_header->component_id);
		printf ("\t\t}\n");
		
		pointer += sizeof (struct cfm_component_header);

		printf ("\t\tFirmware\n");
		printf ("\t\t[\n");

		for (int j = 0; j < component_header->fw_count; ++j)
		{
			struct cfm_fw_header *fw_header = (struct cfm_fw_header*) pointer;
			char *version_id = (char*)malloc (fw_header->version_length + 1);
			if(version_id == NULL)
			{
				printf ("Failed to allocate version ID buffer.\n");
				return -1;
			}

			strncpy (version_id, (char*)((uint8_t*)fw_header + sizeof (struct cfm_fw_header)),
            	fw_header->version_length);
			version_id[fw_header->version_length] = '\0';

			int alignment = fw_header->version_length % 4;
			alignment = (alignment == 0) ? 0 : (4 - alignment);
			pointer += sizeof (struct cfm_fw_header) + fw_header->version_length + alignment;

			printf ("\t\t\t{\n");
			printf ("\t\t\t\tcfm_fw_header\n");
			printf ("\t\t\t\t{\n");
			printf ("\t\t\t\t\tlength: %i\n", fw_header->length);
			printf ("\t\t\t\t\timg_count: %i\n", fw_header->img_count);
			printf ("\t\t\t\t\treserved: %i\n", fw_header->reserved);
			printf ("\t\t\t\t\tversion_length: %i\n", fw_header->version_length);
			printf ("\t\t\t\t\treserved2: %i\n", fw_header->reserved2);
			printf ("\t\t\t\t}\n");

			printf ("\t\t\t\tversion_id: %s\n", version_id);

			printf ("\t\t\t\tSigned Images\n");
			printf ("\t\t\t\t[\n");

			for (int k = 0; k < fw_header->img_count; ++k)
			{
				struct cfm_img_header *img_header = (struct cfm_img_header*) pointer;
				uint8_t *digest = malloc (img_header->digest_length);
				if(digest == NULL)
				{
					printf ("Failed to allocate digest buffer.\n");
					return -1;
				}

				memcpy(digest, (char*)((uint8_t*)img_header + sizeof (struct cfm_img_header)),
					img_header->digest_length);

				pointer += sizeof (struct cfm_img_header) + img_header->digest_length;

				printf ("\t\t\t\t\t{\n");
				printf ("\t\t\t\t\t\tcfm_img_header\n");
				printf ("\t\t\t\t\t\t{\n");
				printf ("\t\t\t\t\t\t\tlength: %i\n", img_header->length);
				printf ("\t\t\t\t\t\t\tdigest_length: %i\n", img_header->digest_length);
				printf ("\t\t\t\t\t\t\tflags: %i\n", img_header->flags);
				printf ("\t\t\t\t\t\t\treserved: %i\n", img_header->reserved);
				printf ("\t\t\t\t\t\t}\n");

				printf ("\t\t\t\t\t\tDigest:");
				for (int l = 0; l < img_header->digest_length; ++l)
				{
					if ((l % 32) == 0)
					{
						printf ("\n\t\t\t\t\t\t\t");
					}
					printf ("%02x", digest[l]);
				}

				printf ("\n");
				printf ("\t\t\t\t\t}\n");
				free (digest);
			}

			printf ("\t\t\t\t]\n");
			printf ("\t\t\t}\n");
		}
		printf ("\t\t]\n");
		printf ("\t}\n");
	}

	printf ("]\n");

	return (pointer - cfm);
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
		printf ("\t\t\ttype_id: %i\n", entry->type_id);
		printf ("\t\t\tparent: %i\n", entry->parent);
		printf ("\t\t\tformat: %i\n", entry->format);
		printf ("\t\t\thash_id: %i\n", entry->hash_id);
		printf ("\t\t\toffset: %i\n", entry->offset);
		printf ("\t\t\tlength: %i\n", entry->length);
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

	printf ("%s\tPorts\n", prefix);
	printf ("%s\t[\n", prefix);

	for (int i = 0; i < rot->port_count; ++i) {
		struct pcd_port *port = (struct pcd_port*) pointer;
		pointer += sizeof (struct pcd_port);

		printf ("%s\t\tpcd_port\n", prefix);
		printf ("%s\t\t{\n", prefix);
		printf ("%s\t\t\tport_id: %i\n", prefix, port->port_id);
		printf ("%s\t\t\tport_flags: 0x%x\n", prefix, port->port_flags);
		printf ("%s\t\t\tpolicy: 0x%x\n", prefix, port->policy);
		printf ("%s\t\t\treserved: %i\n", prefix, port->reserved);
		printf ("%s\t\t\tspi_frequency_hz: %i\n", prefix, port->spi_frequency_hz);
		printf ("%s\t\t}\n", prefix);
	}

	printf ("%s\t]\n", prefix);
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

	type = malloc (component->type_len + 1);
	if (type == NULL) {
		printf ("Failed to allocate type buffer.\n");
		return -1;
	}

	memcpy (type, pointer, component->type_len);
	type[component->type_len] = '\0';

	printf ("%s\tType: %s\n", prefix, type);
	free (type);

	type_len = ((component->type_len + 3) & ~((size_t) 3));
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

	type = malloc (component->type_len + 1);
	if (type == NULL) {
		printf ("Failed to allocate type buffer.\n");
		return -1;
	}

	memcpy (type, pointer, component->type_len);
	type[component->type_len] = '\0';

	printf ("%s\tType: %s\n", prefix, type);
	free (type);

	type_len = ((component->type_len + 3) & ~((size_t) 3));
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
	uint8_t manifest_type;
	uint8_t *pointer;
	uint8_t *manifest;
	unsigned long fileLen;

	if (argc < 3 || argv == NULL) {
		printf ("No manifest file passed in.\n");
		return -1;
	}

	if (strncmp (argv[2], "pfm", 3) == 0) {
		manifest_type = MANIFEST_TYPE_PFM;
	}
	else if (strncmp (argv[2], "cfm", 3) == 0) {
		manifest_type = MANIFEST_TYPE_CFM;
	}
	else if (strncmp (argv[2], "pcd", 3) == 0) {
		manifest_type = MANIFEST_TYPE_PCD;
	}
	else {
		printf ("Manifest type unknown: %s", argv[2]);
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

	switch (manifest_type)
	{
		case MANIFEST_TYPE_PFM:
			offset = visualize_pfm (manifest + sizeof (struct manifest_header));
			break;
		case MANIFEST_TYPE_CFM:
			offset = visualize_cfm (manifest + sizeof (struct manifest_header));
			break;
		case MANIFEST_TYPE_PCD:
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
