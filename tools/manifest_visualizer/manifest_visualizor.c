// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "..\..\core\manifest\manifest_format.h"
#include "..\..\core\manifest\pfm\pfm_format.h"
#include "..\..\core\manifest\cfm\cfm_format.h"
#include "..\..\core\manifest\pcd\pcd_format.h"
#include "..\..\core\manifest\pcd\pcd.h"


enum {
	MANIFEST_TYPE_PFM = 0,
	MANIFEST_TYPE_CFM,
	MANIFEST_TYPE_PCD
};


size_t visualize_pfm (uint8_t *pfm) 
{
	struct pfm_allowable_firmware_header *allowable_fw_header = 
		(struct pfm_allowable_firmware_header*) pfm;
	uint8_t* pointer = ((uint8_t*)allowable_fw_header) +
		sizeof(struct pfm_allowable_firmware_header);

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
		struct pfm_firmware_header *fw_header = (struct pfm_firmware_header*)pointer;
		char *version_id = (char*)malloc (fw_header->version_length + 1);
		if(version_id == NULL)
		{
			printf ("Failed to allocate version id buffer.\n");
			return -1;
		}

		strncpy(version_id, (char*)((uint8_t*)fw_header + sizeof(struct pfm_firmware_header)),
            fw_header->version_length);
		version_id[fw_header->version_length] = '\0';
		int alignment = fw_header->version_length % 4;
		alignment = (alignment == 0) ? 0 : (4 - alignment);
		pointer = (uint8_t*)fw_header + sizeof(struct pfm_firmware_header) +
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
			uint32_t start_addr = *((uint32_t*)pointer);
			uint32_t end_addr = *((uint32_t*)pointer + 1);
			pointer = (uint8_t*)((uint32_t*)pointer + 2);

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
			pointer = (uint8_t*)img_header + sizeof(struct pfm_image_header) +
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
				uint32_t start_addr = *((uint32_t*)pointer);
				uint32_t end_addr = *((uint32_t*)pointer + 1);
				pointer = (uint8_t*)((uint32_t*)pointer + 2);
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

	struct pfm_key_manifest_header *key_manifest_header = (struct pfm_key_manifest_header *)pointer;
	pointer = (uint8_t*)pointer + sizeof(struct pfm_key_manifest_header);

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
		struct pfm_public_key_header *key_header = (struct pfm_public_key_header*)pointer;

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
		pointer = (uint8_t*)key_header + sizeof(struct pfm_public_key_header) +
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

	struct pfm_platform_header *platform_header = (struct pfm_platform_header *)pointer;
	pointer = (uint8_t*)pointer + sizeof(struct pfm_platform_header);

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

size_t visualize_cfm (uint8_t *cfm) 
{
	struct cfm_components_header *components_header = (struct cfm_components_header*)cfm;
	uint8_t* pointer = ((uint8_t*)components_header) + sizeof(struct cfm_components_header);

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
		struct cfm_component_header *component_header = (struct cfm_component_header*)pointer;
		printf ("\t{\n");
		printf ("\t\tcfm_component_header\n");
		printf ("\t\t{\n");
		printf ("\t\t\tlength: %i\n", component_header->length);
		printf ("\t\t\tfw_count: %i\n", component_header->fw_count);
		printf ("\t\t\treserved: %i\n", component_header->reserved);
		printf ("\t\t\tcomponent_id: 0x%x\n", component_header->component_id);
		printf ("\t\t}\n");
		
		pointer += sizeof(struct cfm_component_header);

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

			strncpy (version_id, (char*)((uint8_t*)fw_header + sizeof(struct cfm_fw_header)),
            	fw_header->version_length);
			version_id[fw_header->version_length] = '\0';

			int alignment = fw_header->version_length % 4;
			alignment = (alignment == 0) ? 0 : (4 - alignment);
			pointer += sizeof(struct cfm_fw_header) + fw_header->version_length + alignment;

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

				memcpy(digest, (char*)((uint8_t*)img_header + sizeof(struct cfm_img_header)),
					img_header->digest_length);

				pointer += sizeof(struct cfm_img_header) + img_header->digest_length;

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

size_t visualize_pcd (uint8_t *pcd) 
{
	struct pcd_header *pcd_header = (struct pcd_header*) pcd;
	uint8_t* pointer = pcd + sizeof(struct pcd_header);

	printf ("PCD\n");
	printf ("{\n");
	printf ("\tpcd_header\n");
	printf ("\t{\n");
	printf ("\t\tlength: %i\n", pcd_header->length);
	printf ("\t\theader_len: %i\n", pcd_header->header_len);
	printf ("\t\tformat_id: %i\n", pcd_header->format_id);
	printf ("\t\treserved1: %i\n", pcd_header->reserved1);
	printf ("\t\treserved2: %i\n", pcd_header->reserved2);
	printf ("\t\treserved3: %i\n", pcd_header->reserved3);
	printf ("\t}\n");

	struct pcd_rot_header *rot_header = (struct pcd_rot_header*) pointer;
	pointer += sizeof(struct pcd_rot_header);

	printf ("\tpcd_rot_header\n");
	printf ("\t{\n");
	printf ("\t\tlength: %i\n", rot_header->length);
	printf ("\t\theader_len: %i\n", rot_header->header_len);
	printf ("\t\tformat_id: %i\n", rot_header->format_id);
	printf ("\t\tnum_ports: %i\n", rot_header->num_ports);
	printf ("\t\taddr: 0x%x\n", rot_header->addr);
	printf ("\t\tbmc_i2c_addr: 0x%x\n", rot_header->bmc_i2c_addr);
	printf ("\t\tcpld_addr: 0x%x\n", rot_header->cpld_addr);
	printf ("\t\tcpld_channel: %i\n", rot_header->cpld_channel);
	printf ("\t\tactive: %i\n", rot_header->active);
	printf ("\t\tdefault_failure_action: %i\n", rot_header->default_failure_action);
	printf ("\t\tflags: 0x%x\n", rot_header->flags);
	printf ("\t\treserved1: %i\n", rot_header->reserved1);
	printf ("\t\treserved2: %i\n", rot_header->reserved2);
	printf ("\t\treserved3: %i\n", rot_header->reserved3);
	printf ("\t}\n");

	printf ("\tPorts\n");
	printf ("\t[\n");

	for (int i = 0; i < rot_header->num_ports; ++i)
	{
		struct pcd_port_header *port = (struct pcd_port_header*)pointer;
		pointer += sizeof(struct pcd_port_header);

		printf ("\t\tpcd_port_header\n");
		printf ("\t\t{\n");
		printf ("\t\t\tlength: %i\n", port->length);
		printf ("\t\t\theader_len: %i\n", port->header_len);
		printf ("\t\t\tformat_id: %i\n", port->format_id);
		printf ("\t\t\tid: %i\n", port->id);
		printf ("\t\t\treserved1: %i\n", port->reserverd1);
		printf ("\t\t\treserved2: %i\n", port->reserverd2);
		printf ("\t\t\tfrequency: %i\n", port->frequency);
		printf ("\t\t}\n");
	}

	printf ("\t]\n");

	struct pcd_components_header *components_header = (struct pcd_components_header*) pointer;
	pointer += sizeof(struct pcd_components_header);

	printf ("\tpcd_components_header\n");
	printf ("\t{\n");
	printf ("\t\tlength: %i\n", components_header->length);
	printf ("\t\theader_len: %i\n", components_header->header_len);
	printf ("\t\tformat_id: %i\n", components_header->format_id);
	printf ("\t\tnum_components: %i\n", components_header->num_components);
	printf ("\t\treserved1: %i\n", components_header->reserved1);
	printf ("\t\treserved2: %i\n", components_header->reserved2);
	printf ("\t}\n");

	printf ("\tComponents\n");
	printf ("\t[\n");

	for (int i = 0; i < components_header->num_components; ++i)
	{
		struct pcd_component_header *component_header = (struct pcd_component_header*)pointer;
		pointer += sizeof(struct pcd_component_header);

		printf ("\t\t{\n");
		printf ("\t\t\tpcd_component_header\n");
		printf ("\t\t\t{\n");
		printf ("\t\t\t\tlength: %i\n", component_header->length);
		printf ("\t\t\t\theader_len: %i\n", component_header->header_len);
		printf ("\t\t\t\tformat_id: %i\n", component_header->format_id);
		printf ("\t\t\t\tnum_muxes: %i\n", component_header->num_muxes);
		printf ("\t\t\t\taddr: 0x%x\n", component_header->addr);
		printf ("\t\t\t\tchannel: %i\n", component_header->channel);
		printf ("\t\t\t\tflags: %i\n", component_header->flags);
		printf ("\t\t\t\teid: 0x%x\n", component_header->eid);
		printf ("\t\t\t\tpower_ctrl_reg: 0x%x\n", component_header->power_ctrl_reg);
		printf ("\t\t\t\tpower_ctrl_mask: 0x%x\n", component_header->power_ctrl_mask);
		printf ("\t\t\t\tid: %i\n", component_header->id);
		printf ("\t\t\t}\n");

		printf ("\t\t\tMuxes\n");
		printf ("\t\t\t[\n");

		for (int i = 0; i < component_header->num_muxes; ++i)
		{
			struct pcd_mux_header *mux = (struct pcd_mux_header*)pointer;
			pointer += sizeof(struct pcd_mux_header);

			printf ("\t\t\t\t\tpcd_mux_header\n");
			printf ("\t\t\t\t\t{\n");
			printf ("\t\t\t\t\t\tlength: %i\n", mux->length);
			printf ("\t\t\t\t\t\theader_len: %i\n", mux->header_len);
			printf ("\t\t\t\t\t\tformat_id: %i\n", mux->format_id);
			printf ("\t\t\t\t\t\taddr: 0x%x\n", mux->addr);
			printf ("\t\t\t\t\t\tchannel: %i\n", mux->channel);
			printf ("\t\t\t\t\t\tmux_level: %i\n", mux->mux_level);
			printf ("\t\t\t\t\t}\n");
		}

		printf ("\t\t\t]\n");
		printf ("\t\t}\n");
	}

	printf ("\t]\n");

	struct pcd_platform_header *platform_header = (struct pcd_platform_header*) pointer;
	pointer += sizeof(struct pcd_platform_header);

	printf ("\tpcd_platform_header\n");
	printf ("\t{\n");
	printf ("\t\tlength: %i\n", platform_header->length);
	printf ("\t\theader_len: %i\n", platform_header->header_len);
	printf ("\t\tformat_id: %i\n", platform_header->format_id);
	printf ("\t\tid_len: %i\n", platform_header->id_len);
	printf ("\t\treserved1: %i\n", platform_header->reserved1);
	printf ("\t\treserved2: %i\n", platform_header->reserved2);
	printf ("\t}\n");

	char *platform_id = malloc (platform_header->id_len + 1);
	if (platform_id == NULL) {
		printf ("Failed to allocate platform id buffer.\n");
		return -1;
	}

	memcpy (platform_id, pointer, platform_header->id_len);
	platform_id[platform_header->id_len] = '\0';
	pointer += platform_header->id_len;

	printf ("\tPlatform ID: %s\n", platform_id);
	free (platform_id);
	printf ("}\n");

	return (pointer - pcd);
}

int main (int argc, char** argv)
{
	FILE *fp;
	size_t offset;
	uint8_t manifest_type;
	uint8_t *pointer;
	uint8_t *manifest;
	unsigned long fileLen;

	if (argc < 3 || argv == NULL) {
		printf ("No PCD file passed in.\n");
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
		printf ("Failed to open PCD file.\n");
		return -1;
	}

	fseek (fp, 0, SEEK_END);
	fileLen = ftell (fp);
	fseek (fp, 0, SEEK_SET);

	manifest = (uint8_t*) malloc (fileLen + 1);
	if (manifest == NULL) {
		printf ("Failed to allocate PCD buffer.\n");
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
	free (manifest);
}
