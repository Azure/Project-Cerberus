"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import os
import sys
import ctypes
import binascii
import argparse
import manifest_types
import manifest_common
from Crypto.PublicKey import RSA


PFM_CONFIG_FILENAME = "pfm_generator.config"
VALIDATE_ON_BOOT_FLAG = 1


# Table which indexes public keys used in this PFM file
pbkey_table = []

# List of all FW version strings
version_list = []

# These ctype structs resemble the format the PFM consumer utilizes
class pfm_fw_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('version_length', ctypes.c_ubyte),
                ('blank_byte', ctypes.c_ubyte),
                ('version_addr', ctypes.c_uint),
                ('img_count', ctypes.c_ubyte),
                ('rw_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ushort)]

class pfm_allowable_fw_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('fw_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class pfm_public_key_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('key_length', ctypes.c_ushort),
                ('key_exponent', ctypes.c_uint),
                ('id', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte * 3)]

class pfm_key_manifest_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('key_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class pfm_flash_region(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('start_addr', ctypes.c_uint),
                ('end_addr', ctypes.c_uint)]

class pfm_image_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('flags', ctypes.c_ushort),
                ('key_id', ctypes.c_ubyte),
                ('region_count', ctypes.c_ubyte),
                ('sig_length', ctypes.c_ushort)]

class pfm_platform_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('id_length', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]


def process_pbkey(xml_list):
    """
    Iterate through all public keys used in this PFM and create a public key table.

    :param xml_list: List of parsed XMLs for different FW to be included in PFM
    """

    for _, xml in xml_list.items():
        if "signed_imgs" in xml:
            for img in xml["signed_imgs"]:
                if "pbkey" in img:
                    pbkey = RSA.importKey(img["pbkey"])
                    img.pop("pbkey")
                    if pbkey not in pbkey_table:
                        pbkey_table.append(pbkey)
                        img["pbkey_index"] = len(pbkey_table) - 1
                    else:
                        img["pbkey_index"] =  pbkey_table.index(pbkey)

def generate_pfm(pfm_header_instance, allowable_fw_header_instance, allowable_fw_list,
        keys_header_instance, keys_list, platform_header_instance):
    """
    Create a PFM object from all the different PFM components

    :param pfm_header_instance: Instance of a PFM header
    :param allowable_fw_header_instance: Instance of a PFM allowable FW header
    :param allowable_fw_list: List of allowable FWs to be included in PFM
    :param keys_header_instance: Instance of a PFM key manifest header
    :param keys_list: List of public keys to be included in PFM
    :param platform_header_instance: Instance of a PFM platform header

    :return Instance of a PFM object
    """
    fw_size = allowable_fw_header_instance.length - ctypes.sizeof(allowable_fw_header_instance)
    keys_size = keys_header_instance.length - ctypes.sizeof(keys_header_instance)
    platform_size = ctypes.sizeof(platform_header_instance)

    class pfm(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('manifest_header', manifest_common.manifest_header),
                    ('allowable_fw_header', pfm_allowable_fw_header),
                    ('allowable_fw', ctypes.c_ubyte * fw_size),
                    ('key_manifest_header', pfm_key_manifest_header),
                    ('pb_keys', ctypes.c_ubyte * keys_size),
                    ('platform', ctypes.c_ubyte * platform_size)]

    offset = 0
    fw_buf = (ctypes.c_ubyte * fw_size)()

    for fw in allowable_fw_list:
        ctypes.memmove(ctypes.addressof(fw_buf) + offset, ctypes.addressof(fw), fw.header.length)
        offset += fw.header.length

    offset = 0
    keys_buf = (ctypes.c_ubyte * keys_size)()

    for key in keys_list:
        ctypes.memmove(ctypes.addressof(keys_buf) + offset, ctypes.addressof(key),
            key.header.length)
        offset += key.header.length

    platform_buf = (ctypes.c_ubyte * platform_size)()
    ctypes.memmove (ctypes.addressof(platform_buf), ctypes.addressof(platform_header_instance),
        platform_size)

    return pfm(pfm_header_instance, allowable_fw_header_instance, fw_buf, keys_header_instance,
        keys_buf, platform_buf)

def generate_flash_region(filename, region_list):
    """
    Create a list of flash region struct instances from region list

    :param region_list: List of flash regions

    :return List of flash region struct instances
    """

    flash_list = []

    for region in region_list:
        if "start" in region and "end" in region:
            start_addr = int(region["start"], 16)
            end_addr = int(region["end"], 16)

            if end_addr <= start_addr:
                raise ValueError("Failed to generate PFM: Image has an invalid flash region - {0}"
                    .format(filename))

            flash_list.append(pfm_flash_region(start_addr, end_addr))

    return flash_list

def generate_img_instance(filename, img, regions, signature):
    """
    Create a list of signed image instances

    :param region_list: List of flash regions

    :return List of signed image instances
    """

    if "validate" not in img:
        raise KeyError("Failed to generate PFM: Image has no validate flag - {0}".format(filename))
    if "pbkey_index" not in img:
        raise KeyError("Failed to generate PFM: Image has no public key index - {0}".format(
            filename))

    flags = 1 if img["validate"] == "true" else 0
    header = pfm_image_header(0, flags, img["pbkey_index"], len(regions), len(signature))
    sig_arr = (ctypes.c_ubyte * len(signature)).from_buffer_copy(signature)
    region_arr = (pfm_flash_region * len(regions))(*regions)

    class pfm_signed_img(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', pfm_image_header),
                    ('img_signature', ctypes.c_ubyte * len(signature)),
                    ('flash_regions', pfm_flash_region * len(regions))]

    return pfm_signed_img(header, sig_arr, region_arr)

def generate_signed_image(filename, img_list):
    """
    Create a list of signed image struct instances from image list

    :param img_list: List of allowable firmware images

    :return List of signed image struct instances
    """

    signed_list = []

    for img in img_list:
        if "regions" not in img:
            raise KeyError("Failed to generate PFM: Image has no regions list - {0}".format(
                filename))

        if "signature" not in img:
            raise KeyError("Failed to generate PFM: Image has no signature - {0}".format(filename))

        regions = generate_flash_region(filename, img["regions"])
        img_instance = generate_img_instance(filename, img, regions, img["signature"])
        img_instance.header.length = ctypes.sizeof(img_instance)
        signed_list.append(img_instance)

    return signed_list

def generate_allowable_fw_list(xml_list):
    """
    Create a list of allowable firmware from parsed XML list

    :param xml_list: List of parsed XML of firmware to be included in PFM

    :return list of allowable firmware struct instances
    """

    fw_list = []

    for filename, xml in xml_list.items():
        if "version_id" not in xml:
            raise KeyError("Failed to generate PFM: XML has no version id - {0}".format(filename))

        if "version_addr" not in xml:
            raise KeyError("Failed to generate PFM: XML has no version address - {0}".format(
                filename))

        if "signed_imgs" not in xml:
            raise KeyError("Failed to generate PFM: XML has no signed images list - {0}".format(
                filename))

        if "unused_byte" not in xml:
            raise KeyError("Failed to generate PFM: Unused byte value not known - {0}".format(
                filename))

        if "rw_regions" not in xml:
            xml["rw_regions"]= []

        all_regions = []
        flags = 0
        version_addr = int(xml["version_addr"], 16)
        unused_byte = int(xml["unused_byte"], 16)
        version_addr_valid = False

        for version in version_list:
            if version == xml["version_id"]:
                raise KeyError("Failed to generate PFM: Duplicate version ID - {0}".format (
                    xml["version_id"]))
            elif version.startswith(xml["version_id"]) or xml["version_id"].startswith(version):
                raise ValueError("Failed to generate PFM: Ambiguous version ID - {0}, {1}".format (
                    xml["version_id"], version))

        version_list.append (xml["version_id"])

        if unused_byte > 255:
            raise ValueError("Unused byte value ({0}) is not valid - {1}".format(
                format(unused_byte, '02x'), filename))

        header = pfm_fw_header(0, len(xml["version_id"]), unused_byte, version_addr,
            len(xml["signed_imgs"]), len(xml["rw_regions"]), 0)
        rw_regions_list = generate_flash_region(filename, xml["rw_regions"])
        rw_regions_arr = (pfm_flash_region * len(rw_regions_list))(*rw_regions_list)
        signed_imgs_list = generate_signed_image(filename, xml["signed_imgs"])

        for region in rw_regions_list:
            if region.start_addr & 0xFFFF:
                raise ValueError("Failed to generate PFM: RW Start address (0x{0}) is not 64kB aligned - {1}"
                    .format(format(region.start_addr, '08x'), filename))

            if (region.end_addr & 0xFFFF) != 0xFFFF:
                raise ValueError("Failed to generate PFM: RW End address (0x{0}) is not 64kB aligned - {1}"
                    .format(format(region.end_addr, '08x'), filename))

            all_regions.append([region.start_addr, region.end_addr])

        for img in signed_imgs_list:
            flags |= (img.header.flags & VALIDATE_ON_BOOT_FLAG)
            for region in img.flash_regions:
                all_regions.append([region.start_addr, region.end_addr])

                if (img.header.flags & VALIDATE_ON_BOOT_FLAG) == VALIDATE_ON_BOOT_FLAG:
                    if ((version_addr + header.version_length - 1) <= region.end_addr and
                        version_addr >= region.start_addr):
                        version_addr_valid = True

        if not version_addr_valid:
            raise ValueError("Failed to generate PFM: Version address not in a signed image with validate on boot flag set - {0}"
                .format(filename))

        if flags == 0:
            raise ValueError("Failed to generate PFM: XML has no signed images with validate on boot flag set - {0}"
                .format(filename))

        all_regions.sort()

        for i_region, region in enumerate(all_regions):
            for i_comp in range(i_region + 1, len(all_regions)):
                if region[1] >= all_regions[i_comp][0]:
                    raise ValueError("Failed to generate PFM: XML has overlapping regions - {0}"
                        .format(filename))

        signed_imgs_size = 0
        for img in signed_imgs_list:
            signed_imgs_size = signed_imgs_size + ctypes.sizeof(img)

        offset = 0
        signed_imgs_buf = (ctypes.c_ubyte * signed_imgs_size)()

        for img in signed_imgs_list:
            ctypes.memmove(ctypes.addressof(signed_imgs_buf) + offset, ctypes.addressof(img),
                img.header.length)
            offset += img.header.length

        num_alignment = len(xml["version_id"])  % 4
        num_alignment = 0 if (num_alignment == 0) else (4 - num_alignment)
        alignment_buf = (ctypes.c_ubyte * num_alignment)()
        ctypes.memset(alignment_buf, 0, num_alignment)

        class pfm_allowable_fw(ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('header', pfm_fw_header),
                        ('version_id', ctypes.c_char * len(xml["version_id"])),
                        ('alignment', ctypes.c_ubyte * num_alignment),
                        ('rw_regions', pfm_flash_region * len(rw_regions_list)),
                        ('signed_imgs', ctypes.c_ubyte * signed_imgs_size)]

        fw = pfm_allowable_fw(header, xml["version_id"], alignment_buf, rw_regions_arr,
            signed_imgs_buf)
        fw.header.length = ctypes.sizeof(pfm_allowable_fw)
        fw_list.append(fw)

    return fw_list

def generate_allowable_fw_header(fw_list):
    """
    Create an allowable FW header from an allowable FW list

    :param fw_list: List of allowable FW to be included in PFM

    :return Allowable FW header instance
    """

    size = ctypes.sizeof(pfm_allowable_fw_header)
    for fw in fw_list:
        size = size + ctypes.sizeof(fw)

    return pfm_allowable_fw_header(size, len(fw_list), 0)

def generate_key_instance(header, modulus):
    """
    Create a key instance from header and modulus

    :param header: PFM public key header
    :param modulus: List of public key modulus digits

    :return Public key instance
    """

    arr = (ctypes.c_ubyte * len(modulus)).from_buffer_copy(modulus)

    class pfm_public_key(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', pfm_public_key_header),
                    ('public_key_modulus', ctypes.c_ubyte * len(modulus))]

    return pfm_public_key(header, arr)

def generate_pbkey_list():
    """
    Create a public key list from the public key table

    :return List of public key instances
    """

    keys_list = []

    for pub_key in pbkey_table:
        reserved_buf = (ctypes.c_ubyte * 3)()
        ctypes.memset(reserved_buf, 0, 3)
        mod_fmt = "%%0%dx" % (pub_key.n.bit_length() // 4)
        modulus = binascii.a2b_hex(mod_fmt % pub_key.n)

        header = pfm_public_key_header(0, len(modulus), pub_key.e, pbkey_table.index(pub_key),
            reserved_buf)

        key = generate_key_instance(header, modulus)
        key.header.length = ctypes.sizeof(key)
        keys_list.append(key)

    return keys_list

def generate_pbkey_header(keys_list):
    """
    Create a public key manifest header from list of public key objects

    :param keys_list: List of public key objects

    :return Public key manifest header
    """

    size = ctypes.sizeof(pfm_key_manifest_header)

    for key in keys_list:
        size = size + ctypes.sizeof(key)

    return pfm_key_manifest_header(size, len(keys_list), 0)

def get_platform_id(xml_list):
    """
    Determine the platform ID for the manifest

    :param xml_list: List of parse XML files with version information.

    :return The platform ID
    """

    platform_id = None
    for filename, xml in xml_list.items():
        if "platform_id" not in xml:
            raise KeyError("Failed to generate PFM: XML has no platform id - {0}".format(filename))

        if platform_id:
            if platform_id != xml["platform_id"]:
                raise ValueError("Failed to generate PFM: Version platform ids don't match - ({0}, {1})"
                    .format(platform_id, xml["platform_id"]))
        else:
            platform_id = xml["platform_id"]

    return platform_id

def generate_platform_info(platform_id):
    """
    Create the platform information section of the PFM.

    :param platform_id: ID for the platform

    :return Platform manifest section
    """

    header = pfm_platform_header(0, len(platform_id), 0)

    num_alignment = len(platform_id)  % 4
    num_alignment = 0 if (num_alignment == 0) else (4 - num_alignment)
    alignment_buf = (ctypes.c_ubyte * num_alignment)()
    ctypes.memset(alignment_buf, 0, num_alignment)

    class pfm_platform_id(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', pfm_platform_header),
                    ('platform_id', ctypes.c_char * len(platform_id)),
                    ('alignment', ctypes.c_ubyte * num_alignment)]

    platform = pfm_platform_id(header, platform_id, alignment_buf)
    platform.header.length = ctypes.sizeof(pfm_platform_id)

    return platform

#*************************************** Start of Script ***************************************

default_config = os.path.join(os.path.dirname(os.path.abspath(__file__)), PFM_CONFIG_FILENAME)
parser = argparse.ArgumentParser(description = 'Create a PFM')
parser.add_argument('config', nargs = '?', default = default_config,
    help = 'Path to configurtaion file')
parser.add_argument('--bypass', action = 'store_true', help = 'Create a bypass mode PFM')
args = parser.parse_args()

processed_xml, sign, key_size, key, pfm_id, output = manifest_common.load_xmls (args.config, None,
    manifest_types.PFM)

process_pbkey(processed_xml)

if (args.bypass):
    allowable_fw_list = []
else:
    allowable_fw_list = generate_allowable_fw_list(processed_xml)
allowable_fw_header = generate_allowable_fw_header(allowable_fw_list)

if (args.bypass):
    keys_list = []
else:
    keys_list = generate_pbkey_list()
keys_header = generate_pbkey_header(keys_list)

platform_id = get_platform_id(processed_xml)
platform_header = generate_platform_info(platform_id)

pfm_header_instance = manifest_common.generate_manifest_header(pfm_id, key_size, manifest_types.PFM)
pfm_header_instance.length = ctypes.sizeof(pfm_header_instance) + keys_header.length + \
    allowable_fw_header.length + pfm_header_instance.sig_length + platform_header.header.length

pfm = generate_pfm(pfm_header_instance, allowable_fw_header, allowable_fw_list, keys_header,
    keys_list, platform_header)

manifest_common.write_manifest(sign, pfm, key, output,
    pfm_header_instance.length - pfm_header_instance.sig_length,
    pfm_header_instance.sig_length)

print("Completed PFM generation: {0}".format(output))

