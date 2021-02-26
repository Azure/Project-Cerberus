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
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512


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

class pfm_v2_platform_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('id_length', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte * 3)]

class pfm_v2_flash_device_element(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('blank_byte', ctypes.c_ubyte),
                ('fw_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ushort)]

class pfm_v2_fw_id_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('version_count', ctypes.c_ubyte),
                ('fw_id_length', ctypes.c_ubyte),
                ('fw_flags', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class pfm_v2_fw_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('image_count', ctypes.c_ubyte),
                ('rw_count', ctypes.c_ubyte),
                ('version_length', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class pfm_rw_flash_region(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('flags', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte * 3),
                ('start_addr', ctypes.c_uint),
                ('end_addr', ctypes.c_uint)]

class pfm_v2_image_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('hash_type', ctypes.c_ubyte),
                ('region_count', ctypes.c_ubyte),
                ('flags', ctypes.c_ubyte),
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

def generate_rw_flash_region(filename, region_list):
    """
    Create a list of flash region struct instances from region list

    :param filename: XML file
    :param region_list: List of R/W flash regions

    :return List of R/W flash region struct instances
    """

    flash_list = []

    for region in region_list:
        start_addr = int(region["start"], 16)
        end_addr = int(region["end"], 16)

        if end_addr <= start_addr:
            raise ValueError("Failed to generate PFM: Image has an invalid R/W flash region - {0}"
                .format(filename))

        operation_on_fail = int(region["operation_fail"], 16)

        reserved_buf = (ctypes.c_ubyte * 3)()
        ctypes.memset(reserved_buf, 0, 3)
        flash_list.append(pfm_rw_flash_region(operation_on_fail, reserved_buf, start_addr, end_addr))

    return flash_list

def generate_img_instance(filename, img, regions, signature, xml_version):
    """
    Create a list of signed image instances

    :param filename: Parsed XML file
    :param img: Signed or hashed image for which an image instance to generated
    :param signature: Buffer containing either signature or hash of the image
    :param region_list: List of flash regions

    :return List of signed image instances
    """

    if "validate" not in img:
        raise KeyError("Failed to generate PFM: Image has no validate flag - {0}".format(filename))
    if xml_version == manifest_types.VERSION_1 and "pbkey_index" not in img:
        raise KeyError("Failed to generate PFM: Image has no public key index - {0}".format(
            filename))
    if  xml_version == manifest_types.VERSION_2 and "hash_type" not in img:
        raise KeyError("Failed to generate PFM: Image has no hash type - {0}".format(filename))


    flags = 1 if img["validate"] == "true" else 0
    if xml_version == manifest_types.VERSION_1:
        header = pfm_image_header(0, flags, img["pbkey_index"], len(regions), len(signature))
    else:
        hash_type = int(img["hash_type"], 16)
        header = pfm_v2_image_header(hash_type, len(regions), flags, 0)

    sig_arr = (ctypes.c_ubyte * len(signature)).from_buffer_copy(signature)
    region_arr = (pfm_flash_region * len(regions))(*regions)

    class pfm_signed_img(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', pfm_image_header if xml_version is manifest_types.VERSION_1 else pfm_v2_image_header),
                    ('img_signature', ctypes.c_ubyte * len(signature)),
                    ('flash_regions', pfm_flash_region * len(regions))]

    return pfm_signed_img(header, sig_arr, region_arr)

def generate_signed_image(filename, img_list, xml_version):
    """
    Create a list of signed image struct instances from image list

    :param filename: parsed XML file
    :param img_list: List of allowable firmware images
    :param xml_version: XML file version

    :return List of signed image struct instances
    """

    signed_list = []

    for img in img_list:
        if "regions" not in img:
            raise KeyError("Failed to generate PFM: Image has no regions list - {0}".format(
                filename))

        if xml_version == manifest_types.VERSION_1 and "signature" not in img:
            raise KeyError("Failed to generate PFM: Image has no signature - {0}".format(filename))
        elif xml_version == manifest_types.VERSION_2 and "hash" not in img:
            raise KeyError("Failed to generate PFM: Image has no hash - {0}".format(filename))

        regions = generate_flash_region(filename, img["regions"])
        buffer = img["signature"] if xml_version == manifest_types.VERSION_1 else img["hash"]
        img_instance = generate_img_instance(filename, img, regions, buffer, xml_version)
        if xml_version is manifest_types.VERSION_1:
            img_instance.header.length = ctypes.sizeof(img_instance)
        signed_list.append(img_instance)

    return signed_list

def check_xml_validity(xml, xml_version):
    """
    Create a list of allowable firmware from parsed XML list

    :param xml: parsed XML of firmware to be included in PFM
    :param xml_version: Parsed XML version

    """
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

    if xml_version == manifest_types.VERSION_2 and "fw_type" not in xml:
        raise KeyError("Failed to generate PFM: XML has no firmware type - {0}".format(
            filename))

    if "rw_regions" not in xml:
            xml["rw_regions"]= []

def generate_image_and_rw_region_list(filename, xml, version_addr, version_length):
    """
    Create a list of signed images and RW regions from parsed XML

    :param filename: parsed XML filename
    :param xml: Parsed XML
    :param version_addr: Address of the version string
    :param version_length: Length of the version string

    :return signed images list, rw regions list, rw regions array
    """
    signed_imgs_list = []
    rw_regions_list = []
    rw_regions_arr = None
    all_regions = []

    if "fw_type" not in xml:
        rw_regions_list = generate_flash_region(filename, xml["rw_regions"])
        rw_regions_arr = (pfm_flash_region * len(rw_regions_list))(*rw_regions_list)
        signed_imgs_list = generate_signed_image(filename, xml["signed_imgs"],
            manifest_types.VERSION_1)
    else:
        rw_regions_list = generate_rw_flash_region(filename, xml["rw_regions"])
        rw_regions_arr = (pfm_rw_flash_region * len(rw_regions_list))(*rw_regions_list)
        signed_imgs_list = generate_signed_image(filename, xml["signed_imgs"],
            manifest_types.VERSION_2)

    for region in rw_regions_list:
        if region.start_addr & 0xFFFF:
            raise ValueError("Failed to generate PFM: RW Start address (0x{0}) is not 64kB aligned - {1}"
                .format(format(region.start_addr, '08x'), filename))

        if (region.end_addr & 0xFFFF) != 0xFFFF:
            raise ValueError("Failed to generate PFM: RW End address (0x{0}) is not 64kB aligned - {1}"
                .format(format(region.end_addr, '08x'), filename))

        all_regions.append([region.start_addr, region.end_addr])

    flags = 0
    for img in signed_imgs_list:
        flags |= (img.header.flags & VALIDATE_ON_BOOT_FLAG)
        for region in img.flash_regions:
            all_regions.append([region.start_addr, region.end_addr])

            if (img.header.flags & VALIDATE_ON_BOOT_FLAG) == VALIDATE_ON_BOOT_FLAG:
                if ((version_addr + version_length - 1) <= region.end_addr and
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

    return rw_regions_arr, len(rw_regions_list), signed_imgs_list

def generate_allowable_fw_list(xml_list, xml_version):
    """
    Create a list of allowable firmware from parsed XML list

    :param xml_list: List of parsed XML of firmware to be included in PFM
    :param xml_version: Parsed XML version

    :return list of allowable firmware struct instances
    """

    fw_list = []

    for filename, xml in xml_list.items():
        check_xml_validity (xml, xml_version)

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

        if len(xml["version_id"]) > 255:
            raise ValueError("Version ID length ({0}) is not valid - {1}".format(len(xml["version_id"]), filename))

        header = pfm_fw_header(0, len(xml["version_id"]), unused_byte, version_addr,
            len(xml["signed_imgs"]), len(xml["rw_regions"]), 0)

        rw_regions_buf, rw_regions_size, signed_imgs_list = generate_image_and_rw_region_list(filename, xml,
            version_addr, header.version_length)

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
                        ('rw_regions', pfm_flash_region * rw_regions_size),
                        ('signed_imgs', ctypes.c_ubyte * signed_imgs_size)]

        fw = pfm_allowable_fw(header, xml["version_id"], alignment_buf, rw_regions_buf,
            signed_imgs_buf)
        fw.header.length = ctypes.sizeof(pfm_allowable_fw)
        fw_list.append(fw)

    return fw_list

def generate_allowable_fw_list_v2(xml_list, xml_version):
    """
    Create a list of allowable firmware from parsed XML list

    :param xml_list: List of parsed XML of firmware to be included in PFM

    :return list of allowable firmware struct instances
    """

    fw_list = {}
    fw_type = {}
    fw_flags = {}
    fw_type_version_list = {}
    unused_byte_list = []

    for filename, xml in xml_list.items():
        check_xml_validity (xml, xml_version)

        if len(xml["fw_type"]) > 255:
            raise ValueError("FW Type string ({0}) length ({1}) is not valid - {2}".format(
                xml["fw_type"], len(xml["fw_type"], filename)))

        if xml["fw_type"] not in fw_list:
            fw_list[xml["fw_type"]] = list()

        all_regions = []
        flags = 0
        version_addr = int(xml["version_addr"], 16)
        unused_byte = int(xml["unused_byte"], 16)
        runtime_update = 0 if xml["runtime_update"] == 'false' else 1
        version_addr_valid = False

        if xml["fw_type"] not in fw_type_version_list:
            fw_type_version_list[xml["fw_type"]] = list()
            fw_type_version_list[xml["fw_type"]].append(xml["version_id"])
        else:
            for version_list in fw_type_version_list[xml["fw_type"]]:
                for version in version_list:
                    if version == xml["version_id"]:
                        raise KeyError("Failed to generate PFM: Duplicate version ID - {0}".format (
                            xml["version_id"]))
                    elif version.startswith(xml["version_id"]) or xml["version_id"].startswith(version):
                        raise ValueError("Failed to generate PFM: Ambiguous version ID - {0}, {1}".format (
                            xml["version_id"], version))

        if unused_byte > 255:
            raise ValueError("Unused byte value ({0}) is not valid - {1}".format(
                format(unused_byte, '02x'), filename))

        if len(xml["version_id"]) > 255:
            raise ValueError("Version ID length ({0}) is not valid - {1}".format(len(xml["version_id"]),
                filename))

        for unused_byte_val in unused_byte_list:
            if unused_byte_val != unused_byte:
                raise KeyError("Failed to generate PFM: Different Unused byte value - {0} {1}".format (
                    xml["version_id"], xml["fw_type"]))

        unused_byte_list.append (unused_byte)

        fw_type[xml["fw_type"]] = fw_type.get(xml["fw_type"], 0) + 1
        if xml["fw_type"] in fw_flags:
            if fw_flags[xml["fw_type"]] != runtime_update:
                 raise ValueError("Runtime update policy has different values, current: ({0}) new: {1}".format(
                    fw_flags[xml["fw_type"]], runtime_update))
        else:
            fw_flags[xml["fw_type"]] = runtime_update

        v2_header = pfm_v2_fw_header(len(xml["signed_imgs"]), len(xml["rw_regions"]),
                len(xml["version_id"]), 0)

        rw_regions_buf, rw_regions_size, signed_imgs_list = generate_image_and_rw_region_list (filename, xml,
            version_addr, v2_header.version_length)

        signed_imgs_size = 0
        for img in signed_imgs_list:
            signed_imgs_size = signed_imgs_size + ctypes.sizeof(img)

        offset = 0
        signed_imgs_buf = (ctypes.c_ubyte * signed_imgs_size)()

        for img in signed_imgs_list:
            ctypes.memmove(ctypes.addressof(signed_imgs_buf) + offset, ctypes.addressof(img),
                ctypes.sizeof(img))
            offset += ctypes.sizeof(img)

        num_alignment = len(xml["version_id"])  % 4
        num_alignment = 0 if (num_alignment == 0) else (4 - num_alignment)
        alignment_buf = (ctypes.c_ubyte * num_alignment)()
        ctypes.memset(alignment_buf, 0, num_alignment)

        class pfm_allowable_fw(ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('header', pfm_v2_fw_header),
                        ('version_addr', ctypes.c_uint),
                        ('version_id', ctypes.c_char * len(xml["version_id"])),
                        ('alignment', ctypes.c_ubyte * num_alignment),
                        ('rw_regions', pfm_rw_flash_region * rw_regions_size),
                        ('signed_imgs', ctypes.c_ubyte * signed_imgs_size)]

        fw = pfm_allowable_fw(v2_header, version_addr, xml["version_id"], alignment_buf, rw_regions_buf,
            signed_imgs_buf)
        fw_list[xml["fw_type"]].append(fw)

    return fw_list, fw_type, fw_flags, unused_byte

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

def generate_firmware_elements(fw_id_list, fw_flags_list):
    """
    Create the platform information section of the PFM v2.

    :param platform_id: ID for the platform

    :return Platform manifest section
    """

    fw_elements = {}

    if len(fw_id_list) != len(fw_flags_list):
        raise ValueError("Failed to generate PFM: FW count and FW Flags don't match - ({0}, {1})"
            .format(len(fw_id_list), len(fw_flags_list)))

    for fw_id, count in fw_id_list.items():
        if fw_id not in fw_flags:
            raise ValueError ("Failed to generate PFM: No FW Flags found corresponding to the FW ID - {0})"
                .format(fw_id))

        element_header = pfm_v2_fw_id_header(count, len(fw_id), fw_flags_list[fw_id], 0)

        num_alignment = len(fw_id)  % 4
        num_alignment = 0 if (num_alignment == 0) else (4 - num_alignment)
        alignment_buf = (ctypes.c_ubyte * num_alignment)()
        ctypes.memset(alignment_buf, 0, num_alignment)

        class pfm_v2_fw_id(ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('header', pfm_v2_fw_id_header),
                        ('platform_id', ctypes.c_char * len(fw_id)),
                        ('alignment', ctypes.c_ubyte * num_alignment)]

        fw_element = pfm_v2_fw_id(element_header, fw_id, alignment_buf)
        fw_elements[fw_id] = fw_element

    return fw_elements

def generate_pfm_v2(pfm_header_instance, toc_header_instance, toc_element_list, toc_elements_hash_list,
    platform_id_header_instance, flash_device_instance, allowable_fw_list, fw_id_list, hash_type):
    """
    Create a PFM V2 object from all the different PFM components

    :param pfm_header_instance: Instance of a PFM header
    :param toc_header_instance: Instance of a TOC header
    :param toc_element_list: List of TOC elements to be included in PFM
    :param toc_elements_hash_list: List of TOC hashes to be included in PFM
    :param platform_id_header_instance: Instance of a PFM platform header
    :param flash_device_instance: Instance of a PFM flash device header
    :param allowable_fw_list: List of all allowable FWs to be included in PFM
    :param fw_id_list: List of all FW ID instances
    :hash_type: Hashing algorithm to be used for hashing TOC elements


    :return Instance of a PFM object
    """
    hash_algo = None

    if hash_type == 2:
        hash_algo = SHA512
    elif hash_type == 1:
        hash_algo = SHA384
    elif hash_type == 0:
        hash_algo = SHA256
    else:
        raise ValueError ("Invalid manifest hash type: {0}".format (hash_type))

    toc_elements_size = ctypes.sizeof(toc_element_list[0]) * len (toc_element_list)
    toc_hash_size = ctypes.sizeof(toc_elements_hash_list[0]) * len (toc_elements_hash_list)

    # Table Hash
    table_hash_buf = (ctypes.c_ubyte * ctypes.sizeof(toc_header))()
    ctypes.memmove(ctypes.addressof(table_hash_buf), ctypes.addressof(toc_header), ctypes.sizeof(toc_header))
    table_hash_object = hash_algo.new(table_hash_buf)

    offset = 0
    toc_elements_buf = (ctypes.c_ubyte * toc_elements_size)()
    for toc_element in toc_elements_list:
        ctypes.memmove(ctypes.addressof(toc_elements_buf) + offset, ctypes.addressof(toc_element), ctypes.sizeof(toc_element))
        offset += ctypes.sizeof(toc_element)

    # Update table hash with TOC elements
    table_hash_object.update(toc_elements_buf)

    toc_hash_buf = (ctypes.c_ubyte * toc_hash_size)()
    offset = 0
    for toc_hash in toc_elements_hash_list:
        ctypes.memmove(ctypes.addressof(toc_hash_buf) + offset, ctypes.addressof(toc_hash), ctypes.sizeof(toc_hash))
        offset += ctypes.sizeof(toc_hash)

    # Update table hash with TOC
    table_hash_object.update(toc_hash_buf)
    table_hash_buf_size = ctypes.c_ubyte * table_hash_object.digest_size
    table_hash_buf = (ctypes.c_ubyte * table_hash_object.digest_size).from_buffer_copy(table_hash_object.digest())
    table_hash_buf_size = ctypes.sizeof(table_hash_buf)

    platform_id_size = ctypes.sizeof(platform_id_header_instance)
    platform_id_buf = (ctypes.c_ubyte * platform_id_size)()
    ctypes.memmove(ctypes.addressof(platform_id_buf), ctypes.addressof(platform_id_header_instance), platform_id_size)

    allowable_fw_size = 0
    for fw_id in fw_id_list.values():
        allowable_fw_size += ctypes.sizeof(fw_id)

    for fw_list in allowable_fw_list.values():
        for allowable_fw in fw_list:
            allowable_fw_size += ctypes.sizeof(allowable_fw)

    flash_device_size = 0
    if flash_device_instance != None:
        flash_device_size = ctypes.sizeof(flash_device_instance)

    flash_device_buf = (ctypes.c_ubyte * flash_device_size)()
    if flash_device_size:
        ctypes.memmove(ctypes.addressof(flash_device_buf), ctypes.addressof(flash_device_instance), flash_device_size)


    class pfm_v2(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('manifest_header', manifest_common.manifest_header),
                    ('toc_header', manifest_common.manifest_toc_header),
                    ('toc_elements', ctypes.c_ubyte * toc_elements_size),
                    ('toc_hash', ctypes.c_ubyte * toc_hash_size),
                    ('table_hash', ctypes.c_ubyte * table_hash_buf_size),
                    ('platform_id', ctypes.c_ubyte * platform_id_size),
                    ('flash_device', ctypes.c_ubyte * flash_device_size),
                    ('allowable_fw', ctypes.c_ubyte * allowable_fw_size)]


    offset = 0
    fw_buf = (ctypes.c_ubyte * allowable_fw_size)()

    for fw_type, fw_id in fw_id_list.items():
        ctypes.memmove(ctypes.addressof(fw_buf) + offset, ctypes.addressof(fw_id), ctypes.sizeof(fw_id))
        offset += ctypes.sizeof(fw_id)

        fw_list = allowable_fw_list.get(fw_type)
        for allowed_fw in fw_list:
            ctypes.memmove(ctypes.addressof(fw_buf) + offset, ctypes.addressof(allowed_fw), ctypes.sizeof(allowed_fw))
            offset += ctypes.sizeof(allowed_fw)

    return pfm_v2(pfm_header_instance, toc_header_instance, toc_elements_buf, toc_hash_buf, table_hash_buf,
        platform_id_buf, flash_device_buf, fw_buf)

def generate_pfm_toc (manifest_header_len, toc_header, platform_id_element, flash_device_element,
    fw_id_element_list, fw_id_list, allowable_fw_list, hash_type):
    """
    Create a manifest table of contents

    :param manifest_header_len: Length of the manifest header
    :param toc_header: Table of contents header
    :platform_id_element_len: Platform ID header instance
    :flash_device_header_len: Flash device header instance
    :param fw_id_list: List of FW with different FW IDs
    :param hash_type: Hash to be used

    :return List of a manifest table of contents instances
    """
    toc_elements_list = []
    toc_elements_hash_list = []
    hash_id = 0
    hash_len = None

    if hash_type == 2:
        hash_algo = SHA512
        hash_len = 64
    elif hash_type == 1:
        hash_algo = SHA384
        hash_len = 48
    elif hash_type == 0:
        hash_algo = SHA256
        hash_len = 32
    else:
        raise ValueError ("Invalid manifest hash type: {0}".format (hash_type))

    offset = manifest_header_len + ctypes.sizeof (toc_header) + \
        (toc_header.entry_count * ctypes.sizeof (manifest_common.manifest_toc_entry)) + \
        (hash_len * (toc_header.hash_count + 1))

    platform_id_entry = manifest_common.manifest_toc_entry (manifest_common.V2_PLATFORM_TYPE_ID, 
        manifest_common.V2_BASE_TYPE_ID, 1, hash_id, offset, ctypes.sizeof (platform_id_element))
    toc_elements_list.append(platform_id_entry)
    hash_id += 1
    offset += platform_id_entry.length

    toc_elements_hash_list.append(manifest_common.generate_hash(platform_id_element, hash_algo))

    if flash_device_element != None:
        flash_device_entry = manifest_common.manifest_toc_entry (
            manifest_common.PFM_V2_FLASH_DEVICE_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 0, 
            hash_id, offset, ctypes.sizeof (flash_device_element))
        toc_elements_list.append(flash_device_entry)
        hash_id += 1
        offset += flash_device_entry.length

        toc_elements_hash_list.append(manifest_common.generate_hash(flash_device_element, 
            hash_algo))

        for fw_type, count in fw_id_list.items ():
            fw_id_entry = manifest_common.manifest_toc_entry (manifest_common.PFM_V2_FW_TYPE_ID, 
                manifest_common.V2_BASE_TYPE_ID, 1, hash_id, offset, 
                ctypes.sizeof (fw_id_element_list[fw_type]))
            toc_elements_list.append(fw_id_entry)

            hash_id += 1
            offset += fw_id_entry.length

            toc_elements_hash_list.append(manifest_common.generate_hash(fw_id_element_list[fw_type], 
                hash_algo))

            fw_list = allowable_fw_list.get (fw_type)
            for num in range (0, count):
                fw_version_element = manifest_common.manifest_toc_entry (
                    manifest_common.PFM_V2_FW_VERSION_TYPE_ID, manifest_common.PFM_V2_FW_TYPE_ID, 1, 
                    hash_id, offset, ctypes.sizeof (fw_list[num]))
                toc_elements_list.append(fw_version_element)
                hash_id += 1
                offset += fw_version_element.length
                toc_elements_hash_list.append(manifest_common.generate_hash(fw_list[num], 
                    hash_algo))

    return toc_elements_list, toc_elements_hash_list, hash_len

#*************************************** Start of Script ***************************************

default_config = os.path.join (os.path.dirname (os.path.abspath (__file__)), PFM_CONFIG_FILENAME)
parser = argparse.ArgumentParser (description = 'Create a PFM')
parser.add_argument ('config', nargs = '?', default = default_config,
    help = 'Path to configurtaion file')
parser.add_argument ('--bypass', action = 'store_true', help = 'Create a bypass mode PFM')
args = parser.parse_args ()
platform_header = None
allowable_fw_list = None
pfm = None

processed_xml, sign, key_size, key, key_type, hash_type, pfm_id, output, xml_version = manifest_common.load_xmls (
    args.config, None, manifest_types.PFM)

pfm_header_instance = manifest_common.generate_manifest_header (pfm_id, key_size, 
    manifest_types.PFM, hash_type, key_type, xml_version)

platform_id = manifest_common.get_platform_id (processed_xml)

if xml_version == manifest_types.VERSION_2:
    flash_device = None
    if (args.bypass):
        allowable_fw_list = {}
        fw_types = {}
        fw_flags = {}
    else:
        allowable_fw_list, fw_types, fw_flags, unused_byte = generate_allowable_fw_list_v2 (
            processed_xml, xml_version)
        flash_device = pfm_v2_flash_device_element (unused_byte, len (fw_types), 0)

    reserved_buf = (ctypes.c_ubyte * 3) ()
    ctypes.memset (reserved_buf, 0, 3)
    platform_id_header = pfm_v2_platform_header (len (platform_id), reserved_buf)
    platform_header = manifest_common.generate_platform_info (platform_id_header, platform_id)

    toc_header = manifest_common.generate_manifest_toc_header (fw_types, hash_type, args.bypass)

    fw_elements = generate_firmware_elements (fw_types, fw_flags)

    toc_elements_list, toc_elements_hash_list, hash_len = generate_pfm_toc(ctypes.sizeof(pfm_header_instance),
        toc_header, platform_header, flash_device, fw_elements, fw_types,
        allowable_fw_list, hash_type)

    flash_device_size = 0 if args.bypass else ctypes.sizeof(flash_device)
    pfm_header_instance.length = ctypes.sizeof(pfm_header_instance) + ctypes.sizeof(toc_header) + \
        ((toc_header.hash_count + 1) * hash_len) + ctypes.sizeof(platform_header) + flash_device_size + \
        pfm_header_instance.sig_length

    toc_element_size = 0
    for toc_element in toc_elements_list:
        toc_element_size += ctypes.sizeof(toc_element)

    pfm_header_instance.length += toc_element_size

    fw_id_element_size = 0
    for fw_id in fw_elements.values():
        fw_id_element_size += ctypes.sizeof(fw_id)

    pfm_header_instance.length += fw_id_element_size

    all_allowable_fw_size = 0
    for fw_list in allowable_fw_list.values():
        for allowable_fw in fw_list:
            all_allowable_fw_size += ctypes.sizeof(allowable_fw)

    pfm_header_instance.length += all_allowable_fw_size

    pfm = generate_pfm_v2(pfm_header_instance, toc_header, toc_elements_list, toc_elements_hash_list, platform_header,
        flash_device, allowable_fw_list, fw_elements, hash_type)

else:
    process_pbkey(processed_xml)

    if (args.bypass):
        allowable_fw_list = []
    else:
        allowable_fw_list = generate_allowable_fw_list(processed_xml, xml_version)
    allowable_fw_header = generate_allowable_fw_header(allowable_fw_list)

    if (args.bypass):
        keys_list = []
    else:
        keys_list = generate_pbkey_list()
    keys_header = generate_pbkey_header(keys_list)

    platform_id_header = pfm_platform_header(0, len(platform_id), 0)
    platform_header = manifest_common.generate_platform_info(platform_id_header, platform_id)

    platform_header_length = ctypes.sizeof(platform_header)
    platform_header_length_buf = platform_header_length.to_bytes(ctypes.sizeof(ctypes.c_ushort), byteorder = "little")
    platform_header.header[0] = platform_header_length_buf[0]
    platform_header.header[1] = platform_header_length_buf[1]

    pfm_header_instance.length = ctypes.sizeof(pfm_header_instance) + keys_header.length + \
        allowable_fw_header.length + pfm_header_instance.sig_length + platform_header_length

    pfm = generate_pfm(pfm_header_instance, allowable_fw_header, allowable_fw_list, keys_header,
        keys_list, platform_header)

manifest_common.write_manifest(xml_version, sign, pfm, key, key_size, key_type, output,
    pfm_header_instance.length - pfm_header_instance.sig_length,
    pfm_header_instance.sig_length)

print("Completed PFM generation: {0}".format(output))

