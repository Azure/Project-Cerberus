"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import os
import copy
import ctypes
import argparse
import itertools
import manifest_types
import manifest_common
import pfm_generator_v1
import warnings


PFM_CONFIG_FILENAME = "pfm_generator.config"


def generate_rw_regions_buf (xml_rw):
    """
    Create a buffer of pfm_rw_region struct instances from parsed XML list

    :param xml_rw: List of parsed XML of RW regions to be included in PFM

    :return RW regions buffer, length of RW regions buffer, number of RW regions, list of all
        regions
    """

    if xml_rw is None or len (xml_rw) < 1:
        return (ctypes.c_ubyte * 0) (), 0, 0, []

    class pfm_rw_region (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('rw_flags', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte * 3),
                    ('rw_start_addr', ctypes.c_uint),
                    ('rw_end_addr', ctypes.c_uint)]

    num_rw_regions = len (xml_rw)
    rw_regions_buf = (ctypes.c_ubyte * (ctypes.sizeof (pfm_rw_region) * num_rw_regions)) ()
    rw_regions_len = 0
    all_regions = []

    reserved_buf = (ctypes.c_ubyte * 3) ()
    ctypes.memset (reserved_buf, 0, 3)
    for rw_region in xml_rw:
        rw_start_addr = int (manifest_common.get_key_from_dict (rw_region, "start",
            "RW region start address"), 16)
        rw_end_addr = int (manifest_common.get_key_from_dict (rw_region, "end",
            "RW region end address"), 16)
        manifest_common.check_region_address_validity (rw_start_addr, rw_end_addr)

        all_regions.append ([rw_start_addr, rw_end_addr])

        rw_flags = int (manifest_common.get_key_from_dict (rw_region, "operation_fail",
            "Operation on Fail"), 16)

        rw_region_body = pfm_rw_region (rw_flags, reserved_buf, rw_start_addr, rw_end_addr)
        rw_regions_len = manifest_common.move_list_to_buffer (rw_regions_buf, rw_regions_len,
            [rw_region_body])

    return rw_regions_buf, rw_regions_len, num_rw_regions, all_regions

def generate_signed_imgs_buf (xml_signed_imgs):
    """
    Create a buffer of pfm_signed_image struct instances from parsed XML list

    :param xml_signed_imgs: List of parsed XML of signed images to be included in PFM

    :return Signed images buffer, length of signed images buffer, number of signed images, list of
        all regions
    """

    if xml_signed_imgs is None or len (xml_signed_imgs) < 1:
        return None, 0, 0

    class pfm_signed_image_header (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('hash_type', ctypes.c_ubyte),
                    ('region_count', ctypes.c_ubyte),
                    ('image_flags', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte)]

    class pfm_signed_image_region (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('img_start_addr', ctypes.c_uint),
                    ('img_end_addr', ctypes.c_uint)]

    signed_imgs = []
    signed_imgs_len = 0
    num_signed_imgs = len (xml_signed_imgs)
    all_regions = []

    for signed_img in xml_signed_imgs:
        hash_type = int (manifest_common.get_key_from_dict (signed_img, "hash_type", "Hash type"),
            16)
        validate = manifest_common.get_key_from_dict (signed_img, "validate", "Validate region")
        signed_img_hash = manifest_common.get_key_from_dict (signed_img, "hash",
            "Signed image hash")
        signed_img_hash_arr = (ctypes.c_ubyte * len (signed_img_hash)).from_buffer_copy (
            signed_img_hash)
        signed_img_hash_arr_len = ctypes.sizeof (signed_img_hash_arr)

        img_flags = 1 if validate == "true" else 0

        num_signed_regions = 0
        signed_regions_len = 0

        if "regions" in signed_img:
            signed_regions_buf = (ctypes.c_ubyte * (ctypes.sizeof (pfm_signed_image_region) * \
                len (signed_img["regions"]))) ()

            for region in signed_img["regions"]:
                img_start_addr = int (manifest_common.get_key_from_dict (region, "start",
                    "Signed image start address"), 16)
                img_end_addr = int (manifest_common.get_key_from_dict (region, "end",
                    "Signed image end address"), 16)
                manifest_common.check_region_address_validity (img_start_addr, img_end_addr, False)

                all_regions.append ([img_start_addr, img_end_addr])

                signed_image_region = pfm_signed_image_region (img_start_addr, img_end_addr)
                signed_regions_len = manifest_common.move_list_to_buffer (signed_regions_buf,
                    signed_regions_len, [signed_image_region])
                num_signed_regions += 1

        signed_img_buf = (ctypes.c_ubyte * (ctypes.sizeof (pfm_signed_image_header) + \
            signed_regions_len + signed_img_hash_arr_len)) ()
        signed_img_header = pfm_signed_image_header (hash_type, num_signed_regions, img_flags, 0)

        signed_img_len = manifest_common.move_list_to_buffer (signed_img_buf, 0, [signed_img_header,
            signed_img_hash_arr, signed_regions_buf])

        signed_imgs_len += signed_img_len
        signed_imgs.append (signed_img_buf)

    signed_imgs_buf = (ctypes.c_ubyte * signed_imgs_len) ()
    signed_img_len = manifest_common.move_list_to_buffer (signed_imgs_buf, 0, signed_imgs)

    return signed_imgs_buf, signed_imgs_len, len (signed_imgs), all_regions

def generate_permutations (src_list):
    """
    Generate all possible permutations of 1 version from each FW type in incoming src_list

    :param src_list: List of FW types, with a list of FW versions per FW type, and a list of regions
        per FW version

    :return A list of all possible permutations
    """

    # Each element in src_list is a list of versions for a firmware type
    # Each version is a list of regions
    # itertools.product will generate all possible combinations (one version per firmware type)
    all_combinations = itertools.product(*src_list)
    
    # For each combination, flatten the regions from each selected version into a single list
    total_permutations = []
    
    for combo in all_combinations:
        flat = []
        
        for version in combo:
            flat.extend(version)
        
        total_permutations.append(flat)
    
    return total_permutations

def deduplicate_src_list(src_list):
    """
    Remove duplicate region lists within each firmware type in src_list

    :param src_list: List of FW types, with a list of FW versions per FW type, and a list of regions
        per FW version

    :return A new src_list with duplicates removed per firmware type
    """
    
    deduplicated_list = []

    for fw_type in src_list:

        seen = set()
        unique_versions = []
        
        for version in fw_type:
            
            # Convert version (list of lists) to tuple of tuples for hashing
            version_tuple = tuple(tuple(region) for region in version)
            version_tuple = tuple(sorted(version_tuple))  # Sort to ensure order doesn't affect uniqueness

            if version_tuple not in seen:
                seen.add(version_tuple)
                unique_versions.append(version)
        
        # Remove firmware types where all unique versions are empty lists
        if not (len(unique_versions) == 1 and unique_versions[0] == []):
        
            # Only add if at least one version is not an empty list
            # (or if there are multiple unique versions, at least one must be non-empty)
            if any(len(v) > 0 for v in unique_versions):
                deduplicated_list.append(unique_versions)
    
    return deduplicated_list

def check_max_rw_sections (all_rw_regions, max_rw_sections):
    """
    Ensure RW regions fit into maximum number of RW sections

    :param all_rw_regions: All RW regions for each FW type
    :param max_rw_sections: Number of non-contiguous RW sections supported
    """

    # Create empty set to store list of RW Regions
    rw_regions_set = set()
    raise_error = False
    section_count = 0

    de_duplicated_rw_regions = deduplicate_src_list(all_rw_regions)
    all_rw_permutations = generate_permutations (de_duplicated_rw_regions)

    for permutation in all_rw_permutations:
        permutation_copy = copy.deepcopy (permutation)
        permutation_copy = sorted (permutation_copy)

        for i_region in range (len (permutation_copy) - 1, 0, -1):
            region1 = permutation_copy[i_region - 1]
            region2 = permutation_copy[i_region]

            if manifest_common.check_if_regions_contiguous (region1, region2):
                permutation_copy[i_region - 1][1] = permutation_copy[i_region][1]
                permutation_copy.remove (permutation_copy[i_region])

                # Add the adjusted region that we're keeping.
                rw_regions_set.add((permutation_copy[i_region - 1][0], permutation_copy[i_region - 1][1]))
            else:
                # Add the two regions being compared
                rw_regions_set.add((region1[0], region1[1]))
                rw_regions_set.add((region2[0], region2[1]))

        if len (permutation_copy) > max_rw_sections:
            # We no longer want to halt upon first finding a number of regions greater than max_rw_regions.
            # Instead, we want to keep checking to complete the list of all RW Regions.
            raise_error = True
            section_count = len(permutation_copy)

    print ()
    print ()
    print ("The following RW Regions were found:")
    print ()

    for region in rw_regions_set:
        message = "Region [0x{0}:0x{1}]".format(
            format (region[0], 'x'), format (region[1], 'x')
        )

        print(message)

    print ()
    print ()

    if raise_error:
        raise ValueError (
            "Number of non-contiguous RW regions greater than maximum defined: {0} vs {1}".format (
                section_count, max_rw_sections))

def check_overlapping_regions (all_regions, ignore_overlap = False):
    """
    Ensure no regions overlap with regions from other FW types.  Method gathers all overlapping
    regions in a set and displays them at the end of the function.  If overlaps are found, method
    will halt with a ValueError, unless `ignore_overlap` is True.

    :param all_regions: All RW and signed image regions for each FW type
    :param ignore_overlap:  Bool - Flag to ignore overlapping regions.  Will create PFM even if
           overlapping regions are found, if set to True.

    :return overlaps: Returns the overlaps found in the region definitions.
    """

    # Create empty set to store list of overlapping regions.
    overlaps = set()

    for i_fw_type1 in range (len (all_regions)):
        for version1 in all_regions[i_fw_type1]:
            for i_region1 in range (len (version1)):
                region1 = version1[i_region1]

                for i_region2 in range (i_region1 + 1, len (version1)):
                    region2 = version1[i_region2]

                    if manifest_common.check_if_regions_overlap (region1, region2):
                        # add overlap to set
                        overlaps.add(((region1[0], region1[1]), (region2[0],region2[1])))

                for i_fw_type2 in range (i_fw_type1 + 1, len (all_regions)):
                    for version2 in all_regions[i_fw_type2]:
                        for region2 in version2:
                            if manifest_common.check_if_regions_overlap (region1, region2):
                                # add overlap to set
                                overlaps.add(((region1[0], region1[1]), (region2[0],region2[1])))

    # Output warning message if ignore_overlap flag is set, and there are actual overlaps found.
    if ignore_overlap and overlaps:
        print ()
        print ()
        print ("        ***   Warning:  ignore_overlap flag is set to TRUE.                                                  ***")
        print ("        ***   Overlapping regions will be checked for, but ignored.                                          ***")        
        print ("        ***   Overlapping Flash regions can cause Cerberus Flash Verification to fail when in active mode.   ***")
        print ("        ***   PFM will be generated anyway.  See logs below for potential overlaps.                          ***")
        print ()
        print ()

    # Output overlap message for each overlap found
    for overlap in overlaps:
        regionA = overlap[0]
        regionB = overlap[1]
        
        message = "Region at [0x{0}:0x{1}] overlapping with region at [0x{2}:0x{3}]".format (
            format (regionA[0], 'x'), format (regionA[1], 'x'),
            format (regionB[0], 'x'), format (regionB[1], 'x')
        )
        
        print(message)

    # Halt if ignore_overlap flag is not set
    if overlaps and not ignore_overlap:
        raise ValueError ("Overlapping Regions have been found.  Halting!")

    # Return the overlaps found for further processing, if we get this far.
    return overlaps

def output_overlap_warning_file (output, overlaps):
    """
    Takes the list of overlaps, and the pfm output filename (with which it determines the filepath)
    and creates a file containing a list of the xml manifest overlaps found.

    :param output: Path and filename of the PFM output file.  This is used to determine the path
                   where PFM output will occur.
    :param overlaps: Tuple of overlaps collected from running check_overlapping_regions against all_regions_list
                     and all_rw_regions list.  All regions are in index 0 and RW regions in index 1.
    """

    output = os.path.split(output)[0]
    output = os.path.join(output, 'overlap_warning.txt')

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open (output, 'wt') as fh:
        fh.write ("      ***   Warning:  ignore_overlap flag is set to TRUE.  PFM has been generated anyway.   ***\n")
        fh.write ("      ***   If overlapping regions are found, they will be listed below.                    ***\n")
        fh.write ("      ***   Overlapping flash regions can cause Cerberus Flash Verification to fail when    ***\n")
        fh.write ("      ***   in active mode.                                                                 ***\n")
        fh.write ("\n")
        fh.write ("\n")

        for index, overlap_list in enumerate(overlaps):
            if (overlap_list):
                if (index == 0):
                    fh.write ("Overlaps found for all regions:\n")
                if (index == 1):
                    fh.write ("Overlaps found in RW regions:\n")

                for overlap in overlap_list:
                    regionA = overlap[0]
                    regionB = overlap[1]

                    message = "Region at [0x{0}:0x{1}] overlapping with region at [0x{2}:0x{3}]\n".format (
                        format (regionA[0], 'x'), format (regionA[1], 'x'),
                        format (regionB[0], 'x'), format (regionB[1], 'x')
                    )

                    fh.write (message)

    print ("Outputting overlap warning file ({0})".format(output))

def generate_fw_versions_list (xml_list, max_rw_sections, ignore_overlap = False):
    """
    Create a list of FW version struct instances for each FW type from parsed XML list

    :param xml_list: List of parsed XML of FW versions to be included in PFM
    :param max_rw_sections: Maximum number of non-contiguous RW sections supported
    :param ignore_overlap:  Bool - Flag to ignore overlapping regions.

    :return FW version list, runtime update list, Unused byte,
            (all_regions_overlap, rw_regions_overlap)
    """

    if xml_list is None or len (xml_list) < 1:
        return None, 0, None, None, 0

    fw_version_list = {}
    runtime_update_list = {}
    unused_byte = None
    all_regions = {}
    all_rw_regions = {}

    for filename, xml in xml_list.items():
        fw_type = manifest_common.get_key_from_dict (xml, "fw_type", "FW Type")
        manifest_common.check_maximum (len (fw_type), 255, "FW type {0} string length".format (
            fw_type))

        if fw_type not in fw_version_list:
            fw_version_list[fw_type] = dict ()
            all_regions[fw_type] = []
            all_rw_regions[fw_type] = []

        unused_byte_val = int (manifest_common.get_key_from_dict (xml, "unused_byte",
            "Unused Byte"), 16)
        manifest_common.check_maximum (unused_byte_val, 255, "Unused byte")

        if unused_byte is None:
            unused_byte = unused_byte_val
        else:
            if unused_byte_val != unused_byte:
                raise ValueError ("Different unused byte values found: ({0}) vs ({1}) - {2}".format (
                    unused_byte_val, unused_byte, filename))

        runtime_update_val = manifest_common.get_key_from_dict (xml, "runtime_update",
            "Runtime Update")
        if fw_type not in runtime_update_list:
            runtime_update_list[fw_type] = runtime_update_val
        else:
            if runtime_update_list[fw_type] != runtime_update_val:
                raise ValueError (
                    "Different runtime update values found for FW type ({0}): ({1}) vs ({2}) - {3}".format (
                        fw_type, runtime_update_val, runtime_update_list[fw_type], filename))

        version_addr = int (manifest_common.get_key_from_dict (xml, "version_addr",
            "Version Address"), 16)

        version_id = manifest_common.get_key_from_dict (xml, "version_id", "Version ID")
        version_id_len = len (version_id)
        manifest_common.check_maximum (version_id_len, 255, "Version ID {0} length".format (
            version_id))
        padding, padding_len = manifest_common.generate_4byte_padding_buf (version_id_len)

        all_regions_list = []

        if "rw_regions" in xml:
            rw_regions_buf, rw_regions_len, num_rw_regions, rw_regions = generate_rw_regions_buf (
                xml["rw_regions"])
            all_regions_list.extend (rw_regions)
            all_rw_regions[fw_type].append (rw_regions)

        if "signed_imgs" in xml:
            signed_imgs_buf, signed_imgs_len, num_signed_imgs, signed_regions = \
                generate_signed_imgs_buf (xml["signed_imgs"])
            all_regions_list.extend (signed_regions)

        all_regions[fw_type].append (all_regions_list)

        class pfm_fw_version (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('image_count', ctypes.c_ubyte),
                        ('rw_count', ctypes.c_ubyte),
                        ('version_length', ctypes.c_ubyte),
                        ('reserved', ctypes.c_ubyte),
                        ('version_addr', ctypes.c_uint),
                        ('version_id', ctypes.c_char * version_id_len),
                        ('version_id_padding', ctypes.c_ubyte * padding_len),
                        ('rw_regions', ctypes.c_ubyte * rw_regions_len),
                        ('signed_imgs', ctypes.c_ubyte * signed_imgs_len)]

        fw_version = pfm_fw_version (num_signed_imgs, num_rw_regions, version_id_len, 0,
            version_addr, version_id.encode ('utf-8'), padding, rw_regions_buf, signed_imgs_buf)

        for prev_version_id, prev_fw_version in fw_version_list[fw_type].items ():

            if prev_version_id == version_id:
                raise KeyError (
                    "Failed to generate PFM: Duplicate version ID - {0} in FW type {1}".format (
                        version_id, fw_type))
            
            elif prev_version_id.startswith(version_id) or version_id.startswith(prev_version_id):
                warnings.warn (
                    "Ambiguous version ID - {0}, {1} in FW type {2}".format (
                        prev_version_id, version_id, fw_type), UserWarning)

        fw_version_list[fw_type].update ({version_id: fw_version})

    all_regions_list = []
    all_rw_regions_list = []

    for fw_id, fw_id_list in all_regions.items():
        all_regions_list.append (fw_id_list)
    for fw_id, fw_id_list in all_rw_regions.items():
        all_rw_regions_list.append (fw_id_list)

    all_regions_overlap = check_overlapping_regions (all_regions_list, ignore_overlap)
    rw_regions_overlap = check_overlapping_regions (all_rw_regions_list, ignore_overlap)
    check_max_rw_sections (all_rw_regions_list, max_rw_sections)

    return fw_version_list, runtime_update_list, unused_byte, (all_regions_overlap, rw_regions_overlap)

def generate_fw (xml_list, max_rw_sections, ignore_overlap = False):
    """
    Create a buffer of FW struct instances from parsed XML list

    :param xml_list: List of parsed XML of FW to be included in PFM
    :param max_rw_sections: Maximum number of non-contiguous RW sections supported
    :param ignore_overlap:  Bool - Flag to ignore overlapping regions.

    :return List of (FW, FW TOC entry), number of FW, Unused byte, overlaps
    """

    if xml_list is None or len (xml_list) < 1:
        return None, 0, None, None, 0

    fw_list = []
    num_fw = 0

    fw_version_list, runtime_update_list, unused_byte, overlaps = generate_fw_versions_list (xml_list,
        max_rw_sections, ignore_overlap)

    for fw_id, fw_versions in fw_version_list.items ():
        fw_id_len = len (fw_id)
        manifest_common.check_maximum (fw_id_len, 255, "FW ID {0} length".format (fw_id))
        padding, padding_len = manifest_common.generate_4byte_padding_buf (fw_id_len)

        class pfm_fw (ctypes.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('version_count', ctypes.c_ubyte),
                        ('fw_id_length', ctypes.c_ubyte),
                        ('fw_flags', ctypes.c_ubyte),
                        ('reserved', ctypes.c_ubyte),
                        ('fw_id', ctypes.c_char * fw_id_len),
                        ('fw_id_padding', ctypes.c_ubyte * padding_len)]

        fw_flags = 0 if runtime_update_list[fw_id] == "false" else 1
        fw = pfm_fw (len (fw_versions), fw_id_len, fw_flags, 0, fw_id.encode ('utf-8'), padding)
        fw_toc_entry = manifest_common.manifest_toc_entry (manifest_common.PFM_V2_FW_TYPE_ID,
            manifest_common.V2_BASE_TYPE_ID, 1, 0, 0, ctypes.sizeof (fw))

        fw_list.append ((fw, fw_toc_entry))

        for version_id, fw_version in fw_versions.items ():
            fw_version_toc_entry = manifest_common.manifest_toc_entry (
                manifest_common.PFM_V2_FW_VERSION_TYPE_ID, manifest_common.PFM_V2_FW_TYPE_ID, 1,
                0, 0, ctypes.sizeof (fw_version))
            fw_list.append ((fw_version, fw_version_toc_entry))

        num_fw += 1

    return fw_list, num_fw, unused_byte, overlaps

def generate_flash_device (unused_byte, fw_count):
    """
    Create a buffer of FW struct instances from parsed XML list

    :param unused_byte: Unused byte
    :param fw_count: Number of FW types in flash device

    :return (Flash device, Flash device TOC entry)
    """

    class pfm_flash_device (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('blank_byte', ctypes.c_ubyte),
                    ('fw_count', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ushort)]

    flash_device = pfm_flash_device (unused_byte, fw_count, 0)
    flash_device_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.PFM_V2_FLASH_DEVICE_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 0, 0, 0,
        ctypes.sizeof (flash_device))

    return (flash_device, flash_device_toc_entry)

#*************************************** Start of Script ***************************************

def main(argv=None):
	"""
	Usage:
		python3 pfm_generator.py [path/to/pfm_generator.config] [--bypass] [--ignore_overlap]

	Required input:
		A generator configuration file that specifies one or more PFM XML inputs and output
		settings. The default pfm_generator.config in this directory is used when no file is
		provided.

	Optional arguments:
		--bypass
			Generate a bypass-mode PFM (header/platform data without FW policy sections).
		--ignore_overlap
			Continue generating output even if FW/RW regions overlap; overlaps are reported in
			a warning file instead of stopping generation.
	"""
	default_config = os.path.join (os.path.dirname (os.path.abspath (__file__)), PFM_CONFIG_FILENAME)
	parser = argparse.ArgumentParser (description = 'Create a PFM')
	parser.add_argument ('config', nargs = '?', default = default_config,
		help = 'Path to configuration file')
	parser.add_argument ('--bypass', action = 'store_true', help = 'Create a bypass mode PFM')
	parser.add_argument ('--ignore_overlap', action = 'store_true',
		help = 'Warn on PFM region overlaps, but output PFM anyway.')
	args = parser.parse_args (argv)

	processed_xml, sign, key_size, key, key_type, hash_type, pfm_id, output, xml_version, empty, \
		max_rw_sections, selection_list, component_map, component_map_file = \
			manifest_common.load_xmls (args.config, None, manifest_types.PFM)

	if xml_version == manifest_types.VERSION_2:
		elements_list = []

		hash_engine = manifest_common.get_hash_engine (hash_type)

		platform_id = manifest_common.get_platform_id_from_xml_list (processed_xml)
		platform_id = manifest_common.generate_platform_id ({"platform_id": platform_id})

		elements_list.append (platform_id)

		if not args.bypass:
			fw, num_fw, unused_byte, overlaps = generate_fw (processed_xml, 
															max_rw_sections, args.ignore_overlap)

			flash_device = generate_flash_device (unused_byte, num_fw)

			elements_list.append (flash_device)
			elements_list.extend (fw)

			if args.ignore_overlap:
				output_overlap_warning_file (output, overlaps)

		manifest_common.generate_manifest (hash_engine, hash_type, pfm_id, manifest_types.PFM,
			xml_version, sign, key, key_size, key_type, elements_list, output)

	else:
		pfm_generator_v1.generate_v1_pfm (pfm_id, key_size, hash_type, key_type, processed_xml,
			args.bypass, sign, key, output)

	print ("Completed PFM generation: {0}".format (output))


if __name__ == '__main__':
    main()
