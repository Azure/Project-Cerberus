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
import manifest_types
import manifest_common
import manifest_parser
from Crypto.PublicKey import RSA


CFM_CONFIG_FILENAME = "cfm_generator.config"


class cfm_components_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('components_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte)]

class cfm_component_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('fw_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte),
                ('component_id', ctypes.c_uint)]

class cfm_fw_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('img_count', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte),
                ('version_length', ctypes.c_ushort),
                ('reserved2', ctypes.c_ushort)]

class cfm_img_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('digest_length', ctypes.c_ushort),
                ('flags', ctypes.c_ushort),
                ('reserved', ctypes.c_ushort)]



def generate_cfm(cfm_header_instance, components_header_instance, components_list):
    """
    Create a CFM object from all the different CFM components

    :param cfm_header_instance: Instance of a manifest header
    :param components_header_instance: Instance of a CFM components header
    :param components_list: List of components to be included in CFM

    :return Instance of a CFM object
    """
    components_size = components_header_instance.length - ctypes.sizeof(components_header_instance)

    class cfm(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('manifest_header', manifest_common.manifest_header),
                    ('components_header', cfm_components_header),
                    ('components', ctypes.c_ubyte * components_size)]

    offset = 0
    components_buf = (ctypes.c_ubyte * components_size)()
    
    for component in components_list:
        ctypes.memmove(ctypes.addressof(components_buf) + offset, ctypes.addressof(component), 
                       component.header.length)
        offset += component.header.length
    
    return cfm(cfm_header_instance, components_header_instance, components_buf)

def generate_img_instance(filename, device_id, version, img):
    """
    Create a signed image instance

    :param filename: XML filename
    :param device_id: ID of component currently being processed
    :param version: Firmware version
    :param img: Signed image

    :return Signed image instance
    """

    if "failure_action" not in img:
        raise ValueError("Failed to generate CFM: Component {0}, FW {1} has signed image with no failure action - {2}".format(device_id, version, filename))

    if "digest" not in img:
        raise ValueError("Failed to generate CFM: Component {0}, FW {1} has signed image with no digest - {2}".format(device_id, version, filename))

    flags = int(img["failure_action"])
    digest = img["digest"]

    header = cfm_img_header(0, len(digest), flags, 0)
    digest_arr = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)

    class cfm_signed_img(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('header', cfm_img_header),
                    ('digest', ctypes.c_ubyte * len(digest))]

    return cfm_signed_img(header, digest_arr)

def generate_signed_images(filename, device_id, version, img_list):
    """
    Create a list of signed image struct instances from image list

    :param filename: XML filename
    :param device_id: ID of component currently being processed
    :param version: Firmware version
    :param img_list: List of signed images

    :return List of signed image struct instances
    """

    signed_list = []

    for img in img_list:
        img_instance = generate_img_instance(filename, device_id, version, img)
        img_instance.header.length = ctypes.sizeof(img_instance)
        signed_list.append(img_instance)

    return signed_list

def generate_fw_instance(filename, device_id, version, imgs):
    """
    Create a firmware struct instance

    :param filename: XML filename
    :param device_id: ID of component currently being processed
    :param version: Firmware version
    :param imgs: List of signed image struct instances

    :return A firmware struct instance
    """

    imgs_size = 0
    for img in imgs:
        imgs_size = imgs_size + ctypes.sizeof(img)

    offset = 0
    imgs_buf = (ctypes.c_ubyte * imgs_size)()
    
    for img in imgs:
        ctypes.memmove(ctypes.addressof(imgs_buf) + offset, ctypes.addressof(img), 
            img.header.length)
        offset += img.header.length

    header = cfm_fw_header(0, len(imgs), 0, len(version), 0)

    num_alignment = len(version)  % 4
    num_alignment = 0 if (num_alignment == 0) else (4 - num_alignment)
    alignment_buf = (ctypes.c_ubyte * num_alignment)()
    ctypes.memset(alignment_buf, 0, num_alignment)

    class cfm_component_fw(ctypes.LittleEndianStructure):
        _pack_ = 1  
        _fields_ = [('header', cfm_fw_header),
                    ('version_id', ctypes.c_char * len(version)),
                    ('alignment', ctypes.c_ubyte * num_alignment),
                    ('signed_imgs', ctypes.c_ubyte * imgs_size)]

    fw = cfm_component_fw(header, version.encode('utf-8'), alignment_buf, imgs_buf)

    return fw

def generate_firmware_list(filename, device_id, fw_list):
    """
    Create a list of firmware struct instances from firmware list

    :param filename: XML filename
    :param device_id: ID of component currently being processed
    :param fw_list: List of supported component firmware

    :return List of firmware struct instances
    """

    firmware_list = []

    for fw in fw_list:
        if "version" not in fw:
            raise KeyError("Failed to generate CFM: Component {0} firmware has no version - {1}".format(device_id, filename))

        if "signed_imgs" not in fw:
            raise KeyError("Failed to generate CFM: Component {0} firmware has no signed images - {1}".format(device_id, filename))

        version = fw["version"]

        imgs = generate_signed_images(filename, device_id, version, fw["signed_imgs"])
        fw_instance = generate_fw_instance(filename, device_id, version, imgs)
        fw_instance.header.length = ctypes.sizeof(fw_instance)
        firmware_list.append(fw_instance)

    return firmware_list

def generate_components_list(xml_list):
    """
    Create a list of components from parsed XML list

    :param xml_list: List of parsed XML of components to be included in CFM

    :return list of component struct instances
    """

    component_list = []

    for filename, xml in xml_list.items():
        if "device_id" not in xml:
            raise KeyError("Failed to generate CFM: XML has no device id - {0}".format(filename)) 

        if "fw_list" not in xml:
            raise KeyError("Failed to generate CFM: XML has no firmware defined - {0}".format(filename))  

        device_id = int(xml["device_id"])

        firmware_list = generate_firmware_list(filename, device_id, xml["fw_list"])

        fw_size = 0
        for fw in firmware_list:
            fw_size += ctypes.sizeof(fw)

        offset = 0
        fw_buf = (ctypes.c_ubyte * fw_size)()
        
        for fw in firmware_list:
            ctypes.memmove(ctypes.addressof(fw_buf) + offset, ctypes.addressof(fw), 
                fw.header.length)
            offset += fw.header.length

        header = cfm_component_header(0, len(firmware_list), 0, device_id)

        class cfm_component(ctypes.LittleEndianStructure):
            _pack_ = 1  
            _fields_ = [('header', cfm_component_header),
                        ('firmware', ctypes.c_ubyte * fw_size)]

        component = cfm_component(header, fw_buf)
        component.header.length = ctypes.sizeof(cfm_component)
        component_list.append(component)

    return component_list

def generate_components_header(components_list):
    """
    Create a components header from a components list

    :param components_list: List of components to be included in CFM

    :return Components header instance    
    """

    size = ctypes.sizeof(cfm_components_header)
    
    for component in components_list:
        size = size + ctypes.sizeof(component)
    
    return cfm_components_header(size, len(components_list), 0)


#*************************************** Start of Script ***************************************

if len(sys.argv) < 2:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), CFM_CONFIG_FILENAME)
else:
    path = os.path.abspath(sys.argv[1])

processed_xml, sign, key_size, key, id, output = manifest_common.load_xmls (path, None, 
                                                                            manifest_types.CFM)

components_list = generate_components_list(processed_xml)
components_header = generate_components_header(components_list)
cfm_header_instance = manifest_common.generate_manifest_header(id, key_size, manifest_types.CFM)
cfm_header_instance.length = ctypes.sizeof(cfm_header_instance) + components_header.length + \
    cfm_header_instance.sig_length

cfm = generate_cfm(cfm_header_instance, components_header, components_list)

manifest_common.write_manifest(sign, cfm, key, output,
	cfm_header_instance.length - cfm_header_instance.sig_length, 
	cfm_header_instance.sig_length)

print ("Completed CFM generation: {0}".format(output))

