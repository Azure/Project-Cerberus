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


PCD_CONFIG_FILENAME = "pcd_generator.config"


class pcd_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('header_len', ctypes.c_ushort),
                ('format_id', ctypes.c_ubyte),
                ('reserved1', ctypes.c_ubyte),
                ('reserved2', ctypes.c_ubyte),
                ('reserved3', ctypes.c_ubyte)]

class pcd_rot_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('header_len', ctypes.c_ushort),
                ('format_id', ctypes.c_ubyte),
                ('num_ports', ctypes.c_ubyte),
                ('addr', ctypes.c_ubyte),
                ('bmc_i2c_addr', ctypes.c_ubyte),
                ('cpld_addr', ctypes.c_ubyte),
                ('cpld_channel', ctypes.c_ubyte),
                ('active', ctypes.c_ubyte),
                ('default_failure_action', ctypes.c_ubyte),
                ('flags', ctypes.c_ubyte),
                ('reserved1', ctypes.c_ubyte),
                ('reserved2', ctypes.c_ubyte),
                ('reserved3', ctypes.c_ubyte)]

class pcd_port_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('header_len', ctypes.c_ushort),
                ('format_id', ctypes.c_ubyte),
                ('id', ctypes.c_ubyte),
                ('reserved1', ctypes.c_ubyte),
                ('reserved2', ctypes.c_ubyte),
    			('frequency', ctypes.c_ulong)]

class pcd_components_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('header_len', ctypes.c_ushort),
                ('format_id', ctypes.c_ubyte),
                ('num_components', ctypes.c_ubyte),
                ('reserved1', ctypes.c_ubyte),
                ('reserved2', ctypes.c_ubyte)]

class pcd_component_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('header_len', ctypes.c_ushort),
                ('format_id', ctypes.c_ubyte),
                ('num_muxes', ctypes.c_ubyte),
                ('addr', ctypes.c_ubyte),
                ('channel', ctypes.c_ubyte),
                ('flags', ctypes.c_ubyte),
    			('eid', ctypes.c_ubyte),
                ('power_ctrl_reg', ctypes.c_ubyte),
                ('power_ctrl_mask', ctypes.c_ubyte),
                ('id', ctypes.c_ulong)]

class pcd_mux_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('header_len', ctypes.c_ushort),
                ('format_id', ctypes.c_ubyte),
                ('addr', ctypes.c_ubyte),
                ('channel', ctypes.c_ubyte),
                ('mux_level', ctypes.c_ubyte),]

class pcd_platform_id_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('length', ctypes.c_ushort),
                ('header_len', ctypes.c_ushort),
                ('format_id', ctypes.c_ubyte),
                ('id_len', ctypes.c_ubyte),
                ('reserved1', ctypes.c_ubyte),
                ('reserved2', ctypes.c_ubyte)]


def get_key_from_dict (dictionary, key, group, required=True):
    if key not in dictionary:
        if required:
            raise KeyError ("Failed to generate PCD: {0} missing {1}".format (group, key))
        else:
            return None
    else:
        return dictionary[key]

def generate_ports_buf (xml_ports):
    """
    Create a buffer of pcd_port struct instances from parsed XML list

    :param xml_ports: List of parsed XML of ports to be included in PCD

    :return Ports buffer, number of ports
    """ 

    if xml_ports is None or len (xml_ports) < 1:
        return None, 0

    ports_buf = (ctypes.c_ubyte * (ctypes.sizeof (pcd_port_header) * len (xml_ports))) ()
    ports_len = 0

    for id, port in xml_ports.items ():
        freq = int (get_key_from_dict (port, "spifreq", "Port"))

        port_body = pcd_port_header (ctypes.sizeof (pcd_port_header), 
            ctypes.sizeof (pcd_port_header), 0, int (id), 0, 0, freq)
        
        ctypes.memmove (ctypes.addressof (ports_buf) + ports_len, ctypes.addressof (port_body), 
            ctypes.sizeof (pcd_port_header))
        ports_len += ctypes.sizeof (pcd_port_header)

    return ports_buf, len (xml_ports)

def generate_rot_header (xml_rot, xml_rot_interface, xml_cpld, xml_policy, num_ports):
    """
    Create a PCD RoT header

    :param xml_rot: List of parsed XML of RoT to be included in PCD
    :param xml_rot_interface: List of parsed XML of RoT interface to be included in PCD
    :param xml_cpld: List of parsed XML of CPLD to be included in PCD
    :param xml_policy: List of parsed XML of policy to be included in PCD
    :param num_ports: Number of RoT ports

    :return PCD RoT header instance    
    """

    is_pa_rot = bool (get_key_from_dict (xml_rot, "is_pa_rot", "PA RoT Flag"))
    addr = int (get_key_from_dict (xml_rot_interface, "address", "RoT interface"), base=16)
    bmc_i2c_addr = int (get_key_from_dict (xml_rot_interface, "bmc_address", "RoT interface"), 
        base=16)
    cpld_addr = int (get_key_from_dict (xml_cpld, "address", "CPLD"), base=16)
    cpld_channel = int (get_key_from_dict (xml_cpld, "channel", "CPLD"))
    active = bool (get_key_from_dict (xml_policy, "active", "Policy"))
    failure_action = int (get_key_from_dict (xml_policy, "defaultfailureaction", "Policy"))

    ports_buf_len = ctypes.sizeof (pcd_port_header) * num_ports

    flags = 0
    flags |= (is_pa_rot << 0)

    return pcd_rot_header (ports_buf_len + ctypes.sizeof (pcd_rot_header), 
        ctypes.sizeof (pcd_rot_header), 0, num_ports, addr, bmc_i2c_addr, cpld_addr, cpld_channel, 
        active, failure_action, flags)

def generate_muxes_buf (xml_muxes):
    """
    Create a buffer of pcd_mux struct instances from parsed XML list

    :param xml_muxes: List of parsed XML of muxes to be included in PCD

    :return Muxes buffer, number of muxes
    """ 

    if xml_muxes is None or len (xml_muxes) < 1:
        return None, 0

    muxes_buf = (ctypes.c_ubyte * (ctypes.sizeof (pcd_mux_header) * len (xml_muxes))) ()
    muxes_len = 0

    for level, mux in xml_muxes.items ():
        addr = int (get_key_from_dict (mux, "address", "Mux"), base=16)
        channel = int (get_key_from_dict (mux, "channel", "Mux"))

        mux_body = pcd_mux_header (ctypes.sizeof (pcd_mux_header), ctypes.sizeof (pcd_mux_header),
            0, addr, channel, int (level))
        
        ctypes.memmove (ctypes.addressof (muxes_buf) + muxes_len, ctypes.addressof (mux_body), 
            ctypes.sizeof (pcd_mux_header))
        muxes_len += ctypes.sizeof (pcd_mux_header)

    return muxes_buf, len (xml_muxes)

def generate_components_buf (xml_components):
    """
    Create a buffer of component section struct instances from parsed XML list

    :param xml_components: List of parsed XML of components to be included in PCD

    :return Components buffer, number of components
    """

    if xml_components is None or len (xml_components) < 1:
        return None, 0, 0

    components_list = []
    components_len = 0

    for component in xml_components:
        device_type = int (get_key_from_dict (component, "devicetype", "Component"), base=16)
        bus = int (get_key_from_dict (component, "bus", "Component"))
        address = int (get_key_from_dict (component, "address", "Component"), base=16)
        i2c_mode = int (get_key_from_dict (component, "i2cmode", "Component"), base=10)
        eid = int (get_key_from_dict (component, "eid", "Component"), base=16)
        powerctrl = get_key_from_dict (component, "powerctrl", "Component")
        powerctrl_reg = int (get_key_from_dict (powerctrl, "register", "Component PowerCtrl"), 
            base=16)
        powerctrl_mask = int (get_key_from_dict (powerctrl, "mask", "Component PowerCtrl"), base=16)

        flags = 0 
        flags |= (i2c_mode << 0)

        muxes = get_key_from_dict (component, "muxes", "Component", required=False)
        muxes_buf, num_muxes = generate_muxes_buf (muxes)

        if muxes_buf is None:
            muxes_buf = (ctypes.c_ubyte * 0)()
            num_muxes = 0

        class pcd_component (ctypes.LittleEndianStructure):
            _pack_ = 1  
            _fields_ = [('component_header', pcd_component_header),
                        ('muxes', ctypes.c_ubyte * ctypes.sizeof (muxes_buf))]

        component_header = pcd_component_header (ctypes.sizeof (pcd_component), 
        	ctypes.sizeof (pcd_component_header), 0, num_muxes, address, bus, flags, eid, 
            powerctrl_reg, powerctrl_mask, device_type)
        component_section = pcd_component (component_header, muxes_buf)
        components_list.append (component_section)
        components_len += ctypes.sizeof (component_section)
        
    components_buf = (ctypes.c_ubyte * components_len) ()
    offset = 0

    for component in components_list:
        ctypes.memmove (ctypes.addressof (components_buf) + offset, ctypes.addressof (component), 
            ctypes.sizeof (component))
        offset += ctypes.sizeof (component)

    return components_buf, len (xml_components)

def generate_components_header (components_len, num_components):
    """
    Create a PCD components header

    :param components_len: Length of components buffer
    :param num_components: Number of components in PCD

    :return PCD components header instance    
    """

    return pcd_components_header (components_len + ctypes.sizeof (pcd_components_header), 
        ctypes.sizeof (pcd_components_header), 0, num_components, 0, 0)

def generate_platform_id_header (id_len):
    """
    Create a PCD platform ID header

    :param id_len: Length of platform ID buffer

    :return PCD platform ID header instance    
    """

    return pcd_platform_id_header (id_len + ctypes.sizeof (pcd_platform_id_header), 
        ctypes.sizeof (pcd_platform_id_header), 0, id_len, 0, 0)

def generate_pcd_header (pcd_length):
    """
    Create a PCD header

    :param pcd_length: Length of PCD

    :return PCD header instance    
    """

    return pcd_header (pcd_length + ctypes.sizeof (pcd_header), ctypes.sizeof (pcd_header), 
        0, 0, 0, 0)

def generate_pcd (manifest_header, header, rot_header, ports, components_header, 
    components, platform_id_header, platform_id):
    """
    Create a PCD object from all the different PCD sections

    :param manifest_header: Instance of a manifest header
    :param header: Instance of a PCD header
    :param rot_header: Instance of a PCD RoT header
    :param ports: Ports section buffer
    :param components_header: Instance of a PCD components header
    :param components: Components section buffer
    :param platform_id_header: Instance of a PCD platform ID header
    :param platform_id: PCD platform ID

    :return Instance of a PCD object
    """

    ports_len = ctypes.sizeof (pcd_port_header) * rot_header.num_ports

    components_len = components_header.length - components_header.header_len
    components_buf = (ctypes.c_ubyte * components_len) ()

    ctypes.memmove (ctypes.addressof (components_buf), ctypes.addressof (components), 
        components_len)

    class pcd (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('manifest_header', manifest_common.manifest_header),
                    ('header', pcd_header),
                    ('rot_header', pcd_rot_header),
                    ('ports', ctypes.c_ubyte * ports_len),
                    ('components_header', pcd_components_header),
                    ('components', ctypes.c_ubyte * components_len),
                    ('platform_id_header', pcd_platform_id_header),
                    ('platform_id', ctypes.c_char * len (platform_id))]
    
    return pcd (manifest_header, header, rot_header, ports, components_header, components_buf, 
        platform_id_header, platform_id.encode('utf-8'))

#*************************************** Start of Script ***************************************

if len (sys.argv) < 2:
    path = os.path.join (os.path.dirname (os.path.abspath (__file__)), PCD_CONFIG_FILENAME)
else:
    path = os.path.abspath (sys.argv[1])

processed_xml, sign, key_size, key, id, output = manifest_common.load_xmls (path, 1, 
    manifest_types.PCD)

processed_xml = list(processed_xml.items())[0][1]

ports = (ctypes.c_ubyte * 0)()
num_ports = 0

if "ports" in processed_xml["rot"]:
    ports, num_ports = generate_ports_buf (processed_xml["rot"]["ports"])
	
components = (ctypes.c_ubyte * 0)()
num_components = 0
	
if "components" in processed_xml:
    components, num_components = generate_components_buf (
        processed_xml["components"])
	
components_header = generate_components_header (ctypes.sizeof (components), num_components)

rot_header = generate_rot_header (processed_xml["rot"], processed_xml["rot"]["interface"], 
                                  processed_xml["cpld"], processed_xml["policy"], num_ports)
	
platform_id_header = generate_platform_id_header (len (processed_xml["platform_id"]))

header = generate_pcd_header (rot_header.length + components_header.length + \
                              platform_id_header.length)
manifest_header = manifest_common.generate_manifest_header (id, key_size, 
                                                            manifest_types.PCD)
manifest_header.length = ctypes.sizeof (manifest_header) + header.length + \
    manifest_header.sig_length

pcd = generate_pcd (manifest_header, header, rot_header, ports, components_header, 
                    components, platform_id_header, processed_xml["platform_id"])

manifest_common.write_manifest (sign, pcd, key, output, manifest_header.length - \
                                manifest_header.sig_length, manifest_header.sig_length)

print ("Completed PCD generation: {0}".format(output))


