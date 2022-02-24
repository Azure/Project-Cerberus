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
import manifest_parser
from Crypto.PublicKey import RSA


PCD_CONFIG_FILENAME = "pcd_generator.config"


class pcd_mux (ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('mux_address', ctypes.c_ubyte),
                ('mux_channel', ctypes.c_ubyte),
                ('reserved', ctypes.c_ushort)]


def generate_ports (xml_ports, hash_engine):
    """
    Create a list of SPI flash port objects from parsed XML list

    :param xml_ports: List of parsed XML of ports to be included in PCD

    :return Ports buffer, number of ports, list of port ToC entries, list of port hashes
    """

    if xml_ports is None or len (xml_ports) < 1:
        return None, 0, None, None

    ports = []
    toc_entries = []
    hashes = []
    num_ports = len (xml_ports)
    ports_len = 0
    class pcd_port (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('port_id', ctypes.c_ubyte),
                    ('port_flags', ctypes.c_ubyte),
                    ('policy', ctypes.c_ubyte),
                    ('pulse_interval', ctypes.c_ubyte),
                    ('spi_frequency_hz', ctypes.c_uint)]

    for id, port in xml_ports.items ():
        spi_freq = int (manifest_common.get_key_from_dict (port, "spi_freq", "Port"))
        reset_ctrl = int (manifest_common.get_key_from_dict (port, "reset_ctrl", "Port"))
        flash_mode = int (manifest_common.get_key_from_dict (port, "flash_mode", "Port"))
        policy = int (manifest_common.get_key_from_dict (port, "policy", "Port"))
        runtime_verification = int (manifest_common.get_key_from_dict (port, "runtime_verification",
            "Port"))
        watchdog_monitoring = int (manifest_common.get_key_from_dict (port, "watchdog_monitoring",
            "Port"))
        pulse_interval = int (manifest_common.get_key_from_dict (port, "pulse_interval", "Port"))

        port_flags = (watchdog_monitoring << 5) | (runtime_verification << 4) | \
            (flash_mode << 2) | reset_ctrl

        port_buf = pcd_port (int (id), port_flags, policy, pulse_interval, spi_freq)
        port_toc_entry = manifest_common.manifest_toc_entry (
            manifest_common.PCD_V2_SPI_FLASH_PORT_TYPE_ID, manifest_common.PCD_V2_ROT_TYPE_ID, 1, 0,
            0, ctypes.sizeof (pcd_port))
        port_hash = manifest_common.generate_hash (port_buf, hash_engine)

        ports.append (port_buf)
        toc_entries.append (port_toc_entry)
        hashes.append (port_hash)

        ports_len += ctypes.sizeof (port_buf)

    ports_buf = (ctypes.c_ubyte * ports_len) ()
    ports_buf_len = manifest_common.move_list_to_buffer (ports_buf, 0, ports)

    return ports_buf, num_ports, toc_entries, hashes

def generate_rot (xml_rot, num_components, num_ports, hash_engine):
    """
    Create an RoT object from parsed XML list and ports buffer

    :param xml_rot: List of parsed XML of RoT to be included in RoT object
    :param num_components: Number of components
    :param num_ports: Number of SPI flash ports
    :param hash_engine: Hashing engine

    :return Instance of an RoT object, RoT's TOC entry, RoT hash
    """

    rot_type = int (manifest_common.get_key_from_dict (xml_rot, "type", "RoT"))
    rot_address = int (manifest_common.get_key_from_dict (xml_rot["interface"], "address",
        "RoT interface"))
    rot_eid = int (manifest_common.get_key_from_dict (xml_rot["interface"], "rot_eid",
        "RoT interface"))
    bridge_eid = int (manifest_common.get_key_from_dict (xml_rot["interface"], "bridge_eid",
        "RoT interface"))
    bridge_address = int (manifest_common.get_key_from_dict (xml_rot["interface"], "bridge_address",
        "RoT interface"))

    rot_flags = rot_type

    class pcd_rot_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('rot_flags', ctypes.c_ubyte),
                    ('port_count', ctypes.c_ubyte),
                    ('components_count', ctypes.c_ubyte),
                    ('rot_address', ctypes.c_ubyte),
                    ('rot_eid', ctypes.c_ubyte),
                    ('bridge_address', ctypes.c_ubyte),
                    ('bridge_eid', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte)]

    rot = pcd_rot_element (rot_flags, num_ports, num_components, rot_address, rot_eid,
        bridge_address, bridge_eid, 0)
    rot_len = ctypes.sizeof (rot)
    rot_toc_entry = manifest_common.manifest_toc_entry (manifest_common.PCD_V2_ROT_TYPE_ID,
        manifest_common.V2_BASE_TYPE_ID, 1, 0, 0, rot_len)

    rot_hash = manifest_common.generate_hash (rot, hash_engine)

    return rot, rot_toc_entry, rot_hash

def generate_muxes_buf (xml_muxes):
    """
    Create a buffer of pcd_mux struct instances from parsed XML list

    :param xml_muxes: List of parsed XML of muxes to be included in PCD

    :return Muxes buffer, length of muxes buffer, number of muxes
    """

    if xml_muxes is None or len (xml_muxes) < 1:
        return None, 0

    num_muxes = len (xml_muxes)
    muxes_buf = (ctypes.c_ubyte * (ctypes.sizeof (pcd_mux) * num_muxes)) ()
    muxes_len = 0

    for mux in sorted (xml_muxes.items ()):
        address = int (manifest_common.get_key_from_dict (mux[1], "address", "Mux"))
        channel = int (manifest_common.get_key_from_dict (mux[1], "channel", "Mux"))

        mux_body = pcd_mux (address, channel, 0)
        muxes_len = manifest_common.move_list_to_buffer (muxes_buf, muxes_len, [mux_body])

    return muxes_buf, muxes_len, num_muxes

def generate_power_controller (xml_power_controller, hash_engine):
    """
    Create a power_controller object from parsed XML list

    :param xml_power_controller: List of parsed XML of power_controller to be included in
        power_controller object
    :param hash_engine: Hashing engine

    :return Instance of a power_controller object, power_controller's TOC entry,
        hash of power_controller object
    """

    if xml_power_controller["interface"]["type"] != 0:
        raise ValueError ("Unsupported power_controller interface type: {0}".format (
            xml_power_controller["interface"]["type"]))

    if "muxes" in xml_power_controller["interface"]:
        muxes, muxes_len, num_muxes = generate_muxes_buf (
            xml_power_controller["interface"]["muxes"])
    else:
        muxes = (ctypes.c_ubyte * 0)()
        muxes_len = 0
        num_muxes = 0

    bus = int (manifest_common.get_key_from_dict (xml_power_controller["interface"], "bus",
        "Power controller interface"))
    address = int (manifest_common.get_key_from_dict (xml_power_controller["interface"], "address",
        "Power controller interface"))
    eid = int (manifest_common.get_key_from_dict (xml_power_controller["interface"], "eid",
        "Power controller interface"))
    i2c_mode = int (manifest_common.get_key_from_dict (xml_power_controller["interface"],
        "i2c_mode", "Power controller interface"))

    i2c_flags = i2c_mode

    class pcd_power_controller_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('mux_count', ctypes.c_ubyte, 4),
                    ('i2c_flags', ctypes.c_ubyte, 4),
                    ('bus', ctypes.c_ubyte),
                    ('address', ctypes.c_ubyte),
                    ('eid', ctypes.c_ubyte),
                    ('muxes', ctypes.c_ubyte * muxes_len)]

    power_controller = pcd_power_controller_element (num_muxes, i2c_flags, bus, address, eid, muxes)
    power_controller_len = ctypes.sizeof (power_controller)
    power_controller_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.PCD_V2_I2C_POWER_CONTROLLER_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 1, 0,
        0, power_controller_len)

    power_controller_hash = manifest_common.generate_hash (power_controller, hash_engine)

    return power_controller, power_controller_toc_entry, power_controller_hash

def generate_direct_component_buf (xml_component):
    """
    Create a direct component object from parsed XML list

    :param xml_component: List of parsed XML of component to be included in direct component object

    :return Instance of a component object, component's TOC entry, component hash
    """

    if xml_component["interface"]["type"] != 0:
        raise ValueError ("Unsupported direct component interface type: {0}".format (
            xml_component["interface"]["type"]))

    policy = int (manifest_common.get_key_from_dict (xml_component, "policy", "Direct Component"))
    powerctrl_reg = int (manifest_common.get_key_from_dict (xml_component["powerctrl"], "register",
        "Direct Component"))
    powerctrl_mask = int (manifest_common.get_key_from_dict (xml_component["powerctrl"], "mask",
        "Direct Component"))
    component_type = manifest_common.get_key_from_dict (xml_component, "type", "Direct Component")
    i2c_mode = int (manifest_common.get_key_from_dict (xml_component["interface"], "i2c_mode",
        "Direct Component"))
    bus = int (manifest_common.get_key_from_dict (xml_component["interface"], "bus",
        "Direct Component"))
    address = int (manifest_common.get_key_from_dict (xml_component["interface"], "address",
        "Direct Component"))
    eid = int (manifest_common.get_key_from_dict (xml_component["interface"], "eid",
        "Direct Component"))

    type_len = len (component_type)
    i2c_flags = i2c_mode

    manifest_common.check_maximum (type_len, 255, "Component type {0} length".format (
        component_type))
    padding, padding_len = manifest_common.generate_4byte_padding_buf (type_len)

    if "muxes" in xml_component["interface"]:
        muxes, muxes_len, num_muxes = generate_muxes_buf (xml_component["interface"]["muxes"])
    else:
        muxes = (ctypes.c_ubyte * 0) ()
        muxes_len = 0
        num_muxes = 0

    class pcd_direct_i2c_component_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('policy', ctypes.c_ubyte),
                    ('power_ctrl_reg', ctypes.c_ubyte),
                    ('power_ctrl_mask', ctypes.c_ubyte),
                    ('type_len', ctypes.c_ubyte),
                    ('type', ctypes.c_char * type_len),
                    ('type_padding', ctypes.c_ubyte * padding_len),
                    ('mux_count', ctypes.c_ubyte, 4),
                    ('i2c_flags', ctypes.c_ubyte, 4),
                    ('bus', ctypes.c_ubyte),
                    ('address', ctypes.c_ubyte),
                    ('eid', ctypes.c_ubyte),
                    ('muxes', ctypes.c_ubyte * muxes_len)]

    component = pcd_direct_i2c_component_element (policy, powerctrl_reg, powerctrl_mask, type_len,
        component_type.encode ('utf-8'), padding, num_muxes, i2c_flags, bus, address, eid, muxes)
    component_len = ctypes.sizeof (component)

    component_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.PCD_V2_DIRECT_COMPONENT_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 1,
        0, 0, component_len)

    component_hash = manifest_common.generate_hash (component, hash_engine)

    return component, component_toc_entry, component_hash

def generate_mctp_bridge_component_buf (xml_component):
    """
    Create an MCTP bridges component object from parsed XML list

    :param xml_component: List of parsed XML of component to be included in MCTP bridge component
        object

    :return Instance of a component object, component's TOC entry, component hash
    """

    policy = int (manifest_common.get_key_from_dict (xml_component, "policy",
        "MCTP Bridge Component"))
    powerctrl_reg = int (manifest_common.get_key_from_dict (xml_component["powerctrl"], "register",
        "MCTP Bridge Component"))
    powerctrl_mask = int (manifest_common.get_key_from_dict (xml_component["powerctrl"], "mask",
        "MCTP Bridge Component"))
    component_type = manifest_common.get_key_from_dict (xml_component, "type",
        "MCTP Bridge Component")
    device_id = int (manifest_common.get_key_from_dict (xml_component, "deviceid",
        "MCTP Bridge Component"))
    vendor_id = int (manifest_common.get_key_from_dict (xml_component, "vendorid",
        "MCTP Bridge Component"))
    sub_device_id = int (manifest_common.get_key_from_dict (xml_component, "subdeviceid",
        "MCTP Bridge Component"))
    sub_vendor_id = int (manifest_common.get_key_from_dict (xml_component, "subvendorid",
        "MCTP Bridge Component"))
    sub_vendor_id = int (manifest_common.get_key_from_dict (xml_component, "subvendorid",
        "MCTP Bridge Component"))
    components_count = int (manifest_common.get_key_from_dict (xml_component, "count",
        "MCTP Bridge Component"))
    eid = int (manifest_common.get_key_from_dict (xml_component, "eid", "MCTP Bridge Component"))

    type_len = len (component_type)

    manifest_common.check_maximum (type_len, 255, "Component type {0} length".format (
        component_type))
    padding, padding_len = manifest_common.generate_4byte_padding_buf (type_len)

    class pcd_mctp_bridge_component_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('policy', ctypes.c_ubyte),
                    ('power_ctrl_reg', ctypes.c_ubyte),
                    ('power_ctrl_mask', ctypes.c_ubyte),
                    ('type_len', ctypes.c_ubyte),
                    ('type', ctypes.c_char * type_len),
                    ('type_padding', ctypes.c_ubyte * padding_len),
                    ('device_id', ctypes.c_ushort),
                    ('vendor_id', ctypes.c_ushort),
                    ('subsystem_device_id', ctypes.c_ushort),
                    ('subsystem_vendor_id', ctypes.c_ushort),
                    ('components_count', ctypes.c_ubyte),
                    ('eid', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ushort)]

    component = pcd_mctp_bridge_component_element (policy, powerctrl_reg, powerctrl_mask, type_len,
        component_type.encode ('utf-8'), padding, device_id, vendor_id, sub_device_id,
        sub_vendor_id, components_count, eid, 0)
    component_len = ctypes.sizeof (component)

    component_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.PCD_V2_MCTP_BRIDGE_COMPONENT_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 1,
        0, 0, component_len)

    component_hash = manifest_common.generate_hash (component, hash_engine)

    return component, component_toc_entry, component_hash

def generate_components (xml_components, hash_engine):
    """
    Create a buffer of component section struct instances from parsed XML list

    :param xml_components: List of parsed XML of components to be included in PCD
    :param hash_engine: Hashing engine

    :return Components buffer, number of components, list of component TOC entries,
        list of component hashes
    """

    if xml_components is None or len (xml_components) < 1:
        return None, 0, None, None

    components_list = []
    components_toc_list = []
    hash_list = []
    components_len = 0

    for component in xml_components:
        connection = manifest_common.get_key_from_dict (component, "connection", "Component")

        if connection is manifest_parser.PCD_COMPONENT_CONNECTION_DIRECT:
            component_buf, component_toc_entry, component_hash = generate_direct_component_buf (
                component)
        elif connection is manifest_parser.PCD_COMPONENT_CONNECTION_MCTP_BRIDGE:
            component_buf, component_toc_entry, component_hash = \
                generate_mctp_bridge_component_buf (component)
        else:
            raise ValueError ("Unsupported component connection type: {0}".format (connection))

        components_list.append (component_buf)
        components_toc_list.append (component_toc_entry)
        hash_list.append (component_hash)

        components_len += ctypes.sizeof (component_buf)

    components_buf = (ctypes.c_ubyte * components_len) ()
    components_buf_len = manifest_common.move_list_to_buffer (components_buf, 0, components_list)

    return components_buf, len (xml_components), components_toc_list, hash_list


#*************************************** Start of Script ***************************************

default_config = os.path.join (os.path.dirname (os.path.abspath (__file__)), PCD_CONFIG_FILENAME)
parser = argparse.ArgumentParser (description = 'Create a PCD')
parser.add_argument ('config', nargs = '?', default = default_config,
    help = 'Path to configuration file')
args = parser.parse_args ()

processed_xml, sign, key_size, key, key_type, hash_type, pcd_id, output, xml_version, empty, \
    max_num_rw_sections, selection_list = \
        manifest_common.load_xmls (args.config, 1, manifest_types.PCD)

hash_engine = manifest_common.get_hash_engine (hash_type)

processed_xml = list (processed_xml.items())[0][1]

num_components = 0
num_ports = 0
elements_list = []
toc_list = []
hash_list = []

platform_id, platform_id_toc_entry, platform_id_hash = manifest_common.generate_platform_id_buf (
    processed_xml, hash_engine)

pcd_len = ctypes.sizeof (platform_id)
elements_list.append (platform_id)
toc_list.append (platform_id_toc_entry)
hash_list.append (platform_id_hash)

if not empty:
    if "power_controller" in processed_xml:
        power_controller, power_controller_toc_entry, power_controller_hash = \
            generate_power_controller (processed_xml["power_controller"], hash_engine)

        pcd_len += ctypes.sizeof (power_controller)
        elements_list.append (power_controller)
        toc_list.append (power_controller_toc_entry)
        hash_list.append (power_controller_hash)

    if "components" in processed_xml:
        components, num_components, components_toc_list, components_hash_list = generate_components (
            processed_xml["components"], hash_engine)

        pcd_len += ctypes.sizeof (components)
        elements_list.append (components)
        toc_list.extend (components_toc_list)
        hash_list.extend (components_hash_list)

    if "ports" in processed_xml["rot"]:
        ports, num_ports, ports_toc_entries, ports_hash = generate_ports (
            processed_xml["rot"]["ports"], hash_engine)

    rot, rot_toc_entry, rot_hash = generate_rot (processed_xml["rot"], num_components, num_ports,
        hash_engine)

    pcd_len += ctypes.sizeof (rot)
    elements_list.append (rot)
    toc_list.append (rot_toc_entry)
    hash_list.append (rot_hash)

    if num_ports > 0:
        pcd_len += ctypes.sizeof (ports)
        elements_list.append (ports)
        toc_list.extend (ports_toc_entries)
        hash_list.extend (ports_hash)

manifest_common.generate_manifest (hash_engine, hash_type, pcd_id, manifest_types.PCD, xml_version,
    sign, key, key_size, key_type, toc_list, hash_list, elements_list, pcd_len, output)

print ("Completed PCD generation: {0}".format (output))


