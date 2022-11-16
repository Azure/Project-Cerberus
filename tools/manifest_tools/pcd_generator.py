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


def get_greater_timeout (curr, check):
    '''
    Get the greater of two timeout values

    :param curr: Current timeout value
    :param check: Timeout value to check against

    :return The greater timeout value
    '''
    if ((curr is None) or (check > curr)):
        return check
    else:
        return curr

def get_lower_timeout (curr, check):
    '''
    Get the lower of two timeout values

    :param curr: Current timeout value
    :param check: Timeout value to check against

    :return The lower timeout value
    '''
    if ((curr is None) or (check < curr)):
       return check
    else:
       return curr

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
        host_reset_action = int (manifest_common.get_key_from_dict (port, "host_reset_action",
            "Port"))

        port_flags = (host_reset_action << 6) | (watchdog_monitoring << 5) | \
            (runtime_verification << 4) | (flash_mode << 2) | reset_ctrl

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

def generate_rot (xml_rot, num_components, num_ports, hash_engine, timeouts):
    """
    Create an RoT object from parsed XML list and ports buffer

    :param xml_rot: List of parsed XML of RoT to be included in RoT object
    :param num_components: Number of components
    :param num_ports: Number of SPI flash ports
    :param hash_engine: Hashing engine
    :param timeouts: Dictionary of component timeouts

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
    mctp_ctrl_timeout = int (manifest_common.get_key_from_dict (xml_rot, 'mctp_ctrl_timeout',
        "RoT"))
    mctp_bridge_get_table_wait = int (manifest_common.get_key_from_dict (xml_rot,
        'mctp_bridge_get_table_wait', "RoT"))

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
                    ('reserved', ctypes.c_ubyte),
                    ('attestation_success_retry', ctypes.c_int32),
                    ('attestation_fail_retry', ctypes.c_int32),
                    ('discovery_fail_retry', ctypes.c_int32),
                    ('mctp_ctrl_timeout', ctypes.c_int32),
                    ('mctp_bridge_get_table_wait', ctypes.c_int32),
                    ('mctp_bridge_additional_timeout', ctypes.c_int32),
                    ('attestation_rsp_not_ready_max_duration', ctypes.c_int32),
                    ('attestation_rsp_not_ready_max_retry', ctypes.c_ubyte),
                    ('reserved2', ctypes.c_ubyte * 3)]

    if timeouts is None:
        attestation_success_retry = 0
        attestation_fail_retry = 0
        discovery_fail_retry = 0
        mctp_bridge_additional_timeout = 0
        attestation_rsp_not_ready_max_duration = 0
        attestation_rsp_not_ready_max_retry = 0
    else:
        attestation_success_retry = timeouts.get ("attestation_success_retry")
        if attestation_success_retry is None:
            attestation_success_retry = 0

        attestation_fail_retry = timeouts.get ("attestation_fail_retry")
        if attestation_fail_retry is None:
            attestation_fail_retry = 0

        discovery_fail_retry = timeouts.get ("discovery_fail_retry")
        if discovery_fail_retry is None:
            discovery_fail_retry = 0

        mctp_bridge_additional_timeout = timeouts.get ("mctp_bridge_additional_timeout")
        if mctp_bridge_additional_timeout is None:
            mctp_bridge_additional_timeout = 0

        attestation_rsp_not_ready_max_duration = \
            timeouts.get ("attestation_rsp_not_ready_max_duration")
        if attestation_rsp_not_ready_max_duration is None:
            attestation_rsp_not_ready_max_duration = 0

        attestation_rsp_not_ready_max_retry = timeouts.get ("attestation_rsp_not_ready_max_retry")
        if attestation_rsp_not_ready_max_retry is None:
            attestation_rsp_not_ready_max_retry = 0

    rot = pcd_rot_element (rot_flags, num_ports, num_components, rot_address, rot_eid,
        bridge_address, bridge_eid, 0, attestation_success_retry,
        attestation_fail_retry, discovery_fail_retry, mctp_ctrl_timeout, mctp_bridge_get_table_wait,
        mctp_bridge_additional_timeout, attestation_rsp_not_ready_max_duration,
        attestation_rsp_not_ready_max_retry, (ctypes.c_ubyte * 3)())
    rot_len = ctypes.sizeof (rot)
    rot_toc_entry = manifest_common.manifest_toc_entry (manifest_common.PCD_V2_ROT_TYPE_ID,
        manifest_common.V2_BASE_TYPE_ID, 2, 0, 0, rot_len)

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

def generate_direct_component_buf (xml_component, component_map, component_map_file):
    """
    Create a direct component object from parsed XML list. Create new component type to ID mapping
    in provided component map file if a mapping doesn't exist.

    :param xml_component: List of parsed XML of component to be included in direct component object
    :param component_map_file: Component map file to add mapping to

    :return Instance of a component object, component's TOC entry, component hash, dictionary of
        component's timeouts
    """

    if xml_component["interface"]["type"] != 0:
        raise ValueError ("Unsupported direct component interface type: {0}".format (
            xml_component["interface"]["type"]))

    timeouts = {}

    policy = int (manifest_common.get_key_from_dict (xml_component, "policy", "Direct Component"))
    component_type = manifest_common.get_key_from_dict (xml_component, "type", "Direct Component")
    timeouts["attestation_success_retry"] = int (manifest_common.get_key_from_dict (xml_component,
        "attestation_success_retry", "Direct Component"))
    timeouts["attestation_fail_retry"] = int (manifest_common.get_key_from_dict (xml_component,
        "attestation_fail_retry", "Direct Component"))
    timeouts["attestation_rsp_not_ready_max_retry"] = int (manifest_common.get_key_from_dict (
        xml_component, "attestation_rsp_not_ready_max_retry", "Direct Component"))
    timeouts["attestation_rsp_not_ready_max_duration"] = int (
        manifest_common.get_key_from_dict (xml_component, "attestation_rsp_not_ready_max_duration",
        "Direct Component"))
    powerctrl_reg = int (manifest_common.get_key_from_dict (xml_component["powerctrl"], "register",
        "Direct Component"))
    powerctrl_mask = int (manifest_common.get_key_from_dict (xml_component["powerctrl"], "mask",
        "Direct Component"))
    i2c_mode = int (manifest_common.get_key_from_dict (xml_component["interface"], "i2c_mode",
        "Direct Component"))
    bus = int (manifest_common.get_key_from_dict (xml_component["interface"], "bus",
        "Direct Component"))
    address = int (manifest_common.get_key_from_dict (xml_component["interface"], "address",
        "Direct Component"))
    eid = int (manifest_common.get_key_from_dict (xml_component["interface"], "eid",
        "Direct Component"))

    component_id = component_map.get (component_type)
    if component_id is None:
        component_id = manifest_common.add_component_mapping (component_type, component_map_file)

    i2c_flags = i2c_mode

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
                    ('reserved', ctypes.c_ubyte),
                    ('component_id', ctypes.c_int32),
                    ('mux_count', ctypes.c_ubyte, 4),
                    ('i2c_flags', ctypes.c_ubyte, 4),
                    ('bus', ctypes.c_ubyte),
                    ('address', ctypes.c_ubyte),
                    ('eid', ctypes.c_ubyte),
                    ('muxes', ctypes.c_ubyte * muxes_len)]

    component = pcd_direct_i2c_component_element (policy, powerctrl_reg, powerctrl_mask, 0,
        int (component_id), num_muxes, i2c_flags, bus, address, eid, muxes)
    component_len = ctypes.sizeof (component)

    component_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.PCD_V2_DIRECT_COMPONENT_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 2,
        0, 0, component_len)

    component_hash = manifest_common.generate_hash (component, hash_engine)

    return component, component_toc_entry, component_hash, timeouts

def generate_mctp_bridge_component_buf (xml_component, component_map, component_map_file):
    """
    Create an MCTP bridges component object from parsed XML list. Create new component type to ID
    mapping in provided component map file if a mapping doesn't exist.

    :param xml_component: List of parsed XML of component to be included in MCTP bridge component
        object
    :param component_map: Dictionary mapping component types to component IDs
    :param component_map_file: Component map file to add mapping to

    :return Instance of a component object, component's TOC entry, component hash, dictionary of
        component's timeouts
    """

    timeouts = {}

    policy = int (manifest_common.get_key_from_dict (xml_component, "policy",
        "MCTP Bridge Component"))
    powerctrl_reg = int (manifest_common.get_key_from_dict (xml_component["powerctrl"], "register",
        "MCTP Bridge Component"))
    powerctrl_mask = int (manifest_common.get_key_from_dict (xml_component["powerctrl"], "mask",
        "MCTP Bridge Component"))
    component_type = manifest_common.get_key_from_dict (xml_component, "type",
        "MCTP Bridge Component")
    timeouts["attestation_success_retry"] = int (manifest_common.get_key_from_dict (xml_component,
        "attestation_success_retry", "MCTP Bridge Component"))
    timeouts["attestation_fail_retry"] = int (manifest_common.get_key_from_dict (xml_component,
        "attestation_fail_retry", "MCTP Bridge Component"))
    timeouts["discovery_fail_retry"] = int (manifest_common.get_key_from_dict (xml_component,
        "discovery_fail_retry", "MCTP Bridge Component"))
    timeouts["mctp_bridge_additional_timeout"] = int (manifest_common.get_key_from_dict (
        xml_component, "mctp_bridge_additional_timeout", "MCTP Bridge Component"))
    timeouts["attestation_rsp_not_ready_max_retry"] = int (manifest_common.get_key_from_dict (
        xml_component, "attestation_rsp_not_ready_max_retry", "MCTP Bridge Component"))
    timeouts["attestation_rsp_not_ready_max_duration"] = int (
        manifest_common.get_key_from_dict (xml_component, "attestation_rsp_not_ready_max_duration",
        "MCTP Bridge Component"))
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

    component_id = component_map.get (component_type)
    if component_id is None:
        component_id = manifest_common.add_component_mapping (component_type, component_map_file)

    class pcd_mctp_bridge_component_element (ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('policy', ctypes.c_ubyte),
                    ('power_ctrl_reg', ctypes.c_ubyte),
                    ('power_ctrl_mask', ctypes.c_ubyte),
                    ('reserved', ctypes.c_ubyte),
                    ('component_id', ctypes.c_int32),
                    ('device_id', ctypes.c_ushort),
                    ('vendor_id', ctypes.c_ushort),
                    ('subsystem_device_id', ctypes.c_ushort),
                    ('subsystem_vendor_id', ctypes.c_ushort),
                    ('components_count', ctypes.c_ubyte),
                    ('eid', ctypes.c_ubyte),
                    ('reserved2', ctypes.c_ushort)]

    component = pcd_mctp_bridge_component_element (policy, powerctrl_reg, powerctrl_mask, 0,
        int (component_id), device_id, vendor_id, sub_device_id, sub_vendor_id, components_count,
        eid, 0)
    component_len = ctypes.sizeof (component)

    component_toc_entry = manifest_common.manifest_toc_entry (
        manifest_common.PCD_V2_MCTP_BRIDGE_COMPONENT_TYPE_ID, manifest_common.V2_BASE_TYPE_ID, 2,
        0, 0, component_len)

    component_hash = manifest_common.generate_hash (component, hash_engine)

    return component, component_toc_entry, component_hash, timeouts

def generate_components (xml_components, hash_engine, component_map, component_map_file):
    """
    Create a buffer of component section struct instances from parsed XML list

    :param xml_components: List of parsed XML of components to be included in PCD
    :param hash_engine: Hashing engine
    :param component_map: Dictionary mapping component types to component IDs
    :param component_map_file: Path to component map file

    :return Components buffer, number of components, list of component TOC entries,
        list of component hashes, list of extreme component timeout values
    """

    if xml_components is None or len (xml_components) < 1:
        return None, 0, None, None, None

    components_list = []
    components_toc_list = []
    hash_list = []
    timeout_common = {
        "attestation_success_retry": None,
        "attestation_fail_retry": None,
        "attestation_rsp_not_ready_max_retry": None,
        "attestation_rsp_not_ready_max_duration": None
    }
    timeout_mctp_bridge = {
        "discovery_fail_retry": None,
        "mctp_bridge_additional_timeout": None
    }
    timeouts = {}
    components_len = 0

    for component in xml_components:
        connection = manifest_common.get_key_from_dict (component, "connection", "Component")

        if connection is manifest_parser.PCD_COMPONENT_CONNECTION_DIRECT:
            component_buf, component_toc_entry, component_hash, curr_timeouts = \
                generate_direct_component_buf (component, component_map, component_map_file)
        elif connection is manifest_parser.PCD_COMPONENT_CONNECTION_MCTP_BRIDGE:
            component_buf, component_toc_entry, component_hash, curr_timeouts = \
                generate_mctp_bridge_component_buf (component, component_map, component_map_file)

            timeout_mctp_bridge["mctp_bridge_additional_timeout"] = \
                get_greater_timeout (timeout_mctp_bridge["mctp_bridge_additional_timeout"],
                    curr_timeouts["mctp_bridge_additional_timeout"])

            timeout_mctp_bridge["discovery_fail_retry"] = \
                get_lower_timeout (timeout_mctp_bridge["discovery_fail_retry"],
                    curr_timeouts["discovery_fail_retry"])
        else:
            raise ValueError ("Unsupported component connection type: {0}".format (connection))

        components_list.append (component_buf)
        components_toc_list.append (component_toc_entry)
        hash_list.append (component_hash)

        timeout_common["attestation_rsp_not_ready_max_retry"] = \
            get_greater_timeout (timeout_common["attestation_rsp_not_ready_max_retry"],
                curr_timeouts["attestation_rsp_not_ready_max_retry"])

        timeout_common["attestation_rsp_not_ready_max_duration"] = \
            get_greater_timeout (timeout_common["attestation_rsp_not_ready_max_duration"],
                curr_timeouts["attestation_rsp_not_ready_max_duration"])

        timeout_common["attestation_success_retry"] = \
            get_lower_timeout (timeout_common["attestation_success_retry"],
                curr_timeouts["attestation_success_retry"])

        timeout_common["attestation_fail_retry"] = \
            get_lower_timeout (timeout_common["attestation_fail_retry"],
                curr_timeouts["attestation_fail_retry"])

        components_len += ctypes.sizeof (component_buf)

    timeouts.update (timeout_common)
    timeouts.update (timeout_mctp_bridge)

    components_buf = (ctypes.c_ubyte * components_len) ()
    components_buf_len = manifest_common.move_list_to_buffer (components_buf, 0, components_list)

    return components_buf, len (xml_components), components_toc_list, hash_list, timeouts


#*************************************** Start of Script ***************************************

default_config = os.path.join (os.path.dirname (os.path.abspath (__file__)), PCD_CONFIG_FILENAME)
parser = argparse.ArgumentParser (description = 'Create a PCD')
parser.add_argument ('config', nargs = '?', default = default_config,
    help = 'Path to configuration file')
args = parser.parse_args ()

processed_xml, sign, key_size, key, key_type, hash_type, pcd_id, output, xml_version, empty, \
    max_num_rw_sections, selection_list, component_map, component_map_file = \
        manifest_common.load_xmls (args.config, 1, manifest_types.PCD)

hash_engine = manifest_common.get_hash_engine (hash_type)

processed_xml = list (processed_xml.items())[0][1]

num_components = 0
num_ports = 0
elements_list = []
toc_list = []
hash_list = []
timeouts_dict = {}

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
        components, num_components, components_toc_list, components_hash_list, timeouts_dict = \
            generate_components (processed_xml["components"], hash_engine, component_map,
                component_map_file)

        pcd_len += ctypes.sizeof (components)
        elements_list.append (components)
        toc_list.extend (components_toc_list)
        hash_list.extend (components_hash_list)

    if "ports" in processed_xml["rot"]:
        ports, num_ports, ports_toc_entries, ports_hash = generate_ports (
            processed_xml["rot"]["ports"], hash_engine)

    rot, rot_toc_entry, rot_hash = generate_rot (processed_xml["rot"], num_components, num_ports,
        hash_engine, timeouts_dict)

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


