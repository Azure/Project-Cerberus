"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import print_function
from __future__ import unicode_literals
import re
import binascii
import traceback
import xml.etree.ElementTree as et
import manifest_types


XML_ID_ATTRIB = "id"
XML_VERSION_ATTRIB = "version"
XML_PLATFORM_ATTRIB = "platform"
XML_SKU_ATTRIB = "sku"
XML_LEVEL_ATTRIB = "level"
XML_TYPE_ATTRIB = "type"
XML_CONNECTION_ATTRIB = "connection"
XML_COUNT_ATTRIB = "count"

XML_FW_TAG = "Firmware"
XML_DIGEST_TAG = "Digest"
XML_FAILURE_ACTION_TAG = "FailureAction"
XML_RW_TAG = "ReadWrite"
XML_REGION_TAG = "Region"
XML_IMG_TAG = "SignedImage"
XML_START_ADDR_TAG = "StartAddr"
XML_END_ADDR_TAG = "EndAddr"
XML_PB_KEY_TAG = "PublicKey"
XML_SIG_TAG = "Signature"
XML_VALIDATE_TAG = "ValidateOnBoot"
XML_VERSION_ADDR_TAG = "VersionAddr"
XML_UNUSED_BYTE_TAG = "UnusedByte"
XML_VERSION_TAG = "Version"
XML_ROT_TAG = "RoT"
XML_PORTS_TAG = "Ports"
XML_PORT_TAG = "Port"
XML_INTERFACE_TAG = "Interface"
XML_ADDRESS_TAG = "Address"
XML_ROT_EID_TAG = "RoTEID"
XML_BRIDGE_EID_TAG = "BridgeEID"
XML_BRIDGE_ADDRESS_TAG = "BridgeAddress"
XML_EID_TAG = "EID"
XML_POWER_CONTROLLER_TAG = "PowerController"
XML_CHANNEL_TAG = "Channel"
XML_COMPONENTS_TAG = "Components"
XML_COMPONENT_TAG = "Component"
XML_DEVICETYPE_TAG = "DeviceType"
XML_BUS_TAG = "Bus"
XML_I2CMODE_TAG = "I2CMode"
XML_PWRCTRL_TAG = "PwrCtrl"
XML_REGISTER_TAG = "Register"
XML_MASK_TAG = "Mask"
XML_MUXES_TAG = "Muxes"
XML_MUX_TAG = "Mux"
XML_POLICY_TAG = "Policy"
XML_ACTIVE_TAG = "Active"
XML_SPIFREQ_TAG = "SPIFreq"
XML_RESETCTRL_TAG = "ResetCtrl"
XML_FLASHMODE_TAG = "FlashMode"
XML_PULSEINTERVAL_TAG = "PulseInterval"
XML_RUNTIMEVERIFICATION_TAG = "RuntimeVerification"
XML_WATCHDOGMONITORING_TAG = "WatchdogMonitoring"
XML_RUNTIME_UPDATE_TAG = "RuntimeUpdate"
XML_OPERATION_ON_FAILURE_TAG = "OperationOnFailure"
XML_IMAGE_HASH_TAG = "Hash"
XML_IMAGE_HASH_TYPE_TAG = "HashType"
XML_DEVICE_ID_TAG = "DeviceID"
XML_VENDOR_ID_TAG = "VendorID"
XML_SUB_DEVICE_ID_TAG = "SubsystemDeviceID"
XML_SUB_VENDOR_ID_TAG = "SubsystemVendorID"

PCD_ROT_TYPE_PA_ROT = "PA-RoT"
PCD_ROT_TYPE_AC_ROT = "AC-RoT"
PCD_FLASH_MODE_SINGLE = "Single"
PCD_FLASH_MODE_DUAL = "Dual"
PCD_FLASH_MODE_SINGLE_FILTERED_BYPASS = "SingleFilteredBypass"
PCD_FLASH_MODE_DUAL_FILTERED_BYPASS = "DualFilteredBypass"
PCD_RESET_CTRL_NOTIFY = "Notify"
PCD_RESET_CTRL_RESET = "Reset"
PCD_RESET_CTRL_PULSE = "Pulse"
PCD_POLICY_ACTIVE = "Active"
PCD_POLICY_PASSIVE = "Passive"
PCD_INTERFACE_TYPE_I2C = "I2C"
PCD_INTERFACE_I2C_MODE_MM = "MultiMaster"
PCD_INTERFACE_I2C_MODE_MS = "MasterSlave"
PCD_COMPONENT_CONNECTION_DIRECT = "Direct"
PCD_COMPONENT_CONNECTION_MCTP_BRIDGE = "MCTPBridge"
PCD_ENABLED = "Enabled"
PCD_DISABLED = "Disabled"


def xml_extract_attrib (root, attrib_name, string, required=True):
    """
    Fetch attribute from an XML tag.

    :param root: XML tag to utilize
    :param attrib_name: Attribute to fetch
    :param string: A boolean indicating whether attribute value is expected to be a string
    :param key: A boolean indicating whether attribute is required for a valid manifest XML

    :return Attribute value
    """

    attrib = root.attrib.get(attrib_name)
    if not attrib:
        if required:
            print ("Missing {0} attribute in manifest".format (attrib_name))
        return None

    if string:
        attrib.encode("utf8")

    return attrib.strip ()

def xml_find_single_tag (root, tag_name, required=True):
    """
    Fetch an XML tag from XML.

    :param root: XML to utilize
    :param tag_name: Name of tag to fetch
    :param key: A boolean indicating whether tag is required for a valid manifest XML

    :return Tag if found
    """

    tag = root.findall (tag_name)
    if not tag:
        if required:
            print ("Missing {0} tag in manifest".format (tag_name))
        return None
    elif len (tag) > 1:
        print ("Too many {0} tags in manifest".format (tag_name))
        return None

    return tag[0]

def xml_extract_single_value (root, requests):
    """
    Fetch element values from XML tag.

    :param root: XML tag to utilize
    :param requests: A list of XML elements to get values of

    :return Dictionary of elements and their values
    """

    result = {}

    for name, tag_name in requests.items ():
        tag = root.findall (tag_name)
        if not tag:
            print ("Missing {0} tag in manifest".format (tag_name))
            return None
        elif len (tag) > 1:
            print ("Too many {0} tags in manifest".format (tag_name))
            return None

        result.update ({name:tag[0].text.strip ()})

    return result

def process_pfm (root):
    """
    Process PFM XML and generate list of element and attribute values.

    :param root: XML to utilize

    :return List of PFM values, manifest version
    """

    xml = {}
    pfm_version = manifest_types.VERSION_1

    def process_region (root, version_id):
        region = {}

        addr = root.findall (XML_START_ADDR_TAG)

        if not addr or len (addr) > 1:
            print ("Invalid number of StartAddr tags in Firmware: {0}".format (version_id))
            return None

        region["start"] = addr[0].text.strip()

        addr = root.findall (XML_END_ADDR_TAG)

        if not addr or len (addr) > 1:
            print ("Invalid number of EndAddr tags in Firmware: {0}".format (version_id))
            return None

        region["end"] = addr[0].text.strip()

        return region

    version_id = root.attrib.get(XML_VERSION_ATTRIB)

    if version_id is None:
        print ("No Firmware version ID provided")
        return None, None

    platform_id = root.attrib.get(XML_PLATFORM_ATTRIB)

    if platform_id is None:
        print ("No Platform ID provided")
        return None, None

    xml["version_id"] = version_id.strip().encode("utf8")
    xml["platform_id"] = platform_id.strip().encode("utf8")

    firmware_type = root.attrib.get(XML_TYPE_ATTRIB)

    if firmware_type != None:
        pfm_version = manifest_types.VERSION_2
        xml["fw_type"] = firmware_type.strip().encode("utf8")
        runtime_update = root.findall (XML_RUNTIME_UPDATE_TAG)

        if runtime_update is None or len (runtime_update) > 1:
            print ("Invalid number of RuntimeUpdate tags in Firmware: {0}".format (
                    xml["fw_type"].decode("utf8")))
            return None, None

        xml["runtime_update"] = runtime_update[0].text.strip().lower()

    version = root.findall (XML_VERSION_ADDR_TAG)

    if not version or len (version) > 1:
        print ("Invalid number of VersionAddr tags in Firmware: {0}".format (xml["version_id"]))
        return None, None

    xml["version_addr"] = version[0].text.strip()

    unused_byte = root.findall (XML_UNUSED_BYTE_TAG)

    if len (unused_byte) > 1:
        print ("Invalid number of UnusedByte tags in Firmware: {0}".format (xml["version_id"]))
        return None, None

    if unused_byte:
        xml["unused_byte"] = unused_byte[0].text.strip()
    else:
        xml["unused_byte"] = "0xff"

    xml["rw_regions"] = []

    for rw in root.findall (XML_RW_TAG):
        for region in rw.findall (XML_REGION_TAG):
            processed_region = process_region (region, xml["version_id"])

            if processed_region is None:
                return None, None
            else:
                if "fw_type" in xml:
                    fail_operation = region.findall (XML_OPERATION_ON_FAILURE_TAG)

                    if len (fail_operation) > 1:
                        print ("Invalid number of OperationOnFailure tags in ReadWrite: {0}".format (version_id))
                        return None, None

                    if fail_operation and fail_operation[0].text.strip() == "Erase":
                        processed_region["operation_fail"] = "0x2"
                    elif fail_operation and fail_operation[0].text.strip() == "Restore":
                        processed_region["operation_fail"] = "0x1"
                    else:
                        processed_region["operation_fail"] = "0x0"

            xml["rw_regions"].append (processed_region)

    xml["signed_imgs"] = []
    for img in root.findall (XML_IMG_TAG):
        image = {}
        image["regions"] = []

        if "fw_type" in xml:
            img_hash = img.findall (XML_IMAGE_HASH_TAG)

            if not img_hash or len (img_hash) > 1:
                print ("Invalid number of Image Hash tags in SignedImage, Firmware {0} - {1}".format (xml["version_id"], xml["fw_type"]))
                return None, None

            image["hash"] = binascii.a2b_hex(re.sub("\s", "", img_hash[0].text.strip()))

            hash_type = img.findall (XML_IMAGE_HASH_TYPE_TAG)

            if len (hash_type) > 1:
                print ("Invalid number of Image Hash Type tags in SignedImage, Firmware {0} - {1}".format (xml["version_id"], xml["fw_type"]))
                return None, None

            if hash_type and hash_type[0].text.strip() == "SHA512":
                image["hash_type"] = "0x2"
            elif hash_type and hash_type[0].text.strip() == "SHA384":
                image["hash_type"] = "0x1"
            else:
                image["hash_type"] = "0x0"

        else:
            pbkey = img.findall (XML_PB_KEY_TAG)

            if not pbkey or len (pbkey) > 1:
                print ("Invalid number of PublicKey tags in SignedImage, Firmware {0}".format (xml["version_id"]))
                return None, None

            image["pbkey"] = pbkey[0].text.strip()

            sig = img.findall (XML_SIG_TAG)

            if not sig or len (sig) > 1:
               print ("Invalid number of Signature tags in SignedImage, Firmware {0}".format (xml["version_id"]))
               return None, None

            image["signature"] = binascii.a2b_hex(re.sub("\s", "", sig[0].text.strip()))

        for region in img.findall (XML_REGION_TAG):
            processed_region = process_region (region, xml["version_id"])

            if processed_region is None:
                return None, None

            image["regions"].append (processed_region)

        if not image["regions"]:
            print ("No regions found for SignedImage, Firmware: {0}".format (xml["version_id"]))
            return None, None

        prop = img.findall (XML_VALIDATE_TAG)

        if not prop or len (prop) > 1:
            print ("Invalid number of ValidateOnBoot tags in SignedImage, Firmware {0}".format (xml["version_id"]))
            return None, None

        image["validate"] = prop[0].text.strip()

        xml["signed_imgs"].append (image)

    if not xml["signed_imgs"]:
        print ("No signed images found for Firmware: {0}".format (xml["version_id"]))
        return None, None

    return xml, pfm_version

def process_cfm (root):
    """
    Process CFM XML and generate list of element and attribute values.

    :param root: XML to utilize

    :return List of CFM values, manifest version
    """

    xml = {}
    xml["fw_list"] = []

    device_id = root.attrib.get(XML_ID_ATTRIB)

    if device_id is None:
        print ("No Device ID provided")
        return None, None

    xml["device_id"] = device_id.strip()

    for fw in root.findall (XML_FW_TAG):
        firmware = {}
        firmware["signed_imgs"] = []

        version = fw.attrib.get(XML_VERSION_ATTRIB)

        if version is None:
            print ("No Firmware version provided for Device: {0}".format (xml["device_id"]))
            return None, None

        firmware["version"] = version.strip()

        for img in fw.findall (XML_IMG_TAG):
            image = {}

            digest = img.findall (XML_DIGEST_TAG)

            if not digest or len (digest) > 1:
                print ("Invalid number of Digest tags in Device: {0}, Firmware: {1}".format (xml["device_id"], firmware["version"]))
                return None, None

            image["digest"] = binascii.a2b_hex(re.sub("\s", "", digest[0].text.strip()))

            action = img.findall (XML_FAILURE_ACTION_TAG)

            if not action or len (action) > 1:
                print ("Invalid number of FailureAction tags in Device: {0}, Firmware: {1}".format (xml["device_id"], firmware["version"]))
                return None, None

            image["failure_action"] = action[0].text.strip()

            firmware["signed_imgs"].append (image)

        if not firmware["signed_imgs"]:
            print ("No signed images found for Device: {0}, Firmware: {1}".format (xml["device_id"], firmware["version"]))
            return None, None

        xml["fw_list"].append (firmware)

    if not xml["fw_list"]:
        print ("No firmware found for Device: {0}".format (xml["device_id"]))
        return None, None

    return xml, manifest_types.VERSION_1

def process_pcd (root):
    """
    Process PCD XML and generate list of element and attribute values.

    :param root: XML to utilize

    :return List of PCD values, manifest version
    """

    xml = {}

    result = xml_extract_attrib (root, XML_SKU_ATTRIB, True)
    if result is None:
        return None, None

    xml.update ({"platform_id":result})

    result = xml_extract_attrib (root, XML_VERSION_ATTRIB, False)
    if result is None:
        return None, None

    xml.update ({"version":int (result, 16)})

    rot = xml_find_single_tag (root, XML_ROT_TAG)
    if rot is None:
        return None, None

    xml["rot"] = {}

    result = xml_extract_attrib (rot, XML_TYPE_ATTRIB, True)
    if result is None:
        return None, None
    if result == PCD_ROT_TYPE_PA_ROT:
        result = 0
    elif result == PCD_ROT_TYPE_AC_ROT:
        result = 1
    else:
        print ("Unknown RoT type: {0}".format (result))

    xml["rot"].update ({"type":result})

    ports = xml_find_single_tag (rot, XML_PORTS_TAG, False)
    if ports != None:
        xml["rot"]["ports"] = {}

        for port in ports.findall (XML_PORT_TAG):
            port_id = xml_extract_attrib (port, XML_ID_ATTRIB, False)
            if port_id is None:
                return None, None

            xml["rot"]["ports"][port_id] = {}

            result = xml_extract_single_value (port, {"spi_freq": XML_SPIFREQ_TAG, 
                "flash_mode": XML_FLASHMODE_TAG, "reset_ctrl": XML_RESETCTRL_TAG, 
                "policy": XML_POLICY_TAG, "pulse_interval": XML_PULSEINTERVAL_TAG, 
                "runtime_verification": XML_RUNTIMEVERIFICATION_TAG, 
                "watchdog_monitoring": XML_WATCHDOGMONITORING_TAG})
            if result is None:
                return None, None

            if result["flash_mode"] == PCD_FLASH_MODE_DUAL:
                result["flash_mode"] = 0
            elif result["flash_mode"] == PCD_FLASH_MODE_SINGLE:
                result["flash_mode"] = 1
            elif result["flash_mode"] == PCD_FLASH_MODE_DUAL_FILTERED_BYPASS:
                result["flash_mode"] = 2
            elif result["flash_mode"] == PCD_FLASH_MODE_SINGLE_FILTERED_BYPASS:
                result["flash_mode"] = 3
            else: 
                print ("Unknown port {0} flash mode: {1}".format (port_id, result["flash_mode"]))

            if result["reset_ctrl"] == PCD_RESET_CTRL_NOTIFY:
                result["reset_ctrl"] = 0
            elif result["reset_ctrl"] == PCD_RESET_CTRL_RESET:
                result["reset_ctrl"] = 1
            elif result["reset_ctrl"] == PCD_RESET_CTRL_PULSE:
                result["reset_ctrl"] = 2
            else: 
                print ("Unknown port {0} reset control: {1}".format (port_id, result["reset_ctrl"]))

            if result["policy"] == PCD_POLICY_PASSIVE:
                result["policy"] = 0
            elif result["policy"] == PCD_POLICY_ACTIVE:
                result["policy"] = 1
            else: 
                print ("Unknown port {0} policy: {1}".format (port_id, result["policy"]))

            if result["runtime_verification"] == PCD_DISABLED:
                result["runtime_verification"] = 0
            elif result["runtime_verification"] == PCD_ENABLED:
                result["runtime_verification"] = 1
            else: 
                print ("Unknown port {0} runtime verification setting: {1}".format (port_id, 
                    result["runtime_verification"]))

            if result["watchdog_monitoring"] == PCD_DISABLED:
                result["watchdog_monitoring"] = 0
            elif result["watchdog_monitoring"] == PCD_ENABLED:
                result["watchdog_monitoring"] = 1
            else: 
                print ("Unknown port {0} watchdog monitoring setting: {1}".format (port_id, 
                    result["watchdog_monitoring"]))

            xml["rot"]["ports"].update ({port_id:result})

    interface = xml_find_single_tag (rot, XML_INTERFACE_TAG)
    if interface is None:
        return None, None

    xml["rot"]["interface"] = {}

    interface_type = xml_extract_attrib (interface, XML_TYPE_ATTRIB, True)
    if interface_type is None:
        return None, None
    if interface_type == PCD_INTERFACE_TYPE_I2C:
        interface_type = 0
    else:
        print ("Unknown RoT interface type: {0}".format (interface_type))

    xml["rot"]["interface"].update ({"type":interface_type})

    result = xml_extract_single_value (interface, {"address": XML_ADDRESS_TAG, 
        "rot_eid": XML_ROT_EID_TAG, "bridge_eid": XML_BRIDGE_EID_TAG, 
        "bridge_address": XML_BRIDGE_ADDRESS_TAG})
    if result is None:
        return None, None

    result["address"] = int (result["address"], 16)
    result["rot_eid"] = int (result["rot_eid"], 16)
    result["bridge_eid"] = int (result["bridge_eid"], 16)
    result["bridge_address"] = int (result["bridge_address"], 16)

    xml["rot"]["interface"].update (result)

    power_controller = xml_find_single_tag (root, XML_POWER_CONTROLLER_TAG, False)
    if power_controller != None:
        xml["power_controller"] = {}

        interface = xml_find_single_tag (power_controller, XML_INTERFACE_TAG)
        if interface is None:
            return None, None

        xml["power_controller"]["interface"] = {}

        interface_type = xml_extract_attrib (interface, XML_TYPE_ATTRIB, True)
        if interface_type is None:
            return None, None
        if interface_type == PCD_INTERFACE_TYPE_I2C:
            interface_type = 0
        else:
            print ("Unknown PowerController interface type: {0}".format (interface_type))

        xml["power_controller"]["interface"].update ({"type":interface_type})

        result = xml_extract_single_value (interface, {"bus": XML_BUS_TAG, 
            "eid": XML_EID_TAG, "address": XML_ADDRESS_TAG, "i2c_mode": XML_I2CMODE_TAG})
        if result is None:
            return None, None

        result["eid"] = int (result["eid"], 16)
        result["address"] = int (result["address"], 16)

        if result["i2c_mode"] is None:
            return None, None
        if result["i2c_mode"] == PCD_INTERFACE_I2C_MODE_MM:
            result["i2c_mode"] = 0
        elif result["i2c_mode"] == PCD_INTERFACE_I2C_MODE_MS:
            result["i2c_mode"] = 1
        else:
            print ("Unknown PowerController interface I2C mode: {0}".format (result["i2c_mode"]))

        xml["power_controller"]["interface"].update (result)

        muxes = xml_find_single_tag (interface, XML_MUXES_TAG, False)
        if muxes != None:
            xml["power_controller"]["interface"]["muxes"] = {}

            for mux in muxes.findall (XML_MUX_TAG):
                level = xml_extract_attrib (mux, XML_LEVEL_ATTRIB, False)
                if level is None:
                    return None, None

                result = xml_extract_single_value (mux, {"address": XML_ADDRESS_TAG, 
                    "channel": XML_CHANNEL_TAG})
                if result is None:
                    return None, None

                result["address"] = int (result["address"], 16)

                xml["power_controller"]["interface"]["muxes"].update ({level:result})

    components = xml_find_single_tag (root, XML_COMPONENTS_TAG, False)
    if components != None:
        xml["components"] = []

        for component in components.findall (XML_COMPONENT_TAG):
            curr_component = {}

            result = xml_extract_attrib (component, XML_TYPE_ATTRIB, True)
            if result is None:
                return None, None

            curr_component.update ({"type":result})

            cnxn_type = xml_extract_attrib (component, XML_CONNECTION_ATTRIB, True)
            if cnxn_type is None:
                return None, None
            if cnxn_type == PCD_COMPONENT_CONNECTION_DIRECT:
                curr_component.update ({"connection":PCD_COMPONENT_CONNECTION_DIRECT})

                interface = xml_find_single_tag (component, XML_INTERFACE_TAG)
                if interface is None:
                    return None, None

                curr_component["interface"] = {}

                interface_type = xml_extract_attrib (interface, XML_TYPE_ATTRIB, True)
                if interface_type is None:
                    return None, None
                if interface_type == PCD_INTERFACE_TYPE_I2C:
                    interface_type = 0
                else:
                    print ("Unknown component {0} interface type: {1}".format (
                        curr_component["type"], interface_type))

                curr_component["interface"].update ({"type":interface_type})

                result = xml_extract_single_value (interface, {"bus": XML_BUS_TAG, 
                    "eid": XML_EID_TAG, "address": XML_ADDRESS_TAG, "i2c_mode": XML_I2CMODE_TAG})
                if result is None:
                    return None, None

                result["eid"] = int (result["eid"], 16)
                result["address"] = int (result["address"], 16)

                if result["i2c_mode"] is None:
                    return None, None
                if result["i2c_mode"] == PCD_INTERFACE_I2C_MODE_MM:
                    result["i2c_mode"] = 0
                elif result["i2c_mode"] == PCD_INTERFACE_I2C_MODE_MS:
                    result["i2c_mode"] = 1
                else:
                    print ("Unknown component {0} interface I2C mode: {1}".format (
                        curr_component["type"], result["i2c_mode"]))

                curr_component["interface"].update (result)

                muxes = xml_find_single_tag (interface, XML_MUXES_TAG, False)
                if muxes != None:
                    curr_component["interface"]["muxes"] = {}

                    for mux in muxes.findall (XML_MUX_TAG):
                        level = xml_extract_attrib (mux, XML_LEVEL_ATTRIB, False)
                        if level is None:
                            return None, None

                        result = xml_extract_single_value (mux, {"address": XML_ADDRESS_TAG, 
                            "channel": XML_CHANNEL_TAG})
                        if result is None:
                            return None, None

                        result["address"] = int (result["address"], 16)

                        curr_component["interface"]["muxes"].update ({level:result})
                        
            elif cnxn_type == PCD_COMPONENT_CONNECTION_MCTP_BRIDGE:
                curr_component.update ({"connection":PCD_COMPONENT_CONNECTION_MCTP_BRIDGE})

                count = xml_extract_attrib (component, XML_COUNT_ATTRIB, False)
                if count is None:
                    return None, None

                curr_component.update ({"count": int (count)})

                result = xml_extract_single_value (component, {"eid": XML_EID_TAG, 
                    "deviceid": XML_DEVICE_ID_TAG, "vendorid": XML_VENDOR_ID_TAG, 
                    "subdeviceid": XML_SUB_DEVICE_ID_TAG, "subvendorid": XML_SUB_VENDOR_ID_TAG})
                if result is None:
                    return None, None

                result["eid"] = int (result["eid"], 16)
                result["deviceid"] = int (result["deviceid"], 16)
                result["vendorid"] = int (result["vendorid"], 16)
                result["subdeviceid"] = int (result["subdeviceid"], 16)
                result["subvendorid"] = int (result["subvendorid"], 16)

                curr_component.update (result)
            else:
                print ("Unknown component {0} connection type: {1}".format (curr_component["type"], 
                    cnxn_type))

            result = xml_extract_single_value (component, {"policy": XML_POLICY_TAG})
            if result is None:
                return None, None
            if result["policy"] == PCD_POLICY_PASSIVE:
                result["policy"] = 0
            elif result["policy"] == PCD_POLICY_ACTIVE:
                result["policy"] = 1
            else: 
                print ("Unknown component {0} policy: {1}".format (curr_component["type"], 
                    result["policy"]))

            curr_component.update (result)

            powerctrl = xml_find_single_tag (component, XML_PWRCTRL_TAG)
            if powerctrl is None:
                return None, None

            curr_component["powerctrl"] = {}

            result = xml_extract_single_value (powerctrl, {"register": XML_REGISTER_TAG, 
                "mask": XML_MASK_TAG})
            if result is None:
                return None, None

            result["register"] = int (result["register"], 16)
            result["mask"] = int (result["mask"], 16)

            curr_component["powerctrl"].update (result)

            xml["components"].append (curr_component)

    return xml, manifest_types.VERSION_2

def load_and_process_xml (xml_file, xml_type):
    """
    Process XML and generate list of element and attribute values.

    :param xml_file: XML to utilize
    :param xml_type: Type of manifest

    :return List of manifest values, manifest version
    """

    root = et.parse (xml_file).getroot ()

    if xml_type is manifest_types.PFM:
        return process_pfm (root)
    elif xml_type is manifest_types.CFM:
        return process_cfm (root)
    elif xml_type is manifest_types.PCD:
        return process_pcd (root)
    else:
        raise ValueError ("Unknown XML type: {0}".format (xml_type))

def get_manifest_format (xml_file):
    root = et.parse(xml_file).getroot()
    fw_type = xml_extract_attrib (root, XML_FW_TYPE_ATTRIB, True, False)
    return manifest_types.VERSION_1 if fw_type is None else manifest_types.VERSION_2

def get_manifest_version (xml_file):
    root = et.parse(xml_file).getroot()
    return xml_extract_attrib (root, XML_VERSION_ATTRIB, True, False)

def get_manifest_type (xml_file):
    root = et.parse(xml_file).getroot()
    return xml_extract_attrib (root, XML_FW_TYPE_ATTRIB, True, False)
