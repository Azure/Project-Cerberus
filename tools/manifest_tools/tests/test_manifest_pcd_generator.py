"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

"""
PCD generator/parsing tests.

These tests validate the end-to-end PCD flow by invoking `pcd_generator.main()` directly:
1) Build a temporary generator config via `helpers.utils.create_temp_config`.
2) Generate a signed PCD binary into `tmp_path`.
3) Parse the generated blob and validate header/hashes/signature.
4) Convert the manifest to a Python tree and compare against the expected structure.

Required input files are checked into this repository:
  - XML inputs:
      * tools/testing/test_xml/pcd_sku_specific.xml
      * tools/testing/test_xml/pcd_empty.xml
  - Component map:
      * tools/manifest_tools/component_map.json
  - Signing key (test/dev key):
      * core/testing/keys/rsapriv.pem

How to run (from repo root):
  - Run this test module:
      pytest tools/manifest_tools/tests/test_manifest_pcd_generator.py
  - Run all manifest_tools tests:
      pytest tools/manifest_tools
  - Run a single test:
      pytest tools/manifest_tools/tests/test_manifest_pcd_generator.py::test_pcd_sku_specific_valid
"""

from pathlib import Path
import pytest
import sys

from helpers.manifest_blob_parse import load_manifest_blob, manifest_to_tree
from helpers.manifest_blob_assert import (
    assert_header, assert_hashes_valid, assert_signature_valid
)
from helpers.utils import create_temp_config
from helpers.utils import xsd_unexpected_child_regex

sys.path.append(str(Path(__file__).resolve().parent.parent))

from manifest_common import PCD_MAGIC_NUM
from pcd_generator import main as pcd_gen

CERBERUS_DIR = Path(__file__).resolve().parent.parent.parent.parent
PCD_XML_DIR = CERBERUS_DIR / "tools/testing/test_xml"
COMPONENT_JSON = Path(__file__).resolve().parent.parent / "component_map.json"
TEST_KEY = CERBERUS_DIR / "core/testing/keys" / "rsapriv.pem"

global_config_template = [
    "KeyType=RSA",
    "HashType=SHA256",
    "ComponentMap=" + str(COMPONENT_JSON)
]

def test_pcd_sku_specific_valid(tmp_path):
    xml_file = PCD_XML_DIR / "pcd_sku_specific.xml"
    output_file = tmp_path / "output_pcd.bin"
    config_file = create_temp_config(tmp_path, [str(xml_file)], str(output_file), str(TEST_KEY), global_config_template)
    pcd_gen([config_file])
    assert output_file.exists()
    m = load_manifest_blob(output_file)
    assert_header(m, magic=PCD_MAGIC_NUM)
    assert_hashes_valid(m)
    assert_signature_valid(m, str(TEST_KEY))
    manifest_tree = manifest_to_tree(m)
    valid_tree = {
        "platform_id": "SKU1-Specific",
        "rot": {
            "type": 0,
            "port_count": 2,
            "components_count": 2,
            "ports": {
                0: {
                    "spi_freq": 32000000,
                    "flash_mode": 0,
                    "reset_ctrl": 1,
                    "policy": 0,
                    "pulse_interval": 0,
                    "runtime_verification": 1,
                    "watchdog_monitoring": 1,
                    "host_reset_action": 1,
                },
                1: {
                    "spi_freq": 64000000,
                    "flash_mode": 1,
                    "reset_ctrl": 0,
                    "policy": 1,
                    "pulse_interval": 10,
                    "runtime_verification": 0,
                    "watchdog_monitoring": 0,
                    "host_reset_action": 0,
                },
            },
            "timeouts": {
                "attestation_success_retry": 86400000,
                "attestation_fail_retry": 10000,
                "discovery_fail_retry": 10000,
                "mctp_ctrl_timeout": 2000,
                "mctp_bridge_get_table_wait": 3000,
                "mctp_bridge_additional_timeout": 0,
                "attestation_rsp_not_ready_max_duration": 1000,
                "attestation_rsp_not_ready_max_retry": 3
            },
            "interface": {
                "type": "I2C",
                "address": 65,
                "rot_eid": 11,
                "bridge_eid": 10,
                "bridge_address": 16,
            },
        },
        "power_controller": {
            "interface": {
                "type": "I2C",
                "bus": 2,
                "eid": 20,
                "address": 34,
                "i2c_mode": 0,
                "muxes": {
                    2: {"address": 69, "channel": 4},
                    1: {"address": 102, "channel": 7},
                },
            },
        },
        "components": [
            {
                "component_id": 0,
                "connection": "Direct",
                "interface": {
                    "type": "I2C",
                    "bus": 3,
                    "eid": 119,
                    "address": 117,
                    "i2c_mode": 0,
                    "muxes": {0: {"address": 85, "channel": 3}},
                },
                "policy": 0,
                "powerctrl": {"register": 80, "mask": 224},
            },
            {
                "component_id": 1,
                "connection": "MCTPBridge",
                "count": 2,
                "eid": 48,
                "deviceid": 10,
                "vendorid": 11,
                "subdeviceid": 12,
                "subvendorid": 13,
                "policy": 0,
                "powerctrl": {"register": 112, "mask": 240},
            },
        ],
    }
    assert manifest_tree == valid_tree, "Manifest structure does not match"

def test_pcd_empty_valid(tmp_path):
    xml_file = PCD_XML_DIR / "pcd_empty.xml"
    output_file = tmp_path / "output_pcd.bin"
    config_file = create_temp_config(tmp_path, [str(xml_file)], str(output_file), str(TEST_KEY), global_config_template)
    pcd_gen([config_file])
    assert output_file.exists()
    m = load_manifest_blob(output_file)
    assert_header(m, magic=PCD_MAGIC_NUM)
    assert_hashes_valid(m)
    assert_signature_valid(m, str(TEST_KEY))
    manifest_tree = manifest_to_tree(m)
    valid_tree = {'platform_id': 'SKU1'}
    assert manifest_tree == valid_tree, "Manifest structure does not match"

# List of malformed XML test cases: (case_name, xml_content, expected_error_match)
malformed_cases = [
    (
        "malformed_rot_not_valid",
        """<PCD sku="SKU1" version="0x20">
               <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
                   <Ethernet/>
               </RoT>
           </PCD>""",
        xsd_unexpected_child_regex(unexpected_tag="Ethernet", expected_tag="Interface", path="/PCD/RoT")
    ),
    (
        "malformed_ports_not_valid",
        """<PCD sku="SKU1" version="0x20">
               <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
                   <Ports>
                       <Ethernet/>
                   </Ports>
               </RoT>
           </PCD>""",
        xsd_unexpected_child_regex(unexpected_tag="Ethernet", expected_tag="Port", path="/PCD/RoT/Ports")
    ),
    (
        "malformed_powercontroller_not_valid",
        """<PCD sku="SKU1" version="0x20">
               <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
                   <Interface type="I2C">
                       <Address>0x41</Address>
                       <RoTEID>0x0b</RoTEID>
                       <BridgeEID>0x0a</BridgeEID>
                       <BridgeAddress>0x10</BridgeAddress>
                   </Interface>
               </RoT>
               <PowerController>
                   <Port/>
               </PowerController>
           </PCD>""",
        xsd_unexpected_child_regex(unexpected_tag="Port", expected_tag="Interface", path="/PCD/PowerController")
    ),
    (
        "malformed_components_not_valid",
        """<PCD sku="SKU1" version="0x20">
               <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
                   <Interface type="I2C">
                       <Address>0x41</Address>
                       <RoTEID>0x0b</RoTEID>
                       <BridgeEID>0x0a</BridgeEID>
                       <BridgeAddress>0x10</BridgeAddress>
                   </Interface>
               </RoT>
               <Components>
                   <Port/>
               </Components>
           </PCD>""",
        xsd_unexpected_child_regex(unexpected_tag="Port", expected_tag=None, path="/PCD/Components")
    )
]

@pytest.mark.parametrize("case_name, xml_content, expected_error_match", malformed_cases)
def test_pcd_malformed_cases(tmp_path, case_name, xml_content, expected_error_match):
    """
    Parametrised test for malformed PCD XML cases.
    Each test writes XML content to a temp file and expects ValueError.
    """
    xml_file = tmp_path / f"{case_name}.xml"
    xml_file.write_text(xml_content)
    output_file = tmp_path / "output_pcd.bin"
    config_file = create_temp_config(tmp_path, [str(xml_file)], str(output_file), str(TEST_KEY), global_config_template)

    with pytest.raises(ValueError, match=expected_error_match):
        pcd_gen([config_file])
