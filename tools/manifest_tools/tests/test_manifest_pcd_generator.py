"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

"""
PCD generator/parsing tests.

Each test:
  1. Writes a small PCD XML to a temp file.
  2. Invokes ``pcd_generator.main()`` to produce a signed binary.
  3. Validates the manifest header, hashes and signature.
  4. Decodes the binary into a Python tree via ``manifest_to_tree`` and
     asserts on the *parsed* fields.

No test inspects raw manifest bytes - all decoding lives in
``helpers/manifest_blob_parse.py``.

How to run:
  pytest tools/manifest_tools/tests/test_manifest_pcd_generator.py
"""

import json
import shutil
from pathlib import Path

import pytest

from manifest_common import PCD_MAGIC_NUM, PCD_V3_MAGIC_NUM
from pcd_generator import main as pcd_gen

from conftest import COMPONENT_JSON, TEST_KEY, TEST_XML_DIR
from helpers.manifest_blob_parse import load_manifest_blob, manifest_to_tree
from helpers.manifest_blob_assert import (
    assert_header, assert_hashes_valid, assert_signature_valid,
)
from helpers.utils import create_temp_config, xsd_unexpected_child_regex


PCD_XML_DIR = TEST_XML_DIR

GLOBAL_CONFIG = [
    "KeyType=RSA",
    "HashType=SHA256",
    f"ComponentMap={COMPONENT_JSON}",
]


# ---------------------------------------------------------------------------
# Fixture / builder helpers
# ---------------------------------------------------------------------------
def _build(tmp_path, xml, name, config_overrides=None):
    """Run the generator on ``xml`` and return ``(manifest, tree)``."""
    xml_file = tmp_path / f"{name}.xml"
    xml_file.write_text(xml)
    out_file = tmp_path / f"{name}.bin"
    config_file = create_temp_config(
        tmp_path, [str(xml_file)], str(out_file), str(TEST_KEY),
        config_overrides if config_overrides is not None else GLOBAL_CONFIG,
    )
    pcd_gen([config_file])
    assert out_file.exists()
    m = load_manifest_blob(out_file)
    return m, manifest_to_tree(m)


def _build_from_fixture(tmp_path, fixture_xml, name, config_overrides=None):
    return _build(tmp_path, Path(fixture_xml).read_text(), name, config_overrides)


def _expect_value_error(tmp_path, xml, name, match):
    xml_file = tmp_path / f"{name}.xml"
    xml_file.write_text(xml)
    out_file = tmp_path / f"{name}.bin"
    config_file = create_temp_config(
        tmp_path, [str(xml_file)], str(out_file), str(TEST_KEY), GLOBAL_CONFIG,
    )
    with pytest.raises((ValueError, KeyError), match=match):
        pcd_gen([config_file])


def _components_by_kind(tree, kind):
    return [c for c in tree["components"] if c["kind"] == kind]


def _assert_signed_pcd(m, magic=PCD_MAGIC_NUM):
    assert_header(m, magic=magic)
    assert_hashes_valid(m)
    assert_signature_valid(m, str(TEST_KEY))


# ---------------------------------------------------------------------------
# Reusable XML snippets
# ---------------------------------------------------------------------------
ROT_I2C_INTERFACE = """\
        <Interface type="I2C">
            <Address>0x41</Address>
            <RoTEID>0x0b</RoTEID>
            <BridgeEID>0x0a</BridgeEID>
            <BridgeAddress>0x10</BridgeAddress>
        </Interface>"""

PORT_0 = """\
            <Port id="0">
                <SPIFreq>32000000</SPIFreq>
                <ResetCtrl>Reset</ResetCtrl>
                <FlashMode>Dual</FlashMode>
                <Policy>Passive</Policy>
                <RuntimeVerification>Enabled</RuntimeVerification>
                <WatchdogMonitoring>Enabled</WatchdogMonitoring>
                <HostResetAction>ResetFlash</HostResetAction>
                <PulseInterval>0</PulseInterval>
            </Port>"""

PORT_1 = """\
            <Port id="1">
                <SPIFreq>64000000</SPIFreq>
                <ResetCtrl>Notify</ResetCtrl>
                <FlashMode>Single</FlashMode>
                <Policy>Active</Policy>
                <RuntimeVerification>Disabled</RuntimeVerification>
                <WatchdogMonitoring>Disabled</WatchdogMonitoring>
                <HostResetAction>None</HostResetAction>
                <PulseInterval>10</PulseInterval>
            </Port>"""

PORT_2 = """\
            <Port id="2">
                <SPIFreq>25000000</SPIFreq>
                <ResetCtrl>Reset</ResetCtrl>
                <FlashMode>Dual</FlashMode>
                <Policy>Passive</Policy>
                <RuntimeVerification>Enabled</RuntimeVerification>
                <WatchdogMonitoring>Enabled</WatchdogMonitoring>
                <HostResetAction>ResetFlash</HostResetAction>
                <PulseInterval>1</PulseInterval>
            </Port>"""


# ===========================================================================
# Fixture-based tests
# ===========================================================================
def test_pcd_sku_specific_valid(tmp_path):
    """``pcd_sku_specific.xml``: SKU1-Specific PCD with one Direct + one MCTPBridge."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_sku_specific.xml", "sku_specific"
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1-Specific"

    rot = tree["rot"]
    assert rot["port_count"] == 2
    assert rot["components_count"] == 2
    assert rot["timeouts"]["mctp_ctrl_timeout"] == 2000
    assert rot["timeouts"]["mctp_bridge_get_table_wait"] == 3000
    assert rot["timeouts"]["attestation_success_retry"] == 86400000
    assert rot["timeouts"]["attestation_fail_retry"] == 10000
    assert sorted(rot["ports"].keys()) == [0, 1]

    assert tree["power_controller"] is not None
    assert tree["power_controller"]["interface"]["type"] == "I2C"

    assert len(_components_by_kind(tree, "direct")) == 1
    assert len(_components_by_kind(tree, "mctp_bridge")) == 1


def test_pcd_empty_valid(tmp_path):
    """``pcd_empty.xml``: ``empty="true"`` skips RoT/PowerController/Components entirely."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_empty.xml", "empty"
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    assert tree["rot"] is None
    assert tree["power_controller"] is None
    assert tree["components"] == []


def test_pcd_sha384_hash_valid(tmp_path):
    """Generator must produce a valid signed PCD when ``HashType=SHA384`` is set."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_empty.xml", "sha384",
        config_overrides=[
            "KeyType=RSA",
            "HashType=SHA384",
            f"ComponentMap={COMPONENT_JSON}",
        ],
    )
    _assert_signed_pcd(m)
    assert tree["platform_id"] == "SKU1"


# ---------------------------------------------------------------------------
# Additional fixture-based tests, one per checked-in PCD XML in
# ``tools/testing/test_xml/`` that successfully validates against pcd.xsd.
# ---------------------------------------------------------------------------
def test_pcd_fixture_no_components_valid(tmp_path):
    """``pcd_no_components.xml``: RoT + ports + PowerController, no Components."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_no_components.xml", "no_components",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert sorted(rot["ports"].keys()) == [0, 1]
    assert rot["components_count"] == 0
    assert tree["power_controller"] is not None
    assert tree["components"] == []


def test_pcd_fixture_no_ports_valid(tmp_path):
    """``pcd_no_ports.xml``: RoT without ``<Ports>``, but with components."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_no_ports.xml", "no_ports",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 0
    assert rot["ports"] == {}
    assert rot["components_count"] == 2
    assert tree["power_controller"] is not None
    assert len(_components_by_kind(tree, "direct")) == 1
    assert len(_components_by_kind(tree, "mctp_bridge")) == 1


def test_pcd_fixture_no_ports_power_controller_components_valid(tmp_path):
    """``pcd_no_ports_power_controller_components.xml``: bare RoT only."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_no_ports_power_controller_components.xml",
        "no_ports_pc_components",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 0
    assert rot["components_count"] == 0
    assert rot["ports"] == {}
    assert tree["power_controller"] is None
    assert tree["components"] == []


def test_pcd_fixture_no_power_controller_valid(tmp_path):
    """``pcd_no_power_controller.xml``: RoT + ports + components, no PowerController."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_no_power_controller.xml", "no_power_controller",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert sorted(rot["ports"].keys()) == [0, 1]
    assert rot["components_count"] == 2
    assert tree["power_controller"] is None
    assert len(_components_by_kind(tree, "direct")) == 1
    assert len(_components_by_kind(tree, "mctp_bridge")) == 1


def test_pcd_fixture_only_direct_components_valid(tmp_path):
    """``pcd_only_direct_components.xml``: two Direct components, no others."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_only_direct_components.xml", "only_direct",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert rot["components_count"] == 2
    assert tree["power_controller"] is not None

    direct = _components_by_kind(tree, "direct")
    assert len(direct) == 2
    assert _components_by_kind(tree, "mctp_bridge") == []
    assert _components_by_kind(tree, "tcg_log") == []


def test_pcd_fixture_v3_valid(tmp_path):
    """``pcd_v3.xml``: full v3 PCD (Direct + MCTPBridge + TCGLog) -> v3 magic."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_v3.xml", "v3_full",
    )
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert sorted(rot["ports"].keys()) == [0, 1]
    assert rot["components_count"] == 4
    assert tree["power_controller"] is not None

    assert len(_components_by_kind(tree, "direct")) == 1
    assert len(_components_by_kind(tree, "mctp_bridge")) == 2
    assert len(_components_by_kind(tree, "tcg_log")) == 1
    # All components must be encoded in v3 format.
    assert all(c["format"] == 3 for c in tree["components"])


def test_pcd_fixture_extended_component_elements_valid(tmp_path):
    """
    ``pcd_extended_component_elements.xml``: 255 TCGLog components plus a
    PowerController. PCD components are capped at the schema's
    ``maxOccurs=255`` for ``<Component>``; adding the PowerController pushes
    the total entry count past the single-TOC limit of 255 entries and
    forces a v3 TOC extension.

    Most component types in the fixture aren't in the checked-in component
    map, so a temp copy is used to keep ``component_map.json`` untouched.
    """
    temp_map = tmp_path / "component_map_temp.json"
    shutil.copy(COMPONENT_JSON, temp_map)
    config = [
        "KeyType=RSA",
        "HashType=SHA256",
        f"ComponentMap={temp_map}",
    ]
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_extended_component_elements.xml",
        "extended_component_elements", config_overrides=config,
    )
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert rot["components_count"] == 255
    assert tree["power_controller"] is not None
    assert tree["power_controller"]["interface"]["address"] == 0x22

    tcg = _components_by_kind(tree, "tcg_log")
    assert len(tcg) == 255
    assert all(c["format"] == 3 for c in tcg)
    assert _components_by_kind(tree, "direct") == []
    assert _components_by_kind(tree, "mctp_bridge") == []

    # Total entry count exceeds the single-TOC limit of 255, so exactly one
    # TOC extension must be emitted.
    assert len(m.toc_extensions) == 1
    ext = m.toc_extensions[0]
    assert len(m.outer_entries) == 255
    marker_entries = [e for e in m.outer_entries if e.type_id == 0x01]
    assert len(marker_entries) == 1
    marker = marker_entries[0]
    assert marker.parent == 0xFF
    assert marker.offset == ext.toc_offset
    assert marker.length == ext.toc_length
    # Outer TOC carries 254 element entries + 1 extension marker, all of
    # which are present in the flattened ``m.entries``; the rest live in
    # the sub-TOC.
    assert ext.toc_header.entry_count == len(m.entries) - 255
    assert ext.toc_header.entry_count == len(ext.entries)
    assert ext.toc_header.entry_count == len(ext.hashes)


# ---------------------------------------------------------------------------
# Fixture-based tests: PCDs whose worst-case per-component timeouts are
# aggregated into the binary RoT element by the generator
# (smallest values from each ``<Component>`` per the Attestation Specification).
# ---------------------------------------------------------------------------
def test_pcd_fixture_filtered_bypass_pulse_reset_valid(tmp_path):
    """``pcd_filtered_bypass_pulse_reset.xml``: RoT, PowerController and one
    Direct + one MCTPBridge component on a v2 PCD."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_filtered_bypass_pulse_reset.xml",
        "filtered_bypass_pulse_reset",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert sorted(rot["ports"].keys()) == [0, 1]
    assert rot["components_count"] == 2
    assert rot["timeouts"]["mctp_ctrl_timeout"] == 40
    assert rot["timeouts"]["mctp_bridge_get_table_wait"] == 50
    assert tree["power_controller"] is not None
    assert len(_components_by_kind(tree, "direct")) == 1
    assert len(_components_by_kind(tree, "mctp_bridge")) == 1


def test_pcd_fixture_multiple_bridge_components_valid(tmp_path):
    """``pcd_multiple_bridge_components.xml``: one Direct and two MCTPBridge."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_multiple_bridge_components.xml",
        "multiple_bridge_components",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert rot["components_count"] == 3
    assert tree["power_controller"] is not None
    assert len(_components_by_kind(tree, "direct")) == 1
    assert len(_components_by_kind(tree, "mctp_bridge")) == 2


def test_pcd_fixture_multiple_direct_components_valid(tmp_path):
    """``pcd_multiple_direct_components.xml``: two Direct and one MCTPBridge."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_multiple_direct_components.xml",
        "multiple_direct_components",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert rot["components_count"] == 3
    assert tree["power_controller"] is not None
    direct = _components_by_kind(tree, "direct")
    assert len(direct) == 2
    assert sorted(c["interface"]["address"] for c in direct) == [0x75, 0x81]
    assert len(_components_by_kind(tree, "mctp_bridge")) == 1


def test_pcd_fixture_multiple_tcg_log_components_valid(tmp_path):
    """``pcd_multiple_tcg_log_components.xml``: v3 PCD with MCTPBridge + 2 TCGLog."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_multiple_tcg_log_components.xml",
        "multiple_tcg_log_components",
    )
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert rot["components_count"] == 3
    assert tree["power_controller"] is not None
    assert len(_components_by_kind(tree, "mctp_bridge")) == 1
    assert len(_components_by_kind(tree, "tcg_log")) == 2
    assert all(c["format"] == 3 for c in tree["components"])


def test_pcd_fixture_only_bridge_components_valid(tmp_path):
    """``pcd_only_bridge_components.xml``: two MCTPBridge components, nothing else."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_only_bridge_components.xml",
        "only_bridge_components",
    )
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 2
    assert rot["components_count"] == 2
    assert tree["power_controller"] is not None
    assert _components_by_kind(tree, "direct") == []
    assert len(_components_by_kind(tree, "mctp_bridge")) == 2
    assert _components_by_kind(tree, "tcg_log") == []


def test_pcd_fixture_only_tcg_log_components_valid(tmp_path):
    """``pcd_only_tcg_log_components.xml``: v3 PCD with two TCGLog components only."""
    m, tree = _build_from_fixture(
        tmp_path, PCD_XML_DIR / "pcd_only_tcg_log_components.xml",
        "only_tcg_log_components",
    )
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    assert tree["platform_id"] == "SKU1"
    rot = tree["rot"]
    assert rot is not None
    assert rot["port_count"] == 0
    assert rot["ports"] == {}
    assert rot["components_count"] == 2
    assert tree["power_controller"] is None
    assert _components_by_kind(tree, "direct") == []
    assert _components_by_kind(tree, "mctp_bridge") == []
    tcg = _components_by_kind(tree, "tcg_log")
    assert len(tcg) == 2
    assert all(c["format"] == 3 for c in tcg)

# ===========================================================================
# Malformed XML
# ===========================================================================
def test_pcd_malformed_rot_unexpected_child(tmp_path):
    """An unknown child element under ``<RoT>`` must be rejected by the schema."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ethernet/>
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "rot_unexpected_child",
        xsd_unexpected_child_regex(
            unexpected_tag="Ethernet", expected_tag="Interface", path="/PCD/RoT",
        ),
    )


def test_pcd_malformed_ports_unexpected_child(tmp_path):
    """An unknown child element under ``<Ports>`` must be rejected by the schema."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
            <Ethernet/>
        </Ports>
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "ports_unexpected_child",
        xsd_unexpected_child_regex(
            unexpected_tag="Ethernet", expected_tag="Port", path="/PCD/RoT/Ports",
        ),
    )


def test_pcd_malformed_power_controller_unexpected_child(tmp_path):
    """An unknown child element under ``<PowerController>`` must be rejected."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <PowerController>
        <Port/>
    </PowerController>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "power_controller_unexpected_child",
        xsd_unexpected_child_regex(
            unexpected_tag="Port", expected_tag="Interface", path="/PCD/PowerController",
        ),
    )


def test_pcd_malformed_components_unexpected_child(tmp_path):
    """An unknown child element under ``<Components>`` must be rejected."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Port/>
    </Components>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "components_unexpected_child",
        xsd_unexpected_child_regex(
            unexpected_tag="Port", expected_tag=None, path="/PCD/Components",
        ),
    )


# ===========================================================================
# Schema-rejected XML — invalid attribute values, wrong enums, wrong types.
# ===========================================================================
def test_pcd_schema_missing_sku_attribute(tmp_path):
    """``<PCD>`` is missing the required ``sku`` attribute."""
    xml = f"""<PCD version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(tmp_path, xml, "missing_sku", r"(?s).*sku.*")


def test_pcd_schema_missing_version_attribute(tmp_path):
    """``<PCD>`` is missing the required ``version`` attribute."""
    xml = f"""<PCD sku="SKU1">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(tmp_path, xml, "missing_version", r"(?s).*version.*")


def test_pcd_schema_invalid_rot_type(tmp_path):
    """``RoT@type`` must be ``PA-RoT`` or ``AC-RoT`` per ``RoTType`` enum."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="XX-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "invalid_rot_type",
        r"(?s).*(RoTType|enumeration).*",
    )


def test_pcd_schema_invalid_format_version_above_max(tmp_path):
    """``format_version`` above ``PCDVersion`` maxInclusive (3) must be rejected."""
    xml = f"""<PCD sku="SKU1" version="0x20" format_version="5">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "format_version_above_max",
        r"(?s).*(PCDVersion|maxInclusive|format_version).*",
    )


def test_pcd_schema_invalid_flash_mode_enum(tmp_path):
    """A ``<FlashMode>`` value outside ``FlashModeType`` enum must be rejected."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
            <Port id="0">
                <SPIFreq>32000000</SPIFreq>
                <ResetCtrl>Reset</ResetCtrl>
                <FlashMode>Sextuple</FlashMode>
                <Policy>Passive</Policy>
                <RuntimeVerification>Enabled</RuntimeVerification>
                <WatchdogMonitoring>Enabled</WatchdogMonitoring>
                <HostResetAction>ResetFlash</HostResetAction>
                <PulseInterval>0</PulseInterval>
            </Port>
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "invalid_flash_mode",
        r"(?s).*(FlashModeType|enumeration|Sextuple).*",
    )


def test_pcd_schema_port_id_out_of_range_above_max(tmp_path):
    """``Port@id`` of 999 violates ``PortId`` maxExclusive (255)."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
            <Port id="999">
                <SPIFreq>32000000</SPIFreq>
                <ResetCtrl>Reset</ResetCtrl>
                <FlashMode>Dual</FlashMode>
                <Policy>Passive</Policy>
                <RuntimeVerification>Enabled</RuntimeVerification>
                <WatchdogMonitoring>Enabled</WatchdogMonitoring>
                <HostResetAction>ResetFlash</HostResetAction>
                <PulseInterval>0</PulseInterval>
            </Port>
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "port_id_above_max",
        r"(?s).*(PortId|maxExclusive|999|lesser).*",
    )


def test_pcd_schema_negative_spi_freq(tmp_path):
    """``<SPIFreq>`` is xs:unsignedInt; a negative value must be rejected."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
            <Port id="0">
                <SPIFreq>-1</SPIFreq>
                <ResetCtrl>Reset</ResetCtrl>
                <FlashMode>Dual</FlashMode>
                <Policy>Passive</Policy>
                <RuntimeVerification>Enabled</RuntimeVerification>
                <WatchdogMonitoring>Enabled</WatchdogMonitoring>
                <HostResetAction>ResetFlash</HostResetAction>
                <PulseInterval>0</PulseInterval>
            </Port>
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "negative_spi_freq",
        r"(?s).*(unsignedInt|SPIFreq|negative|-1|2\^32).*",
    )


def test_pcd_schema_invalid_component_connection(tmp_path):
    """``Component@connection`` value outside ``ConnectionType`` enum must be rejected."""
    xml = f"""<PCD sku="SKU1" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Alpha" connection="Carrier-Pigeon"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "invalid_component_connection",
        r"(?s).*(connection|Carrier-Pigeon|alternative|error).*",
    )


def test_pcd_schema_mctp_bridge_missing_count(tmp_path):
    """An MCTPBridge ``<Component>`` without the required ``count`` attribute is rejected."""
    xml = f"""<PCD sku="SKU1" version="0x20" format_version="3">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Gamma" connection="MCTPBridge"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            discovery_fail_retry="50"
            mctp_bridge_additional_timeout="0"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <DeviceID>0x0c</DeviceID>
            <VendorID>0x0d</VendorID>
            <SubsystemDeviceID>0x0e</SubsystemDeviceID>
            <SubsystemVendorID>0xaa</SubsystemVendorID>
            <EID>0x35</EID>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "mctp_bridge_missing_count",
        r"(?s).*(count|attribute).*",
    )


def test_pcd_schema_missing_rot_element(tmp_path):
    """A non-empty PCD without a ``<RoT>`` child must be rejected."""
    xml = """<PCD sku="SKU1" version="0x20">
</PCD>"""
    _expect_value_error(tmp_path, xml, "missing_rot", r"(?s).*RoT.*")


def test_pcd_schema_non_hex_version(tmp_path):
    """``PCD@version`` must match the ``HexInteger`` pattern."""
    xml = f"""<PCD sku="SKU1" version="not-hex">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "non_hex_version",
        r"(?s).*(HexInteger|version|hex|pattern).*",
    )


# ===========================================================================
# Generator-level negatives (config / signing / IO failures)
# ===========================================================================
_VALID_MIN_PCD_XML = f"""\
<PCD sku="SKU-NEG" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>
"""


def test_pcd_missing_signing_key_file(tmp_path):
    """Generator must fail when the configured signing key file does not exist."""
    xml_file = tmp_path / "ok.xml"
    xml_file.write_text(_VALID_MIN_PCD_XML)
    out_file = tmp_path / "out.bin"
    bogus_key = tmp_path / "does_not_exist.pem"
    config_file = create_temp_config(
        tmp_path, [str(xml_file)], str(
            out_file), str(bogus_key), GLOBAL_CONFIG,
    )
    with pytest.raises((FileNotFoundError, OSError, ValueError)):
        pcd_gen([config_file])
    assert not out_file.exists()


def test_pcd_nonexistent_xml_file(tmp_path):
    """Generator must fail when the configured XML input file does not exist."""
    out_file = tmp_path / "out.bin"
    config_file = create_temp_config(
        tmp_path, [str(tmp_path / "missing.xml")], str(out_file),
        str(TEST_KEY), GLOBAL_CONFIG,
    )
    with pytest.raises((FileNotFoundError, OSError, ValueError)):
        pcd_gen([config_file])
    assert not out_file.exists()


def test_pcd_empty_attribute_skips_body(tmp_path):
    """``empty="true"`` causes the generator to ignore RoT/components."""
    xml = """\
<PCD sku="SKU-EMPTY" version="0x20" empty="true">
</PCD>
"""
    m, tree = _build(tmp_path, xml, "empty_attr")
    _assert_signed_pcd(m)
    assert tree["platform_id"] == "SKU-EMPTY"
    assert tree["rot"] is None
    assert tree["power_controller"] is None
    assert tree["components"] == []


# ===========================================================================
# Topology variations (v2)
# ===========================================================================
def test_pcd_no_ports_no_components(tmp_path):
    """Minimal PCD: only RoT (no ports, no PowerController, no Components)."""
    xml = f"""\
<PCD sku="SKU-NO-PORTS" version="0x2A">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2100" mctp_bridge_get_table_wait="3100">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "no_ports")
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU-NO-PORTS"
    rot = tree["rot"]
    assert rot["port_count"] == 0
    assert rot["components_count"] == 0
    assert rot["ports"] == {}
    assert rot["timeouts"]["mctp_ctrl_timeout"] == 2100
    assert rot["timeouts"]["mctp_bridge_get_table_wait"] == 3100
    assert tree["power_controller"] is None
    assert tree["components"] == []


def test_pcd_multiple_ports(tmp_path):
    """Three ports with distinct SPI frequencies are all preserved in the binary."""
    xml = f"""\
<PCD sku="SKU-3PORTS" version="0x2B">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
{PORT_0}
{PORT_1}
{PORT_2}
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "multiple_ports")
    _assert_signed_pcd(m)

    rot = tree["rot"]
    assert rot["port_count"] == 3
    assert sorted(rot["ports"].keys()) == [0, 1, 2]
    assert rot["ports"][0]["spi_freq"] == 32000000
    assert rot["ports"][1]["spi_freq"] == 64000000
    assert rot["ports"][2]["spi_freq"] == 25000000


def test_pcd_no_components_with_two_ports_and_power_controller(tmp_path):
    """PCD with ports and a muxed PowerController, but no ``<Components>``."""
    xml = f"""\
<PCD sku="SKU1" version="0x1A">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
{PORT_0}
{PORT_1}
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
    <PowerController>
        <Interface type="I2C">
            <Bus>2</Bus>
            <EID>0x14</EID>
            <Address>0x22</Address>
            <I2CMode>MultiMaster</I2CMode>
            <Muxes>
                <Mux level="2"><Address>0x45</Address><Channel>4</Channel></Mux>
                <Mux level="1"><Address>0x66</Address><Channel>7</Channel></Mux>
            </Muxes>
        </Interface>
    </PowerController>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "no_components")
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU1"
    assert tree["rot"]["components_count"] == 0
    assert tree["rot"]["port_count"] == 2
    assert tree["power_controller"]["interface"]["type"] == "I2C"
    assert tree["components"] == []


def test_pcd_no_power_controller_with_direct_component(tmp_path):
    """A single Direct component is emitted when no ``<PowerController>`` is provided."""
    xml = f"""\
<PCD sku="SKU-NO-PWR" version="0x2C">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Alpha" connection="Direct"
            attestation_success_retry="86400000"
            attestation_fail_retry="10000"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="1000">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl>
                <Register>0x50</Register>
                <Mask>0xe0</Mask>
            </PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "no_power_controller")
    _assert_signed_pcd(m)

    assert tree["platform_id"] == "SKU-NO-PWR"
    assert tree["rot"]["components_count"] == 1
    assert tree["power_controller"] is None
    direct = _components_by_kind(tree, "direct")
    assert len(direct) == 1
    assert direct[0]["interface"]["address"] == 0x75
    assert direct[0]["interface"]["eid"] == 0x77


def test_pcd_power_controller_without_components(tmp_path):
    """PowerController-only PCD: no ports, no Components, but a valid PC interface."""
    xml = f"""\
<PCD sku="SKU-PWR-ONLY" version="0x2D">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <PowerController>
        <Interface type="I2C">
            <Bus>2</Bus>
            <EID>0x14</EID>
            <Address>0x22</Address>
            <I2CMode>MultiMaster</I2CMode>
        </Interface>
    </PowerController>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "power_only")
    _assert_signed_pcd(m)

    assert tree["rot"]["components_count"] == 0
    assert tree["rot"]["port_count"] == 0
    assert tree["power_controller"] is not None
    assert tree["power_controller"]["interface"]["address"] == 0x22
    assert tree["components"] == []


# ===========================================================================
# v3 features
# ===========================================================================
def test_pcd_v3_components_and_tcg_log(tmp_path):
    """v3 PCD with one of each component kind (Direct, MCTPBridge, TCGLog) plus sources."""
    xml = f"""\
<PCD sku="SKU-V3" version="0x22" format_version="3">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
{PORT_0}
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Alpha" connection="Direct" count="1"
            attestation_success_retry="86400000"
            attestation_fail_retry="10000"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="1000">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl>
                <Register>0x50</Register>
                <Mask>0xe0</Mask>
            </PwrCtrl>
        </Component>
        <Component type="Gamma" connection="MCTPBridge" count="2"
            attestation_success_retry="86400000"
            attestation_fail_retry="10000"
            discovery_fail_retry="10000"
            mctp_bridge_additional_timeout="11"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="1000">
            <Policy>Passive</Policy>
            <DeviceID>0x0c</DeviceID>
            <VendorID>0x0d</VendorID>
            <SubsystemDeviceID>0x0e</SubsystemDeviceID>
            <SubsystemVendorID>0xaa</SubsystemVendorID>
            <EID>0x35</EID>
            <ComponentTypes>
                <ComponentType type="Component1" />
                <ComponentType type="Component2" min="0" max="0" />
                <ComponentType type="Sigma" min="1" max="2" />
            </ComponentTypes>
            <PwrCtrl>
                <Register>0x70</Register>
                <Mask>0xF0</Mask>
            </PwrCtrl>
        </Component>
        <Component type="Theta" connection="TCGLog"
            attestation_success_retry="86400000"
            attestation_fail_retry="10000"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="1000">
            <Policy>Passive</Policy>
            <PwrCtrl>
                <Register>0x70</Register>
                <Mask>0xF0</Mask>
            </PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "v3_components")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    assert tree["platform_id"] == "SKU-V3"
    assert all(c["format"] == 3 for c in tree["components"])

    direct = _components_by_kind(tree, "direct")
    bridge = _components_by_kind(tree, "mctp_bridge")
    tcg = _components_by_kind(tree, "tcg_log")
    assert len(direct) == 1
    assert len(bridge) == 1
    assert len(tcg) == 1

    assert direct[0]["instances_count"] == 1
    assert direct[0]["sources"] == []

    assert bridge[0]["instances_count"] == 2
    assert bridge[0]["count"] == 2
    assert bridge[0]["deviceid"] == 0x0c
    assert bridge[0]["vendorid"] == 0x0d
    assert bridge[0]["subdeviceid"] == 0x0e
    assert bridge[0]["subvendorid"] == 0xaa
    assert bridge[0]["eid"] == 0x35
    assert len(bridge[0]["sources"]) == 3
    sigma = next(s for s in bridge[0]["sources"]
                 if s["min"] == 1 and s["max"] == 2)
    assert sigma is not None

    assert tcg[0]["instances_count"] == 1
    assert tcg[0]["sources"] == []
    assert tcg[0]["powerctrl"] == {"register": 0x70, "mask": 0xF0}


def test_pcd_v3_aggregates_component_timeouts_into_rot(tmp_path):
    """The RoT element aggregates worst-case timeouts from all components."""
    xml = f"""\
<PCD sku="SKU-TIMEOUTS" version="0x21" format_version="3">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
{PORT_0}
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Alpha" connection="Direct"
            attestation_success_retry="200"
            attestation_fail_retry="20"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="100">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>
        <Component type="Beta" connection="MCTPBridge" count="2"
            attestation_success_retry="300"
            attestation_fail_retry="10"
            discovery_fail_retry="5"
            mctp_bridge_additional_timeout="7"
            attestation_rsp_not_ready_max_retry="6"
            attestation_rsp_not_ready_max_duration="250">
            <Policy>Passive</Policy>
            <DeviceID>0x0a</DeviceID>
            <VendorID>0x0b</VendorID>
            <SubsystemDeviceID>0x0c</SubsystemDeviceID>
            <SubsystemVendorID>0x0d</SubsystemVendorID>
            <EID>0x30</EID>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
        <Component type="Theta" connection="TCGLog"
            attestation_success_retry="150"
            attestation_fail_retry="30"
            attestation_rsp_not_ready_max_retry="4"
            attestation_rsp_not_ready_max_duration="500">
            <Policy>Passive</Policy>
            <PwrCtrl><Register>0x60</Register><Mask>0x0f</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "timeout_aggregation")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    timeouts = tree["rot"]["timeouts"]
    assert tree["rot"]["components_count"] == 3
    # Min of attestation_success_retry across components -> chosen.
    assert timeouts["attestation_success_retry"] == 150
    assert timeouts["attestation_fail_retry"] == 10
    assert timeouts["discovery_fail_retry"] == 5
    assert timeouts["mctp_bridge_additional_timeout"] == 7
    assert timeouts["attestation_rsp_not_ready_max_duration"] == 500
    assert timeouts["attestation_rsp_not_ready_max_retry"] == 6


def test_pcd_v2_aggregates_component_timeouts_into_rot(tmp_path):
    """Same aggregation rules apply on a v2 PCD (Direct + MCTPBridge only)."""
    xml = f"""\
<PCD sku="SKU-TIMEOUTS-V2" version="0x21">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
{PORT_0}
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Alpha" connection="Direct"
            attestation_success_retry="500"
            attestation_fail_retry="40"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="100">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>
        <Component type="Beta" connection="MCTPBridge" count="1"
            attestation_success_retry="200"
            attestation_fail_retry="80"
            discovery_fail_retry="50"
            mctp_bridge_additional_timeout="33"
            attestation_rsp_not_ready_max_retry="9"
            attestation_rsp_not_ready_max_duration="400">
            <Policy>Passive</Policy>
            <DeviceID>0x0a</DeviceID>
            <VendorID>0x0b</VendorID>
            <SubsystemDeviceID>0x0c</SubsystemDeviceID>
            <SubsystemVendorID>0x0d</SubsystemVendorID>
            <EID>0x30</EID>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "timeout_aggregation_v2")
    _assert_signed_pcd(m)  # v2 magic

    timeouts = tree["rot"]["timeouts"]
    assert tree["rot"]["components_count"] == 2
    # MIN-wins fields
    assert timeouts["attestation_success_retry"] == 200      # min(500, 200)
    assert timeouts["attestation_fail_retry"] == 40          # min(40, 80)
    assert timeouts["discovery_fail_retry"] == 50            # only Bridge has it
    # MAX-wins fields
    assert timeouts["mctp_bridge_additional_timeout"] == 33  # only Bridge has it
    assert timeouts["attestation_rsp_not_ready_max_retry"] == 9     # max(2, 9)
    assert timeouts["attestation_rsp_not_ready_max_duration"] == 400  # max(100, 400)


def test_pcd_aggregates_min_max_across_multiple_mctp_bridges(tmp_path):
    """
    Two MCTPBridge components must produce:
      - ``discovery_fail_retry`` = MIN of the two values
      - ``mctp_bridge_additional_timeout`` = MAX of the two values
    """
    xml = f"""\
<PCD sku="SKU-2BRIDGES" version="0x22">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Beta" connection="MCTPBridge" count="1"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            discovery_fail_retry="800"
            mctp_bridge_additional_timeout="11"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <DeviceID>0x0a</DeviceID>
            <VendorID>0x0b</VendorID>
            <SubsystemDeviceID>0x0c</SubsystemDeviceID>
            <SubsystemVendorID>0x0d</SubsystemVendorID>
            <EID>0x30</EID>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
        <Component type="Theta" connection="MCTPBridge" count="1"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            discovery_fail_retry="50"
            mctp_bridge_additional_timeout="999"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <DeviceID>0x0d</DeviceID>
            <VendorID>0x0e</VendorID>
            <SubsystemDeviceID>0x0f</SubsystemDeviceID>
            <SubsystemVendorID>0x0a</SubsystemVendorID>
            <EID>0x35</EID>
            <PwrCtrl><Register>0x71</Register><Mask>0xF1</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "two_bridges_min_max")
    _assert_signed_pcd(m)

    timeouts = tree["rot"]["timeouts"]
    assert tree["rot"]["components_count"] == 2
    assert timeouts["discovery_fail_retry"] == 50            # MIN(800, 50)
    assert timeouts["mctp_bridge_additional_timeout"] == 999  # MAX(11, 999)


def test_pcd_single_component_timeouts_pass_through_to_rot(tmp_path):
    """
    With a single component, the aggregated RoT timeouts must equal the
    component's own timeouts (degenerate min/max).
    """
    xml = f"""\
<PCD sku="SKU-SINGLE" version="0x23">
    <RoT type="PA-RoT" mctp_ctrl_timeout="500" mctp_bridge_get_table_wait="600">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Beta" connection="MCTPBridge" count="1"
            attestation_success_retry="12345"
            attestation_fail_retry="678"
            discovery_fail_retry="42"
            mctp_bridge_additional_timeout="77"
            attestation_rsp_not_ready_max_retry="9"
            attestation_rsp_not_ready_max_duration="333">
            <Policy>Passive</Policy>
            <DeviceID>0x0a</DeviceID>
            <VendorID>0x0b</VendorID>
            <SubsystemDeviceID>0x0c</SubsystemDeviceID>
            <SubsystemVendorID>0x0d</SubsystemVendorID>
            <EID>0x30</EID>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "single_component_timeouts")
    _assert_signed_pcd(m)

    timeouts = tree["rot"]["timeouts"]
    assert tree["rot"]["components_count"] == 1
    assert timeouts["mctp_ctrl_timeout"] == 500
    assert timeouts["mctp_bridge_get_table_wait"] == 600
    assert timeouts["attestation_success_retry"] == 12345
    assert timeouts["attestation_fail_retry"] == 678
    assert timeouts["discovery_fail_retry"] == 42
    assert timeouts["mctp_bridge_additional_timeout"] == 77
    assert timeouts["attestation_rsp_not_ready_max_retry"] == 9
    assert timeouts["attestation_rsp_not_ready_max_duration"] == 333


# ===========================================================================
# v3-only features rejected when format_version="2"
# ===========================================================================
def test_pcd_v2_rejects_component_types(tmp_path):
    """``<ComponentTypes>`` is a v3-only feature; using it with ``format_version="2"`` fails."""
    xml = f"""<PCD sku="SKU1" version="0x1A" format_version="2">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Gamma" connection="MCTPBridge" count="2"
            attestation_success_retry="86400000"
            attestation_fail_retry="10000"
            discovery_fail_retry="10000"
            mctp_bridge_additional_timeout="0"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="1000">
            <Policy>Passive</Policy>
            <DeviceID>0x0c</DeviceID>
            <VendorID>0x0d</VendorID>
            <SubsystemDeviceID>0x0e</SubsystemDeviceID>
            <SubsystemVendorID>0xaa</SubsystemVendorID>
            <EID>0x35</EID>
            <ComponentTypes>
                <ComponentType type="Component1" min="1" max="2" />
            </ComponentTypes>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "v2_component_types",
        r"(?s).*(ComponentTypes|format_version|assert).*",
    )


def test_pcd_v2_rejects_tcg_log_connection(tmp_path):
    """``connection="TCGLog"`` is a v3-only feature; using it with ``format_version="2"`` fails."""
    xml = f"""<PCD sku="SKU1" version="0x1A" format_version="2">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Theta" connection="TCGLog"
            attestation_success_retry="86400000"
            attestation_fail_retry="10000"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="1000">
            <Policy>Passive</Policy>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "v2_tcg_log",
        r"(?s).*(TCGLog|format_version|assert).*",
    )


def test_pcd_ac_rot_with_alternate_port_enums(tmp_path):
    """
    Exercises every non-default enum branch in process_pcd port parsing:
      RoT type   = AC-RoT             (rot_flags == 1)
      FlashMode  = SingleFilteredBypass (=> 3) and DualFilteredBypass (=> 2)
      ResetCtrl  = Pulse              (=> 2)
      Policy     = Active             (=> 1)
      RuntimeVerification / WatchdogMonitoring = Disabled (=> 0)
      HostResetAction = None          (=> 0)
    """
    xml = f"""\
<PCD sku="SKU-AC" version="0x30">
    <RoT type="AC-RoT" mctp_ctrl_timeout="1500" mctp_bridge_get_table_wait="2500">
        <Ports>
            <Port id="0">
                <SPIFreq>16000000</SPIFreq>
                <ResetCtrl>Pulse</ResetCtrl>
                <FlashMode>SingleFilteredBypass</FlashMode>
                <Policy>Active</Policy>
                <RuntimeVerification>Disabled</RuntimeVerification>
                <WatchdogMonitoring>Disabled</WatchdogMonitoring>
                <HostResetAction>None</HostResetAction>
                <PulseInterval>5</PulseInterval>
            </Port>
            <Port id="1">
                <SPIFreq>20000000</SPIFreq>
                <ResetCtrl>Notify</ResetCtrl>
                <FlashMode>DualFilteredBypass</FlashMode>
                <Policy>Passive</Policy>
                <RuntimeVerification>Enabled</RuntimeVerification>
                <WatchdogMonitoring>Enabled</WatchdogMonitoring>
                <HostResetAction>ResetFlash</HostResetAction>
                <PulseInterval>0</PulseInterval>
            </Port>
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "ac_rot_alt_enums")
    _assert_signed_pcd(m)

    rot = tree["rot"]
    assert rot["type"] == 1  # AC-RoT
    assert rot["port_count"] == 2

    p0 = rot["ports"][0]
    assert p0["flash_mode"] == 3            # SingleFilteredBypass
    assert p0["reset_ctrl"] == 2            # Pulse
    assert p0["policy"] == 1                # Active
    assert p0["runtime_verification"] == 0
    assert p0["watchdog_monitoring"] == 0
    assert p0["host_reset_action"] == 0
    assert p0["pulse_interval"] == 5

    p1 = rot["ports"][1]
    assert p1["flash_mode"] == 2            # DualFilteredBypass
    assert p1["reset_ctrl"] == 0            # Notify
    assert p1["policy"] == 0                # Passive
    assert p1["host_reset_action"] == 1     # ResetFlash


def test_pcd_master_slave_i2c_modes(tmp_path):
    """Exercise MasterSlave i2c_mode in PowerController and Direct component."""
    xml = f"""\
<PCD sku="SKU-MS" version="0x31">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <PowerController>
        <Interface type="I2C">
            <Bus>1</Bus>
            <EID>0x14</EID>
            <Address>0x22</Address>
            <I2CMode>MasterSlave</I2CMode>
        </Interface>
    </PowerController>
    <Components>
        <Component type="Alpha" connection="Direct"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="500">
            <Policy>Active</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MasterSlave</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl>
                <Register>0x50</Register>
                <Mask>0xe0</Mask>
            </PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "master_slave")
    _assert_signed_pcd(m)

    # MasterSlave
    assert tree["power_controller"]["interface"]["i2c_mode"] == 1
    direct = _components_by_kind(tree, "direct")
    assert len(direct) == 1
    assert direct[0]["interface"]["i2c_mode"] == 1
    assert direct[0]["policy"] == 1  # Active


def test_pcd_direct_component_with_muxes(tmp_path):
    """A direct component with I2C muxes: exercises generate_muxes_buf for components."""
    xml = f"""\
<PCD sku="SKU-MUXED-DIRECT" version="0x32">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Alpha" connection="Direct"
            attestation_success_retry="2000"
            attestation_fail_retry="200"
            attestation_rsp_not_ready_max_retry="3"
            attestation_rsp_not_ready_max_duration="500">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
                <Muxes>
                    <Mux level="0"><Address>0x55</Address><Channel>3</Channel></Mux>
                    <Mux level="1"><Address>0x66</Address><Channel>5</Channel></Mux>
                </Muxes>
            </Interface>
            <PwrCtrl>
                <Register>0x50</Register>
                <Mask>0xe0</Mask>
            </PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "direct_with_muxes")
    _assert_signed_pcd(m)

    direct = _components_by_kind(tree, "direct")[0]
    muxes = direct["interface"]["muxes"]
    assert len(muxes) == 2
    assert muxes[0]["address"] == 0x55 and muxes[0]["channel"] == 3
    assert muxes[1]["address"] == 0x66 and muxes[1]["channel"] == 5


def test_pcd_multiple_direct_components(tmp_path):
    """Ensure two Direct components on the same PCD are both emitted."""
    xml = f"""\
<PCD sku="SKU-2DIRECT" version="0x33">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Alpha" connection="Direct"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>
        <Component type="Beta" connection="Direct"
            attestation_success_retry="3000"
            attestation_fail_retry="300"
            attestation_rsp_not_ready_max_retry="4"
            attestation_rsp_not_ready_max_duration="400">
            <Policy>Active</Policy>
            <Interface type="I2C">
                <Bus>4</Bus>
                <Address>0x76</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x78</EID>
            </Interface>
            <PwrCtrl><Register>0x60</Register><Mask>0xf0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "two_direct")
    _assert_signed_pcd(m)

    direct = _components_by_kind(tree, "direct")
    assert len(direct) == 2
    addrs = sorted(c["interface"]["address"] for c in direct)
    assert addrs == [0x75, 0x76]
    # The aggregated RoT timeouts must reflect the smaller success/fail retries.
    timeouts = tree["rot"]["timeouts"]
    assert timeouts["attestation_success_retry"] == 1000
    assert timeouts["attestation_fail_retry"] == 100


def test_pcd_unknown_component_type_added_to_map(tmp_path):
    """
    When a component's ``type`` is not in the component map, the generator must
    register it via ``add_component_mapping`` so the resulting binary still
    contains a valid component_id. Use a temp copy of the map so the checked-in
    file is not mutated.
    """
    temp_map = tmp_path / "component_map_temp.json"
    shutil.copy(COMPONENT_JSON, temp_map)
    new_type = "BrandNewWidget_Test_28b41a"
    # Ensure the new type is genuinely not present.
    assert new_type not in json.loads(temp_map.read_text())

    config = [
        "KeyType=RSA",
        "HashType=SHA256",
        f"ComponentMap={temp_map}",
    ]

    xml = f"""\
<PCD sku="SKU-NEWMAP" version="0x34">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="{new_type}" connection="Direct"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "newmap", config_overrides=config)
    _assert_signed_pcd(m)

    # The new type must now appear in the (temp) component map.
    updated_map = json.loads(temp_map.read_text())
    assert new_type in updated_map

    direct = _components_by_kind(tree, "direct")
    assert len(direct) == 1
    assert direct[0]["component_id"] == updated_map[new_type]


def test_pcd_v3_mctp_bridge_without_component_types(tmp_path):
    """v3 MCTPBridge component without ``<ComponentTypes>`` must still parse."""
    xml = f"""\
<PCD sku="SKU-NO-CT" version="0x35" format_version="3">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Gamma" connection="MCTPBridge" count="1"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            discovery_fail_retry="50"
            mctp_bridge_additional_timeout="0"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <DeviceID>0x0c</DeviceID>
            <VendorID>0x0d</VendorID>
            <SubsystemDeviceID>0x0e</SubsystemDeviceID>
            <SubsystemVendorID>0xaa</SubsystemVendorID>
            <EID>0x35</EID>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "v3_no_component_types")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    bridge = _components_by_kind(tree, "mctp_bridge")
    assert len(bridge) == 1
    assert bridge[0]["format"] == 3
    assert bridge[0]["sources"] == []
    assert bridge[0]["instances_count"] == 1


def test_pcd_v3_unknown_source_types_added_to_map(tmp_path):
    """
    v3 ``<ComponentTypes>`` entries whose ``type`` isn't yet mapped should be
    auto-registered in the component map (one mapping per source).
    """
    temp_map = tmp_path / "component_map_temp.json"
    shutil.copy(COMPONENT_JSON, temp_map)
    src_a = "NewSrcA_28b41a"
    src_b = "NewSrcB_28b41a"
    initial_map = json.loads(temp_map.read_text())
    assert src_a not in initial_map and src_b not in initial_map

    config = [
        "KeyType=RSA",
        "HashType=SHA256",
        f"ComponentMap={temp_map}",
    ]

    xml = f"""\
<PCD sku="SKU-NEWSRC" version="0x36" format_version="3">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Gamma" connection="MCTPBridge" count="2"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            discovery_fail_retry="50"
            mctp_bridge_additional_timeout="0"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <DeviceID>0x0c</DeviceID>
            <VendorID>0x0d</VendorID>
            <SubsystemDeviceID>0x0e</SubsystemDeviceID>
            <SubsystemVendorID>0xaa</SubsystemVendorID>
            <EID>0x35</EID>
            <ComponentTypes>
                <ComponentType type="{src_a}" min="1" max="2" />
                <ComponentType type="{src_b}" min="0" max="3" />
            </ComponentTypes>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "v3_new_sources", config_overrides=config)
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    updated_map = json.loads(temp_map.read_text())
    assert src_a in updated_map
    assert src_b in updated_map

    bridge = _components_by_kind(tree, "mctp_bridge")[0]
    source_ids = {s["cfm_component_id"] for s in bridge["sources"]}
    assert updated_map[src_a] in source_ids
    assert updated_map[src_b] in source_ids


# ===========================================================================
# Multi-source MCTPBridge components (<ComponentTypes>)
#
# Schema constraints (pcd.xsd):
#   * <ComponentType> maxOccurs=255 (binary ``component_types_count`` is uint8)
#   * @min and @max are xs:unsignedByte (binary ``min_usage`` / ``max_usage``
#     are uint8)
#   * Asserted: min <= max, OR min==0, OR max==0 (asymmetric escape clause
#     for "unbounded" semantics)
# ===========================================================================
def _v3_bridge_with_component_types(component_types_xml, sku="SKU-MS"):
    """Build a v3 PCD with a single MCTPBridge component carrying the supplied
    ``<ComponentTypes>`` body."""
    return f"""\
<PCD sku="{sku}" version="0x20" format_version="3">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
        <Component type="Gamma" connection="MCTPBridge" count="1"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            discovery_fail_retry="50"
            mctp_bridge_additional_timeout="0"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <DeviceID>0x0c</DeviceID>
            <VendorID>0x0d</VendorID>
            <SubsystemDeviceID>0x0e</SubsystemDeviceID>
            <SubsystemVendorID>0xaa</SubsystemVendorID>
            <EID>0x35</EID>
            <ComponentTypes>
{component_types_xml}
            </ComponentTypes>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>
    </Components>
</PCD>
"""


# ---- Positive: min/max round-trip --------------------------------------
def test_pcd_multi_source_min_max_roundtrip(tmp_path):
    """Each ``<ComponentType>``'s min/max attribute must appear in the 
    binary's source records."""
    types_xml = """\
<ComponentType type="Component1" min="1" max="2" />
<ComponentType type="Component2" min="3" max="7" />
<ComponentType type="Sigma" min="0" max="0" />"""
    m, tree = _build(tmp_path, _v3_bridge_with_component_types(types_xml),
                     "ms_roundtrip")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    bridge = _components_by_kind(tree, "mctp_bridge")[0]
    pairs = sorted((s["min"], s["max"]) for s in bridge["sources"])
    assert pairs == [(0, 0), (1, 2), (3, 7)]


def test_pcd_multi_source_at_byte_boundary_accepted(tmp_path):
    """``min`` and ``max`` at the xs:unsignedByte upper bound (255) must build."""
    types_xml = '<ComponentType type="Component1" min="255" max="255" />'
    m, tree = _build(tmp_path, _v3_bridge_with_component_types(types_xml),
                     "ms_byte_max")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    bridge = _components_by_kind(tree, "mctp_bridge")[0]
    assert len(bridge["sources"]) == 1
    assert bridge["sources"][0]["min"] == 255
    assert bridge["sources"][0]["max"] == 255


def test_pcd_multi_source_zero_max_escape_accepted(tmp_path):
    """The ``min``/``max`` ordering assert exempts pairs where either value is
    0 (e.g. ``min=5, max=0``), modelling "unbounded upper" semantics."""
    types_xml = '<ComponentType type="Component1" min="5" max="0" />'
    m, tree = _build(tmp_path, _v3_bridge_with_component_types(types_xml),
                     "ms_zero_max_escape")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    bridge = _components_by_kind(tree, "mctp_bridge")[0]
    assert bridge["sources"][0]["min"] == 5
    assert bridge["sources"][0]["max"] == 0


def test_pcd_multi_source_default_min_max_accepted(tmp_path):
    """``min`` and ``max`` are optional (default 0) per pcd.xsd."""
    types_xml = '<ComponentType type="Component1" />'
    m, tree = _build(tmp_path, _v3_bridge_with_component_types(types_xml),
                     "ms_defaults")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    bridge = _components_by_kind(tree, "mctp_bridge")[0]
    assert bridge["sources"][0]["min"] == 0
    assert bridge["sources"][0]["max"] == 0


def test_pcd_multi_source_only_min_specified_max_defaults_to_zero(tmp_path):
    """Specifying only ``min`` defaults ``max`` to 0 (the unbounded escape)."""
    types_xml = '<ComponentType type="Component1" min="4" />'
    m, tree = _build(tmp_path, _v3_bridge_with_component_types(types_xml),
                     "ms_only_min")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    bridge = _components_by_kind(tree, "mctp_bridge")[0]
    assert bridge["sources"][0]["min"] == 4
    assert bridge["sources"][0]["max"] == 0


def test_pcd_multi_source_only_max_specified_min_defaults_to_zero(tmp_path):
    """Specifying only ``max`` defaults ``min`` to 0."""
    types_xml = '<ComponentType type="Component1" max="6" />'
    m, tree = _build(tmp_path, _v3_bridge_with_component_types(types_xml),
                     "ms_only_max")
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    bridge = _components_by_kind(tree, "mctp_bridge")[0]
    assert bridge["sources"][0]["min"] == 0
    assert bridge["sources"][0]["max"] == 6


# ---- Negative: out-of-range min/max ---------------------------------------
def test_pcd_multi_source_min_above_byte_max_rejected(tmp_path):
    """``ComponentType@min`` must fit into a uint8 (binary ``min_usage``)."""
    types_xml = '<ComponentType type="Component1" min="256" max="0" />'
    _expect_value_error(
        tmp_path, _v3_bridge_with_component_types(types_xml),
        "ms_min_above_byte",
        r"(?s).*(unsignedByte|UnsignedByte|0 <= x < 256|too high|too low|FORG0001).*",
    )


def test_pcd_multi_source_max_above_byte_max_rejected(tmp_path):
    """``ComponentType@max`` must fit into a uint8 (binary ``max_usage``)."""
    types_xml = '<ComponentType type="Component1" min="0" max="999" />'
    _expect_value_error(
        tmp_path, _v3_bridge_with_component_types(types_xml),
        "ms_max_above_byte",
        r"(?s).*(unsignedByte|UnsignedByte|0 <= x < 256|too high|too low|FORG0001).*",
    )


def test_pcd_multi_source_min_negative_rejected(tmp_path):
    """A negative ``ComponentType@min`` must be rejected (xs:unsignedByte)."""
    types_xml = '<ComponentType type="Component1" min="-1" max="3" />'
    _expect_value_error(
        tmp_path, _v3_bridge_with_component_types(types_xml),
        "ms_min_negative",
        r"(?s).*(unsignedByte|UnsignedByte|0 <= x < 256|too high|too low|FORG0001).*",
    )


# ---- Negative: min/max ordering -------------------------------------------
def test_pcd_multi_source_min_greater_than_max_rejected(tmp_path):
    """``min`` > ``max`` (with both > 0) must be rejected by the XSD assert."""
    types_xml = '<ComponentType type="Component1" min="5" max="3" />'
    _expect_value_error(
        tmp_path, _v3_bridge_with_component_types(types_xml),
        "ms_min_gt_max",
        r"(?s).*(assert|min|max).*",
    )


# ===========================================================================
# TOC extension support
# ===========================================================================
def _build_many_direct_components(count, eid_base=0x40):
    """Render ``count`` minimal Direct components as a single XML fragment."""
    lines = []
    for i in range(count):
        lines.append(f"""\
        <Component type="ManyType_{i:03d}" connection="Direct"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x{(0x10 + (i % 0xE0)):02x}</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x{((eid_base + i) & 0xFF):02x}</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>""")
    return "\n".join(lines)


def test_pcd_no_toc_extension_for_small_manifest(tmp_path):
    """A small PCD has no TOC extension and ``outer_entries`` mirrors ``entries``."""
    xml = f"""\
<PCD sku="SKU-NOEXT" version="0x40">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "no_toc_ext")
    _assert_signed_pcd(m)
    assert m.toc_extensions == []
    assert len(m.outer_entries) == len(m.entries)
    # Every outermost entry should be a "real" element entry, never a TOC marker.
    assert all(e.type_id != 0x01 for e in m.outer_entries)


def test_pcd_v3_toc_extension_with_many_components(tmp_path):
    """
    Generate a PCD with 255 components in v3 format. The total element count
    (255 components + platform_id + RoT = 257) exceeds the single-TOC limit
    of 255, forcing the generator to emit one TOC extension.
    """
    temp_map = tmp_path / "component_map_temp.json"
    shutil.copy(COMPONENT_JSON, temp_map)
    config = [
        "KeyType=RSA",
        "HashType=SHA256",
        f"ComponentMap={temp_map}",
    ]

    component_count = 255
    components_xml = _build_many_direct_components(component_count)
    xml = f"""\
<PCD sku="SKU-MANY" version="0x41" format_version="3">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
{components_xml}
    </Components>
</PCD>
"""
    m, tree = _build(tmp_path, xml, "many_components", config_overrides=config)
    _assert_signed_pcd(m, magic=PCD_V3_MAGIC_NUM)

    # Exactly one TOC extension must have been emitted.
    assert len(m.toc_extensions) == 1
    ext = m.toc_extensions[0]

    # The outer TOC carries 254 element entries + 1 extension marker entry.
    assert len(m.outer_entries) == 255
    marker_entries = [e for e in m.outer_entries if e.type_id == 0x01]
    assert len(marker_entries) == 1
    marker = marker_entries[0]
    assert marker.parent == 0xFF
    assert marker.offset == ext.toc_offset
    assert marker.length == ext.toc_length

    # The flattened entry list must contain every real element from both
    # TOCs plus the extension marker entry that points at the sub-TOC.
    # platform_id + RoT + components + 1 extension marker
    expected_total = 1 + 1 + component_count + 1
    assert len(m.entries) == expected_total
    assert tree["platform_id"] == "SKU-MANY"
    assert tree["rot"]["components_count"] == component_count
    assert len(_components_by_kind(tree, "direct")) == component_count

    # The extension's sub-TOC holds the entries that didn't fit (3 of them).
    assert ext.toc_header.entry_count == expected_total - 255
    assert ext.toc_header.entry_count == len(ext.entries)
    assert ext.toc_header.entry_count == len(ext.hashes)


# ===========================================================================
# Numeric boundary / out-of-range tests
#
# These exercise the XSD numeric facets:
#   * xs:unsignedInt   -> 0 <= x < 2^32
#   * xs:unsignedByte  -> 0 <= x < 256
#   * PortId           -> 0 <= x < 255  (minInclusive=0, maxExclusive=255)
#   * PCDVersion       -> 2 <= x <= 3
#   * HexByte          -> 1-2 hex digits, optional 0x prefix
#   * HexInteger16     -> up to 4 hex digits, optional 0x prefix
#   * PlatformIdSKU    -> length <= 255
#   * Mux maxOccurs    -> 16
#
# ===========================================================================
def _pcd_with_port(port_xml):
    """Minimal PCD with a single Port whose body is provided by the caller."""
    return f"""<PCD sku="SKU-NUM" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Ports>
{port_xml}
        </Ports>
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""


def _pcd_with_power_controller(pc_interface_xml):
    """Minimal PCD with a single PowerController carrying ``pc_interface_xml``."""
    return f"""<PCD sku="SKU-NUM" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <PowerController>
{pc_interface_xml}
    </PowerController>
</PCD>"""


def _pcd_with_components(component_xml, format_version=None):
    """Minimal PCD with a single Component (caller supplies the XML)."""
    fv_attr = f' format_version="{format_version}"' if format_version else ""
    return f"""<PCD sku="SKU-NUM" version="0x20"{fv_attr}>
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
    <Components>
{component_xml}
    </Components>
</PCD>"""


def _port_xml(*, port_id="0", spi_freq="32000000", pulse_interval="0",
              flash_mode="Dual", reset_ctrl="Reset"):
    """Build a Port XML element using safe defaults; override fields via kwargs."""
    return f"""\
            <Port id="{port_id}">
                <SPIFreq>{spi_freq}</SPIFreq>
                <ResetCtrl>{reset_ctrl}</ResetCtrl>
                <FlashMode>{flash_mode}</FlashMode>
                <Policy>Passive</Policy>
                <RuntimeVerification>Enabled</RuntimeVerification>
                <WatchdogMonitoring>Enabled</WatchdogMonitoring>
                <HostResetAction>ResetFlash</HostResetAction>
                <PulseInterval>{pulse_interval}</PulseInterval>
            </Port>"""


# Regex patterns matching the common xmlschema validation messages.
_UINT_OUT_OF_RANGE = r"(?s).*(unsignedInt|2\^32|0 <= x).*"
_UBYTE_OUT_OF_RANGE = r"(?s).*(unsignedByte|0 <= x < 256).*"
_MIN_INCLUSIVE = r"(?s).*(minInclusive|greater or equal).*"
_MAX_EXCLUSIVE = r"(?s).*(maxExclusive|lesser than).*"
_PATTERN_MISMATCH = r"(?s).*(pattern|XsdPatternFacets|doesn't match).*"
_MAX_LENGTH = r"(?s).*(maxLength|length cannot be greater).*"


# ---- xs:unsignedInt out-of-range (RoT timeouts and other 32-bit fields) ----
def test_pcd_mctp_ctrl_timeout_above_uint_max(tmp_path):
    """``mctp_ctrl_timeout`` larger than 2^32-1 must be rejected by the schema."""
    xml = f"""<PCD sku="SKU-NUM" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="9999999999" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(tmp_path, xml, "mctp_ctrl_too_big", _UINT_OUT_OF_RANGE)


def test_pcd_mctp_bridge_get_table_wait_above_uint_max(tmp_path):
    """``mctp_bridge_get_table_wait`` larger than 2^32-1 must be rejected."""
    xml = f"""<PCD sku="SKU-NUM" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="9999999999">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "bridge_wait_too_big", _UINT_OUT_OF_RANGE)


def test_pcd_spi_freq_above_uint_max(tmp_path):
    """``SPIFreq`` larger than 2^32-1 must be rejected (xs:unsignedInt)."""
    xml = _pcd_with_port(_port_xml(spi_freq="4294967296"))  # 2^32
    _expect_value_error(tmp_path, xml, "spi_freq_too_big", _UINT_OUT_OF_RANGE)


def test_pcd_attestation_success_retry_above_uint_max(tmp_path):
    """``attestation_success_retry`` larger than 2^32-1 must be rejected."""
    xml = _pcd_with_components("""\
        <Component type="Alpha" connection="Direct"
            attestation_success_retry="9999999999"
            attestation_fail_retry="100"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>""")
    _expect_value_error(tmp_path, xml, "att_retry_too_big", _UINT_OUT_OF_RANGE)


def test_pcd_negative_attestation_fail_retry(tmp_path):
    """A negative ``attestation_fail_retry`` must be rejected (xs:unsignedInt)."""
    xml = _pcd_with_components("""\
        <Component type="Alpha" connection="Direct"
            attestation_success_retry="1000"
            attestation_fail_retry="-1"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>""")
    _expect_value_error(tmp_path, xml, "att_fail_negative", _UINT_OUT_OF_RANGE)


# ---- xs:unsignedByte out-of-range (ports, bus, channel, count, ...) --------
def test_pcd_pulse_interval_above_byte_max(tmp_path):
    """``PulseInterval`` is xs:unsignedByte; values >= 256 must be rejected."""
    xml = _pcd_with_port(_port_xml(pulse_interval="256"))
    _expect_value_error(tmp_path, xml, "pulse_too_big", _UBYTE_OUT_OF_RANGE)


def test_pcd_pulse_interval_negative(tmp_path):
    """A negative ``PulseInterval`` (xs:unsignedByte) must be rejected."""
    xml = _pcd_with_port(_port_xml(pulse_interval="-1"))
    _expect_value_error(tmp_path, xml, "pulse_negative", _UBYTE_OUT_OF_RANGE)


def test_pcd_bus_above_byte_max(tmp_path):
    """``Bus`` (xs:unsignedByte) values >= 256 must be rejected."""
    pc = """\
        <Interface type="I2C">
            <Bus>256</Bus>
            <EID>0x14</EID>
            <Address>0x22</Address>
            <I2CMode>MultiMaster</I2CMode>
        </Interface>"""
    _expect_value_error(
        tmp_path, _pcd_with_power_controller(
            pc), "bus_too_big", _UBYTE_OUT_OF_RANGE,
    )


def test_pcd_bus_negative(tmp_path):
    """A negative ``Bus`` value must be rejected."""
    pc = """\
        <Interface type="I2C">
            <Bus>-1</Bus>
            <EID>0x14</EID>
            <Address>0x22</Address>
            <I2CMode>MultiMaster</I2CMode>
        </Interface>"""
    _expect_value_error(
        tmp_path, _pcd_with_power_controller(
            pc), "bus_negative", _UBYTE_OUT_OF_RANGE,
    )


def test_pcd_mux_channel_above_byte_max(tmp_path):
    """``Mux/Channel`` (xs:unsignedByte) values >= 256 must be rejected."""
    pc = """\
        <Interface type="I2C">
            <Bus>1</Bus>
            <EID>0x14</EID>
            <Address>0x22</Address>
            <I2CMode>MultiMaster</I2CMode>
            <Muxes>
                <Mux level="0"><Address>0x55</Address><Channel>500</Channel></Mux>
            </Muxes>
        </Interface>"""
    _expect_value_error(
        tmp_path, _pcd_with_power_controller(pc), "channel_too_big",
        _UBYTE_OUT_OF_RANGE,
    )


def test_pcd_component_count_above_byte_max(tmp_path):
    """``count`` on a Component is xs:unsignedByte; values >= 256 must be rejected."""
    xml = _pcd_with_components("""\
        <Component type="Alpha" connection="Direct" count="999"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>""")
    _expect_value_error(tmp_path, xml, "count_too_big", _UBYTE_OUT_OF_RANGE)


def test_pcd_component_count_negative(tmp_path):
    """A negative ``count`` on a Component must be rejected."""
    xml = _pcd_with_components("""\
        <Component type="Alpha" connection="Direct" count="-1"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <Interface type="I2C">
                <Bus>3</Bus>
                <Address>0x75</Address>
                <I2CMode>MultiMaster</I2CMode>
                <EID>0x77</EID>
            </Interface>
            <PwrCtrl><Register>0x50</Register><Mask>0xe0</Mask></PwrCtrl>
        </Component>""")
    _expect_value_error(tmp_path, xml, "count_negative", _UBYTE_OUT_OF_RANGE)


# ---- PortId range (0 <= id < 255) -----------------------------------------
def test_pcd_port_id_negative(tmp_path):
    """``Port@id`` minInclusive=0, so a negative id must be rejected."""
    xml = _pcd_with_port(_port_xml(port_id="-1"))
    _expect_value_error(tmp_path, xml, "port_id_negative", _MIN_INCLUSIVE)


def test_pcd_port_id_at_max_exclusive(tmp_path):
    """``Port@id`` maxExclusive=255, so id=255 must be rejected (only 0..254 valid)."""
    xml = _pcd_with_port(_port_xml(port_id="255"))
    _expect_value_error(tmp_path, xml, "port_id_at_255", _MAX_EXCLUSIVE)


# ---- PCDVersion (format_version) range ------------------------------------
def test_pcd_format_version_below_minimum(tmp_path):
    """``format_version`` < 2 (PCDVersion minInclusive=2) must be rejected."""
    xml = f"""<PCD sku="SKU-NUM" version="0x20" format_version="1">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "format_version_below_min",
        r"(?s).*(PCDVersion|minInclusive|format_version|greater or equal).*",
    )


def test_pcd_format_version_zero(tmp_path):
    """``format_version="0"`` must be rejected (PCDVersion minInclusive=2)."""
    xml = f"""<PCD sku="SKU-NUM" version="0x20" format_version="0">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "format_version_zero",
        r"(?s).*(PCDVersion|minInclusive|format_version|greater or equal).*",
    )


# ---- Hex pattern violations -----------------------------------------------
def test_pcd_address_too_many_hex_digits(tmp_path):
    """``HexByte`` allows at most 2 hex digits; ``0xFFF`` must be rejected."""
    xml = f"""<PCD sku="SKU-NUM" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Interface type="I2C">
            <Address>0xFFF</Address>
            <RoTEID>0x0b</RoTEID>
            <BridgeEID>0x0a</BridgeEID>
            <BridgeAddress>0x10</BridgeAddress>
        </Interface>
    </RoT>
</PCD>"""
    _expect_value_error(
        tmp_path, xml, "address_too_long_hex", _PATTERN_MISMATCH)


def test_pcd_address_non_hex_characters(tmp_path):
    """``HexByte`` only accepts hex digits; ``0xZZ`` must be rejected."""
    xml = f"""<PCD sku="SKU-NUM" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
        <Interface type="I2C">
            <Address>0xZZ</Address>
            <RoTEID>0x0b</RoTEID>
            <BridgeEID>0x0a</BridgeEID>
            <BridgeAddress>0x10</BridgeAddress>
        </Interface>
    </RoT>
</PCD>"""
    _expect_value_error(tmp_path, xml, "address_non_hex", _PATTERN_MISMATCH)


def test_pcd_deviceid_too_many_hex_digits(tmp_path):
    """``HexInteger16`` allows at most 4 hex digits; ``0x12345`` must be rejected."""
    xml = _pcd_with_components("""\
        <Component type="Gamma" connection="MCTPBridge" count="1"
            attestation_success_retry="1000"
            attestation_fail_retry="100"
            discovery_fail_retry="50"
            mctp_bridge_additional_timeout="0"
            attestation_rsp_not_ready_max_retry="2"
            attestation_rsp_not_ready_max_duration="200">
            <Policy>Passive</Policy>
            <DeviceID>0x12345</DeviceID>
            <VendorID>0x0d</VendorID>
            <SubsystemDeviceID>0x0e</SubsystemDeviceID>
            <SubsystemVendorID>0xaa</SubsystemVendorID>
            <EID>0x35</EID>
            <PwrCtrl><Register>0x70</Register><Mask>0xF0</Mask></PwrCtrl>
        </Component>""")
    _expect_value_error(tmp_path, xml, "deviceid_too_long", _PATTERN_MISMATCH)


# ---- String length / maxOccurs limits -------------------------------------
def test_pcd_sku_exceeds_max_length(tmp_path):
    """``PlatformIdSKU`` maxLength=255 — anything longer must be rejected."""
    long_sku = "A" * 256
    xml = f"""<PCD sku="{long_sku}" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    _expect_value_error(tmp_path, xml, "sku_too_long", _MAX_LENGTH)


def test_pcd_too_many_muxes(tmp_path):
    """The ``Muxes`` group has maxOccurs=16 on Mux; a 17th mux must be rejected."""
    muxes = "\n".join(
        f'<Mux level="{i}"><Address>0x55</Address><Channel>1</Channel></Mux>'
        for i in range(17)
    )
    pc = f"""\
        <Interface type="I2C">
            <Bus>1</Bus>
            <EID>0x14</EID>
            <Address>0x22</Address>
            <I2CMode>MultiMaster</I2CMode>
            <Muxes>
{muxes}
            </Muxes>
        </Interface>"""
    _expect_value_error(
        tmp_path, _pcd_with_power_controller(pc), "too_many_muxes",
        r"(?s).*(Mux|Unexpected child|maxOccurs).*",
    )


# ===========================================================================
# Boundary-positive tests: maximum valid values must still build successfully.
# ===========================================================================
def test_pcd_pulse_interval_at_byte_max_accepted(tmp_path):
    """``PulseInterval=255`` (maximum xs:unsignedByte) must be accepted."""
    xml = _pcd_with_port(_port_xml(pulse_interval="255"))
    m, tree = _build(tmp_path, xml, "pulse_max")
    _assert_signed_pcd(m)
    assert tree["rot"]["ports"][0]["pulse_interval"] == 255


def test_pcd_port_id_at_max_valid_accepted(tmp_path):
    """``Port@id=254`` is the maximum valid id (maxExclusive=255) and must be accepted."""
    xml = _pcd_with_port(_port_xml(port_id="254"))
    m, tree = _build(tmp_path, xml, "port_id_max")
    _assert_signed_pcd(m)
    assert sorted(tree["rot"]["ports"].keys()) == [254]


def test_pcd_uint_at_max_value_accepted(tmp_path):
    """RoT timeouts at 2^32-1 (the maximum xs:unsignedInt value) must build."""
    xml = f"""<PCD sku="SKU-NUM" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="4294967295" mctp_bridge_get_table_wait="4294967295">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    m, tree = _build(tmp_path, xml, "uint_max")
    _assert_signed_pcd(m)
    assert tree["rot"]["timeouts"]["mctp_ctrl_timeout"] == 4294967295
    assert tree["rot"]["timeouts"]["mctp_bridge_get_table_wait"] == 4294967295


def test_pcd_format_version_at_minimum_accepted(tmp_path):
    """``format_version="2"`` (PCDVersion minimum) must be accepted."""
    xml = f"""<PCD sku="SKU-NUM" version="0x20" format_version="2">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    m, tree = _build(tmp_path, xml, "fv_min")
    _assert_signed_pcd(m)
    assert tree["platform_id"] == "SKU-NUM"


def test_pcd_sku_at_max_length_accepted(tmp_path):
    """A 255-char SKU (PlatformIdSKU max length) must be accepted."""
    sku = "S" * 255
    xml = f"""<PCD sku="{sku}" version="0x20">
    <RoT type="PA-RoT" mctp_ctrl_timeout="2000" mctp_bridge_get_table_wait="3000">
{ROT_I2C_INTERFACE}
    </RoT>
</PCD>"""
    m, tree = _build(tmp_path, xml, "sku_max")
    _assert_signed_pcd(m)
    assert tree["platform_id"] == sku
