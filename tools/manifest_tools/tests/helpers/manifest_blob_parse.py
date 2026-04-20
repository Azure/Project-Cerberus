"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict, Any
import struct
from Crypto.Hash import SHA256, SHA384, SHA512

# =============================================================================
# Helpers
# =============================================================================
def _u8(b: bytes, off: int) -> int:
    return b[off]

def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]

def _need(total_len: int, off: int, n: int) -> None:
    """Ensure [off, off+n) is within [0, total_len)."""
    if off < 0 or n < 0 or off + n > total_len:
        raise ValueError(f"Truncated manifest: need {n} at 0x{off:x}")

def _pad4_len(n: int) -> int:
    """Return padding length to 4-byte boundary for a segment of size n."""
    return ((n + 3) & ~3) - n

def _read(b: bytes, off: int, n: int) -> Tuple[bytes, int]:
    _need(len(b), off, n)
    return b[off:off + n], off + n

# =============================================================================
# Constants
# =============================================================================
V2_BASE_TYPE_ID                         = 0xFF
V2_PLATFORM_TYPE_ID                     = 0x00

PFM_V2_FLASH_DEVICE_TYPE_ID             = 0x10
PFM_V2_FW_TYPE_ID                       = 0x11
PFM_V2_FW_VERSION_TYPE_ID               = 0x12

PCD_V2_ROT_TYPE_ID                      = 0x40
PCD_V2_SPI_FLASH_PORT_TYPE_ID           = 0x41
PCD_V2_I2C_POWER_CONTROLLER_TYPE_ID     = 0x42
PCD_V2_DIRECT_COMPONENT_TYPE_ID         = 0x43
PCD_V2_MCTP_BRIDGE_COMPONENT_TYPE_ID    = 0x44

CFM_V2_COMPONENT_DEVICE_TYPE_ID         = 0x70
CFM_V2_PMR_TYPE_ID                      = 0x71
CFM_V2_PMR_DIGEST_TYPE_ID               = 0x72
CFM_V2_MEASUREMENT_TYPE_ID              = 0x73
CFM_V2_MEASUREMENT_DATA_TYPE_ID         = 0x74
CFM_V2_ALLOWABLE_DATA_TYPE_ID           = 0x75
CFM_V2_ALLOWABLE_PFM_TYPE_ID            = 0x76
CFM_V2_ALLOWABLE_CFM_TYPE_ID            = 0x77
CFM_V2_ALLOWABLE_PCD_TYPE_ID            = 0x78
CFM_V2_ALLOWABLE_ID_TYPE_ID             = 0x79
CFM_V2_ROOT_CA_TYPE_ID                  = 0x7A

PFM_MAGIC_NUM                           = 0x504D
CFM_MAGIC_NUM                           = 0xA592
PCD_MAGIC_NUM                           = 0x1029

MANIFEST_HASH_SHA256            = 0
MANIFEST_HASH_SHA384            = 1
MANIFEST_HASH_SHA512            = 2

_HASH_LEN = {
    MANIFEST_HASH_SHA256: 32,
    MANIFEST_HASH_SHA384: 48,
    MANIFEST_HASH_SHA512: 64,
}

# =============================================================================
# Data classes
# =============================================================================
@dataclass
class ManifestHeader:
    length: int      # total file length claimed by manifest (includes signature)
    magic: int
    id: int
    sig_length: int
    sig_type: int
    reserved: int

@dataclass
class ManifestTocHeader:
    entry_count: int
    hash_count: int
    hash_type: int
    reserved: int

@dataclass
class ManifestTocEntry:
    type_id: int
    parent: int
    format: int
    hash_id: int
    offset: int      # absolute offset from start of manifest (0 = first header byte)
    length: int

@dataclass
class Manifest:
    header: ManifestHeader
    toc_header: ManifestTocHeader
    entries: List[ManifestTocEntry]
    hashes: List[bytes]
    table_hash: bytes
    signature: bytes

    # Computed fields for tests
    signed_bytes: bytes = b""                    # header + payload (excluding signature)
    computed_hashes: List[bytes] = None          # per-element hashes
    computed_table_hash: bytes = b""             # hash(TOC header + entries + element hashes)

# =============================================================================
# Parsing functions
# =============================================================================
def parse_manifest_header(b: bytes) -> Tuple[ManifestHeader, int]:
    """
    struct manifest_header (packed, 12 bytes, at file start):
    uint16 length;
    uint16 magic;
    uint32 id;
    uint16 sig_length;
    uint8  sig_type;
    uint8  reserved;
    """
    if len(b) < 12:
        raise ValueError("File too small for manifest_header (need 12 bytes).")
    length = _u16(b, 0)
    magic = _u16(b, 2)
    _id = _u32(b, 4)
    sig_len = _u16(b, 8)
    sig_type = _u8(b, 10)
    reserved = _u8(b, 11)
    return ManifestHeader(length, magic, _id, sig_len, sig_type, reserved), 12

def parse_toc_header(b: bytes, off: int) -> Tuple[ManifestTocHeader, int, int]:
    """
    struct manifest_toc_header (packed, 4 bytes):
    uint8 entry_count;
    uint8 hash_count;
    uint8 hash_type;
    uint8 reserved;
    Returns (toc_header, next_off, hash_len).
    """
    _need(len(b), off, 4)
    entry_count = _u8(b, off + 0)
    hash_count = _u8(b, off + 1)
    hash_type = _u8(b, off + 2)
    reserved = _u8(b, off + 3)
    hdr = ManifestTocHeader(entry_count, hash_count, hash_type, reserved)

    hash_len = _HASH_LEN.get(hash_type)
    if hash_len is None:
        raise ValueError(f"Unsupported hash_type {hash_type}")

    return hdr, off + 4, hash_len

def parse_toc_entries(b: bytes, off: int, count: int) -> Tuple[List[ManifestTocEntry], int]:
    """
    struct manifest_toc_entry (packed, 8 bytes each):
    uint8  type_id;
    uint8  parent;
    uint8  format;
    uint8  hash_id;
    uint16 offset;   (absolute, from start of file)
    uint16 length;   (bytes)
    """
    entries: List[ManifestTocEntry] = []
    total = len(b)
    for _ in range(count):
        _need(total, off, 8)
        type_id = _u8(b, off + 0)
        parent = _u8(b, off + 1)
        format_ = _u8(b, off + 2)
        hash_id = _u8(b, off + 3)
        offset = _u16(b, off + 4)
        length = _u16(b, off + 6)
        entries.append(ManifestTocEntry(type_id, parent, format_, hash_id, offset, length))
        off += 8
    return entries, off

def parse_hashes(b: bytes, off: int, hash_len: int, hash_count: int) -> Tuple[List[bytes], bytes, int]:
    """Read 'hash_count' element hashes followed by 1 table hash (all of size 'hash_len')."""
    hashes: List[bytes] = []
    for _ in range(hash_count):
        h, off = _read(b, off, hash_len)
        hashes.append(h)
    table_hash, off = _read(b, off, hash_len)
    return hashes, table_hash, off

# =============================================================================
# helpers
# =============================================================================
def _get_hash_engine(hash_type: int):
    if hash_type == MANIFEST_HASH_SHA256:
        return SHA256
    if hash_type == MANIFEST_HASH_SHA384:
        return SHA384
    if hash_type == MANIFEST_HASH_SHA512:
        return SHA512
    raise ValueError(f"Unsupported hash_type {hash_type}")

# =============================================================================
# Top-level parser
# =============================================================================
def parse_manifest(b: bytes) -> Manifest:
    """
    Parse a manifest blob and compute additional test-friendly values:
    - computed_hashes: per-element hashes over element bytes
    - computed_table_hash: hash over TOC header + entries + element hashes
    - signed_bytes: header + payload (excluding signature)
    """
    total_len = len(b)

    # 1) Header (fixed 12 bytes at start)
    hdr, after_hdr = parse_manifest_header(b)
    if hdr.length > total_len:
        raise ValueError(f"Truncated manifest: header.length={hdr.length} > file_size={total_len}")

    # 2) Signature region (from end of claimed size)
    sig_len = hdr.sig_length
    sig_start = hdr.length - sig_len
    if sig_start < 0:
        raise ValueError(f"Invalid signature start: {sig_start}")
    _need(total_len, sig_start, sig_len)
    signature = b[sig_start: sig_start + sig_len]

    # 3) TOC header
    toc_hdr, off, hash_len = parse_toc_header(b, after_hdr)
    if off > sig_start:
        raise ValueError("TOC header overruns payload region")

    # 4) TOC entries
    entries, off = parse_toc_entries(b, off, toc_hdr.entry_count)
    if off > sig_start:
        raise ValueError("TOC entries overrun payload region")

    # 5) Element hashes + table hash
    hashes, table_hash, off = parse_hashes(b, off, hash_len, toc_hdr.hash_count)
    if off > sig_start:
        raise ValueError("TOC hashes overrun payload region")

    # 6) Payload window (exclude signature)
    payload_off = off             # start of payload (immediately after TOC)
    payload_end = sig_start       # start of signature
    if payload_off > payload_end:
        raise ValueError("Invalid payload bounds: header overlaps signature")

    # 7) Compute per-element hashes and table hash
    hash_engine = _get_hash_engine(toc_hdr.hash_type)

    # Per-element hashes from element bytes
    computed_hashes: List[bytes] = []
    for entry in entries:
        el = b[entry.offset: entry.offset + entry.length]
        computed_hashes.append(hash_engine.new(el).digest())

    # Table hash over TOC table:
    # TOC table bytes = TOC header + entries + element hashes.
    # 'after_hdr' points to TOC header, 'off - hash_len' now points to start of the table hash field.
    toc_table_bytes = b[after_hdr: off - hash_len]
    computed_table_hash = hash_engine.new(toc_table_bytes).digest()

    # 8) Signed bytes = header + TOC + entire payload (excluding signature)
    signed_bytes = b[:payload_end]

    return Manifest(
        header=hdr,
        toc_header=toc_hdr,
        entries=entries,
        hashes=hashes,
        table_hash=table_hash,
        signature=signature,
        signed_bytes=signed_bytes,
        computed_hashes=computed_hashes,
        computed_table_hash=computed_table_hash,
    )

# =============================================================================
# Convenience for tests
# =============================================================================
def load_manifest_blob(path: str) -> Manifest:
    with open(path, "rb") as f:
        data = f.read()
    return parse_manifest(data)

def manifest_to_tree(m: Manifest) -> Dict[str, Any]:
    """
    Convert Manifest object into a hierarchical dictionary.
    """
    tree: Dict[str, Any] = {
        "platform_id": None
    }

    if m.header.magic == CFM_MAGIC_NUM:
        if "components" not in tree:
            tree["components"] = []

    data = m.signed_bytes  # full manifest payload excluding signature
    current_component: Dict[str, Any] = None
    current_measurement_data_node: Dict[str, Any] = None
    last_allowable_manifest: Dict[str, Any] = None
    current_firmware_node: Dict[str, Any] = None
    pending_rot_ports: Dict[int, Dict[str, Any]] = {}

    for entry in m.entries:
        start = entry.offset
        end = start + entry.length
        chunk = data[start:end]

        # platform ID
        if entry.parent == V2_BASE_TYPE_ID and entry.type_id == V2_PLATFORM_TYPE_ID:
            # platform_id_length (u8), reserved[3], platform_id string, padding
            platform_len = chunk[0]
            platform_id = chunk[4:4 + platform_len].decode("utf-8", errors="strict")
            tree["platform_id"] = platform_id
            continue

        # Flash device
        if entry.parent == V2_BASE_TYPE_ID and entry.type_id == PFM_V2_FLASH_DEVICE_TYPE_ID:
            blank_byte = chunk[0]
            fw_count = chunk[1]
            # reserved = chunk[2:4]
            tree["unused_byte"] = blank_byte
            tree["fw_count"] = fw_count
            tree["fw_list"] = []
            continue

        # Firmware
        if entry.parent == V2_BASE_TYPE_ID and entry.type_id == PFM_V2_FW_TYPE_ID:
            version_count = chunk[0]
            id_length = chunk[1]
            flags = chunk[2]
            # reserved = chunk[3]
            fw_id = chunk[4:4 + id_length].decode("utf-8", errors="strict")
            firmware_node = {
                "fw_id": fw_id,
                "fw_flags": flags,
                "version_count": version_count,
                "versions": []
            }
            tree["fw_list"].append(firmware_node)
            current_firmware_node = firmware_node
            continue

        # Firmware version
        if entry.parent == PFM_V2_FW_TYPE_ID and entry.type_id == PFM_V2_FW_VERSION_TYPE_ID:
            img_count = chunk[0]
            rw_count = chunk[1]
            version_length = chunk[2]
            # reserved = chunk[3]
            version_addr = _u32(chunk, 4)
            version_str = chunk[8:8 + version_length].decode("utf-8", errors="strict")
            off = 8 + version_length + _pad4_len(version_length)

            # RW regions
            rw_regions = []
            for _ in range(rw_count):
                flags = chunk[off]
                # reserved = chunk[off+1:off+4]
                start_addr = _u32(chunk, off+4)
                end_addr = _u32(chunk, off+8)
                rw_regions.append({
                    "flags": flags,
                    "start_addr": start_addr,
                    "end_addr": end_addr
                })
                off += 12

            # Images
            images = []
            for _ in range(img_count):
                hash_type = chunk[off]
                region_count = chunk[off+1]
                img_flags = chunk[off+2]
                # reserved = chunk[off+3]
                off += 4
                hash_len = _HASH_LEN.get(hash_type)
                if hash_len is None:
                    raise ValueError(f"Unsupported hash_type {hash_type}")
                hash_bytes = chunk[off:off+hash_len]
                off += hash_len
                regions = []
                for _ in range(region_count):
                    img_start_addr = _u32(chunk, off)
                    img_end_addr = _u32(chunk, off+4)
                    regions.append({
                        "start": img_start_addr,
                        "end": img_end_addr
                    })
                    off += 8
                images.append({
                    "hash_type": hash_type,
                    "flags": img_flags,
                    "hash": bytes(hash_bytes),
                    "regions": regions
                })

            version_node = {
                "version": version_str,
                "version_addr": version_addr,
                "rw_regions": rw_regions,
                "images": images
            }
            current_firmware_node["versions"].append(version_node)
            continue

        # RoT element
        if entry.parent == V2_BASE_TYPE_ID and entry.type_id == PCD_V2_ROT_TYPE_ID:
            rot_flags                     = chunk[0]
            port_count                    = chunk[1]
            components_count              = chunk[2]
            rot_address                   = chunk[3]
            rot_eid                       = chunk[4]
            bridge_address                = chunk[5]
            bridge_eid                    = chunk[6]
            # reserved                    = chunk[7]
            attestation_success_retry     = _u32(chunk, 8)
            attestation_fail_retry        = _u32(chunk, 12)
            discovery_fail_retry          = _u32(chunk, 16)
            mctp_ctrl_timeout             = _u32(chunk, 20)
            mctp_bridge_get_table_wait    = _u32(chunk, 24)
            mctp_bridge_additional_timeout= _u32(chunk, 28)
            rsp_not_ready_max_duration    = _u32(chunk, 32)
            rsp_not_ready_max_retry       = chunk[36]
            # reserved2[3]                = chunk[37:40]  # ignore

            rot_node = {
                "type": rot_flags,
                "port_count": port_count,
                "components_count": components_count,
                "timeouts": {
                    "attestation_success_retry": attestation_success_retry,
                    "attestation_fail_retry": attestation_fail_retry,
                    "discovery_fail_retry": discovery_fail_retry,
                    "mctp_ctrl_timeout": mctp_ctrl_timeout,
                    "mctp_bridge_get_table_wait": mctp_bridge_get_table_wait,
                    "mctp_bridge_additional_timeout": mctp_bridge_additional_timeout,
                    "attestation_rsp_not_ready_max_duration": rsp_not_ready_max_duration,
                    "attestation_rsp_not_ready_max_retry": rsp_not_ready_max_retry,
                },
                "interface": {
                    "type": "I2C",
                    "address": rot_address,
                    "rot_eid": rot_eid,
                    "bridge_eid": bridge_eid,
                    "bridge_address": bridge_address,
                },
                "ports": {}
            }
            if pending_rot_ports:
                rot_node["ports"].update(pending_rot_ports)
                pending_rot_ports = {}
            tree["rot"] = rot_node
            continue

        # SPI Flash Port
        if entry.parent == PCD_V2_ROT_TYPE_ID and entry.type_id == PCD_V2_SPI_FLASH_PORT_TYPE_ID:
            port_id          = chunk[0]
            port_flags       = chunk[1]
            host_reset_action = port_flags >> 6
            watchdog_monitoring = (port_flags >> 5) & 1
            runtime_verification = (port_flags >> 4) & 1
            flash_mode = (port_flags >> 2) & 3
            reset_ctrl = port_flags & 3

            port_flags_new = (host_reset_action << 6) | (watchdog_monitoring << 5) | (runtime_verification << 4) | (flash_mode << 2) | reset_ctrl
            assert port_flags == port_flags_new, f"Expected port_flags {port_flags}, got {port_flags_new}"

            policy           = chunk[2]
            pulse_interval   = chunk[3]
            spi_frequency_hz = _u32(chunk, 4)

            port_obj = {
                "policy": policy,
                "pulse_interval": pulse_interval,
                "spi_freq": spi_frequency_hz,
                "flash_mode": flash_mode,
                "reset_ctrl": reset_ctrl,
                "runtime_verification": runtime_verification,
                "watchdog_monitoring": watchdog_monitoring,
                "host_reset_action": host_reset_action
            }

            if tree.get("rot") is None:
                pending_rot_ports[port_id] = port_obj
            else:
                tree["rot"]["ports"][port_id] = port_obj
            continue

        # Power controller
        if entry.parent == V2_BASE_TYPE_ID and entry.type_id == PCD_V2_I2C_POWER_CONTROLLER_TYPE_ID:
            # Bitfield byte: low 4 bits = mux_count, high 4 bits = i2c_flags
            bf0        = chunk[0]
            mux_count  = bf0 & 0x0F
            i2c_flags  = (bf0 >> 4) & 0x0F
            bus        = chunk[1]
            address    = chunk[2]
            eid        = chunk[3]
            off        = 4

            muxes: Dict[Dict[str, Any]] = {}
            for index in range(mux_count):
                mux_addr   = chunk[off + 0]
                mux_chan   = chunk[off + 1]
                # reserved u16 at off+2..off+3
                off += 4
                muxes[index + 1] = {"address": mux_addr, "channel": mux_chan}

            power_ctrl_node = { "interface": {
                "type": "I2C",
                "i2c_mode": i2c_flags,
                "bus": bus,
                "address": address,
                "eid": eid,
                "muxes": muxes
            }}

            tree["power_controller"] = power_ctrl_node
            continue

        # Direct I2C component
        if entry.parent == V2_BASE_TYPE_ID and entry.type_id == PCD_V2_DIRECT_COMPONENT_TYPE_ID:
            policy          = chunk[0]
            pwr_reg         = chunk[1]
            pwr_mask        = chunk[2]
            # reserved       = chunk[3]
            component_id    = _u32(chunk, 4)
            bf              = chunk[8]
            mux_count       = bf & 0x0F
            i2c_flags       = (bf >> 4) & 0x0F
            bus             = chunk[9]
            address         = chunk[10]
            eid             = chunk[11]
            off             = 12

            muxes: Dict[Dict[str, Any]] = {}
            for index in range(mux_count):
                mux_addr   = chunk[off + 0]
                mux_chan   = chunk[off + 1]
                off += 4  # skip reserved u16
                muxes[index] = {"address": mux_addr, "channel": mux_chan}

            comp = {
                "connection": "Direct",
                "policy": policy,
                "powerctrl": {"register": pwr_reg, "mask": pwr_mask},
                "component_id": component_id,
                "interface": {
                    "type": "I2C",
                    "i2c_mode": i2c_flags,
                    "bus": bus,
                    "address": address,
                    "eid": eid,
                    "muxes": muxes
                }
            }
            if "components" not in tree:
                tree["components"] = []
            tree["components"].append(comp)
            continue

        # MCTP Bridge component
        if entry.parent == V2_BASE_TYPE_ID and entry.type_id == PCD_V2_MCTP_BRIDGE_COMPONENT_TYPE_ID:
            policy                = chunk[0]
            pwr_reg               = chunk[1]
            pwr_mask              = chunk[2]
            # reserved            = chunk[3]
            component_id          = _u32(chunk, 4)
            device_id             = _u16(chunk, 8)
            vendor_id             = _u16(chunk, 10)
            subsystem_device_id   = _u16(chunk, 12)
            subsystem_vendor_id   = _u16(chunk, 14)
            components_count      = chunk[16]
            eid                   = chunk[17]
            # reserved2 u16        = _u16(chunk, 18)  # not used

            comp = {
                "connection": "MCTPBridge",
                "policy": policy,
                "powerctrl": {"register": pwr_reg, "mask": pwr_mask},
                "component_id": component_id,
                "deviceid": device_id,
                "vendorid": vendor_id,
                "subdeviceid": subsystem_device_id,
                "subvendorid": subsystem_vendor_id,
                "count": components_count,
                "eid": eid
            }
            if "components" not in tree:
                tree["components"] = []
            tree["components"].append(comp)
            continue

        # Component device
        if entry.parent == V2_BASE_TYPE_ID and entry.type_id == CFM_V2_COMPONENT_DEVICE_TYPE_ID:
            cert_slot = chunk[0]
            att_proto = chunk[1]
            # bitfield: transcript_hash_type (3 bits, LSB) | measurement_hash_type (next 3 bits) | reserved (2 bits, MSB)
            bf = chunk[2]
            transcript_hash_type = (bf & 0x07)            # lowest 3 bits
            measurement_hash_type = (bf >> 3) & 0x07      # next 3 bits

            component_id = _u32(chunk, 4)
            # New component node
            comp: Dict[str, Any] = {
                "component_id": component_id,
                "slot_num": cert_slot,
                "attestation_protocol": att_proto,
                "transcript_hash_type": transcript_hash_type,
                "measurement_hash_type": measurement_hash_type,
            }
            if "components" not in tree:
                tree["components"] = []
            tree["components"].append(comp)
            current_component = comp
            current_measurement_data_node = None
            last_allowable_manifest = None
            continue

        # Root CA digests
        if entry.parent == CFM_V2_COMPONENT_DEVICE_TYPE_ID and entry.type_id == CFM_V2_ROOT_CA_TYPE_ID:
            ca_count = chunk[0]
            # digest area starts at offset 4; length is (entry.length - 4)
            digests: List[bytes] = []
            off = 4
            hash_len = _HASH_LEN.get(current_component["measurement_hash_type"])
            for _ in range(ca_count):
                d = chunk[off: off + hash_len]
                digests.append(bytes(d))
                off += hash_len
            current_component["root_ca_digests"] = {"allowable_digests": digests}
            continue

        # PMR initial value
        if entry.parent == CFM_V2_COMPONENT_DEVICE_TYPE_ID and entry.type_id == CFM_V2_PMR_TYPE_ID:
            pmr_id = chunk[0]
            init_val = bytes(chunk[4:])
            if "pmr" not in current_component:
                current_component["pmr"] = {}
            current_component["pmr"][pmr_id] = {"initial_value": init_val}
            continue

        # PMR digests
        if entry.parent == CFM_V2_COMPONENT_DEVICE_TYPE_ID and entry.type_id == CFM_V2_PMR_DIGEST_TYPE_ID:
            pmr_id = chunk[0]
            count = chunk[1]
            off = 4
            digests = []
            hash_len = _HASH_LEN.get(current_component["measurement_hash_type"])
            for _ in range(count):
                d = chunk[off: off + hash_len]
                digests.append(bytes(d))
                off += hash_len
            if "pmr_digests" not in current_component:
                current_component["pmr_digests"] = {}
            current_component["pmr_digests"][pmr_id] = {"allowable_digests": digests}
            continue

        # Measurement
        if entry.parent == CFM_V2_COMPONENT_DEVICE_TYPE_ID and entry.type_id == CFM_V2_MEASUREMENT_TYPE_ID:
            pmr_id = chunk[0]
            measurement_id = chunk[1]
            count = chunk[2]
            off = 4
            digests = []
            hash_len = _HASH_LEN.get(current_component["measurement_hash_type"])
            # Each allowable_digest entry: u16 version_set, u8 digest_count, u8 reserved, followed by digest_count * digest_len bytes
            for _ in range(count):
                version_set = _u16(chunk, off)
                digest_count = chunk[off + 2]
                off += 4
                for _ in range(digest_count):
                    d = chunk[off: off + hash_len]
                    digests.append(bytes(d))
                    off += hash_len
            if "measurements" not in current_component:
                current_component["measurements"] = {}
            current_component["measurements"].setdefault(pmr_id, {})
            current_component["measurements"][pmr_id][measurement_id] = { "allowable_digests": digests }
            continue

        # Measurement Data header
        if entry.parent == CFM_V2_COMPONENT_DEVICE_TYPE_ID and entry.type_id == CFM_V2_MEASUREMENT_DATA_TYPE_ID:
            pmr_id = chunk[0]
            measurement_id = chunk[1]
            # Create the node that will receive subsequent allowable_data children
            if "measurement_data" not in current_component:
                current_component["measurement_data"] = {}
            current_component["measurement_data"].setdefault(pmr_id, {})
            node = {"allowable_data": []}
            current_component["measurement_data"][pmr_id][measurement_id] = node
            current_measurement_data_node = node
            continue

        # Allowable Data group: parent=measurement_data
        if entry.parent == CFM_V2_MEASUREMENT_DATA_TYPE_ID and entry.type_id == CFM_V2_ALLOWABLE_DATA_TYPE_ID:
            if current_measurement_data_node is None:
                raise ValueError(f"Malformed order with ID {entry.type_id}")
            flags = chunk[0]
            check = flags & 0x07
            endianness = (flags >> 7) & 0x01
            num_data = chunk[1]
            bitmask_len = _u16(chunk, 2)
            off = 4

            group: Dict[str, Any] = {"check": check, "endianness": endianness, "data": []}

            if bitmask_len:
                bitmask = bytes(chunk[off: off + bitmask_len])
                group["bitmask"] = bitmask
                group["bitmask_length"] = bitmask_len
                off += bitmask_len
                off += _pad4_len(bitmask_len)  # skip padding

            # Read each data entry: u16 version_set, u16 data_length, data bytes, padding to 4
            for _ in range(num_data):
                version_set = _u16(chunk, off)
                data_len = _u16(chunk, off + 2)
                off += 4
                data_bytes = bytes(chunk[off: off + data_len])
                off += data_len
                off += _pad4_len(data_len)
                group["data"].append(data_bytes)

            current_measurement_data_node["allowable_data"].append(group)
            continue

        # Allowable PFM/CFM/PCD
        if entry.parent == CFM_V2_COMPONENT_DEVICE_TYPE_ID and entry.type_id in (
            CFM_V2_ALLOWABLE_PFM_TYPE_ID,
            CFM_V2_ALLOWABLE_CFM_TYPE_ID,
            CFM_V2_ALLOWABLE_PCD_TYPE_ID,
        ):
            manifest_index = chunk[0]   # port (PFM) or index (CFM); PCD uses 0
            platform_len = chunk[1]
            platform = chunk[2: 2 + platform_len].decode("utf-8", errors="strict")

            manifest_node = {"platform": platform, "manifest_id": []}
            last_allowable_manifest = manifest_node

            if entry.type_id == CFM_V2_ALLOWABLE_PFM_TYPE_ID:
                if "allowable_pfm" not in current_component:
                    current_component["allowable_pfm"] = {}
                current_component["allowable_pfm"][manifest_index] = manifest_node
            elif entry.type_id == CFM_V2_ALLOWABLE_CFM_TYPE_ID:
                if "allowable_cfm" not in current_component:
                    current_component["allowable_cfm"] = {}
                current_component["allowable_cfm"][manifest_index] = manifest_node
            else:
                if "allowable_pcd" not in current_component:
                    current_component["allowable_pcd"] = {}
                current_component["allowable_pcd"] = manifest_node
            continue

        # Allowable IDs: parent is one of allowable_* PFM/CFM/PCD
        if entry.type_id == CFM_V2_ALLOWABLE_ID_TYPE_ID and entry.parent in (
            CFM_V2_ALLOWABLE_PFM_TYPE_ID,
            CFM_V2_ALLOWABLE_CFM_TYPE_ID,
            CFM_V2_ALLOWABLE_PCD_TYPE_ID,
        ):
            parent_manifest = last_allowable_manifest
            if parent_manifest is None:
                raise ValueError(f"Malformed order with ID {entry.type_id}")
            flags = chunk[0]
            check = flags & 0x07
            endianness = (flags >> 7) & 0x01
            num_id = chunk[1]
            off = 4
            ids: List[int] = []
            for _ in range(num_id):
                ids.append(_u32(chunk, off))
                off += 4
            parent_manifest["manifest_id"].append({"check": check, "endianness": endianness, "ids": ids})
            continue

        raise ValueError(f"Element with ID {entry.type_id} is not handled in the function")

    return tree
