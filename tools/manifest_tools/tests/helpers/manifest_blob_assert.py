"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

from typing import Iterable, Mapping, Any

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256, SHA384, SHA512

from .manifest_blob_parse import (Manifest, CFM_V2_MEASUREMENT_TYPE_ID)

# -------------------------
# Basic checks
# -------------------------


def assert_header(m: Manifest, *, magic: int, sig_len: int = None) -> None:
    assert m.header.magic == magic, f"magic mismatch: 0x{m.header.magic:08x}"
    if sig_len is not None:
        assert m.header.sig_length == sig_len, f"sig_length mismatch: {m.header.sig_length} != {sig_len}"

# -------------------------
# Hash integrity checks
# -------------------------


def assert_hashes_valid(m: Manifest) -> None:
    """
    Recompute element hashes and table hash and compare against parsed values.
    """
    # Ensure that the parser already computed hashes
    assert m.computed_hashes is not None, "Computed hashes not present on manifest object"
    # Compare element hashes by index
    for idx, (parsed_h, comp_h) in enumerate(zip(m.hashes, m.computed_hashes)):
        assert parsed_h == comp_h, f"Element hash mismatch at index {idx}: parsed {parsed_h.hex()} != computed {comp_h.hex()}"
    # Table hash
    assert m.table_hash == m.computed_table_hash, (
        f"Table hash mismatch: parsed {m.table_hash.hex()} != computed {m.computed_table_hash.hex()}"
    )

# -------------------------
# Signature verification
# -------------------------


def _load_public_key_from_pem(pem_bytes: bytes):
    """
    Load RSA public key from PEM. If PEM contains a private key, derive public key.
    """
    key = RSA.import_key(pem_bytes)
    return key.publickey() if key.has_private() else key


def assert_signature_valid(m, key_pem_path: str) -> None:
    """
    Verify RSA PKCS#1 v1.5 signature over the signed_bytes using the hash that matches toc_header.hash_type.
    - key_pem_path may point to a private key (we derive public key) or a public key.
    - Raises AssertionError on mismatch; raises NotImplementedError for non-RSA sig types.
    """
    # Ensure we have the signed bytes available
    assert hasattr(
        m, "signed_bytes") and m.signed_bytes is not None, "signed_bytes not present on manifest object"

    with open(key_pem_path, "rb") as f:
        pem = f.read()

    # Determine hash algorithm for signature
    if m.header.sig_length == 256:
        hash_engine = SHA256.new(m.signed_bytes)
    elif m.header.sig_length == 384:
        hash_engine = SHA384.new(m.signed_bytes)
    elif m.header.sig_length == 512:
        hash_engine = SHA512.new(m.signed_bytes)
    else:
        raise ValueError(
            f"Unsupported size for signature: {m.header.sig_length}")

    # For now we support RSA PKCS#1 v1.5
    if (m.header.sig_type >> 6) != 0:
        raise NotImplementedError(
            f"Signature type {(m.header.sig_type >> 6)} not supported by this verifier")

    # Load public key (from private or public PEM)
    try:
        pub = _load_public_key_from_pem(pem)
    except Exception as ex:
        raise AssertionError(f"Failed to load key: {ex}")

    # Verify
    verifier = PKCS1_v1_5.new(pub)
    if not verifier.verify(hash_engine, m.signature):
        raise AssertionError("Signature verification failed")
