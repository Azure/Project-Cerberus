#!/usr/bin/env python3

"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""

import os
import sys
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding

def print_usage():
    print ("Usage: {0} <CSR> <CA key> <root CA key>".format (sys.argv[0]))
    sys.exit (1)

if (len (sys.argv) < 4):
    print_usage ()


if (not os.path.exists (sys.argv[1])):
    print ("Can't find CSR file to sign: {0}".format (sys.argv[1]))
    sys.exit (1)

with (open (sys.argv[1], "rb")) as csr_file:
    csr_data = csr_file.read ()
    csr = x509.load_der_x509_csr (csr_data, backend = default_backend ())


if (not os.path.exists (sys.argv[2])):
    print ("Can't find CA key file: {0}".format (sys.argv[2]))
    sys.exit (1)

with (open (sys.argv[2], "rb")) as key_file:
    key_data = key_file.read ()
    ca_key_priv = serialization.load_pem_private_key (key_data, password = None,
        backend = default_backend ())
    ca_key = ca_key_priv.public_key ()
    if ((ca_key_priv.key_size == 384) or (ca_key_priv.key_size > 2048)):
        ca_hash = hashes.SHA384 ()
    else:
        ca_hash = hashes.SHA256 ()


if (not os.path.exists (sys.argv[3])):
    print ("Can't find root CA key file: {0}".format (sys.argv[3]))
    sys.exit (1)

with (open (sys.argv[3], "rb")) as key_file:
    key_data = key_file.read ()
    root_key_priv = serialization.load_pem_private_key (key_data, password = None,
        backend = default_backend ())
    root_key = root_key_priv.public_key ()
    if ((root_key_priv.key_size == 384) or (root_key_priv.key_size > 2048)):
        root_hash = hashes.SHA384 ()
    else:
        root_hash = hashes.SHA256 ()


# Generate the root CA certificate
root = x509.CertificateBuilder ()

root = root.subject_name (x509.Name ([x509.NameAttribute (NameOID.COMMON_NAME, "Root")]))
root = root.issuer_name (x509.Name ([x509.NameAttribute (NameOID.COMMON_NAME, "Root")]))

root = root.serial_number (0x12345678)
root = root.not_valid_before (datetime.datetime (2019, 1, 1, 0, 0, 0))
root = root.not_valid_after (datetime.datetime (9999, 12, 31, 23, 59, 59))

root = root.add_extension (x509.SubjectKeyIdentifier.from_public_key (root_key), critical = False)
root = root.add_extension (x509.AuthorityKeyIdentifier.from_issuer_public_key (root_key),
    critical = False)

root = root.add_extension (x509.BasicConstraints (ca = True, path_length = None), critical = True)
root = root.add_extension (x509.KeyUsage (digital_signature = False, content_commitment = False,
    key_encipherment = False, data_encipherment = False, key_agreement = False,
    key_cert_sign = True, crl_sign = False, encipher_only = False, decipher_only = False),
    critical = True)

root = root.public_key (root_key)
root_cert = root.sign (private_key = root_key_priv, algorithm = root_hash,
    backend = default_backend ())

with (open ("root.crt", "wb")) as cert_file:
    cert_file.write (root_cert.public_bytes (Encoding.DER))


# Generate an intermediate CA certificate
ca = x509.CertificateBuilder ()

ca = ca.subject_name (x509.Name ([x509.NameAttribute (NameOID.COMMON_NAME, "IntrCA")]))
ca = ca.issuer_name (x509.Name ([x509.NameAttribute (NameOID.COMMON_NAME, "Root")]))

ca = ca.serial_number (0x76543210)
ca = ca.not_valid_before (datetime.datetime (2019, 1, 1, 0, 0, 0))
ca = ca.not_valid_after (datetime.datetime (9999, 12, 31, 23, 59, 59))

ca = ca.add_extension (x509.SubjectKeyIdentifier.from_public_key (ca_key), critical = False)
ca = ca.add_extension (x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier (
    root_cert.extensions.get_extension_for_class (x509.SubjectKeyIdentifier).value),
    critical = False)

ca = ca.add_extension (x509.BasicConstraints (ca = True, path_length = None), critical = True)
ca = ca.add_extension (x509.KeyUsage (digital_signature = False, content_commitment = False,
    key_encipherment = False, data_encipherment = False, key_agreement = False,
    key_cert_sign = True, crl_sign = False, encipher_only = False, decipher_only = False),
    critical = True)

ca = ca.public_key (ca_key)
ca_cert = ca.sign (private_key = root_key_priv, algorithm = root_hash,
    backend = default_backend ())

with (open ("ca.crt", "wb")) as cert_file:
    cert_file.write (ca_cert.public_bytes (Encoding.DER))


# Sign the CSR
cert = x509.CertificateBuilder ()

cert = cert.subject_name (csr.subject)
cert = cert.issuer_name (x509.Name ([x509.NameAttribute (NameOID.COMMON_NAME, "IntrCA")]))

cert = cert.serial_number (0x11223344)
cert = cert.not_valid_before (datetime.datetime (2019, 1, 1, 0, 0, 0))
cert = cert.not_valid_after (datetime.datetime (9999, 12, 31, 23, 59, 59))

cert = cert.add_extension (x509.SubjectKeyIdentifier.from_public_key (csr.public_key ()),
    critical = False)
cert = cert.add_extension (x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier (
    ca_cert.extensions.get_extension_for_class (x509.SubjectKeyIdentifier).value),
    critical = False)

for ext in csr.extensions:
    cert = cert.add_extension (ext.value, critical = ext.critical)

cert = cert.public_key (csr.public_key ())
image_cert = cert.sign (private_key = ca_key_priv, algorithm = ca_hash,
    backend = default_backend ())

with (open ("cert.crt", "wb")) as cert_file:
    cert_file.write (image_cert.public_bytes (Encoding.DER))
