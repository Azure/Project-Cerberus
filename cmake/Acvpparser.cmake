# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	Acvpparser.cmake
#
# Abstract:
#
#	CMake build script for acvpparser.
#
# --

set(ACVPPARSER_DIR ${CERBERUS_ROOT}/external/acvpparser)
set(PROTO_DIR ${ACVPPARSER_DIR}/proto)
set(PARSER_DIR ${ACVPPARSER_DIR}/parser)
set(ACVPBACKEND_DIR ${ACVPPARSER_DIR}/backends)
set(PROTOBUFBACKEND_DIR ${ACVPPARSER_DIR}/backend_interfaces/protobuf)
set(PROTOBUF_DIR ${PROTOBUFBACKEND_DIR}/pb)

file(GLOB ACVPPARSER_SOURCES
    ${PROTO_DIR}/proto.c
    ${PROTO_DIR}/proto_aead.c
    ${PROTO_DIR}/proto_ecdsa.c
    ${PROTO_DIR}/proto_hkdf.c
    ${PROTO_DIR}/proto_hmac.c
    ${PROTO_DIR}/proto_rsa.c
    ${PROTO_DIR}/proto_sha.c
    ${PROTO_DIR}/proto_sym.c
    ${PROTOBUFBACKEND_DIR}/src/protobuf-c.c
    ${PROTOBUF_DIR}/aead.pb-c.c
    ${PROTOBUF_DIR}/ecdsa.pb-c.c
    ${PROTOBUF_DIR}/hmac.pb-c.c
    ${PROTOBUF_DIR}/kda_hkdf.pb-c.c
    ${PROTOBUF_DIR}/rsa.pb-c.c
    ${PROTOBUF_DIR}/sha.pb-c.c
    ${PROTOBUF_DIR}/sym.pb-c.c
    ${PARSER_DIR}/algorithms.c
)

set(ACVPPARSER_INCLUDES
    ${CERBERUS_ROOT}/core/acvp
    ${ACVPPARSER_DIR}
    ${PROTO_DIR}
    ${PARSER_DIR}
    ${ACVPBACKEND_DIR}
    ${PROTOBUFBACKEND_DIR}
    ${PROTOBUF_DIR}
)

# Include references for platform memory allocation functions and ignore some warnings
set_source_files_properties(
    ${ACVPPARSER_SOURCES}
    PROPERTIES
    COMPILE_OPTIONS "-Wno-unused-but-set-variable;-Wno-format;-Wno-unused-parameter;-D__EXTERNAL_FRONTEND_HEADER__"
)
