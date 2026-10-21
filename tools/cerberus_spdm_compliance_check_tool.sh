#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# SPDM Compliance Check Tool
#
# Description:
# This tool uses the mctptool in openBMC to send raw MCTP commands to SPDM responder to perform basic sanity checks.
# It implements exact behaviour of the SPDM requester and supports checking below commands:
# a. GET_VERSION
# b. GET_CAPABILITIES
# c. NEGOTIATE_ALGORITHMS
# d. GET_DIGESTS
# e. GET_CERTIFICATE
# f. GET_MEASUREMENTS - Takes CFM XML as input to compare the measurements
# Also takes PCD XML as input to validate the PCIe Identifiers.
#
# Usage:
# To execute this script, run the following command in your terminal:
# ./cerberus_spdm_compliance_check_tool.sh -e <component_eid> -v [spdm_version] -x [cfm_xml_filename] -d [debug_level] -t [timeout] -s -l
# Example:
# ./cerberus_spdm_compliance_check_tool.sh -e 0x5
# ./cerberus_spdm_compliance_check_tool.sh -e 0x5 -v 0x10 // To specify SPDM version (1.0 - 0x10, 1.1 - 0x11, 1.2 - 0x12)
# ./cerberus_spdm_compliance_check_tool.sh -e 0x5 -v 0x11 -x cfm.xml // To specify CFM XML file
# ./cerberus_spdm_compliance_check_tool.sh -e 0x5 -v 0x12 -c component_name -p pcd.xml // To specify component name and PCD XML file
# ./cerberus_spdm_compliance_check_tool.sh -e 0x5 -v 0x12 -x cfm.xml -d 1 // To enable debug mode (0 - No debug, 1 - Basic debug, 2 - Detailed debug)
# ./cerberus_spdm_compliance_check_tool.sh -e 0x5 -v 0x12 -x cfm.xml -d 1 -s // To enable stress test
# ./cerberus_spdm_compliance_check_tool.sh -e 0x5 -v 0x12 -x cfm.xml -d 1 -s -l // To enable logging

#TODOS:
#1. Add support for validating the measurement signature using the certificate chain.
#2. Add support for other SPDM commands - CHALLENGE, KEY_EXCHANGE, FINISH, PSK_EXCHANGE, PSK_FINISH etc.

# Set default values for optional arguments
spdm_version=0x12 # Default SPDM version is 1.2
max_buffer_size_requester=4096 # 4096 bytes
base_hash_algo_bytes=48 # 48 bytes
cfm_xml_filename="" # CFM XML filename
component_name="" # Component name
pcd_xml_filename="" # PCD XML filename
debug_level=0 # Debug level
stress_enabled=0 # Stress test enabled
total_count=0 # Number of stress iterations
success_count=0 # Number of successful iterations
failure_count=0 # Number of failed iterations
summary_report_count=100 # Number of iterations to print summary report
log_enabled=0 # Log enabled
timeout=500 # Sleep duration in miliseconds. Default 500

# Associative arrays to store command arguments for different SPDM versions and commands
declare -A spdm_cmd_common=()
declare -A spdm_cmd_1_0=()
declare -A spdm_cmd_1_1=()
declare -A spdm_cmd_1_2=()

# Variables to store parsed values
declare -A measurement_data=()
declare -A measurement_mask=()
declare -A measurement_digest=()
declare -A printed_ids=()
declare pcd_device_id=""
declare pcd_vendor_id=""
declare pcd_subsystem_device_id=""
declare pcd_subsystem_vendor_id=""
declare cert_cap_flag="" # Get digests and get certs support flag

# Function to display usage information
usage() {
    echo "Usage: $0 -e <component_eid> -v [spdm_version] -x [cfm_xml_filename] -c [component_name] -p [pcd_xml_filename] -d [debug_level] -t [timeout] -s -l"
    echo "Options:"
    echo " -s : Enable stress test"
    echo " -l : Enable logging"
    exit 1
}

# Parse arguments using getopts
while getopts ":e:v:x:c:p:d:slt:" opt; do
    case ${opt} in
        e )
            component_eid=$OPTARG
            ;;
        v )
            spdm_version=$OPTARG
            ;;
	    x )
	        cfm_xml_filename=$OPTARG
	    ;;
        c )
            component_name=$OPTARG
            ;;
        p )
            pcd_xml_filename=$OPTARG
            ;;
        d )
            debug_level=$OPTARG
            ;;
        s )
            stress_enabled=1
            ;;
        l )
            log_enabled=1
            ;;
		t )
			timeout=$OPTARG
			;;
        \? )
            echo "Invalid option: -$OPTARG" 1>&2
            usage
            ;;
        : )
            echo "Option -$OPTARG requires an argument." 1>&2
            usage
            ;;
    esac
done

# Check if all required arguments are provided
if [ -z "$component_eid" ] || [ -z "$spdm_version" ]; then
    usage
fi

#initialize the command arguments for different SPDM versions and commands
mctp_get_message_type="0x00 0x80 0x05"
spdm_cmd_common["GET_VERSION"]="0x05 0x10 0x84 0x00 0x00"
spdm_cmd_1_0["GET_CAPABILITIES"]="0x05 0x10 0xE1 0x0 0x0"
spdm_cmd_1_1["GET_CAPABILITIES"]="0x05 $spdm_version 0xE1 0x00 0x00 0x00 0x1F 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x10 0x00 0x00 0x00 0x10 0x00 0x00"
spdm_cmd_1_2["GET_CAPABILITIES"]="0x05 $spdm_version 0xE1 0x00 0x00 0x00 0x1F 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x10 0x00 0x00 0x00 0x10 0x00 0x00"
spdm_cmd_common["NEGOTIATE_ALGORITHMS"]="0x05 $spdm_version 0xE3 0x00 0x00 0x20 0x00 0x01 0x00 0x90 0x01 0x00 0x00 0x07 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
spdm_cmd_common["GET_DIGESTS"]="0x05 $spdm_version 0x81 00 00"
spdm_cmd_common["GET_CERTIFICATE"]="0x05 $spdm_version 0x82 0x00 0x00"
spdm_cmd_common["GET_MEASUREMENT_DATA"]="0x05 $spdm_version 0xE0 0x03"
spdm_cmd_common["GET_MEASUREMENT_DATA_WITHOUT_SIGNATURE"]="0x05 $spdm_version 0xE0 0x02"
spdm_cmd_common["GET_MEASUREMENT_DIGEST"]="0x05 $spdm_version 0xE0 0x01"
spdm_cmd_common["GET_MEASUREMENT_DIGEST_WITHOUT_SIGNATURE"]="0x05 $spdm_version 0xE0 0x00"
spdm_cmd_common["GET_MEASUREMENT_NONCE"]="0xdb 0x6b 0xf3 0xa5 0xb5 0xab 0x4d 0x67 0xbd 0xb1 0x18 0x40 0x29 0x10 0x7b 0x88 0x8e 0x69 0x4b 0xac 0xf4 0x62 0xe5 0x4a 0x6d 0x68 0xd9 0xd4 0xc6 0xb4 0x60 0x81"
spdm_cmd_1_1["GET_MEASUREMENT_SLOTID"]="0x00"
spdm_cmd_1_2["GET_MEASUREMENT_SLOTID"]="0x00"

# Display input parameters
echo "Input Params: component_eid $component_eid, spdm_version $spdm_version, cfm_xml_filename "$cfm_xml_filename", pcd_xml_filename "$pcd_xml_filename", debug_level $debug_level, stress_enabled $stress_enabled, timeout $timeout"
echo ""

# Helper functions
# Function to convert hex to decimal
hex_to_dec() {
    echo $((16#$1))
}

# Function to convert bits to bytes
bits_to_bytes() {
    local bits=$1
    echo $(( bits / 8 ))
}

# Function to decode hash algorithm
decode_hash_algo() {
    local value=$1

    case $value in
        0x00000000)
            echo "Raw Bit Stream Only"
            ;;
        0x01000000)
            echo "TPM_ALG_SHA_256"
            ;;
        0x02000000)
            echo "TPM_ALG_SHA_384"
            ;;
        0x03000000)
            echo "TPM_ALG_SHA_512"
            ;;
        0x04000000)
            echo "TPM_ALG_SHA3_256"
            ;;
        0x05000000)
            echo "TPM_ALG_SHA3_384"
            ;;
        0x06000000)
            echo "TPM_ALG_SHA3_512"
            ;;
        0x07000000)
            echo "TPM_ALG_SM3_256"
            ;;
        *)
            echo "Unknown"
            ;;
    esac
}

# Function to get hash algorithm bits
get_hash_algo_bits() {
    local algo=$1

    case "$algo" in
        "TPM_ALG_SHA_256")
            echo "256"
            ;;
        "TPM_ALG_SHA_384")
            echo "384"
            ;;
        "TPM_ALG_SHA_512")
            echo "512"
            ;;
        "TPM_ALG_SHA3_256")
            echo "256"
            ;;
        "TPM_ALG_SHA3_384")
            echo "384"
            ;;
        "TPM_ALG_SHA3_512")
            echo "512"
            ;;
        "TPM_ALG_SM3_256")
            echo "256"
            ;;
        *)
            echo "0"
            ;;
    esac
}

# Function to print debug messages
log_debug() {
    local level=$1
    local message=$2

    if [ "$debug_level" -ge "$level" ]; then
        if [ $log_enabled -eq 1 ]; then
            echo "[DEBUG $level]: $message" >> cerberus_spdm_compliance_check_tool_$(date +"%Y-%m-%d").log
        else
            echo "[DEBUG $level]: $message" >&2
        fi
    fi
}

log_error() {
    local message=$1
    if [ $log_enabled -eq 1 ]; then
        echo "[ERROR]: $message" >> cerberus_spdm_compliance_check_tool_`date +"%Y-%m-%d"`.log
    else
        echo "[ERROR]: $message" >&2
    fi
}

log_info() {
    local message=$1
    if [ $log_enabled -eq 1 ]; then
        echo "[INFO]: $message" >> cerberus_spdm_compliance_check_tool_$(date +"%Y-%m-%d").log
    else
        echo "[INFO]: $message" >&2
    fi
}

# Function to validate MCTP raw response
mctp_raw_validate_response() {
    local response="$1"
    local command_name="$2"

    if [[ $response == *"mctptool: Rx:"* ]]; then
        local rx_data=$(echo "$response" | grep -o 'mctptool: Rx: .*' | sed 's/mctptool: Rx: //')
        local status_byte=$(echo "$rx_data" | cut -d' ' -f3)

	if [[ $rx_data == *"not found"* ]]; then
            log_error "EID not found in $command_name response."
            return 1 # Failure
        fi

        if [ "$status_byte" == "7f" ]; then
            log_error "$command_name command failed."
            return 1 # Failure
        fi
    else
        log_error "No response received for $command_name command."
        return 1 # Failure
    fi

    return 0 # Success
}

# Fucntion to send MCTP raw request
send_mctp_raw_request() {
    local command_name="$1"
    shift
    local response=$(mctptool raw -m $component_eid -t $timeout -d "$@")
    if [ $? -ne 0 ]; then
        log_error "mctptool command failed for $command_name."
        return 1 # Failure
    fi

    log_debug 2 "$command_name: $response"

    mctp_raw_validate_response "$response" "$command_name"
    if [ $? -ne 0 ]; then
	    log_error "SPDM validate failed for $command_name."
	    return 1 # Failure
    fi

    echo "$response"
    return 0 # Success
}

# Function to MCTP GET_MESSAGE_TYPE request
send_get_message_type() {
    local command_name="GET_MESSAGE_TYPE"

    log_debug 1 "$command_name"

    response=$(send_mctp_raw_request "$command_name" $mctp_get_message_type)
    if [ $? -ne 0 ]; then
        log_error "$command_name.. Failed"
        return 1 # Failure
    fi

    log_debug 1 "$command_name.. OK"
    return 0 # Success
}

# Function to send SPDM GET_VERSION request
send_get_version_request() {
    local command_name="GET_VERSION"

    log_debug 1 "$command_name"

    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common["$command_name"]})
    if [ $? -ne 0 ]; then
        log_error "$command_name.. Failed"
        return 1 # Failure
    fi

    log_debug 1 "$command_name.. OK"
    return 0 # Success
}

# Function to send SPDM GET_CAPABILITIES request
send_get_capabilities_request() {
    local command_name="GET_CAPABILITIES"
    local max_buffer_size_offset=14  # Offset for max buffer size in response
    local max_buffer_size_length=2  # Length of max buffer size in response

    log_debug 1 "$command_name"

    if [[ "$spdm_version" == "0x10" ]]; then
        response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_1_0["$command_name"]})
    elif [[ "$spdm_version" == "0x11" ]]; then
        response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_1_1["$command_name"]})
    else
        response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_1_2["$command_name"]})
    fi
    if [ $? -ne 0 ]; then
        log_error "$command_name.. Failed"
        return 1 # Failure
    fi

    log_debug 1 "$command_name.. OK"

    if [[ "$spdm_version" == "0x10" || "$spdm_version" == "0x11" ]]; then
        max_buffer_size_requester=$((512-8))
        log_debug 1 "$command_name: Max Buffer Size: $max_buffer_size_requester"
    else
        local processed_response=$(echo "$response" | sed -n 's/.*mctptool: Rx: //p')
        local max_buffer_size_hex=$(echo $processed_response | cut -d ' ' -f $((max_buffer_size_offset))-$((max_buffer_size_offset + max_buffer_size_length - 1)) | tr -d ' ')
        local max_buffer_size_swapped_hex=$(echo $max_buffer_size_hex | sed 's/^\(..\)\(..\)$/\2\1/')

        local max_buffer_size_responder=$((16#$max_buffer_size_swapped_hex))
        if [ $max_buffer_size_responder -lt $max_buffer_size_requester ]; then
            max_buffer_size_requester=$max_buffer_size_responder
        fi

        max_buffer_size_requester=$((max_buffer_size_requester - 8))
        log_debug 1 "$command_name: Max Buffer Size: $max_buffer_size_responder"
        log_debug 1 "$command_name: Max Buffer Size: $max_buffer_size_requester"
    fi

    if [[ "$spdm_version" == "0x11" || "$spdm_version" == "0x12" ]]; then
        local capabilities_flags_offset=10 # Offset for Capabilities flags
        local cert_flag_bit_offset=1 # Bit Offset for Certificate support flag
        local rx_data=$(echo "$response" | grep -o 'mctptool: Rx: .*' | sed 's/mctptool: Rx: //')
        local target_byte=$(echo $rx_data | cut -d ' ' -f $((capabilities_flags_offset)))
        local decimal=$((16#$target_byte))
        local bit_value=$(( (decimal >> $cert_flag_bit_offset) & 1 ))
        if [ $bit_value -eq 1 ]; then
            cert_cap_flag=true
        else
            cert_cap_flag=false
        fi
    else
        cert_cap_flag=true
    fi

    echo $max_buffer_size_requester

    return 0 # Success
}

# Function to send SPDM NEGOTIATE_ALGORITHMS request
send_negotiate_algorithms_request() {
    local command_name="NEGOTIATE_ALGORITHMS"
    local base_hash_algo_offset=18  # Offset for base hash algo in response
    local base_hash_algo_length=4  # Length of base hash algo in response

    log_debug 1 "$command_name"

    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common["$command_name"]})
    if [ $? -ne 0 ]; then
        log_error "$command_name.. Failed"
        return 1 # Failure
    fi

    log_debug 1 "$command_name.. OK"

    local processed_response=$(echo "$response" | sed -n 's/.*mctptool: Rx: //p')
    local base_hash_algo_hex=$(echo $processed_response | cut -d ' ' -f $((base_hash_algo_offset))-$((base_hash_algo_offset + base_hash_algo_length - 1)) | tr -d ' ')
    local base_hash_algo_swapped_hex=$(echo $base_hash_algo_hex | sed 's/^\(..\)\(..\)$/\2\1/')

    log_debug 1 "$command_name: Base Hash Algo: $(decode_hash_algo "0x$base_hash_algo_swapped_hex")"
    local base_hash_algo_bits=$(get_hash_algo_bits "$(decode_hash_algo "0x$base_hash_algo_swapped_hex")")
    base_hash_algo_bytes=$(bits_to_bytes "$base_hash_algo_bits")

    log_debug 1 "$command_name: Base Hash Algo Bytes: $base_hash_algo_bytes"

    return 0 # Success
}

# Function to send SPDM GET_DIGESTS request
send_get_digests_request() {
    local command_name="GET_DIGESTS"

    log_debug 1 "$command_name"

    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common["$command_name"]})
    if [ $? -ne 0 ]; then
        log_error "$command_name.. Failed"
        return 1 # Failure
    fi

    log_debug 1 "$command_name.. OK"

    return 0 # Success
}

# Function to send SPDM GET_CERTIFICATE request
send_get_certificate_chain_portion_request() {
    local command_name="GET_CERTIFICATE"
    local offset_byte1=$1
    local offset_byte2=$2
    local size_byte1=$3
    local size_byte2=$4

    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common["$command_name"]} $offset_byte1 $offset_byte2 $size_byte1 $size_byte2)
    if [ $? -ne 0 ]; then
        return 1 # Failure
    fi

    log_debug 1 ".."

    local processed_response=$(echo "$response" | sed -n 's/.*mctptool: Rx: //p')
    # Process the response here
    echo $processed_response
    return 0 # Success
}

spdm_get_single_certificate_request() {
    local response="$1"
    local cert_offset="$2"
    local cert_index="$3"
    local cert_size="$4"
    local command_name="GET_CERTIFICATE"

    local single_cert_size_offset=11  # Offset for cert buffer size in response
    local single_cert_size_length=2  # Length of cert buffer size in response
    local cert_size_to_fetch=7

    log_debug 1 "$command_name: certificate-$cert_index.bin"

    # Swap bytes (little-endian format)
    offset_byte1=$(printf "0x%02X" $((cert_offset & 0xFF)))  # LSB
    offset_byte2=$(printf "0x%02X" $((cert_offset >> 8)))    # MSB
    size_byte1=$(printf "0x%02X" $((cert_size_to_fetch & 0xFF)))  # LSB
    size_byte2=$(printf "0x%02X" $((cert_size_to_fetch >> 8)))    # MSB

    response=$(send_get_certificate_chain_portion_request $offset_byte1 $offset_byte2 $size_byte1 $size_byte2)
    if [ $? -ne 0 ]; then
        return 1 # Failure
    fi
    chain_portion_response=$(echo "$response" | sed 's/^\(\(\([[:xdigit:]]\{2\} \)\{9\}\)[[:space:]]*\)//')
    echo $chain_portion_response | tr -d ' ' | sed 's/../\\x&/g' | xargs printf '%b' > certificate-$cert_index.bin

    # Increment the offset by the size fetched
    cert_offset=$((cert_offset + cert_size_to_fetch))

    local single_cert_size_hex=$(echo $response | cut -d ' ' -f $((single_cert_size_offset + 1))-$((single_cert_size_offset + single_cert_size_length)) | tr -d ' ')
    local single_cert_size=$((16#$single_cert_size_hex))
    local cert_size_to_fetch=$((single_cert_size - 7 + 4))

    # Swap bytes (little-endian format)
    offset_byte1=$(printf "0x%02X" $((cert_offset & 0xFF)))  # LSB
    offset_byte2=$(printf "0x%02X" $((cert_offset >> 8)))    # MSB
    size_byte1=$(printf "0x%02X" $((cert_size_to_fetch & 0xFF)))  # LSB
    size_byte2=$(printf "0x%02X" $((cert_size_to_fetch >> 8)))    # MSB

    while [ $cert_size_to_fetch -gt $max_buffer_size_requester  ]; do
        log_debug 1 "Fetching certificate chunk of size $max_buffer_size_requester"

        # Swap bytes (little-endian format) for max_buffer_size_requester
        size_byte1=$(printf "0x%02X" $((max_buffer_size_requester & 0xFF)))  # LSB
        size_byte2=$(printf "0x%02X" $((max_buffer_size_requester >> 8)))    # MSB

        # Call send_get_certificate_chain_portion_request to get the chunk
        response=$(send_get_certificate_chain_portion_request $offset_byte1 $offset_byte2 $size_byte1 $size_byte2)
        if [ $? -ne 0 ]; then
            return 1 # Failure
        fi
        chain_portion_response=$(echo "$response" | sed 's/^\(\(\([[:xdigit:]]\{2\} \)\{9\}\)[[:space:]]*\)//')
        echo $chain_portion_response | tr -d ' ' | sed 's/../\\x&/g' | xargs printf '%b' >> certificate-$cert_index.bin

        # Increment the offset by the size fetched
        cert_offset=$((cert_offset + max_buffer_size_requester))
        cert_size_to_fetch=$((cert_size_to_fetch - max_buffer_size_requester))

        # Update offset bytes for next chunk
        offset_byte1=$(printf "0x%02X" $((cert_offset & 0xFF)))  # LSB
        offset_byte2=$(printf "0x%02X" $((cert_offset >> 8)))    # MSB
    done

    # Fetch the remaining part if any
    if [ $cert_size_to_fetch -gt 0 ]; then
        log_debug 1 "Fetching remaining certificate chunk of size $cert_size_to_fetch"
        # Swap bytes (little-endian format) for remaining size
        offset_byte1=$(printf "0x%02X" $((cert_offset & 0xFF)))  # LSB
        offset_byte2=$(printf "0x%02X" $((cert_offset >> 8)))    # MSB
        size_byte1=$(printf "0x%02X" $((cert_size_to_fetch & 0xFF)))  # LSB
        size_byte2=$(printf "0x%02X" $((cert_size_to_fetch >> 8)))    # MSB

        # Call send_get_certificate_chain_portion_request to get the remaining part
        response=$(send_get_certificate_chain_portion_request $offset_byte1 $offset_byte2 $size_byte1 $size_byte2)
        if [ $? -ne 0 ]; then
            return 1 # Failure
        fi
        chain_portion_response=$(echo "$response" | sed 's/^\(\(\([[:xdigit:]]\{2\} \)\{9\}\)[[:space:]]*\)//')
        echo $chain_portion_response | tr -d ' ' | sed 's/../\\x&/g' | xargs printf '%b' >> certificate-$cert_index.bin

        # Increment the offset by the size fetched
        cert_offset=$((cert_offset + cert_size_to_fetch))
    fi

    log_debug 1 "$command_name: certificate-$cert_index.bin.. OK"

    echo $cert_offset
    return 0 # Success
}

# Function to get certificate in chunks
send_get_certificate_requests() {
    local total_cert_size_offset=9  # Offset for cert buffer size in response
    local total_cert_size_length=2  # Length of cert buffer size in response
    local cert_index=1
    local cert_offset=0
    local cert_size_to_fetch=$((4 + base_hash_algo_bytes))  # 4 bytes for cert size and base hash algo bytes

    # Swap bytes (little-endian format)
    offset_byte1=$(printf "0x%02X" $((cert_offset & 0xFF)))  # LSB
    offset_byte2=$(printf "0x%02X" $((cert_offset >> 8)))    # MSB
    size_byte1=$(printf "0x%02X" $((cert_size_to_fetch & 0xFF)))  # LSB
    size_byte2=$(printf "0x%02X" $((cert_size_to_fetch >> 8)))    # MSB

    # fetch the certificate chain header
    response=$(send_get_certificate_chain_portion_request $offset_byte1 $offset_byte2 $size_byte1 $size_byte2)
    if [ $? -ne 0 ]; then
        return 1 # Failure
    fi
    cert_offset=$((cert_offset + cert_size_to_fetch))

    local total_cert_size_hex=$(echo $response | cut -d ' ' -f $((total_cert_size_offset + 1))-$((total_cert_size_offset + total_cert_size_length)) | tr -d ' ')
    local total_cert_size=$((16#$(echo "$total_cert_size_hex" | sed 's/\(..\)\(..\)/\2\1/')))

    cert_offset=$(spdm_get_single_certificate_request "$response" $cert_offset $cert_index $single_cert_size)
    if [ $? -ne 0 ]; then
        return 1 # Failure
    fi
    cert_index=$((cert_index + 1))

    while [ $cert_offset -lt $total_cert_size ]; do
        cert_offset=$(spdm_get_single_certificate_request "$response" $cert_offset $cert_index $single_cert_size)
        if [ $? -ne 0 ]; then
            return 1 # Failure
        fi
        cert_index=$((cert_index + 1))
    done

    echo $((cert_index - 1))
    return 0 # Success
}

spdm_validate_certificates_using_openssl() {
    local num_certs=$1

    log_debug 1 "Converting the certs to PEM and Text format"
    for i in $(seq 1 $num_certs)
    do
        log_debug 1 "certificate-${i}.bin => certificate-${i}.pem"
        openssl x509 -inform der -in ./certificate-${i}.bin -out certificate-${i}.pem 2>&1
        openssl x509 -in ./certificate-${i}.pem -noout -text > certificate-${i}.txt 2>&1
    done
    log_debug 1 "Converting the certs to PEM and Text format.. OK"

    # Construct the certificate verify command
    verify_cmd="openssl verify -ignore_critical -show_chain -verbose -CAfile certificate-1.pem" 2>&1
    for i in $(seq 2 $((num_certs-1))); do
        verify_cmd+=" -untrusted certificate-${i}.pem"
    done
    log_debug 1 ""

    # The last certificate to verify
    verify_cmd+=" certificate-${num_certs}.pem"

    # Execute the verify command
    log_debug 1 "Validating Certs: $verify_cmd"
    $verify_cmd > /dev/null 2>&1

    # Check the status of the verify command
    if [ $? -eq 0 ]; then
        log_debug 1 "Validating Certs.. OK"
    else
        log_error "Validating Certs.. Failed"
        return 1 # Failure
    fi

    return 0 # Success
}

# Function to parse PCD XML for PCIe Identifiers
parse_pcd_xml() {
    local component_name="$1"
    local pcd_xml_filename="$2"

    # Extract the relevant component block
    component_block=$(sed -n "/<Component type=\"$component_name\"/,/<\/Component>/p" "$pcd_xml_filename")
    if [ -z "$component_block" ]; then
        log_error "Failed to extract component block for $component_name from PCD XML."
        return 1 # Failure
    fi

    # Extract values using grep and sed
    # Extract individual values
    pcd_device_id=$(echo "$component_block" | grep "<DeviceID>" | sed -e 's/<[^>]*>//g' -e 's/^[ \t]*//')
    pcd_vendor_id=$(echo "$component_block" | grep "<VendorID>" | sed -e 's/<[^>]*>//g' -e 's/^[ \t]*//')
    pcd_subsystem_device_id=$(echo "$component_block" | grep "<SubsystemDeviceID>" | sed -e 's/<[^>]*>//g' -e 's/^[ \t]*//')
    pcd_subsystem_vendor_id=$(echo "$component_block" | grep "<SubsystemVendorID>" | sed -e 's/<[^>]*>//g' -e 's/^[ \t]*//')

    return 0 # Success
}

# Function to parse MeasurementData and Measurement
parse_cfm_xml() {
  local cfm_xml_filename="$1"

  local in_measurement_data=0
  local in_measurement=0
  local measurement_id=""
  local data=""
  local mask=""
  local digest=""

  while IFS= read -r line; do
    # Check if we are entering a MeasurementData block
    if [[ $line =~ \<MeasurementData ]]; then
      in_measurement_data=1
      measurement_id=$(echo "$line" | sed -n 's/.*measurement_id="\([0-9]*\)".*/\1/p')
      data=""
      mask=""
    elif [[ $line =~ \<\/MeasurementData ]]; then
      if [[ $in_measurement_data -eq 1 ]]; then
        measurement_data[$measurement_id]=$data
        measurement_mask[$measurement_id]=$mask
        in_measurement_data=0
      fi
    elif [[ $in_measurement_data -eq 1 ]]; then
      if [[ $line =~ \<Data ]]; then
        data=$(echo "$line" | sed -n 's/.*<Data>\(.*\)<\/Data>.*/\1/p')
      elif [[ $line =~ \<Bitmask ]]; then
        mask=$(echo "$line" | sed -n 's/.*<Bitmask>\(.*\)<\/Bitmask>.*/\1/p')
      fi
    fi

    # Check if we are entering a Measurement block
    if [[ $line =~ \<Measurement[^D] ]]; then
      in_measurement=1
      measurement_id=$(echo "$line" | sed -n 's/.*measurement_id="\([0-9]*\)".*/\1/p')
      digest=""
    elif [[ $line =~ \<\/Measurement[^D] ]]; then
      if [[ $in_measurement -eq 1 ]]; then
        measurement_digest[$measurement_id]=$digest
        in_measurement=0
      fi
    elif [[ $in_measurement -eq 1 ]]; then
      if [[ $line =~ \<Digest ]]; then
        digest=$(echo "$line" | sed -n 's/.*<Digest>\(.*\)<\/Digest>.*/\1/p')
      fi
    fi
  done < "$cfm_xml_filename"
}

compare_and_mask() {
    local data=$1
    local mask=$2
    local masked_data=""

    # Split data and mask into 2-character chunks (hex pairs)
    data_array=($(echo $data | sed 's/\(..\)/\1 /g'))
    mask_array=($(echo $mask | sed 's/\(..\)/\1 /g'))

    # Apply the mask
    for i in "${!data_array[@]}"; do
        # Convert hex to decimal and apply bitwise AND
        data_byte=$((16#${data_array[i]}))
        mask_byte=$((16#${mask_array[i]}))

        # Perform the AND operation and convert back to hex
        result_byte=$(printf "%02x" $((data_byte & mask_byte)))

        # Append the result to the masked data string
        masked_data+="$result_byte"
    done

    echo "$masked_data"
}

compare_data_with_mask() {
    local response=$1
    local measurement_data_expected=$2
    local measurement_mask=$3
    local measurement_length_offset=14  # Offset for measurement length in response
    local measurement_data_offset=16    # Offset for measurement data in response

    if [[ $response == *"mctptool: Rx:"* ]]; then
        local rx_data=$(echo "$response" | grep -o 'mctptool: Rx: .*' | sed 's/mctptool: Rx: //')

        # Extract measurement length from the response (hex value at offset 12)
        local measurement_length_hex=$(echo $rx_data | cut -d ' ' -f $((measurement_length_offset + 1)))
        local measurement_length=$((16#$measurement_length_hex))

        # Extract measurement data
        local start_index=$((measurement_data_offset + 1))
        local end_index=$((start_index + measurement_length - 1))
        local measurement_data=$(echo $rx_data | cut -d ' ' -f $start_index-$end_index | tr -d ' ')
	    log_debug 1 "measurement_data=$measurement_data"

        # Apply the mask to both the extracted measurement data and the expected measurement data
        local masked_measurement_data=$(compare_and_mask "$measurement_data" "$measurement_mask")
        local masked_expected_data=$(compare_and_mask "$measurement_data_expected" "$measurement_mask")

        if [ $debug_level -gt 0 ]; then
            log_debug 1 "measurement_data_expected=$measurement_data_expected"
            log_debug 1 "measurement_mask=$measurement_mask"
            log_debug 1  ""
            log_debug 1  "measurement_data_recieved=$measurement_data"
            log_debug 1  ""
            log_debug 1  "rx_data=$rx_data"
        fi

        # Ensure the extracted and expected data have the correct masked values
        if [[ "$masked_measurement_data" == "$masked_expected_data" ]]; then
            return 0  # Success: masked data matches
        else
            return 1  # Failure: masked data doesn't match
        fi
    else
        return 1  # Failure: No valid response data found
    fi
}

# Function to compare digest from response with the expected digest
compare_digest() {
    local response=$1
    local expected_digest=$2
    local measurement_length_offset=14  # Offset for measurement length in response
    local measurement_data_offset=16    # Offset for measurement data in response

    log_debug 1 "expected_digest=$expected_digest"

    if [[ $response == *"mctptool: Rx:"* ]]; then
        local rx_data=$(echo "$response" | grep -o 'mctptool: Rx: .*' | sed 's/mctptool: Rx: //')

        # Extract measurement length from the response (hex value at offset 12)
        local measurement_length_hex=$(echo $rx_data | cut -d ' ' -f $((measurement_length_offset + 1)))
        local measurement_length=$((16#$measurement_length_hex))

        # Extract measurement data
        local start_index=$((measurement_data_offset + 1))
        local end_index=$((start_index + measurement_length - 1))
        local measurement_data=$(echo $rx_data | cut -d ' ' -f $start_index-$end_index | tr -d ' ')

    	# Ensure the extracted measurement data length matches the expected digest length
    	expected_length=$((${#expected_digest} / 2))

    	if [[ $expected_length -ne $measurement_length ]]; then
            log_error "Error: Measurement length mismatch."
	        return 1 # Failure
        fi

        if [ $debug_level -gt 0 ]; then
            log_debug 1  "measurement_digest_expected=$expected_digest"
            log_debug 1  "measurement_digest_recieved=$measurement_data"
            log_debug 1  ""
            log_debug 1  "rx_data=$rx_data"
        fi

        #Compare the extracted measurement data with the expected digest
	if [[ "${measurement_data,,}" = "${expected_digest,,}" ]]; then
            return 0  # Success
        else
            return 1  # Failure
        fi
    else
    	return 1 # Failure
    fi
}

validate_cfm_xml_measurements() {
    local measurement_id
    local measurement_status=0

    # Print stored values in the correct order
    for measurement_id in "${!measurement_data[@]}" "${!measurement_digest[@]}"; do
        local command_name="GET_MEASUREMENT"
        log_debug 1 "$command_name ($measurement_id)"
        if [[ -n ${measurement_data[$measurement_id]} ]]; then
            if [ "$cert_cap_flag" = "true" ]; then
                if [ "$spdm_version" == "0x10" ]; then
                    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DATA"]} $measurement_id ${spdm_cmd_common[$command_name"_NONCE"]})
                elif [ "$spdm_version" == "0x11" ]; then
                    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DATA"]} $measurement_id ${spdm_cmd_common[$command_name"_NONCE"]} ${spdm_cmd_1_1[$command_name"_SLOTID"]})
                else
                    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DATA"]} $measurement_id ${spdm_cmd_common[$command_name"_NONCE"]} ${spdm_cmd_1_2[$command_name"_SLOTID"]})
                fi
            else
                response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DATA_WITHOUT_SIGNATURE"]} $measurement_id)
            fi
        else
            if [ "$cert_cap_flag" = "true" ]; then
                if [ "$spdm_version" == "0x10" ]; then
                    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DIGEST"]} $measurement_id ${spdm_cmd_common[$command_name"_NONCE"]})
                elif [ "$spdm_version" == "0x11" ]; then
                    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DIGEST"]} $measurement_id ${spdm_cmd_common[$command_name"_NONCE"]} ${spdm_cmd_1_1[$command_name"_SLOTID"]})
                else
                    response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DIGEST"]} $measurement_id ${spdm_cmd_common[$command_name"_NONCE"]} ${spdm_cmd_1_2[$command_name"_SLOTID"]})
                fi
            else
                response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DIGEST_WITHOUT_SIGNATURE"]} $measurement_id)
            fi
        fi

        if [ $? -ne 0 ]; then
            log_error "$command_name.. Failed"
            return 1 # Failure
        else
            log_debug 1 "$command_name ($measurement_id).. OK"
        fi

        log_debug 2 "$response"

        # Compare the measurement with CFM XML contents
        if [[ -n ${measurement_data[$measurement_id]} ]]; then
            compare_data_with_mask "$response" "${measurement_data[$measurement_id]}" "${measurement_mask[$measurement_id]}"
            if [ $? -eq 0 ]; then
                log_debug 1 "Comparing Measurement ID: $measurement_id.. OK"
            else
                log_error "Comparing Measurement ID: $measurement_id.. Failed"
                measurement_status=1
            fi
        elif [[ -n ${measurement_digest[$measurement_id]} ]]; then
            compare_digest "$response" "${measurement_digest[$measurement_id]}"
            if [ $? -eq 0 ]; then
                log_debug 1 "Comparing Measurement ID: $measurement_id.. OK"
            else
                log_error "Comparing Measurement ID: $measurement_id.. Failed"
                measurement_status=1
            fi
        fi
        log_debug 1 ""
    done

    if [ $measurement_status -eq 1 ]; then
        return 1 # Failure
    fi

    return 0 # Success
}

function ctrl_c() {
    total_count=$((success_count + failure_count))
    cerberus_spdm_compliance_check_tool_summary

    rm -f certificate-*.pem certificate-*.txt certificate-*.bin
    exit 1
}

function cerberus_spdm_compliance_check_tool_summary() {
        echo ""
        echo "SPDM Compliance Check Tool Summary.."

        echo "Success Count: $success_count"
        echo "Failure Count: $failure_count"
        echo ""
        echo "Total Count: $total_count"
        echo ""
}

main() {
    # trap ctrl-c and call ctrl_c()
    trap ctrl_c INT

    echo "SPDM Compliance Check Tool.."

    while :
    do
        echo -n "."

        # Dicover the component EID
        if [ -n "$pcd_xml_filename" ] && [ -n "$component_name" ]; then
            local command_name="GET_MEASUREMENT"
            local measurement_id=""

            log_debug 1 "Device Discovery.."

            if [[ "$spdm_version" != "0x11" && "$spdm_version" != "0x12" ]]; then
                log_error "Unsupported SPDM version: $spdm_version"
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi

            log_debug 1 "Component Name: $component_name, PCD XML File: $pcd_xml_filename"
            parse_pcd_xml $component_name $pcd_xml_filename
	    if [ $? -ne 0 ]; then
		log_error "Failed to parse PCD XML."
		failure_count=$((failure_count + 1))
		if [ $stress_enabled -eq 0 ]; then
		    break
		else
		    continue
		fi
	    fi

            send_get_message_type
            if [ $? -ne 0 ]; then
                log_error "GET_MESSAGE_TYPE command failed."
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi

            send_get_version_request
            if [ $? -ne 0 ]; then
                log_error "GET_VERSION command failed."
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi

            max_buffer_size_requester=$(send_get_capabilities_request)
            if [ $? -ne 0 ]; then
                log_error "GET_CAPABILITIES command failed."
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi

            log_debug 1 "Max Buffer Size: $max_buffer_size_requester"

            send_negotiate_algorithms_request
            if [ $? -ne 0 ]; then
                log_error "NEGOTIATE_ALGORITHMS command failed."
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi

            log_debug 1 "Base Hash Algo Bytes: $base_hash_algo_bytes"

            if [[ "$spdm_version" == "0x11" ]]; then
                measurement_id=0x0
            elif [[ "$spdm_version" == "0x12" ]]; then
                measurement_id=0xef
            fi

            log_debug 1 "$command_name ($measurement_id)"
            response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DATA_WITHOUT_SIGNATURE"]} $measurement_id)

            if [ $? -ne 0 ]; then
                log_error "$command_name.. Failed"
                return 1 # Failure
            else
                log_debug 1 "$command_name ($measurement_id).. OK"
            fi

            local vendor_id_offset=27
            local vendor_id_length=2
            local device_id_offset=33
            local device_id_length=2
            local subsystem_vendor_id_offset=39
            local subsystem_vendor_id_length=2
            local subsystem_device_id_offset=45
            local subsystem_device_id_length=2
            local number_of_blocks_offset=5
            local number_of_blocks_length=1

            if [[ "$spdm_version" == "0x11" ]]; then
                local processed_response=$(echo "$response" | sed -n 's/.*mctptool: Rx: //p')
                local number_of_blocks_hex=$(echo $processed_response | cut -d ' ' -f $((number_of_blocks_offset))-$((number_of_blocks_offset + number_of_blocks_length - 1)) | tr -d ' ')
                local number_of_blocks_swapped_hex=$(echo $number_of_blocks_hex | sed 's/^\(..\)\(..\)$/\2\1/')
                local number_of_blocks=$((16#$number_of_blocks_swapped_hex))
                measurement_id=$((number_of_blocks - 1))

                log_debug 1 "$command_name ($measurement_id)"
                response=$(send_mctp_raw_request "$command_name" ${spdm_cmd_common[$command_name"_DATA_WITHOUT_SIGNATURE"]} $measurement_id)

                if [ $? -ne 0 ]; then
                    log_error "$command_name.. Failed"
                    return 1 # Failure
                else
                    log_debug 1 "$command_name ($measurement_id).. OK"
                fi
            fi

            local processed_response=$(echo "$response" | sed -n 's/.*mctptool: Rx: //p')
            local device_id_hex=$(echo $processed_response | cut -d ' ' -f $((device_id_offset))-$((device_id_offset + device_id_length - 1)) | tr -d ' ')
            local device_id_swapped_hex=$(echo $device_id_hex | sed 's/^\(..\)\(..\)$/\2\1/')
            local device_id="0x$device_id_swapped_hex"

            local vendor_id_hex=$(echo $processed_response | cut -d ' ' -f $((vendor_id_offset))-$((vendor_id_offset + vendor_id_length - 1)) | tr -d ' ')
            local vendor_id_swapped_hex=$(echo $vendor_id_hex | sed 's/^\(..\)\(..\)$/\2\1/')
            local vendor_id="0x$vendor_id_swapped_hex"

            local subsystem_device_id_hex=$(echo $processed_response | cut -d ' ' -f $((subsystem_device_id_offset))-$((subsystem_device_id_offset + subsystem_device_id_length - 1)) | tr -d ' ')
            local subsystem_device_id_swapped_hex=$(echo $subsystem_device_id_hex | sed 's/^\(..\)\(..\)$/\2\1/')
            local subsystem_device_id="0x$subsystem_device_id_swapped_hex"

            local subsystem_vendor_id_hex=$(echo $processed_response | cut -d ' ' -f $((subsystem_vendor_id_offset))-$((subsystem_vendor_id_offset + subsystem_vendor_id_length - 1)) | tr -d ' ')
            local subsystem_vendor_id_swapped_hex=$(echo $subsystem_vendor_id_hex | sed 's/^\(..\)\(..\)$/\2\1/')
            local subsystem_vendor_id="0x$subsystem_vendor_id_swapped_hex"

            if [ "${pcd_device_id,,}" != "${device_id,,}" ] || [ "${pcd_vendor_id,,}" != "${vendor_id,,}" ] || [ "${pcd_subsystem_device_id,,}" != "${subsystem_device_id,,}" ] || [ "${pcd_subsystem_vendor_id,,}" != "${subsystem_vendor_id,,}" ]; then
                log_error "Device Discovery.. Failed"

                log_debug 1 "pcd_device_id=$pcd_device_id, pcd_vendor_id=$pcd_vendor_id, pcd_subsystem_device_id=$pcd_subsystem_device_id, pcd_subsystem_vendor_id=$pcd_subsystem_vendor_id"
                log_debug 1 "device_id_recieved=$device_id, vendor_id_recieved=$vendor_id, subsystem_device_id_recieved=$subsystem_device_id, subsystem_vendor_id_recieved=$subsystem_vendor_id"
                log_debug 1 ""
                log_debug 1  "rx_data=$processed_response"

                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            else
                log_debug 1 "Device Discovery.. OK"
            fi
        fi

        # Validate the measurements
        send_get_version_request
        if [ $? -ne 0 ]; then
            log_error "GET_VERSION command failed."
            failure_count=$((failure_count + 1))
            if [ $stress_enabled -eq 0 ]; then
                break
            else
                continue
            fi
        fi

        max_buffer_size_requester=$(send_get_capabilities_request)
        if [ $? -ne 0 ]; then
            log_error "GET_CAPABILITIES command failed."
            failure_count=$((failure_count + 1))
            if [ $stress_enabled -eq 0 ]; then
                break
            else
                continue
            fi
        fi

        log_debug 1 "Max Buffer Size: $max_buffer_size_requester"

        send_negotiate_algorithms_request
        if [ $? -ne 0 ]; then
            log_error "NEGOTIATE_ALGORITHMS command failed."
            failure_count=$((failure_count + 1))
            if [ $stress_enabled -eq 0 ]; then
                break
            else
                continue
            fi
        fi

        log_debug 1 "Base Hash Algo Bytes: $base_hash_algo_bytes"

        if [ "$cert_cap_flag" = "true" ]; then
            send_get_digests_request
            if [ $? -ne 0 ]; then
                log_error "Error: GET_DIGESTS command failed."
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi

            local num_certs=$(send_get_certificate_requests)
            if [ $? -ne 0 ]; then
                log_error "GET_CERTIFICATE command failed."
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi
            log_debug 1 "Number of Certificates: $num_certs"

            if [ -z "$num_certs" ] || [ $num_certs -eq 0 ]; then
                log_error "No certificates found."
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi

            spdm_validate_certificates_using_openssl $num_certs
        fi

        if [ -z "$cfm_xml_filename" ]; then
            log_debug 1 "No CFM File provided, Skipping measurements check."
        else
            parse_cfm_xml $cfm_xml_filename
            validate_cfm_xml_measurements
            if [ $? -ne 0 ]; then
                log_error "Measurements validation failed."
                failure_count=$((failure_count + 1))
                if [ $stress_enabled -eq 0 ]; then
                    break
                else
                    continue
                fi
            fi
        fi

        if [ "$cert_cap_flag" = "true" ]; then
            rm -f certificate-*.pem certificate-*.txt certificate-*.bin
        fi
        success_count=$((success_count + 1))

        if [ -z "$stress_enabled" ] || [ "$stress_enabled" -eq 0 ]; then
            break
        fi

        total_count=$((success_count + failure_count))
        if [ $total_count -ne 0 ] && [ $((total_count % $summary_report_count)) -eq 0 ]; then
            cerberus_spdm_compliance_check_tool_summary
        fi
    done

    echo "SPDM Compliance Check Tool.. OK"

}

# Call the main function
main
