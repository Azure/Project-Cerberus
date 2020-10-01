#!/usr/bin/env python3

"""
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the MIT license.
"""


import os
import sys
import ctypes

from enum import Enum
from Crypto.Hash import SHA256


TCG_EFI_NO_ACTION_EVENT_TYPE = 0x03
TCG_SERVER_PLATFORM_CLASS = 0x01
TCG_SHA256_ALG_ID = 0x0B
TCG_UINT_SIZE_32 = 0x01
TCG_LOG_SIGNATURE =	"Spec ID Event03"

EVENT_HASH_INCORRECT_ERROR_STR = "PCR {} Event ID {} digest does not match event hash"
EVENT_NON_ZERO_ERROR_STR = "PCR {} Event ID {} nonzero despite digest unset"
LOG_LENGTH_ERROR_STR = "Log length too small"
UNSUPPORTED_HASHING_ALGO_ERROR_STR = "Event uses unsupported hashing algorithm {}"
UNSUPPORTED_DIGEST_COUNT_ERROR_STR = "Event uses unsupported number of digests {}"


class Error_Types (Enum):
	UNSUPPORTED_FORMAT_ERROR_TYPE_STR = "Unsupported format"
	INVALID_EVENT_ERROR_TYPE_STR = "Event invalid"

class tcg_event(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('pcr_bank', ctypes.c_uint32),
                ('event_type', ctypes.c_uint32),
                ('pcr', ctypes.c_char * 20),
                ('event_size', ctypes.c_uint32)]

class tcg_algorithm(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('digest_algorithm_id', ctypes.c_uint16),
                ('digest_size', ctypes.c_uint16)]

class tcg_log_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('signature', ctypes.c_char * 16),
                ('platform_class', ctypes.c_uint32),
                ('spec_version_minor', ctypes.c_ubyte),
                ('spec_version_major', ctypes.c_ubyte),
                ('spec_errata', ctypes.c_ubyte),
                ('uintn_size', ctypes.c_ubyte),
				('num_algorithms', ctypes.c_uint32)]

class tcg_event2(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('pcr_bank', ctypes.c_uint32),
                ('event_type', ctypes.c_uint32),
                ('digest_count', ctypes.c_uint32),
                ('digest_algorithm_id', ctypes.c_uint16)]


def print_error (error_type, error_msg):
	"""
    Display error message

    :param error_type: Error type from Error_Types enum
    :param error_msg: Error message string
    """

	print ("TCG Log Test Error | " + error_type.value + " | " + error_msg)

	if error_type == Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR:
		sys.exit (1)

def process_tcg_event (max_len, event):
	"""
    Process TCG event entry

    :param max_len: Maximum entry length
    :param event: Address of entry data

    :return Actual entry length
    """

	if max_len < ctypes.sizeof (tcg_event):
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, LOG_LENGTH_ERROR_STR)

	old_event = ctypes.cast (event, ctypes.POINTER (tcg_event))
	
	if old_event.contents.event_type != TCG_EFI_NO_ACTION_EVENT_TYPE:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, "First event not no action")

	if old_event.contents.event_size < (ctypes.sizeof (tcg_log_header) + 
		ctypes.sizeof (tcg_algorithm) + ctypes.sizeof (ctypes.c_uint8)):
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			"TCG log header size unexpected: {}".format (old_event.contents.event_size))

	return ctypes.sizeof (tcg_event)

def process_tcg_log_header (max_len, header):
	"""
    Process TCG log header

    :param max_len: Maximum header length
    :param header: Address of header data

    :return Actual header length, a list of hashing algorithms used in log
    """

	if max_len < ctypes.sizeof (tcg_log_header):
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, LOG_LENGTH_ERROR_STR)

	log_header = ctypes.cast (header, ctypes.POINTER (tcg_log_header))

	if log_header.contents.signature.decode ("utf-8") != TCG_LOG_SIGNATURE:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			"Unexpected TCG log header signature: {}".format (
				log_header.contents.signature.decode ("utf-8")))
	
	if log_header.contents.platform_class != TCG_SERVER_PLATFORM_CLASS:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			"Unexpected TCG log header platform class: {}".format (
				log_header.contents.platform_class))

	if log_header.contents.spec_version_minor != 0:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			"Spec version 2.00 not supported: Minor version {}".format (
				log_header.contents.spec_version_minor))

	if log_header.contents.spec_version_major != 2:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			"Spec version 2.00 not supported: Major version {}".format (
				log_header.contents.spec_version_major))

	if log_header.contents.spec_errata != 0:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			"Spec version 2.00 not supported: Errata {}".format (
				log_header.contents.spec_version_major))

	if log_header.contents.uintn_size != TCG_UINT_SIZE_32:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			"Unsupported integer length {}".format (log_header.contents.uintn_size))

	offset = ctypes.sizeof (tcg_log_header)
	algorithms = {}

	for i_algorithm in range (log_header.contents.num_algorithms):
		if max_len < (ctypes.sizeof (tcg_algorithm) + offset):
			print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, LOG_LENGTH_ERROR_STR)

		algorithm = ctypes.cast (header + offset, ctypes.POINTER (tcg_algorithm))
		algorithms.update ({algorithm.contents.digest_algorithm_id : 
			algorithm.contents.digest_size})
		offset += ctypes.sizeof (tcg_algorithm)

	if max_len < (offset + ctypes.sizeof (ctypes.c_uint8)):
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, LOG_LENGTH_ERROR_STR)
	
	vendor_info_len = (ctypes.c_uint8).from_address(header + offset).value
	log_header_len = offset + ctypes.sizeof (ctypes.c_uint8) + vendor_info_len

	return (log_header_len, algorithms)

def process_tcg_event2 (max_len, event, algorithms, pcr_banks, entries_with_events_list):
	"""
    Process TCG log event2 entry

    :param max_len: Maximum event length
    :param event: Address of event data
    :param algorithms: List of algorithms utilized in log as per log header
    :param pcr_banks: Dictionary of hashing objects used to compute PCR measurement, keyed by PCR numbers
    :param entries_with_events_list: List of event types which include event data

    :return Actual event length, updated pcr_banks, updated entries_with_events_list
    """

	if max_len < ctypes.sizeof (tcg_event2):
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, LOG_LENGTH_ERROR_STR)

	curr_event = ctypes.cast (event, ctypes.POINTER (tcg_event2))

	if curr_event.contents.digest_count != 1:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			UNSUPPORTED_DIGEST_COUNT_ERROR_STR.format (curr_event.contents.digest_count))
	
	if curr_event.contents.digest_algorithm_id not in algorithms:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			UNSUPPORTED_HASHING_ALGO_ERROR_STR.format (curr_event.contents.digest_algorithm_id))

	# Currently on SHA256 is supported by this test tool
	if curr_event.contents.digest_algorithm_id != TCG_SHA256_ALG_ID:
		print_error (Error_Types.UNSUPPORTED_FORMAT_ERROR_TYPE_STR, 
			UNSUPPORTED_HASHING_ALGO_ERROR_STR.format (curr_event.contents.digest_algorithm_id))

	hash_len = algorithms[curr_event.contents.digest_algorithm_id]
	digest = (ctypes.c_uint8 * hash_len).from_address(event + ctypes.sizeof (tcg_event2))

	if curr_event.contents.pcr_bank not in pcr_banks:
		hash_1 = SHA256.new (bytes ([0 for _ in range (hash_len)]))
	else:
		hash_1 = SHA256.new (pcr_banks[curr_event.contents.pcr_bank].digest ())

	hash_1.update (digest)
	pcr_banks[curr_event.contents.pcr_bank] = hash_1

	event_size = (ctypes.c_uint32).from_address (
		event + ctypes.sizeof (tcg_event2) + hash_len).value
	event = (ctypes.c_uint8 * event_size).from_address (event + ctypes.sizeof (tcg_event2) + \
		hash_len + ctypes.sizeof (ctypes.c_uint32))

	# If digest is unset, then event should be unset as well
	if all (v == 0 for v in bytes (digest)):
		if not all (v == 0 for v in bytes (event)):
			print_error (Error_Types.INVALID_EVENT_ERROR_TYPE_STR, 
				EVENT_NON_ZERO_ERROR_STR.format (curr_event.contents.pcr_bank, 
					hex (curr_event.contents.event_type)))
	
	# If event is not the same as digest, then event hash should be same as digest
	if bytes (digest) != bytes (event):
		entries_with_events_list.append (curr_event.contents.event_type)
		hash_2 = SHA256.new (event)
		computed_hash = hash_2.digest ()

		if bytes (digest) != computed_hash:
			print_error (Error_Types.INVALID_EVENT_ERROR_TYPE_STR, 
				EVENT_HASH_INCORRECT_ERROR_STR.format (curr_event.contents.pcr_bank, 
					hex (curr_event.contents.event_type)))

	return (ctypes.sizeof (tcg_event2) + hash_len + ctypes.sizeof (ctypes.c_uint32) + event_size, 
		pcr_banks, entries_with_events_list)

def process_all_tcg_event2 (max_len, events_list, algorithms):
	"""
    Process all TCG log event2 entries

    :param max_len: Maximum length of all event entries
    :param events_list: Address of first event data
    :param algorithms: List of algorithms utilized in log as per log header

    :return Dictionary of hashing objects used to compute PCR measurements keyed by PCR numbers, 
    	list of event types which include event data
    """

	offset = 0
	pcr_banks = {}
	entries_with_events_list = []

	while (offset < max_len):
		event_len, pcr_banks, entries_with_events_list = process_tcg_event2 (max_len - offset, 
			events_list + offset, algorithms, pcr_banks, entries_with_events_list)
		offset += event_len

	return pcr_banks, entries_with_events_list

def load_log (path):
	"""
    Load log pointed to by path to a ctypes byte array

    :param path: Path to binary log file

    :return log size, byte array containing log bytes
    """

	log_size = os.path.getsize (path)

	with open (path, mode='rb') as file:
		log_buf = (ctypes.c_ubyte * log_size) ()
		file.readinto (log_buf)
		
		return log_size, log_buf

	return 0, None


if len (sys.argv) != 2:
	print ("Log path not provided!")
	print ("Usage:")
	print ("\tpython3 tcg_log_test.py <log_path>")
	sys.exit (1)

print ("-------------------------------------------------------------------------------------")
print ("-------------------------TCG Log Format and Compliance Test--------------------------")
print ("-------------------------------------------------------------------------------------")

log_size, log_bin = load_log (str (sys.argv[1]))

print ("\nParsing log....\n")

old_event_size = process_tcg_event (log_size, ctypes.addressof (log_bin))
header_size, algorithms = process_tcg_log_header (log_size - old_event_size, 
	ctypes.addressof (log_bin) + old_event_size)
pcrs, entries_with_events_list = process_all_tcg_event2 (log_size - old_event_size - header_size, 
	ctypes.addressof (log_bin) + old_event_size + header_size, algorithms)

print ("\nPCR Measurements:")
for pcr, digest in pcrs.items ():
	print ("{}:{}".format (pcr, digest.hexdigest ()))	

print ("\nTCG event types with event data:")
for entry in entries_with_events_list:
	print ("{}".format (hex (entry)))
	
