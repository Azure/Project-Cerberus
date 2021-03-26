#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Script for generating PFMs for unit tests.

if [ $# -lt 2 ]; then
	echo "Usage: $0 <pfm id> <pfm key>"
	exit 1
fi

pfm_id=`printf "0x%x" $1`
if [ $? -ne 0 ]; then
	echo "Invalid PFM ID: $1"
	exit 1
fi

pfm_key=$2
if [ ! -e "$pfm_key" ]; then
	echo "Unknown PFM private key: $pfm_key"
	exit 1
fi

if [ -z "$BLANK_BYTE" ]; then
	BLANK_BYTE=0xff
fi

if [ -z "$PLATFORM" ]; then
	PLATFORM="PFM Test1"
fi

if [ -z "$HASH_TYPE" ]; then
	HASH_TYPE=0
fi

if [ -z "$TOC_HASH_TYPE" ]; then
	TOC_HASH_TYPE=$HASH_TYPE
fi

if [ -z "$MAGIC" ]; then
	MAGIC="0x706d"
fi

if [ -z "$OUTPUT_DIR" ]; then
	OUTPUT_DIR=output
fi

if [ -z "$NUM_FW" ]; then
	NUM_FW=1
elif [ $NUM_FW -gt 3 ]; then
	NUM_FW=3
fi

if [ -z "$NUM_FW_VER" ]; then
	NUM_FW_VER=1
elif [ $NUM_FW_VER -gt 3 ]; then
	NUM_FW_VER=3
fi

if [ -n "$EMPTY_MANIFEST" ]; then
	NUM_FW=0
	NUM_FW_VER=0
	NO_FLASH_DEV=1
fi

mkdir -p $(realpath $OUTPUT_DIR)

pfm_out=$OUTPUT_DIR/pfm.out
pfm_sig=$OUTPUT_DIR/pfm.sig
pfm_img=$OUTPUT_DIR/pfm.img

hash0_out=$OUTPUT_DIR/hash0.out
hash1_out=$OUTPUT_DIR/hash1.out
hash2_out=$OUTPUT_DIR/hash2.out
hash3_out=$OUTPUT_DIR/hash3.out
hash4_out=$OUTPUT_DIR/hash4.out
hash5_out=$OUTPUT_DIR/hash5.out
hash6_out=$OUTPUT_DIR/hash6.out
hash7_out=$OUTPUT_DIR/hash7.out
hash8_out=$OUTPUT_DIR/hash8.out
hash9_out=$OUTPUT_DIR/hash9.out
hash10_out=$OUTPUT_DIR/hash10.out
hash11_out=$OUTPUT_DIR/hash11.out
hash12_out=$OUTPUT_DIR/hash12.out
hash13_out=$OUTPUT_DIR/hash13.out

case $HASH_TYPE in
	0)
		dgst=sha256
		;;

	1)
		dgst=sha384
		;;

	2)
		dgst=sha512
		;;

	*)
		echo "Unsupported signature hash type: $HASH_TYPE"
		exit 1
esac

case $TOC_HASH_TYPE in
	0)
		toc_dgst=sha256
		hash_len=32
		;;

	1)
		toc_dgst=sha384
		hash_len=48
		;;

	2)
		toc_dgst=sha512
		hash_len=64
		;;

	*)
		echo "Unsupported ToC hash type: $TOC_HASH_TYPE"
		exit 1
esac

empty_file() {
	echo -n "" > $1
}

output_binary_dword() {
	printf "%08x" $1 | sed -E 's/(..)(..)(..)(..)/\4\3\2\1/' | xxd -r -p >> $2
}

output_binary_word() {
	printf "%04x" $1 | sed -E 's/(..)(..)/\2\1/' | xxd -r -p >> $2
}

output_binary_byte() {
	printf "%02x" $1 | xxd -r -p >> $2
}

output_binary_array() {
	echo $1 | xxd -r -p >> $2
}

generate_signature() {
	openssl dgst -$dgst -sign $3 -out $2 $1
	if [ $? -ne 0 ]; then
		echo "Failed to sign PFM."
		exit 1
	fi

	out_len=`stat -c %s $2`
	if [ $out_len -lt $sig_len ]; then
		let 'padding = sig_len - out_len'
		head -c $padding /dev/zero >> $2
	fi
}

get_pfm_signature_length() {
	grep -q RSA $1
	if [ $? -eq 0 ]; then
		sig_len=`openssl rsa -text -noout < $1 | grep Private-Key | sed -E 's/.*\((.*) bit.*/\1/'`
		if [ $? -ne 0 ] || [ -z "$sig_len" ]; then
			echo "Failed to get key length for PFM key $1."
			exit 1
		fi

		case $sig_len in
			2048)
				sig_type=0
				;;

			3072)
				sig_type=8
				;;

			4096)
				sig_type=16
				;;

			*)
				echo "Unsupported RSA key length: $sig_len"
				exit 1
		esac

		let 'sig_len = sig_len / 8'
	else
		sig_len=`openssl ec -text -noout < $1 | grep Private-Key | sed -E 's/.*\((.*) bit.*/\1/'`
		if [ $? -ne 0 ] || [ -z "$sig_len" ]; then
			echo "Failed to get key length for PFM key $1."
			exit 1
		fi

		case $sig_len in
			256)
				sig_type=64
				;;

			384)
				sig_type=72
				;;

			521)
				sig_type=80
				;;

			*)
				echo "Unsupported RSA key length: $sig_len"
				exit 1
		esac

		let 'sig_len = (((sig_len / 8) + 3) * 2) + 3'
	fi

	let 'sig_type = sig_type + HASH_TYPE'
}

add_section_length() {
	if [ -n "$3" ]; then
		extra=$3
	else
		extra=0
	fi

	tmp_len=`stat -c %s $1`
	let 'tmp_len = tmp_len + 2 + extra'
	output_binary_word "$tmp_len" "$2"

	cat $1 >> $2
	rm -f $1
}

get_data_length() {
	tmp_len=`stat -c %s $1`
}

get_alignment() {
	let "align = $1 % 4"
	if [ $align -ne 0 ]; then
		let 'align = 4 - align'
	fi
}

get_aligned_length() {
	id_len=${#1}
	get_alignment "$id_len"
}

add_flash_region() {
	output_binary_dword "$1" "$3"
	output_binary_dword "$2" "$3"
}

add_image() {
	img_tmp=$1

	output_binary_byte "$2" "$img_tmp"
	output_binary_byte "$5" "$img_tmp"
	output_binary_byte "$4" "$img_tmp"
	output_binary_byte "0" "$img_tmp"

	head -c $3 /dev/random >> $img_tmp	# image hash

	if [ -z "$IMG_TEST" ] || [ $5 -lt 5 ]; then
		for region in $6; do
			IFS=',' read start end <<< "${region}"
			add_flash_region "$start" "$end" "$img_tmp"
		done
	else
		i=0
		while [ $i -lt $5 ]; do
			add_flash_region "0x${6}${i}0000" "0x${6}${i}ffff" "$img_tmp"
			let 'i = i + 1'
		done
	fi
}

add_rw_region() {
	rw_tmp=$1

	output_binary_byte "$2" "$rw_tmp"
	head -c 3 /dev/zero >> $rw_tmp
	add_flash_region "$3" "$4" "$rw_tmp"
}

create_firmware_version_element() {
	get_aligned_length $2
	if [ $id_len -gt 255 ]; then
		echo "Version identifier too long: $1"
		exit 1
	fi

	ver_tmp="$1.tmp"
	empty_file "$ver_tmp"

	if [ -n "$IMG_TEST" ]; then
		case $3 in
			0)
				images=1
				;;

			1)
				images=2
				;;

			2)
				case $4 in
					0)
						images=7
						;;

					1)
						images=1
						;;

					2)
						images=4
						;;
				esac
				;;
		esac
	elif [ $NUM_FW_VER -eq 1 ] && [ -z "$MAX_VERSION" ] && [ -z "$RW_TEST" ]; then
		images=1
	else
		images=$3
		let 'images = images + 1'
	fi
	if [ -n "$RW_TEST" ]; then
		case $3 in
			0)
				rw_regions=0
				;;

			1)
				rw_regions=21
				;;

			2)
				rw_regions=22
				;;
		esac
	elif [ -n "$IMG_TEST" ]; then
		rw_regions=$3
		let 'rw_regions = rw_regions + 1'
	else
		rw_regions=$images
	fi

	output_binary_byte "$images" "$ver_tmp"
	output_binary_byte "$rw_regions" "$ver_tmp"
	output_binary_byte "$id_len" "$ver_tmp"
	output_binary_byte "0" "$ver_tmp"
	output_binary_dword "0x${3}${4}12345" "$ver_tmp"

	echo -n "$2" >> "$ver_tmp"
	head -c $align /dev/zero >> $ver_tmp

	if [ $NUM_FW_VER -eq 1 ] && [ -z "$MAX_VERSION" ] && [ -z "$RW_TEST" ] && [ -z "$IMG_TEST" ]; then
		case $3 in
			0)
				if [ -z "$BAD_REGIONS" ]; then
					add_rw_region "$ver_tmp" "0" "0x2000000" "0x3ffffff"
					if [ -z "$IMG_MULTI_REGION" ]; then
						add_image "$ver_tmp" "0" "32" "1" "1" "0x0000000,0x1ffffff"
					else
						add_image "$ver_tmp" "0" "32" "1" "4" "0x0000000,0x004ffff 0x0060000,0x00bffff 0x1000000,0x108ffff 0x1100000,0x1ffffff"
					fi
				else
					add_rw_region "$ver_tmp" "0" "0x2000000" "0x1ffffff"
					add_image "$ver_tmp" "0" "32" "1" "1" "0x1000000,0x0ffffff"
				fi
				;;

			1)
				if [ -z "$BAD_REGIONS" ]; then
					add_rw_region "$ver_tmp" "1" "0x6000000" "0x7ffffff"
					add_image "$ver_tmp" "1" "48" "1" "1" "0x4000000,0x5ffffff"
				else
					add_rw_region "$ver_tmp" "1" "0x6000000" "0x6000000"
					add_image "$ver_tmp" "1" "48" "1" "1" "0x4000000,0x4000000"
				fi
				;;

			2)
				add_rw_region "$ver_tmp" "0" "0x8000000" "0x9ffffff"
				add_image "$ver_tmp" "2" "64" "0" "1" "0xa000000,0xbffffff"
				;;

		esac
	else
		case $3 in
			0)
				if [ -z "$RW_TEST" ]; then
					add_rw_region "$ver_tmp" "0" "0x${4}0040000" "0x${4}007ffff"
				fi

				if [ -z "$IMG_TEST" ]; then
					add_image "$ver_tmp" "0" "32" "1" "1" "0x${4}0000000,0x${4}003ffff"
				else
					case $4 in
						0)
							add_image "$ver_tmp" "0" "32" "1" "1" "0x${4}0000000,0x${4}003ffff"
							;;

						1)
							add_image "$ver_tmp" "0" "32" "1" "0"
							;;

						2)
							# Maximum supported image definition
							add_image "$ver_tmp" "0" "32" "1" "27" "$4"
							;;
					esac
				fi
				;;

			1)
				if [ -z "$RW_TEST" ]; then
					add_rw_region "$ver_tmp" "1" "0x${4}00c0000" "0x${4}00fffff"
					add_rw_region "$ver_tmp" "0" "0x${4}0400000" "0x${4}07fffff"
				else
					i=0
					while [ $i -lt $rw_regions ]; do
						add_rw_region "$ver_tmp" "0" "0x${4}${i}0000" "0x${4}${i}ffff"
						let 'i = i + 1'
					done
				fi

				if [ -z "$IMG_TEST" ]; then
					add_image "$ver_tmp" "1" "48" "1" "1" "0x${4}0080000,0x${4}00bffff"
					add_image "$ver_tmp" "0" "32" "1" "1" "0x${4}0100000,0x${4}03fffff"
				else
					case $4 in
						0)
							add_image "$ver_tmp" "1" "48" "2" "1" "0x${4}0080000,0x${4}00bffff"
							add_image "$ver_tmp" "0" "32" "7" "1" "0x${4}0100000,0x${4}03fffff"
							;;

						1)
							add_image "$ver_tmp" "1" "48" "1" "4" "0x${4}0080000,0x${4}008ffff 0x${4}0090000,0x${4}009ffff 0x${4}00a0000,0x${4}00affff 0x${4}00b0000,0x${4}00bffff"
							add_image "$ver_tmp" "0" "32" "1" "2" "0x${4}0100000,0x${4}02fffff 0x${4}0200000,0x${4}03fffff"
							;;

						2)
							add_image "$ver_tmp" "3" "48" "1" "1" "0x${4}0080000,0x${4}00bffff"
							add_image "$ver_tmp" "0" "32" "1" "1" "0x${4}0100000,0x${4}03fffff"
							;;
					esac
				fi
				;;

			2)
				if [ -z "$RW_TEST" ]; then
					add_rw_region "$ver_tmp" "2" "0x${4}0c00000" "0x${4}0ffffff"
					add_rw_region "$ver_tmp" "1" "0x${4}4000000" "0x${4}7ffffff"
					add_rw_region "$ver_tmp" "0" "0x${4}c000000" "0x${4}fffffff"
				else
					i=0
					while [ $i -lt $rw_regions ]; do
						add_rw_region "$ver_tmp" "0" "0x${4}${i}0000" "0x${4}${i}ffff"
						let 'i = i + 1'
					done
				fi

				if [ -z "$IMG_TEST" ]; then
					add_image "$ver_tmp" "2" "64" "1" "1" "0x${4}0800000,0x${4}0bfffff"
					add_image "$ver_tmp" "1" "48" "1" "1" "0x${4}1000000,0x${4}3ffffff"
					add_image "$ver_tmp" "0" "32" "1" "1" "0x${4}8000000,0x${4}bffffff"
				else
					case $4 in
						0)
							add_image "$ver_tmp" "2" "64" "1" "1" "0x${4}0800000,0x${4}0bfffff"
							add_image "$ver_tmp" "1" "48" "1" "1" "0x${4}1000000,0x${4}3ffffff"
							add_image "$ver_tmp" "0" "32" "1" "1" "0x${4}8000000,0x${4}bffffff"
							add_image "$ver_tmp" "2" "64" "1" "1" "0x30500000,0x30bfffff"
							add_image "$ver_tmp" "1" "48" "1" "1" "0x31000000,0x36ffffff"
							add_image "$ver_tmp" "0" "32" "1" "1" "0x38000000,0x3dffffff"
							add_image "$ver_tmp" "2" "64" "1" "2" "0x40000000,0x40bfffff 0x41000000,0x4affffff"
							;;

						1)
							# Too large, unsupported
							add_image "$ver_tmp" "2" "64" "1" "24" "$4"
							;;

						2)
							add_image "$ver_tmp" "2" "64" "1" "13" "$4"	# Incomplete read of second image
							add_image "$ver_tmp" "1" "48" "1" "21" "$4"	# Incomplete read of third image
							add_image "$ver_tmp" "0" "32" "1" "1" "0x${4}8000000,0x${4}bffffff"
							add_image "$ver_tmp" "0" "32" "1" "22" "$4"	# Complete read of both third and fourth image
							;;
					esac
				fi
				;;
		esac
	fi

	cat $ver_tmp > $1
	rm -f $ver_tmp
}

create_firmware_element() {
	get_aligned_length $2
	if [ $id_len -gt 255 ]; then
		echo "FW identifier too long: $1"
		exit 1
	fi

	fw_tmp=$1
	empty_file "$fw_tmp"

	output_binary_byte "$NUM_FW_VER" "$fw_tmp"
	output_binary_byte "$id_len" "$fw_tmp"
	output_binary_word "0" "$fw_tmp"

	echo -n "$2" >> "$fw_tmp"
	head -c $align /dev/zero >> $fw_tmp
}

create_flash_device_element() {
	flash_tmp=$1
	empty_file "$flash_tmp"

	output_binary_byte "$BLANK_BYTE" "$flash_tmp"
	output_binary_byte "$NUM_FW" "$flash_tmp"
	output_binary_word "0" "$flash_tmp"
}

create_platform_id_element() {
	get_aligned_length "$PLATFORM"
	if [ $id_len -gt 255 ]; then
		echo "Platform identifier too long: $PLATFORM"
		exit 1
	fi

	platform_tmp=$1
	empty_file "$platform_tmp"

	output_binary_byte "$id_len" "$platform_tmp"
	head -c 3 /dev/zero >> $platform_tmp

	echo -n "$PLATFORM" >> "$platform_tmp"
	head -c $align /dev/zero >> $platform_tmp
}

toc_add_flash_device() {
	output_binary_byte "0x10" "$1"
	output_binary_byte "0xff" "$1"
	output_binary_byte "0" "$1"
	if [ -z "$SKIP_HASHES" ]; then
		output_binary_byte "0" "$1"
	else
		output_binary_byte "0xff" "$1"
	fi
	output_binary_word "$offset" "$1"
	output_binary_word "4" "$1"

	let 'offset = offset + 4'
}

toc_add_firmware() {
	fw_len=`stat -c %s $2`
	output_binary_byte "0x11" "$1"
	output_binary_byte "0xff" "$1"
	output_binary_byte "1" "$1"
	if [ -z "$SKIP_HASHES" ] && [ -z "$SKIP_FW_HASH" ]; then
		output_binary_byte "$3" "$1"
	else
		if [ -n "$SKIP_FW_HASH" ]; then
			# Indicate no hash by using an invalid hash ID instead of 0xff.
			output_binary_byte "$last_hash" "$1"
			let 'last_hash = last_hash + 1'
		else
			output_binary_byte "0xff" "$1"
		fi
	fi
	output_binary_word "$offset" "$1"
	output_binary_word "$fw_len" "$1"

	let 'offset = offset + fw_len'
}

toc_add_firmware_version() {
	img_len=`stat -c %s $2`
	output_binary_byte "0x12" "$1"
	output_binary_byte "0x11" "$1"
	output_binary_byte "1" "$1"
	if [ -z "$SKIP_HASHES" ]; then
		output_binary_byte "$3" "$1"
	else
		output_binary_byte "0xff" "$1"
	fi
	output_binary_word "$offset" "$1"
	output_binary_word "$img_len" "$1"

	let 'offset = offset + img_len'
}

toc_add_platform_id() {
	plat_id_len=`stat -c %s $2`
	output_binary_byte "0" "$1"
	output_binary_byte "0xff" "$1"
	output_binary_byte "1" "$1"
	if [ -z "$SKIP_HASHES" ]; then
		output_binary_byte "$plat_id_hash" "$1"
	else
		output_binary_byte "0xff" "$1"
	fi
	output_binary_word "$offset" "$1"
	output_binary_word "$plat_id_len" "$1"

	let 'offset = offset + plat_id_len'
}

construct_manifest() {
	toc_file="$1.toc"
	empty_file "$toc_file"

	tmp_file="$1.tmp"
	empty_file "$tmp_file"

	if [ $NUM_FW_VER -eq 0 ]; then
		plat_id_hash=1
	else
		let 'plat_id_hash = NUM_FW + 1'
	fi

	let 'entries = 1 + (NUM_FW * (NUM_FW_VER + 1)) + 1'
	if [ -n "$NO_FLASH_DEV" ]; then
		let 'entries = entries - 1'
		let 'plat_id_hash = plat_id_hash - 1'
	fi

	if [ -z "$SKIP_HASHES" ]; then
		let 'hashes = 1 + (NUM_FW * NUM_FW_VER) + 1'
		if [ -z "$SKIP_FW_HASH" ]; then
			let 'hashes = hashes + NUM_FW'
		fi
		if [ -n "$NO_FLASH_DEV" ]; then
			let 'hashes = hashes - 1'
		fi

		last_hash=$hashes
	else
		hashes=0
	fi

	output_binary_byte "$entries" "$toc_file"
	output_binary_byte "$hashes" "$toc_file"
	output_binary_byte "$TOC_HASH_TYPE" "$toc_file"
	output_binary_byte "0" "$toc_file"

	let 'offset = 12 + 4 + (entries * 8) + ((hashes + 1) * hash_len)'
	if [ -n "$PLATFORM_FIRST" ]; then
		toc_add_platform_id "$toc_file" "$hash4_out"
	fi

	if [ -z "$NO_FLASH_DEV" ]; then
		toc_add_flash_device "$toc_file" "$hash0_out"
	fi

	if [ $NUM_FW -gt 0 ]; then
		if [ -z "$NO_FLASH_DEV" ]; then
			ver_hash=1
		else
			ver_hash=0
		fi

		if [ -z "$SKIP_FW_HASH" ]; then
			if [ $NUM_FW_VER -eq 0 ]; then
				fw_hash=2
			else
				let 'fw_hash = 5 - (3 - NUM_FW)'
			fi
			if [ -n "$NO_FLASH_DEV" ]; then
				let 'fw_hash = fw_hash - 1'
			fi
		else
			let 'fw_hash = ver_hash + 1'
		fi

		toc_add_firmware "$toc_file" "$hash5_out" "$fw_hash"
		if [ $NUM_FW_VER -gt 0 ]; then
			toc_add_firmware_version "$toc_file" "$hash1_out" "$ver_hash"
			let 'ver_hash = fw_hash + NUM_FW'
		fi
		if [ $NUM_FW_VER -gt 1 ]; then
			toc_add_firmware_version "$toc_file" "$hash8_out" "$ver_hash"
			let 'ver_hash = ver_hash + NUM_FW'
		fi
		if [ $NUM_FW_VER -gt 2 ]; then
			toc_add_firmware_version "$toc_file" "$hash11_out" "$ver_hash"
		fi
	fi

	if [ -z "$PLATFORM_FIRST" ]; then
		toc_add_platform_id "$toc_file" "$hash4_out"
	fi

	if [ $NUM_FW -gt 1 ]; then
		if [ -z "$NO_FLASH_DEV" ]; then
			ver_hash=2
		else
			ver_hash=1
		fi

		if [ -z "$SKIP_FW_HASH" ]; then
			if [ $NUM_FW_VER -eq 0 ]; then
				fw_hash=3
			else
				let 'fw_hash = 6 - (3 - NUM_FW)'
			fi
			if [ -n "$NO_FLASH_DEV" ]; then
				let 'fw_hash = fw_hash - 1'
			fi
		else
			let 'fw_hash = ver_hash + 1'
		fi


		toc_add_firmware "$toc_file" "$hash6_out" "$fw_hash"
		if [ $NUM_FW_VER -gt 0 ]; then
			toc_add_firmware_version "$toc_file" "$hash2_out" "$ver_hash"
			let 'ver_hash = fw_hash + NUM_FW'
		fi
		if [ $NUM_FW_VER -gt 1 ]; then
			toc_add_firmware_version "$toc_file" "$hash9_out" "$ver_hash"
			let 'ver_hash = ver_hash + NUM_FW'
		fi
		if [ $NUM_FW_VER -gt 2 ]; then
			toc_add_firmware_version "$toc_file" "$hash12_out" "$ver_hash"
		fi
	fi

	if [ $NUM_FW -gt 2 ]; then
		if [ -z "$NO_FLASH_DEV" ]; then
			ver_hash=3
		else
			ver_hash=2
		fi

		if [ -z "$SKIP_FW_HASH" ]; then
			if [ $NUM_FW_VER -eq 0 ]; then
				fw_hash=4
			else
				let 'fw_hash = 7 - (3 - NUM_FW)'
			fi
			if [ -n "$NO_FLASH_DEV" ]; then
				let 'fw_hash = fw_hash - 1'
			fi
		else
			let 'fw_hash = ver_hash + 1'
		fi

		toc_add_firmware "$toc_file" "$hash7_out" "$fw_hash"
		if [ $NUM_FW_VER -gt 0 ]; then
			toc_add_firmware_version "$toc_file" "$hash3_out" "$ver_hash"
			let 'ver_hash = fw_hash + NUM_FW'
		fi
		if [ $NUM_FW_VER -gt 1 ]; then
			toc_add_firmware_version "$toc_file" "$hash10_out" "$ver_hash"
			let 'ver_hash = ver_hash + NUM_FW'
		fi
		if [ $NUM_FW_VER -gt 2 ]; then
			toc_add_firmware_version "$toc_file" "$hash13_out" "$ver_hash"
		fi
	fi

	if [ -z "$SKIP_HASHES" ]; then
		if [ -z "$NO_FLASH_DEV" ]; then
			hash0=`openssl dgst -$toc_dgst $hash0_out | awk '{print $2}'`
			output_binary_array "$hash0" "$toc_file"
		fi

		if [ $NUM_FW -gt 0 ] && [ $NUM_FW_VER -gt 0 ]; then
			hash1=`openssl dgst -$toc_dgst $hash1_out | awk '{print $2}'`
			output_binary_array "$hash1" "$toc_file"
		fi

		if [ $NUM_FW -gt 1 ] && [ $NUM_FW_VER -gt 0 ]; then
			hash2=`openssl dgst -$toc_dgst $hash2_out | awk '{print $2}'`
			output_binary_array "$hash2" "$toc_file"
		fi

		if [ $NUM_FW -gt 2 ] && [ $NUM_FW_VER -gt 0 ]; then
			hash3=`openssl dgst -$toc_dgst $hash3_out | awk '{print $2}'`
			output_binary_array "$hash3" "$toc_file"
		fi

		hash4=`openssl dgst -$toc_dgst $hash4_out | awk '{print $2}'`
		output_binary_array "$hash4" "$toc_file"

		if [ -z "$SKIP_FW_HASH" ]; then
			if [ $NUM_FW -gt 0 ]; then
				hash5=`openssl dgst -$toc_dgst $hash5_out | awk '{print $2}'`
				output_binary_array "$hash5" "$toc_file"
			fi

			if [ $NUM_FW -gt 1 ]; then
				hash6=`openssl dgst -$toc_dgst $hash6_out| awk '{print $2}'`
				output_binary_array "$hash6" "$toc_file"
			fi

			if [ $NUM_FW -gt 2 ]; then
				hash7=`openssl dgst -$toc_dgst $hash7_out| awk '{print $2}'`
				output_binary_array "$hash7" "$toc_file"
			fi
		fi

		if [ $NUM_FW -gt 0 ] && [ $NUM_FW_VER -gt 1 ]; then
			hash8=`openssl dgst -$toc_dgst $hash8_out| awk '{print $2}'`
			output_binary_array "$hash8" "$toc_file"
		fi

		if [ $NUM_FW -gt 1 ] && [ $NUM_FW_VER -gt 1 ]; then
			hash9=`openssl dgst -$toc_dgst $hash9_out| awk '{print $2}'`
			output_binary_array "$hash9" "$toc_file"
		fi

		if [ $NUM_FW -gt 2 ] && [ $NUM_FW_VER -gt 1 ]; then
			hash10=`openssl dgst -$toc_dgst $hash10_out| awk '{print $2}'`
			output_binary_array "$hash10" "$toc_file"
		fi

		if [ $NUM_FW -gt 0 ] && [ $NUM_FW_VER -gt 2 ]; then
			hash11=`openssl dgst -$toc_dgst $hash11_out| awk '{print $2}'`
			output_binary_array "$hash11" "$toc_file"
		fi

		if [ $NUM_FW -gt 1 ] && [ $NUM_FW_VER -gt 2 ]; then
			hash12=`openssl dgst -$toc_dgst $hash12_out| awk '{print $2}'`
			output_binary_array "$hash12" "$toc_file"
		fi

		if [ $NUM_FW -gt 2 ] && [ $NUM_FW_VER -gt 2 ]; then
			hash13=`openssl dgst -$toc_dgst $hash13_out| awk '{print $2}'`
			output_binary_array "$hash13" "$toc_file"
		fi
	fi

	hash_toc=`openssl dgst -$toc_dgst $toc_file | awk '{print $2}'`
	output_binary_array "$hash_toc" "$toc_file"

	cat $toc_file >> $tmp_file
	if [ -n "$PLATFORM_FIRST" ]; then
		cat $hash4_out >> $tmp_file
	fi
	if [ -z "$NO_FLASH_DEV" ]; then
		cat $hash0_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 0 ]; then
		cat $hash5_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 0 ] && [ $NUM_FW_VER -gt 0 ]; then
		cat $hash1_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 0 ] && [ $NUM_FW_VER -gt 1 ]; then
		cat $hash8_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 0 ] && [ $NUM_FW_VER -gt 2 ]; then
		cat $hash11_out >> $tmp_file
	fi
	if [ -z "$PLATFORM_FIRST" ]; then
		cat $hash4_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 1 ]; then
		cat $hash6_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 1 ] && [ $NUM_FW_VER -gt 0 ]; then
		cat $hash2_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 1 ] && [ $NUM_FW_VER -gt 1 ]; then
		cat $hash9_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 1 ] && [ $NUM_FW_VER -gt 2 ]; then
		cat $hash12_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 2 ]; then
		cat $hash7_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 2 ] && [ $NUM_FW_VER -gt 0 ]; then
		cat $hash3_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 2 ] && [ $NUM_FW_VER -gt 1 ]; then
		cat $hash10_out >> $tmp_file
	fi
	if [ $NUM_FW -gt 2 ] && [ $NUM_FW_VER -gt 2 ]; then
		cat $hash13_out >> $tmp_file
	fi

	cat $tmp_file >> $1
	rm -f $toc_file $tmp_file $hash0_out $hash1_out $hash2_out $hash3_out $hash4_out $hash5_out $hash6_out $hash7_out $hash8_out $hash9_out $hash10_out $hash11_out $hash12_out $hash13_out
}

MAX_VERSION_STR="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
MAX_VERSION_STR_NO_PADDING="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"

if [ -z "$MAX_VERSION" ]; then
	if [ -z "$IMG_TEST" ]; then
		FW_VERSION="Testing"
	else
		# Max version string to read both R/W and Image data in a single read
		FW_VERSION="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	fi
	FW2_VERSION="Testing2"
	FW3_VERSION="Test3"
else
	FW_VERSION=$MAX_VERSION_STR
	# Cause the R/W data to go beyond 264 bytes
	FW2_VERSION=$MAX_VERSION_STR_NO_PADDING
	# Overall element greater than 264 bytes, but R/W regions fit within than size
	FW3_VERSION="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
fi

get_pfm_signature_length $pfm_key

pfm_tmp=$pfm_out.tmp
empty_file "$pfm_tmp"

output_binary_word "$MAGIC" "$pfm_tmp"
output_binary_dword "$pfm_id" "$pfm_tmp"
output_binary_word "$sig_len" "$pfm_tmp"
output_binary_byte "$sig_type" "$pfm_tmp"
output_binary_byte "0" "$pfm_tmp"

if [ -z "$NO_FLASH_DEV" ]; then
	create_flash_device_element "$hash0_out"
fi
if [ $NUM_FW -gt 0 ]; then
	create_firmware_element "$hash5_out" "Firmware"
	if [ $NUM_FW_VER -gt 0 ]; then
		create_firmware_version_element "$hash1_out" "$FW_VERSION" "0" "0"
	fi
	if [ $NUM_FW_VER -gt 1 ]; then
		create_firmware_version_element "$hash8_out" "TestingV2" "1" "0"
	fi
	if [ $NUM_FW_VER -gt 2 ]; then
		create_firmware_version_element "$hash11_out" "TestingV3" "2" "0"
	fi
fi
if [ $NUM_FW -gt 1 ]; then
	create_firmware_element "$hash6_out" "Firmware2"
	if [ $NUM_FW_VER -gt 0 ]; then
		create_firmware_version_element "$hash2_out" "$FW2_VERSION" "1" "1"
	fi
	if [ $NUM_FW_VER -gt 1 ]; then
		create_firmware_version_element "$hash9_out" "Testing2V2" "2" "1"
	fi
	if [ $NUM_FW_VER -gt 2 ]; then
		create_firmware_version_element "$hash12_out" "Testing2V3" "0" "1"
	fi
fi
if [ $NUM_FW -gt 2 ]; then
	create_firmware_element "$hash7_out" "FW3"
	if [ $NUM_FW_VER -gt 0 ]; then
		create_firmware_version_element "$hash3_out" "$FW3_VERSION" "2" "2"
	fi
	if [ $NUM_FW_VER -gt 1 ]; then
		create_firmware_version_element "$hash10_out" "Test3V2" "0" "2"
	fi
	if [ $NUM_FW_VER -gt 2 ]; then
		create_firmware_version_element "$hash13_out" "Test3V3" "1" "2"
	fi
fi
create_platform_id_element "$hash4_out"

construct_manifest "$pfm_tmp"

empty_file "$pfm_out"
add_section_length "$pfm_tmp" "$pfm_out" "$sig_len"

generate_signature "$pfm_out" "$pfm_sig" "$pfm_key"

cat $pfm_out $pfm_sig > $pfm_img
rm -f $pfm_out $pfm_sig
echo $pfm_img
