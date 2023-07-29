#! /bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

pwd=`pwd`

if [ -z "$CERBERUS_ROOT" ]; then
	CERBERUS_ROOT="$(dirname "$(realpath "$BASH_SOURCE")")/../../../.."
fi
if [ -z "$UNSEAL_BUILD_DIR" ]; then
	UNSEAL_BUILD_DIR="build"
fi

if [ -z "$SEAL_SCRIPT_PATH" ]; then
	SEAL_SCRIPT_PATH="$CERBERUS_ROOT/cerberus/tools/testing"
fi
if [ -z "$UNSEAL_APP_PATH" ]; then
	UNSEAL_APP_PATH="$CERBERUS_ROOT/cerberus/tools/testing/unseal/build"
fi

seal_script="$SEAL_SCRIPT_PATH/seal_data.sh"
unseal="$UNSEAL_APP_PATH/unseal"


fatal=1					# Unseal errors are fatal and will terminate the script.
cipher_len=4096			# Length of the ciphertext being sealed.
seed_len=				# Only relevant for RSA unsealing.
pmr0=
pmr1=
pmr2=
pmr3=
pmr4=
random_pmrs=0			# Use random values for all PMRs during seal/unseal.
alias_reuse_cnt=100000	# The number of times to reuse the same alias key.
unseal_retry_cnt=1		# Retry the unseal on failure
once=0					# Run the test once, then exit.

##
# Parse input arguments to adjust execution
##
ARGS=`getopt --unquoted -o "" -l "count,cipher_len:,seed_len:,pmr0:,pmr1:,pmr2:,pmr3:,pmr4:,random_pmr,alias_reuse:,retry:,once" -- "$@"`
if [ $? -ne 0 ]; then
	exit 1
fi

set -- $ARGS
while [ $# -gt 0 ]; do
	case "$1" in
		--count)
			# Do not exit on error, but count the number of failures.
			fatal=0
			shift
		;;

		--cipher_len)
			cipher_len=$2
			shift 2
		;;

		--seed_len)
			# Length of the seed for RSA sealing.  ECDH unsealing seed is a public key.
			seed_len=$2
			shift 2
		;;

		--pmr0)
			pmr0="$2"
			shift 2
		;;

		--pmr1)
			pmr1="$2"
			shift 2
		;;

		--pmr2)
			pmr2="$2"
			shift 2
		;;

		--pmr3)
			pmr3="$2"
			shift 2
		;;

		--pmr4)
			pmr4="$2"
			shift 2
		;;

		--random_pmr)
			random_pmrs=1
			shift
		;;

		--alias_reuse)
			alias_reuse_cnt=$2
			shift 2
		;;

		--retry)
			unseal_retry_cnt=$2
			shift 2
		;;

		--once)
			once=1
			shift
		;;

		--)
			shift
		;;
	esac
done


# Generate a random ECC-256 keypair.
generate_key() {
	ecc=`mktemp -p .`
	openssl ecparam -name prime256v1 -genkey -noout -outform $1 -out $ecc
	if [ $? -ne 0 ]; then
		rm -f $ecc
		exit 1
	fi
}

# Execute the unseal operation.
do_unseal() {
	echo ""
	case $1 in
		RSA-PKCS15)
			seal_params="0 0"
			unseal_params="RSA None"
			echo "RSA Unseal"
			;;

		RSA-SHA1)
			seal_params="0 1"
			unseal_params="RSA SHA1"
			echo "RSA+SHA1 Unseal"
			;;

		RSA-SHA256)
			seal_params="0 2"
			unseal_params="RSA SHA256"
			echo "RSA+SHA256 Unseal"
			;;

		ECDH-RAW)
			seal_params="1 0"
			unseal_params="ECDH None"
			generate_key "PEM"
			echo "ECDH Unseal"
			;;

		ECDH-SHA256)
			seal_params="1 1"
			unseal_params="ECDH SHA256"
			generate_key "PEM"
			echo "ECDH+SHA256 Unseal"
			;;
	esac

	echo "Sealing: $seal_params"

	if [ $random_pmrs -ne 0 ]; then
		pmr0=`head -c 32 /dev/random | xxd -p | tr -d '\n'`
		pmr1=`head -c 32 /dev/random | xxd -p | tr -d '\n'`
		pmr2=`head -c 32 /dev/random | xxd -p | tr -d '\n'`
		pmr3=`head -c 32 /dev/random | xxd -p | tr -d '\n'`
		pmr4=`head -c 32 /dev/random | xxd -p | tr -d '\n'`
	fi

	pmr_args=
	if [ -n "$pmr0" ]; then
		pmr_args="$pmr_args -0 $(echo $pmr0 | xxd -r -p | base64)"
	fi
	if [ -n "$pmr1" ]; then
		pmr_args="$pmr_args -1 $(echo $pmr1 | xxd -r -p | base64)"
	fi
	if [ -n "$pmr2" ]; then
		pmr_args="$pmr_args -2 $(echo $pmr2 | xxd -r -p | base64)"
	fi
	if [ -n "$pmr3" ]; then
		pmr_args="$pmr_args -3 $(echo $pmr3 | xxd -r -p | base64)"
	fi
	if [ -n "$pmr4" ]; then
		pmr_args="$pmr_args -4 $(echo $pmr4 | xxd -r -p | base64)"
	fi

	unseal_cmd="$unseal $pmr_args $alias_key $unseal_params seed.bin cipher.bin sealing.bin hmac.bin"
	seal_cmd="$seal_script $seal_params $alias_pub $ecc"

	sealing=`PMR0="$pmr0" PMR1="$pmr1" PMR2="$pmr2" PMR3="$pmr3" PMR4="$pmr4" \
		CIPHER_LEN="$cipher_len" SEED_LEN="$seed_len" $seal_cmd 2>&1`
	if [ $? -ne 0 ]; then
		out="$sealing"
		return 1
	fi

	key=`echo "$sealing" | grep stdin | awk '{print $2}'`
	echo "$sealing"
	echo "Sealed Key: $key"
	echo ""

	retry=0
	while [ $retry -lt $unseal_retry_cnt ]; do
		out=`$unseal_cmd 2>&1`
		if [ $? -ne 0 ]; then
			let 'retry = retry + 1'
			if [ $retry -ge $unseal_retry_cnt ]; then
				return 1
			else
				echo "$out"
			fi
		else
			break
		fi
	done

	echo "Unsealed Key: $out"
	out=`diff <(echo "$key") <(echo "$out")`
	if [ $? -ne 0 ]; then
		return 1
	fi
}


count_keys=0
count_total=0
error=0
while (true); do
	let 'count_keys = count_keys + 1'
	echo "++++++++++++++++"
	echo "Key:   $count_keys"
	if [ $fatal -eq 0 ]; then
		echo "Errors: $error"
	fi
	echo "++++++++++++++++"

	# Generate a device key for unsealing.
	generate_key "DER"
	alias_key=$ecc
	alias_pub=`mktemp -p .`
	openssl ec -inform DER -in $alias_key -outform PEM -pubout -out $alias_pub
	if [ $? -ne 0 ]; then
		rm -f $alias_key $alias_pub
		exit 1
	fi

	ecc=
	count_alias=0
	while [ $count_alias -lt $alias_reuse_cnt ]; do
		let 'count_alias = count_alias + 1'
		let 'count_total = count_total + 1'
		echo "++++++++++++++++"
		echo "Key:   $count_keys"
		echo "Loop:  $count_alias"
		echo "Total: $count_total"
		if [ $fatal -eq 0 ]; then
			echo "Errors: $error"
		fi
		echo "++++++++++++++++"

		# Run an unseal operation
		do_unseal "ECDH-SHA256"
		if [ $? -ne 0 ]; then
			echo "$out"
			echo "Alias: $alias_key"
			echo "Alias pub: $alias_pub"
			echo "Sealing: $ecc"

			let 'error = error + 1'
			if [ $fatal -eq 1 ]; then
				exit 1
			fi
		fi

		rm -f $ecc
		if [ $once -ne 0 ]; then
			break
		fi
	done

	rm -f $alias_key $alias_pub
	if [ $once -ne 0 ]; then
		break
	fi
done
