#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if [ $# -lt 1 ]; then
	echo "Find an ECC keypair whose ECDH secret has the first byte equal to 0."
	echo "Usage: $0 <pubkey>"
	exit 1
fi

while (true); do
	ecc=`mktemp -p .`
	openssl ecparam -name prime256v1 -genkey -noout -out $ecc
	if [ $? -ne 0 ]; then
		rm -f $ecc
		exit 1
	fi

	seed=`mktemp -p .`
	openssl pkeyutl -derive -inkey $ecc -peerkey $1 -out $seed
	if [ $? -ne 0 ]; then
		rm -f $ecc $seed
		exit 1
	fi

	seed_hex=`cat $seed | xxd -p | tr -d '\n'`
	rm -f $seed

	echo "Seed: $seed_hex" | grep "Seed: 00"
	if [ $? -eq 0 ]; then
		echo "Key: $ecc"
		exit 0
	fi

	rm -f $ecc
done
