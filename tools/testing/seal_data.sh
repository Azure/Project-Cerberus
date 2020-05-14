#! /bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if [ $# -lt 3 ]; then
	echo "Usage: $0 <type> <params> <cert> [privkey]"
	exit 1
fi

cert=$3
key=`tempfile -d .`
openssl x509 -inform DER -outform PEM -noout -pubkey -in $cert -out $key
if [ $? -ne 0 ]; then
	rm -f $key
	exit 1
fi

if [ "$1" = "1" ]; then
	if [ $# -lt 4 ]; then
		echo "No private key provided"
		rm -f $key
		exit 1
	fi

	seed=`tempfile -d .`
	openssl pkeyutl -derive -inkey $4 -peerkey $key -out $seed
	if [ $? -ne 0 ]; then
		rm -f $key $seed
		exit 1
	fi

	if [ "$2" = "1" ]; then
		cat $seed | openssl dgst -sha256 -binary -out $seed
		if [ $? -ne 0 ]; then
			rm -f $key $seed
			exit 1
		fi
	fi

	openssl ec -pubout -outform DER -in $4 -out seed.bin
	if [ $? -ne 0 ]; then
		rm -f $key $seed
		exit 1
	fi
else
	seed=`tempfile -d .`
	head -c 32 /dev/random > $seed

	if [ "$2" = "2" ]; then
		openssl pkeyutl -in $seed -encrypt -inkey $key -pubin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out seed.bin
		if [ $? -ne 0 ]; then
			rm -f $key $seed
			exit 1
		fi
	else
		echo "Unsupported encryption mode"
		rm -f $key $seed
		exit 1
	fi
fi

rm -f $key

seed_hex=`cat $seed | xxd -p | tr -d '\n'`
echo "Seed: $seed_hex"

label=`echo -n "signing key" | xxd -p`
sign_nist="00000001${label}0000000100"

sign_key=`tempfile -d .`
echo -n $sign_nist | xxd -r -p | openssl dgst -sha256 -mac hmac -macopt hexkey:$seed_hex -out $sign_key -binary
if [ $? -ne 0 ]; then
	rm -f $seed $sign_key
	exit 1
fi

sealing="sealing.bin"
head -c 32 /dev/random > cipher.bin

head -c 32 /dev/zero > $sealing
if [ -n "$PMR0" ]; then
	echo $PMR0 | xxd -r -p >> $sealing
else
	head -c 32 /dev/zero >> $sealing
fi

head -c 32 /dev/zero >> $sealing
if [ -n "$PMR1" ]; then
	echo $PMR1 | xxd -r -p >> $sealing
else
	head -c 32 /dev/zero >> $sealing
fi

head -c 32 /dev/zero >> $sealing
if [ -n "$PMR2" ]; then
	echo $PMR2 | xxd -r -p >> $sealing
else
	head -c 32 /dev/zero >> $sealing
fi

head -c 64 /dev/zero >> $sealing
head -c 64 /dev/zero >> $sealing

sign=`cat $sign_key | xxd -p | tr -d '\n'`

payload=`tempfile -d .`
cat cipher.bin $sealing > $payload
openssl dgst -sha256 -mac hmac -macopt hexkey:$sign -out hmac.bin -binary $payload
if [ $? -ne 0 ]; then
	rm -f $sign_key $seed $payload
	exit
fi


label=`echo -n "encryption key" | xxd -p`
enc_nist="00000001${label}0000000100"

echo "Encryption Key:"
echo -n $enc_nist | xxd -r -p | openssl dgst -sha256 -mac hmac -macopt hexkey:$seed_hex

rm -f $sign_key $seed $payload
