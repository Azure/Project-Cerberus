#! /bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if [ $# -lt 3 ]; then
	echo "Usage: $0 <type> <params> <cert> [privkey]"
	exit 1
fi

if [ "x$4" = "xkeep" ]; then
	keep_ecc=1
else
	keep_ecc=0
	privkey=$4
fi

if [ -z "$CIPHER_LEN" ]; then
	CIPHER_LEN=32
fi
if [ -z "$SEED_LEN" ]; then
	SEED_LEN=318		# Maximum length for RSA3k key
fi

cert=$3
key=`mktemp -p .`
openssl x509 -inform DER -outform PEM -noout -pubkey -in $cert > $key
if [ $? -ne 0 ]; then
	rm -f $key
	exit 1
fi

if [ "$1" = "1" ]; then
	ecc=`mktemp -p .`
	if [ -z "$privkey" ]; then
		openssl ecparam -name prime256v1 -genkey -noout -out $ecc
		if [ $? -ne 0 ]; then
			rm -f $key $ecc
			exit 1
		fi
	else
		cp -f $4 $ecc
		if [ $? -ne 0 ]; then
			rm -f $key $ecc
			exit 1
		fi
	fi

	seed=`mktemp -p .`
	openssl pkeyutl -derive -inkey $ecc -peerkey $key -out $seed
	if [ $? -ne 0 ]; then
		rm -f $key $ecc $seed
		exit 1
	fi

	if [ "$2" = "1" ]; then
		hash=`mktemp -p .`
		cat $seed | openssl dgst -sha256 -binary -out $hash
		if [ $? -ne 0 ]; then
			rm -f $key $ecc $seed $hash
			exit 1
		fi

		mv -f $hash $seed
	fi

	openssl ec -pubout -outform DER -in $ecc -out seed.bin
	if [ $? -ne 0 ]; then
		rm -f $key $ecc $seed
		exit 1
	fi
else
	ecc=''
	seed=`mktemp -p .`
	dd if=/dev/random bs=1 count=$SEED_LEN > $seed 2> /dev/null
	
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
if [ $keep_ecc -eq 0 ]; then
	rm -f $ecc
else
	echo "Private Key: $ecc"
fi

seed_len=`stat -c %s seed.bin`
if [ $CIPHER_LEN -lt 0 ]; then
	let 'CIPHER_LEN = -(CIPHER_LEN + seed_len)'
fi

seed_hex=`cat $seed | hexdump -ve '/1 "%02x"' | tr -d '\n'`
echo "Seed: $seed_hex"

label=`echo -n "signing key" | hexdump -ve '/1 "%02x"'`
sign_nist="00000001${label}0000000100"

sign_key=`mktemp -p .`
echo -ne "$(echo -n $sign_nist | sed -e 's/../\\x&/g')" | openssl dgst -sha256 -mac hmac -macopt hexkey:$seed_hex -out $sign_key -binary
if [ $? -ne 0 ]; then
	rm -f $seed $sign_key
	exit 1
fi

sealing="sealing.bin"
dd if=/dev/random bs=1 count=$CIPHER_LEN > cipher.bin 2> /dev/null

dd if=/dev/zero bs=1 count=32 > $sealing 2> /dev/null
if [ -n "$PMR0" ]; then
	echo -ne "$(echo $PMR0 | sed -e 's/../\\x&/g')" >> $sealing
else
	dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
fi

dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
if [ -n "$PMR1" ]; then
	echo -ne "$(echo $PMR1 | sed -e 's/../\\x&/g')" >> $sealing
else
	dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
fi

dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
if [ -n "$PMR2" ]; then
	echo -ne "$(echo $PMR2 | sed -e 's/../\\x&/g')" >> $sealing
else
	dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
fi

dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
if [ -n "$PMR3" ]; then
	echo -ne "$(echo $PMR3 | sed -e 's/../\\x&/g')" >> $sealing
else
	dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
fi

dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
if [ -n "$PMR4" ]; then
	echo -ne "$(echo $PMR4 | sed -e 's/../\\x&/g')" >> $sealing
else
	dd if=/dev/zero bs=1 count=32 >> $sealing 2> /dev/null
fi

sign=`cat $sign_key | hexdump -ve '/1 "%02x"' | tr -d '\n'`

payload=`mktemp -p .`
cat cipher.bin $sealing > $payload
openssl dgst -sha256 -mac hmac -macopt hexkey:$sign -out hmac.bin -binary $payload
if [ $? -ne 0 ]; then
	rm -f $sign_key $seed $payload
	exit
fi

label=`echo -n "encryption key" | hexdump -ve '/1 "%02x"'`
enc_nist="00000001${label}0000000100"

echo "Encryption Key:"
echo -ne "$(echo -n $enc_nist | sed -e 's/../\\x&/g')"| openssl dgst -sha256 -mac hmac -macopt hexkey:$seed_hex
rm -f $sign_key $seed $payload
