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

grep -q "BEGIN PUBLIC KEY" $cert
if [ $? -eq 0 ]; then
	# The cert is a raw public key.
	cp $cert $key
else
	# The cert is an X.509 certificate.
	grep -q "BEGIN CERTIFICATE" $cert
	if [ $? -eq 0 ]; then
		inform=PEM
	else
		inform=DER
	fi

	openssl x509 -inform $inform -outform PEM -noout -pubkey -in $cert > $key
	if [ $? -ne 0 ]; then
		rm -f $key
		exit 1
	fi
fi

if [ "$1" = "1" ]; then
	ecc=`mktemp -p .`
	if [ -z "$privkey" ]; then
		key_curve=`openssl ec -noout -pubin -text -in $key | grep 'ASN1 OID' | awk '{print $3}'`
		
		openssl ecparam -name $key_curve -genkey -noout -out $ecc
		if [ $? -ne 0 ]; then
			rm -f $key $ecc
			exit 1
		fi
	else
		echo "Using $privkey for sealing."
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
		openssl pkeyutl -in $seed -encrypt -inkey $key -pubin -pkeyopt rsa_padding_mode:oaep \
			-pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out seed.bin
		if [ $? -ne 0 ]; then
			rm -f $key $seed
			exit 1
		fi
	elif [ "$2" = "1" ]; then
		openssl pkeyutl -in $seed -encrypt -inkey $key -pubin -pkeyopt rsa_padding_mode:oaep \
			-pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -out seed.bin
		if [ $? -ne 0 ]; then
			rm -f $key $seed
			exit 1
		fi
	elif [ "$2" = "0" ]; then
		openssl pkeyutl -in $seed -encrypt -inkey $key -pubin -out seed.bin
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
echo -ne "$(echo -n $sign_nist | sed -e 's/../\\x&/g')" | openssl dgst -sha256 -mac hmac \
	-macopt hexkey:$seed_hex -out $sign_key -binary
if [ $? -ne 0 ]; then
	rm -f $seed $sign_key
	exit 1
fi

sealing="sealing.bin"
dd if=/dev/random bs=1 count=$CIPHER_LEN > cipher.bin 2> /dev/null

add_pmr_policy () {
	pmr=$1
	
	if [ -n "$pmr" ]; then
		pmr_length=${#pmr}
		let 'padding = 64 - (pmr_length / 2)'
		dd if=/dev/zero bs=1 count=$padding >> $sealing 2> /dev/null
		
		echo -ne "$(echo $pmr | sed -e 's/../\\x&/g')" >> $sealing
	else
		dd if=/dev/zero bs=1 count=64 >> $sealing 2> /dev/null
	fi
}

echo -n "" > $sealing
add_pmr_policy "$PMR0"
add_pmr_policy "$PMR1"
add_pmr_policy "$PMR2"
add_pmr_policy "$PMR3"
add_pmr_policy "$PMR4"

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
echo -ne "$(echo -n $enc_nist | sed -e 's/../\\x&/g')" | openssl dgst -sha256 -mac hmac \
	-macopt hexkey:$seed_hex
rm -f $sign_key $seed $payload
