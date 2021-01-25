#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if [ $# -lt 1 ]; then
	echo "Usage: $0 <file> [out]"
	exit 1
fi

if [ -n "$2" ]; then
	data_out=$2
else
	data_out=app_data
fi

var_name=`echo $data_out | tr 'a-z' 'A-Z'`


img=`xxd -p -c 1 $1 | head --bytes=-1 | tr '\n' ' ' | sed 's/ /,0x/g'`
fmt=`echo 0x$img | fold -w 80`


cat << EOF > $data_out.c
#include <stdint.h>

const uint8_t ${var_name}[] = {
$fmt
};
const uint32_t ${var_name}_LEN = sizeof (${var_name});
EOF
