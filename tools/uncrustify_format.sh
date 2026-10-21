#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.

# Check for tools directory presence
if [ -z "$BUILD_TOOLS" ]; then
	BUILD_TOOLS=`realpath ~/build_tools`
	echo "\$BUILD_TOOLS not set. Using $BUILD_TOOLS"
else
	echo "Using existing \$BUILD_TOOLS=$BUILD_TOOLS"
fi

# Find current path
pwd=`pwd`
current_path=`dirname "$(realpath "$BASH_SOURCE")"`
cerberus_folder="cerberus"
cerberus_root=$(echo "$current_path" | sed -E "s|(.*$cerberus_folder).*|\1|")
cd "$cerberus_root"

# Define variables
UNC_DIR=$BUILD_TOOLS/uncrustify
UNC_BUILD_DIR=$UNC_DIR/build
UNC_EXECUTABLE=$UNC_BUILD_DIR/uncrustify
UNC_CHK_FLAG=0
UNC_SRC_MAX_LINE=10000

# Select repo path and exclude list
UNC_CNF_FILE=$cerberus_root/uncrustify.cfg
UNC_REPO_CHK='cerberus-core'
UNC_CHK_SRC=$cerberus_root
EXC_FILE=$cerberus_root/tools/uncrustify_exclude_list.txt

echo "unc_utility path: $UNC_BUILD_DIR"
echo "unc_config path: $UNC_CNF_FILE"
echo "unc_check repo: $UNC_REPO_CHK"
echo "unc_check path: $UNC_CHK_SRC"
echo "unc_version: $($UNC_EXECUTABLE -v)"
echo "exclude_file: $EXC_FILE"


# Check if Uncrustify is installed
if ! $UNC_EXECUTABLE --version &> /dev/null; then
	echo "Error: Uncrustify unavailable. Please check the build process."
	exit 1
fi

# Check if Repo variable are empty
if [ -z "$UNC_REPO_CHK" ]; then
	echo "Error: No Repository available to check."
	exit 1
fi

# Check for Uncrustify configuration file presence
if [ ! -f "$UNC_CNF_FILE" ]; then
	echo "File $UNC_CNF_FILE does not exist."
	exit 1
fi

# Check for Uncrustify exclude file presence
if [ ! -f "$EXC_FILE" ]; then
	echo "File $EXC_FILE does not exist."
	exit 1
fi

# Filter list of exclude file and dirctories
exclude_path=$(awk '/Exclude directories/{flag=1; next}; \
	/Exclude files/{flag=0;} flag' $EXC_FILE| \
	sed '1s/^/-path /; 2,$s/^/ -o -path /' | tr -d '\n' | sed 's/ -o -path $//')
exclude_file=$(awk '/Exclude files/{flag=1; next}; \
	/Exclude files/{flag=0;} flag' $EXC_FILE | \
	sed 's/^/ ! -name /' | tr -d '\n' | sed 's/ ! -name $//')
echo "Exclude dir $exclude_path"
echo "Exclude file $exclude_file"

run_uncrustify()
{
	# Count lines in the file
	lines=$(wc -l < "$1")

	# Check if the file has 10,000 or fewer lines
	if [ "$lines" -le $UNC_SRC_MAX_LINE ]; then
		# Check formatting without making changes
		$UNC_EXECUTABLE -c "$UNC_CNF_FILE" --check "$1" > /dev/null 2>&1

		if [ $? -ne 0 ]; then
			$UNC_EXECUTABLE -c "$UNC_CNF_FILE" --no-backup "$1" > /dev/null 2>&1
			# TODO: Remove this check once issue resolved on link
			if [ $? -ne 0 ] && [ $? -ne 1 ]; then
				echo "Warning: file $file issue"\
					"link to https://github.com/uncrustify/uncrustify/issues/4272"
				return 0
			fi
			echo "Warning: Uncrustify failed on $1"
			return 1
		fi
	else
		echo "Warning: Skip $1 file as >$UNC_SRC_MAX_LINE lines."
	fi

	return 0
}

# Run Uncrustify formatting check
if [ -d $UNC_CHK_SRC ]; then
		echo "Running Uncrustify check on $UNC_REPO_CHK repo"
		# filter directory which is not require to check
		find $UNC_CHK_SRC -type d \( $exclude_path \) \
		-prune -o \( \( -name '*.c' -o -name '*.h' \) $exclude_file \) \
		-print | \
		while read -r file; do
			# Call uncrustify check
			run_uncrustify $file
			# Check for failure case
			if [ $? -eq 1 ]; then
				echo 1 > unc_chk_temp
			fi
			done
else
	# formatting check for file only while running script individually
	run_uncrustify "$UNC_CHK_SRC"
	if [ $? -eq 1 ]; then
		echo 1 > unc_chk_temp
	fi
fi

# TODO: remove after issue resolved [https://github.com/uncrustify/uncrustify/issues/4272]
# Remove files with ".uncrustify" extension
find $UNC_CHK_SRC -type f -iname "*.uncrustify" | xargs rm -f

# Show git diff modified file
if [ -e unc_chk_temp ]; then
	UNC_CHK_FLAG=$(<unc_chk_temp)
	# Remove temp file
	rm unc_chk_temp
	# Failing the pipeline  if the flag is set to zero
	if [ $UNC_CHK_FLAG -eq 1 ]; then
		pushd $UNC_CHK_SRC && git diff --color && popd
		echo "Uncrustify: formatting issues detected"
		exit 1
	fi
else
	echo "Uncrustify: No format issues detected"
fi
