# Cerberus Source Code

## Linux Unit Test Build

1. Install pre-requisites
	```bash
	sudo apt install git build-essential libssl-dev ninja-build cmake
	```

2. Install latest cmake
	```bash
	# Download CMake install script
	wget https://github.com/Kitware/CMake/releases/download/v3.16.2/cmake-3.16.2-Linux-x86_64.sh
	chmod +x cmake-3.16.2-Linux-x86_64.sh

	# Install CMake
	./cmake-3.16.2-Linux-x86_64.sh --prefix=~/.local #--skip-license

	# Validate CMake version is 3.16
	cmake --version
	```

3. Under the Cerberus source folder create "build" folder
	```bash
	cd <cerberus_src_dir>
	mkdir build
	cd build
	```

4. Create the build scripts
	```bash
	cmake -G Ninja ../projects/linux/testing/
	```

5. Build the Cerberus source
	```bash
	ninja
	```

5. Run Unit Tests
	```bash
	./cerberus-linux-unit-tests
	```
