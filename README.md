# Project Cerberus

Project Cerberus is designed to be a hardware root of trust (RoT) for server platforms.  It provides functionality 
to enforce secure boot for firmware on devices with or without intrinsic secure boot capabilities.  It also
provides a mechanism to securely attest to the state of the device firmware.

Details of Project Cerberus's goals and design can be found at https://github.com/opencomputeproject/Project_Olympus/tree/master/Project_Cerberus.

## Getting the Source Code

The Cerberus source code relies on some external dependencies and allows for customization and extension to
different devices.  To support these various dependencies, the repo tool is used for local source code
management.

Details about the repo tool can be found at https://gerrit.googlesource.com/git-repo/+/refs/heads/master/README.md.

### repo on Linux

In order to use repo, it must be installed on the system and accessible through `$PATH`.

```bash
mkdir ~/.local/bin
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/.local/bin/repo
chmod a+rx ~/.local/bin/repo
```

### repo on Windows

The repo tool is designed to work in a Linux environment, so there are some difficulties working with repo in
Windows.  See the repo documentation for details regarding Windows support at https://gerrit.googlesource.com/git-repo/+/refs/heads/master/docs/windows.md

If repo is still not working, there are two other options for using repo in Windows.

1. Use Windows Subsystem for Linux (WSL).  This has the benefit of not needing anything special for repo to work, but
has the downside of not actually being a Windows development enviroment.

2. There exists an old version of repo ported to work in Windows.  Details of this project can be found on github at
https://github.com/esrlabs/git-repo.  See the README.md in that project for installation details.

If no option for repo is working on Windows and Windows must be used, then git repositories must be manually cloned per
the repo manifest file.

### Download Source

Once repo is installed, it will be used to download the Cerberus source code into a local working copy.

#### Download using HTTPS

This will the typical method for initializing the local repository.
```bash
mkdir Project-Cerberus
cd Project-Cerberus
repo init -u https://github.com/Azure/Project-Cerberus-manifest.git -b master
repo sync
```

#### Download using SSH

If an SSH connection is desired or required to retrieve the Cerberus code, the repository must be initalized in this way.
```bash
mkdir Project-Cerberus
cd Project-Cerberus
repo init -u git@github.com:Azure/Project-Cerberus-manifest.git -m default-ssh.xml -b master
repo sync
```

## Source Layout

The core set of source code provides a set of basline functionality that can be integrated and ported to devices that
require Cerberus functionality.  Most of the code available here is agnostic to the actual device that it will run on,
with abstraction layers defined where necessary.

The Cerberus source tree is structured as follows:

| Folder            | Description                                     |
|-------------------|-------------------------------------------------|
| core              | Platform agnostic Cerberus code and unit tests. |
| external          | Required external components.                   |
| projects          | Platform specific implementations.              |
| testing           | Primitives to support unit tests.               |
| tools             | Scripts and other useful tools.                 |
| cmake             | CMake toolchain and core dependency scripts.    |

### Existing Projects

The baseline Cerberus source code comes with support for some projects that are generally useful.

| Folder     | Description                                            |
|------------|--------------------------------------------------------|
| freertos   | Platform port to FreeRTOS.                             |
| linux      | Platform port to Linux.                                |
| gcc        | Functions needed when using GCC for ARM.               |
| keil       | Functions needed when using Keil/ARMCC.                |

#### Note for Linux Port

The Linux platform port exists only to support development and unit testing of core Cerberus code.  It is not guaranteed
to be production ready code.

### Extending the Baseline

To add support for additional platforms and/or devices, additions must be made to the source tree.  These additional 
components can be added to the local source tree by adding additional project definitions in local repo manifests in the
`.repo/local_manifests` directory.  More details about this process can be found at https://gerrit.googlesource.com/git-repo/+/refs/heads/master/docs/manifest-format.md.

There will typically be two types of additions.  
1. New 3rd party components required for the project.  These will be added to the `external` directory.
2. A target platform or specific application build.  These will be added to the `projects` directory.

## Linux Unit Test Build

Without any additional projects, the Cerberus code can be built on Linux and the unit tests can be run.  This provides
the main development environment for adding core functionality and serves as an example for creating new projects.

1. Install pre-requisites
	```bash
	sudo apt install git build-essential libssl-dev ninja-build cmake lcov
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
	
### Unit Tests With Coverage Report

The unit test build includes a target which runs the unit tests and generates a code coverate 
report. If necessary, this target also builds the unit tests. The report output can be found at
build/coverage_report.

1. Complete steps 1-4 from the previous section

2. Build, run unit tests, and generate coverage report
	```bash
	ninja coverage
	```
## Contributing

Cerberus code is developed following Test-Driven Development (TDD) practices.  Any code submissions are expected to be
similarly developed.

### Agreement and Code of Conduct

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
