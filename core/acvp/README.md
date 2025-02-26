## Notes on integrating ACVP components

**TODO:** Consider building the needed Acvpparser code as a static library. For now, the below steps fully apply.

The interface implementations in the `core/acvp` directory rely on the [Acvpparser library](https://github.com/smuellerDD/acvpparser/tree/42ef9a65a603a488d39771775e7e7cfa2892bd0d). To integrate these implementations and the library into a project build, incorporate the following into your project build's `CMakeLists.txt` file:

### **1. Include the Acvpparser.cmake file**
```cmake
include(Acvpparser)
```
### **2. Include acvp_override.h to override the necessary Acvpparser project headers**
For example:
```cmake
target_compile_options(
	${TARGET_NAME}
	PRIVATE
		-include ${CORE_DIR}/acvp/acvp_override.h
)
```
### **3. Override C standard library memory allocations (if necessary)**
The Acvpparser sources rely on C standard library memory allocations. Override these memory allocations with the platform-specific allocations:
```cmake
set_source_files_properties(
	${ACVPPARSER_SOURCES}
	PROPERTIES
	COMPILE_DEFINITIONS "calloc=platform_calloc;free=platform_free;malloc=platform_malloc"
)
```
