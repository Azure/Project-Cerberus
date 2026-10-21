## Notes on integrating ACVP components

**TODO:** Consider building the needed Acvpparser code as a static library. For now, the below fully applies.

The interface implementations in the `core/acvp` directory rely on the [Acvpparser library](https://github.com/smuellerDD/acvpparser/tree/42ef9a65a603a488d39771775e7e7cfa2892bd0d). To integrate these implementations and the library into a project build, include the Acvpparser CMake in your project build's `CMakeLists.txt` file:

```cmake
include(Acvpparser)
```
