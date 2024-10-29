# Uncrustify (Code Beautifier)

#### _A source code beautifier for C, C++, C#, Objective-C, D, Java, Pawn and Vala._

[Uncrustify-0.78.1](https://github.com/uncrustify/uncrustify/tree/uncrustify-0.78.1)

### Brief about Uncrustify

> Uncrustify is a tool that can automatically format your source code according to a set of rules that you can customize. It can handle various aspects of code formatting, such as indentation, spacing, alignment, and braces. It can also sort your includes, align your comments, and add or remove newlines.

> By using Uncrustify, you can benefit from the following advantages:
  - It can save time and effort by letting Uncrustify do the formatting for you.
  - You can ensure that your code follows a consistent style across different files and projects.
  - It can improve the readability and maintainability of your code, which can help you find and fix bugs faster.
  - You can avoid conflicts and merge issues that may arise from different formatting preferences.

### Ubuntu Uncrustify installation:

> To install Uncrustify on Ubuntu execute `install_dependencies.sh` script.
> Configuration file `uncrustify.cfg` will be present at cerberus-core repo path: `~/<repo_location>/cerberus/uncrustify.cfg`

### Uncrustify build directory.

> Executable will be generated inside build directory.
  `~/build_tools/uncrustify/build/uncrustify`
> Copy the executable to /usr/bin folder.
  `~/build_tools/uncrustify/build$ sudo cp uncrustify /usr/bin`
> Verify with below command (execute from any path).
  `uncrustify -v`

### VSCode setup

> Install Extension: Uncrustify by [Zachary Flower](https://marketplace.visualstudio.com/items?itemName=zachflower.uncrustify)

> Uncrustify either set up the format on save feature in Visual Studio Code.

> Alternatively, format the file manually by right-clicking and selecting the option to format the document (Right Click -> Format Document).

## Manually using shell script

> If you require to run `uncrustify_foramt.sh` script manually then follow below instructions,

  1. Set build tools and directory path:
     - `BUILD_TOOLS`: Set the directory path for build_tools.
     - `BUILD_STAGINGDIRECTORY`: Set repo directory path.

  2. Modify the script variables in `uncrustify_format.sh`:
     - `UNC_DIR`: Set the directory path for Uncrustify.
     - `UNC_EXECUTABLE`: Set the path to the Uncrustify executable.
     - `UNC_CNF_FILE`: Set the path to your Uncrustify configuration file (`uncrustify.cfg`).
     - `UNC_CHK_SRC_FILES`: Set the path to the source code files which would be passed to script to check and format.

  3. Run the script:
     ```sh
      bash uncrustify_format.sh
     ```

  4. Source code formatted changes can be seen by `git diff` on repo.

  5. Re-execute `uncrustify_format.sh` after file update to verify no more formatting error exists.

