# unthemidator

[![@x86rc](https://img.shields.io/badge/%40x86rc-000000?style=flat&logo=x&logoColor=white)](https://x.com/x86rc)
[![Discord Server](https://img.shields.io/badge/Discord%20Server-503010?style=flat&logo=discord&logoColor=white)](https://discord.gg/Dvcj2qQVsg)

A universal unpacker for Themida-protected binaries and runtime protection removal tool. 
Unthemidator does **NOT** run the binary, nor does it call any APIs or execute syscalls used by target binaries 
on the host machine.

Unthemidator works with all kinds of Windows binaries (dll, exe, sys and others) in both x86 (32-bit) 
and x86_64 / amd64 (64-bit) variations.

After unpacking, a full PE rebuild is performed, making the unpacked binary runnable and debuggable.

In addition to unpacking and PE rebuilding, Unthemidator can identify the version of 
Themida / Code Virtualizer virtual machines used in binaries.

## Features

- [x] Full PE unpacking
- [x] Resource unpacking
- [x] Virtual machine decompression
- [x] Import decryption and IAT restoration
- [x] Themida/Code Virtualizer version identification
- [x] Location of all Themida/CV entry points

## How to

Simply drag and drop a packed binary onto unthemidator or use the following CLI command on Windows:
```bash
unthemidator.exe [options] {path_to_bin.exe|.dll|.sys|.bin}
```
and the following CLI command on a Unix-based system:
```bash
./unthemidator [options] {path_to_bin.exe|.dll|.sys|.bin}
```

A PE will only be considered a kernel driver if its file extension is **.sys**. 
This is done to ensure correct parsing of files with any extensions as usermode applications by default. 
Not to mention that packed kernel drivers are extremely rare and can only run on insecure systems.

#### Options

Below is a complete overview of all unthemidator options.

- `--out-file` - output file name / path. Defaults to `{program_name}.unpacked.{program_extension}`
- `--license-file` - license file name / path. Required for successful WinLicense protected binaries unpacking.
- `--imports-file` - name (or path) of the file to save information about imports to. Should be JSON. Defaults to `{program_name}.imports.json`
- `--vms-file` - name (or path) of the file to save information about VM entry points to. Should be JSON. Defaults to `{program_name}.vms.json`
- `--vm-depth` - for virtual machine research and virtual instruction tracing, how many virtualization layers should be single-stepped. Defaults to `0` - no VM exploration.
- `--no-imp` - skip import lookup
- `--no-startup` - skip runtime startup processing. This will prevent ALL unpacking except the initial boot stage.
- `--no-vm-lookup` - skip virtual machine lookup
- `--no-loader` - skip anti-dump fixer loader generation. This may make the binary unrunnable if the OEP is virtualized or there are per-macro security checks

#### Custom Modules

Some binaries rely on custom modules shipped with the program. You can simply put all custom modules 
in the `modules` directory before unpacking such binaries. The same can be done for missing system 
modules, which is useful if you're running unthemidator on a Unix system.

#### Reporting Issues

If you have a problem or something isn't working as intended (or not working at all), create an issue in this repository.

## Download

Check out the [Releases](https://github.com/x86rc/unthemidator/releases) page to find precompiled unthemidator. 
Currently, the following variants are available:

- Windows x64 executable
- macOS (Apple Silicon) executable

### Supported Themida versions:

- Themida v3.0 - v3.2.6.0
- Win License v3.0 - v3.2.6.0
- Code Virtualizer (compressed VMs) v3.0 - v3.2.6.0
- Code Virtualizer (compressed VMs) v4.0

### Limitations

- This will not deobfuscate (devirtualize, unmutate) code

### Research, documentation and useful links

Devirtualize Themida / Code Virtualizer -virtualized code's CFG, see vmcalls as well as memory reads and writes: [Themida Explorer](https://tools.shablyko.com/themida/).

Learn more about Themida obfuscation internals, including its virtual machines, in the following articles:

1. [Devirtualizing Themida's (Code Virtualizer) FALCON VM to readable code](https://blog.shablyko.com/posts/themida-falcon-devirt/). Documentation of the Themida / CV research process, starting with no prior VM knowledge or complex tools.
2. [Detailed analysis of Themida's LION VM (Part 1)](https://blog.shablyko.com/posts/themida-lion-vm/). Documentation of the Lion VM, one of the more recent Themida / Code Virtualizer virtual machines.
3. [Detailed analysis of Themida's LION VM (Part 2)](https://blog.shablyko.com/posts/themida-lion-vm-part-2/). Second part of the Lion VM documentation.

---

<p align="center">
  Want to chat about deobfuscation or reverse engineering?<br><br>
  <a href="https://discord.gg/Dvcj2qQVsg">
    <img src="https://img.shields.io/badge/Find%20us%20here%20too-5865F2?style=for-the-badge&amp;logo=discord&amp;logoColor=white" alt="Find us here too">
  </a>
</p>
