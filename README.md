# Syscall Tracer for ARM64 Android Devices
## Overview
This tool is designed to trace system calls on ARM64-bit Android devices. It allows you to attach to a running process by PID or process name, or execute a command and trace its system calls. The tool provides options to display absolute and relative addresses, as well as backtraces for the system calls.

## Features

**Attach by PID**: Attach to a running process by specifying its PID.

**Attach by Process Name**: Attach to a running process by specifying its name.

**Execute and Trace**: Execute a command and trace its system calls.

**System Call Tracing**: Specify which system calls to trace.

**Address Display**: Option to display absolute and relative addresses.

**Backtrace**: Option to display call stack for each system call.

## Prerequisites

An Android device with root privileges and the ability to execute shell commands.

## Build

1. **Clone the Repository:**

```sh
git clone https://github.com/WangONC/syscallTracer.git
cd syscallTracer
```

2. **Build the Tool**

```sh
\path\to\ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe -target aarch64-linux-android30 -static .\tracer.cpp -o .\syscall_tracer
```

## Usage

**Command Line Options**

```sh
Usage: syscall_tracer [options] -- <command>
Options:
  -p <pid>           Attach to process by PID
  -n <process_name>  Attach to process by name
  -e <command>       Execute and attach to command
  -s <syscall_num>   Specify syscall number to hook (can be used multiple times)
  -a                 Show absolute address
  -r                 Show relative address
  -b                 Show backtrace
  -h                 Show this help message
```

## Examples

1. **Attach to a Process by PID**:

```sh
./syscall_tracer -p 1234
```

2. **Attach to a Process by Name**:

```sh
./syscall_tracer -n init
```

3. **Execute and Trace a Command**:

```sh
./syscall_tracer -e ls
```

4. **Specify System Calls to Trace**:

``` sh
./syscall_tracer -s 63 -s 64 -e "cat /data/local/tmp/test.txt"
```

5. **Show Absolute and Relative Addresses**:

```sh
./syscall_tracer -a -r -e ls
```

6. **Show Backtrace:**

```sh
./syscall_tracer -b -e ls
```

7. **Trace All System Calls**

```sh
./syscall_tracer -n init
```

8. **Show All**

```sh
./syscall_tracer -n init -s 94 -s 222 -s 220 -arb
```

## Output

The tool will output the system calls being executed by the target process, along with the specified address information and backtraces.

Example output:

```shell
New module loaded: /system/framework/arm64/boot.oat (0x6f711000 - 0x6f7a4000) offset 0x0
New module loaded: /system/framework/arm64/boot.oat (0x6f7a4000 - 0x6fa88000) offset 0x93000
New module loaded: /system/framework/arm64/boot.vdex (0x6fa89000 - 0x6fa9c000) offset 0x0
New module loaded: /system/framework/arm64/boot.oat (0x6fa9c000 - 0x6fa9d000) offset 0x377000
New module loaded: /system/framework/arm64/boot.oat (0x6fa9d000 - 0x6fa9e000) offset 0x378000
New module loaded: /system/framework/arm64/boot-core-libart.oat (0x6fa9e000 - 0x6faac000) offset 0x0
New module loaded: /system/framework/arm64/boot-core-libart.oat (0x6faac000 - 0x6faf0000) offset 0xe000
New module loaded: /system/framework/arm64/boot-core-libart.vdex (0x6faf1000 - 0x6faf4000) offset 0x0
New module loaded: /system/framework/arm64/boot-core-libart.oat (0x6faf4000 - 0x6faf5000) offset 0x52000
New module loaded: /system/framework/arm64/boot-core-libart.oat (0x6faf5000 - 0x6faf6000) offset 0x53000
...
Attached to thread: 1936
Attached to thread: 1937
Attached to thread: 1938
Attached to thread: 1942
...
Thread 2252 entering syscall futex(98) at 0x79d36d6e60 Relative address: 0x4de60 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0x4d000)
Backtrace:
  [0] 0x79d36d6e60 Relative address: 0x4de60 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0x4d000)
  [1] 0x79d373e5d8 Relative address: 0xb55d8 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0xa4000)
  [2] 0x769dd4a354 Relative address: 0x79354 in /data/data/com.wachat/virtual/data/user/0/com.whatsapp/files/decompressed/libs.spo/libc++_shared.so (file offset: 0x0)
  [3] 0x769a252a64 Relative address: 0xbdca64 in /data/data/com.wachat/virtual/data/user/0/com.whatsapp/files/decompressed/libs.spo/libwhatsapp.so (file offset: 0x3af000)
  [4] 0x769a2516b8 Relative address: 0xbdb6b8 in /data/data/com.wachat/virtual/data/user/0/com.whatsapp/files/decompressed/libs.spo/libwhatsapp.so (file offset: 0x3af000)
  [5] 0x769a252240 Relative address: 0xbdc240 in /data/data/com.wachat/virtual/data/user/0/com.whatsapp/files/decompressed/libs.spo/libwhatsapp.so (file offset: 0x3af000)
  [6] 0x772ba40358 Relative address: 0x440358 in /apex/com.android.art/lib64/libart.so (file offset: 0x2fc000)
  [7] 0x189ca5dd52421277 Relative address: Not found in any loaded module, possibly in anonymous memory mapping.
Thread 2187 entering syscall futex(98) at 0x79d36d6e60 Relative address: 0x4de60 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0x4d000)
Backtrace:
  [0] 0x79d36d6e60 Relative address: 0x4de60 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0x4d000)
  [1] 0x772ba8638c Relative address: 0x48638c in /apex/com.android.art/lib64/libart.so (file offset: 0x445000)
  [2] 0x6f7a42e0 Relative address: 0x932e0 in /system/framework/arm64/boot.oat (file offset: 0x93000)
Thread 2140 entering syscall futex(98) at 0x79d36d6e60 Relative address: 0x4de60 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0x4d000)
Backtrace:
  [0] 0x79d36d6e60 Relative address: 0x4de60 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0x4d000)
  [1] 0x772ba46334 Relative address: 0x446334 in /apex/com.android.art/lib64/libart.so (file offset: 0x445000)
  [2] 0x6f7a4508 Relative address: 0x93508 in /system/framework/arm64/boot.oat (file offset: 0x93000)
Thread 2134 entering syscall futex(98) at 0x79d36d6e60 Relative address: 0x4de60 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0x4d000)
Backtrace:
  [0] 0x79d36d6e60 Relative address: 0x4de60 in /apex/com.android.runtime/lib64/bionic/libc.so (file offset: 0x4d000)
  [1] 0x772ba46334 Relative address: 0x446334 in /apex/com.android.art/lib64/libart.so (file offset: 0x445000)
  [2] 0x6f7a4508 Relative address: 0x93508 in /system/framework/arm64/boot.oat (file offset: 0x93000)
...
```

## TODO

Bug fixes, optimized backtrace, optimized output, and parsing/printing system call arguments? I might not update it further, who knows?



## TIPS

This tool only parses non-anonymous memory mappings because its purpose is to facilitate reverse engineering. Calculating offset addresses for anonymous memory mappings is meaningless.
