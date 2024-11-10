
# elfspirit

[![arch](https://img.shields.io/badge/arch-i386%20%7C%20amd64-orange)](#)
[![platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-orange)](#)
[![libc](https://img.shields.io/badge/libc-3.31%20%7C%203.32-lightgrey)](#) 
[![ld](https://img.shields.io/badge/ld-3.31%20%7C%203.32-lightgrey)](#)
[![license](https://img.shields.io/github/license/liyansong2018/elfspirit)](https://github.com/liyansong2018/elfspirit/blob/main/LICENSE)

**elfspirit** is a useful program that parse, manipulate and camouflage ELF files. It provides a variety of functions, including adding or deleting a section, injecting a dynamic link library for binary static, deleting the section header table to increase the difficulty of reverse engineering, parse ELF like `readelf` and edit ELF like 010 editor.

More details about static injection: [ELF Static Injection to Load Malicious Dynamic Link Library](https://violentbinary.github.io/posts/1-elf-static-injection-to-load-malicious-dynamic-link-library/). Tips: Only the readme on the project homepage will tell you the latest features of the tool, while other documents will not. But you might like [LIEF](https://github.com/lief-project/LIEF) and [libelfmaster](https://github.com/elfmaster/libelfmaster) more.
## Building

**elfspirit** can be installed easily:

```shell
make
```

## Dependencies

We run **elfspirit** using:

- Ubuntu 20.04 / Kali Linux 2020.4
- gcc 10.2.1
- libc-2.31/2.32

Currently, this is the only supported environment. Other environments may also work, but we unfortunately do not have the manpower to investigate compatibility issues. 

## Usage

### Analyze ELF format, like readelf

```shell
$ elfspirit parse -H myelf
 [+] ELF32 Header
     0 ~ 15bit ----------------------------------------------
     Magic:  7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
            ELF E  L  F  |  |  |  |  |
                  32/64bit  |  |  |  |
            little/big endian  |  |  |
                         os type  |  |
                        ABI version  |
            byte index of padding bytes
     16 ~ 63bit ---------------------------------------------
     [ 0] e_type:                     0x2 (An executable file)
     [ 1] e_machine:                  0x3 (Sun Microsystems SPARC)
     [ 2] e_version:                  0x2 (Unkown)
     [ 3] e_entry:                 0x1077 (Entry point address)
     [ 4] e_phoff:                   0x34 (Start of program headers)
     [ 5] e_shoff:                 0x35d4 (Start of section headers)
     [ 6] e_flags:                  (nil)
     [ 7] e_ehsize:                  0x34 (Size of this header)
     [ 8] e_phentsize:               0x20 (Size of program headers)
     [ 9] e_phnum:                    0xb (Number of program headers)
     [10] e_shentsize:               0x28 (Size of section headers)
     [11] e_shnum:                   0x1d (Number of section headers)
     [12] e_shstrndx:                0x1c (Section header string table index)
```

### Freely edit every byte of ELF, like 010 editor

We can easily edit any byte of ELF files using elfspirit, such as removing the stack non executable feature (`-z noexecstack`) of executable binary files.

The original PT_GNU-STACK segment only had read and write permissions (6=rw), as shown below

![1](pictures/1.png)

You can use elfspirit to grant executable permissions to the PT_GNU-STACK segment. Just set the parameters (i, j) to the coordinates of the target.

```shell
$ elfspirit edit -P -i11 -j6 -m7 myelf 
6->7
```

Wasn't this process a piece of cake?

![2](pictures/2.png)


### Patch IoT firmware for IDA

As is well known, the firmware of many embedded devices is bare metal programs without ELF header. Therefore, elfspirit can be used to add ELF header information, making it convenient to use reverse engineering tools such as IDA to decompile it.

```shell
# Add elf header for IoT firmware.bin
$ ./elfspirit addelfinfo -a arm -m 32 -e big -b 0x18308000 ~/Documents/app.bin
```

In addition, elfspirit also has the function of splicing firmware. A common situation we encounter is that IoT firmware has many bins stored in different partitions. They share an address space, and if you only analyze a single bin, you will find that the function jumps to an unfamiliar address. At this point, we need to use `elfspirit join`

```shell
# Connect multi-bin
$ ./elfspirit joinelf -a arm -m 32 -e big -c ./configure/bininfo.json ~/Documents/app.bin
```

### Add or delete a section

Sometimes we need to limit the size of an ELF file, so deleting a useless section (such as. eh_frame) is a good solution.

```shell
# delete one section
$ ./elfspirit delsec -n .eh_frame_hdr hello
# delete multi-sections
$ ./elfspirit delsec -c configure/multi_sec_name hello
```

### ELF file infection or static injection

ELF file infection is a broad concept, which may only involve modifying specific bytes or modifying the entire section. Let's take a static injection as an example.

How to make a Linux program load a malicious *.so file? Perhaps you would say that hijacking through DLL/SO is sufficient. If you have debugging permissions for the target program, this method is indeed feasible. But the environment is not always so friendly.

**elfspirit** provides the ability for static injection, injecting a piece of code (commonly known as shellcode) through file infection to load a so.

```shell
$ ./elfspirit injectso -n .eh_frame -f libdemo_x32.so -c offset.json -v 2.31 ./testcase/hello_x86
 [+] architecture: x86
 [+] .eh_frame  offset: 0x2060  viraddr: 0x2060
 [+] .eh_frame: U����(�E�libd�E�emo_�E�x32.�E�so
 [+] entry point address: 0x1090 -> 0x2060
 [+] LOAD offset: 0x2000        vaddr: 0x2000
 [+] LOAD flag: 0x4 -> 0x5
 [+] create ./testcase/hello_x86_new
```
We can see that the target process has already loaded the `libdemo_x32.so` 
```shell
$ cat /proc/2507769/maps
565c9000-565ca000 r--p 00000000 08:01 2726664      /home/lys/Documents/elf/testcase/hello_x86_new
...
56709000-5672b000 rw-p 00000000 00:00 0            [heap]
f7da5000-f7dc2000 r--p 00000000 08:01 3155369      /usr/lib32/libc-2.32.so
f7dc2000-f7f1a000 r-xp 0001d000 08:01 3155369      /usr/lib32/libc-2.32.so
...
f7f91000-f7f93000 rw-p 00000000 00:00 0
f7fa7000-f7fa8000 r--p 00000000 08:01 2726661      /home/lys/Documents/elf/testcase/libdemo_x32.so
f7fa8000-f7fa9000 r-xp 00001000 08:01 2726661      /home/lys/Documents/elf/testcase/libdemo_x32.so
f7fa9000-f7faa000 r--p 00002000 08:01 2726661      /home/lys/Documents/elf/testcase/libdemo_x32.so
```

Unfortunately, the static injection feature provided by elfspirit may depend on a specific version of the Linux loader, so we have provided some configuration files: configure/offsetjson, in preparation for future gcc/ld versions.

## Limitations

**elfspirit** is a work in process, and some things still aren't implemented. Following is the current list of know limitations.

-  `addsec`  The location of the added section only supports a specific offset address of ELF file, such as existing section offset, section header table offset and the end of the file. This is because if we add a section in another location, the program may not work properly.
-  `injectso` is an experimental binary, which mainly implements the idea of static injection. The current version only passes the verification test on libc-2.31/2.32. Therefore, we specially provided a JSON file to load the relevant offset addresses of other versions of libc.

## License

**elfspirit** is open source software. See the `LICENSE` file for more details.