
# elfspirit

[![arch](https://img.shields.io/badge/arch-i386%20%7C%20amd64-orange)](#)
[![platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-orange)](#)
[![libc](https://img.shields.io/badge/libc-3.31%20%7C%203.32-lightgrey)](#) 
[![ld](https://img.shields.io/badge/ld-3.31%20%7C%203.32-lightgrey)](#)
[![license](https://img.shields.io/github/license/liyansong2018/elfspirit)](https://github.com/liyansong2018/elfspirit/blob/main/LICENSE)

**elfspirit** is a useful program that parse, manipulate and camouflage ELF files. It provides a variety of functions, including adding or deleting a section, injecting a dynamic link library for binary static, deleting the section header table to increase the difficulty of reverse engineering and parse ELF like `readelf`.

不想看英文？没关系，请戳中文简介:yum:
- [x] :point_right: [elfspirit：Linux平台下的静态分析和注入框架](https://bbs.pediy.com/thread-270194.htm)

但是你想了解静态注入的更多细节目前只有英文:disappointed:(More details about static injection)
- [x] :point_right: [ELF Static Injection to Load Malicious Dynamic Link Library](https://violentbinary.github.io/posts/1-elf-static-injection-to-load-malicious-dynamic-link-library/)

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

```shell
Usage: elfspirit [function] [option]<argument>... ELF
Currently defined functions:
  addsec           Add a section in a ELF file
  delsec           Delete a section of ELF file
  injectso         Inject dynamic link library statically 
  delshtab         Delete section header table
  elfspirit        Parse ELF file statically like readelf
Currently defined options:
  -n, --section-name=<section name>         Set section name
  -z, --section-size=<section size>         Set section size
  -f, --file-name=<file name>               File containing code(e.g. so, etc.)
  -c, --configure-name=<file name>          File containing configure(e.g. json, etc.)
  -a, --architecture=<ELF architecture>     ELF architecture
  -o, --offset=<injection offset>           Offset of injection point
  -v, --version-libc=<libc version>         Libc.so or ld.so version
  -h, --help[={none|English|Chinese}]       Display this output
  -A, (no argument)                         Display all ELF file infomation
  -H, (no argument)                         Display the ELF file header
  -S, (no argument)                         Display the sections\' header
  -P, (no argument)                         Display the program headers
  -L, (no argument)                         Display the link information
Detailed Usage: 
  elfspirit addsec   [-n]<section name> [-z]<section size> [-o]<offset(optional)> ELF
  elfspirit injectso [-n]<section name> [-f]<so name> [-c]<configure file>
                     [-v]<libc version> ELF
  elfspirit delsec   [-n]<section name> ELF
  elfspirit delshtab ELF
  elfspirit parse -A ELF
Current version: 1.1.4

```

### Demo of patching IoT firmware for IDA

command
```shell
$ ./elfspirit addelfinfo -a arm -m 32 -e big -b 0x18308000 ~/Documents/app.bin
```

output: add ELF info to firmware for IDA
```shell
 [+] source file length is 0xdd748
 [+] base address is 0x18308000                                              
 [+] create /home/kali/Documents/app.bin.new 
```

### Demo of static analysis

command
```shell
elfspirit parse -A hello_x86
```

output: details of elf

```shell
[+] ELF Header
     e_type:                       2 -> An executable file                                    
     e_machine:                   62 -> Sun Microsystems SPARC
     e_version:                    1 -> Current version
     e_entry:                   4208
     ...
[+] Section Header Table
     [Nr] Name            Type                Addr    Off   Size Es  Flg  Lk Inf  Al          
     [ 0]                 SHT_NULL               0      0      0  0        0   0   0
     [ 1] .interp         SHT_PROGBITS      4002a8    2a8     1c  0   A    0   0   1
     [ 2] .note.gnu[...]  SHT_NOTE          4002c4    2c4     24  0   A    0   0   4
     ...
[+] Program Header Table
     [Nr] Type            Offset     Virtaddr   Physaddr   Filesiz  Memsiz   Flg  Align       
     [ 0] PT_PHDR         0x40       0x400040   0x400040   0x268    0x268    R    0x8    
     [ 1] PT_INTERP       0x2a8      0x4002a8   0x4002a8   0x1c     0x1c     R    0x1    
     [ 2] PT_LOAD         0x0        0x400000   0x400000   0x4e8    0x4e8    R    0x4096
	 ...
[+] Section to segment mapping
     [ 0]                                                                                     
     [ 1] .interp
     [ 2] .interp .note.gnu[...] .note.ABI-tag .gnu.hash .dynsym .dynstr
     ...
[+] Dynamic link information
[+] Dynamic section at offset 0x2e20 contains 29 entries                                     
     Tag          Type              Name/Value                                                
     0x00000001   DT_NEEDED         Shared library: [libc.so.6]   
     0x0000000c   DT_INIT           0x401000
     ...
```

### Demo of static injection

command

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
output: process load libdemo_x32.so
```shell
$ cat /proc/2507769/maps
565c9000-565ca000 r--p 00000000 08:01 2726664      /home/lys/Documents/elf/testcase/hello_x86_new
565ca000-565cc000 r-xp 00001000 08:01 2726664      /home/lys/Documents/elf/testcase/hello_x86_new
565cc000-565cd000 r--p 00002000 08:01 2726664      /home/lys/Documents/elf/testcase/hello_x86_new
565cd000-565ce000 rw-p 00003000 08:01 2726664      /home/lys/Documents/elf/testcase/hello_x86_new
56709000-5672b000 rw-p 00000000 00:00 0            [heap]
f7da5000-f7dc2000 r--p 00000000 08:01 3155369      /usr/lib32/libc-2.32.so
f7dc2000-f7f1a000 r-xp 0001d000 08:01 3155369      /usr/lib32/libc-2.32.so
f7f1a000-f7f8c000 r--p 00175000 08:01 3155369      /usr/lib32/libc-2.32.so
f7f8c000-f7f8d000 ---p 001e7000 08:01 3155369      /usr/lib32/libc-2.32.so
f7f8d000-f7f8f000 r--p 001e7000 08:01 3155369      /usr/lib32/libc-2.32.so
f7f8f000-f7f91000 rw-p 001e9000 08:01 3155369      /usr/lib32/libc-2.32.so
f7f91000-f7f93000 rw-p 00000000 00:00 0
f7fa7000-f7fa8000 r--p 00000000 08:01 2726661      /home/lys/Documents/elf/testcase/libdemo_x32.so
f7fa8000-f7fa9000 r-xp 00001000 08:01 2726661      /home/lys/Documents/elf/testcase/libdemo_x32.so
f7fa9000-f7faa000 r--p 00002000 08:01 2726661      /home/lys/Documents/elf/testcase/libdemo_x32.so
f7faa000-f7fab000 r--p 00002000 08:01 2726661      /home/lys/Documents/elf/testcase/libdemo_x32.so
f7fab000-f7fac000 rw-p 00003000 08:01 2726661      /home/lys/Documents/elf/testcase/libdemo_x32.so
```


## Limitations

**elfspirit** is a work in process, and some things still aren't implemented. Following is the current list of know limitations.

-  `addsec`  The location of the added section only supports a specific offset address of ELF file, such as existing section offset, section header table offset and the end of the file. This is because if we add a section in another location, the program may not work properly.
-  `injectso` is an experimental binary, which mainly implements the idea of static injection. The current version only passes the verification test on libc-2.31/2.32. Therefore, we specially provided a JSON file to load the relevant offset addresses of other versions of libc.

## License

**elfspirit** is open source software. See the `LICENSE` file for more details.