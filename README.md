
**elfspirit** is a useful program that parse, manipulate and camouflage ELF files. It provides a variety of functions, including adding or deleting a section, injecting a dynamic link library for binary static, deleting the section header table to increase the difficulty of reverse engineering and parse ELF like `readelf`.

If you don't know anything about static injection, you can refer to the [ELF Static Injection to Load Malicious Dynamic Link Library](https://violentbinary.github.io/posts/1-elf-static-injection-to-load-malicious-dynamic-link-library/)

## Usage

Add a section to the ELF file

```shell
elfspirit addsec   [-n]<section name> [-z]<section size> [-o]<offset(optional)> ELF
```

Delete a section of the ELF file

```shell
elfspirit delsec   [-n]<section name> ELF
```

Statically injected dynamic link library

```shell
elfspirit injectso [-n]<section name> [-f]<so name> [-c]<configure file> [-v]<libc version> ELF
```

Delete section header table

```shell
elfspirit delshtab ELF
```

Parse ELF file

```shell
elfspirit parse ELF
```

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

## Building

**elfspirit** can also be installed easily:

```shell
make
```

## Dependencies

We run **elfspirit** using:

- Ubuntu 20.04 / Kali Linux 2020.4
- gcc 10.2.1
- libc-2.31/2.32

Currently, this is the only supported environment. Other environments may also work, but we unfortunately do not have the manpower to investigate compatibility issues. 

## Limitations

**elfspirit** is a work in process, and some things still aren't implemented. Following is the current list of know limitations.

-  `addsec`  The location of the added section only supports a specific offset address of ELF file, such as existing section offset, section header table offset and the end of the file. This is because if we add a section in another location, the program may not work properly.
-  `injectso` is an experimental binary, which mainly implements the idea of static injection. The current version only passes the verification test on libc-2.31/2.32. Therefore, we specially provided a JSON file to load the relevant offset addresses of other versions of libc.

## License

**elfspirit** is open source software. Its code is in the public domain. See the `LICENSE` file for more details.