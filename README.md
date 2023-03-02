# codeFromDll
A code I made to get a function code from a dll without loading it in memory

The purpose of this code was to better understand PE file, and also make some try on AV

# Result
```
[+] Dumping code of function NtReadVirtualMemory:

unsigned char myFunc[] = {
        0x4C, 0x8B, 0xD1, 0xB8,
        0x3F, 0x00, 0x00, 0x00,
        0xF6, 0x04, 0x25, 0x08,
        0x03, 0xFE, 0x7F, 0x01,
        0x75, 0x03, 0x0F, 0x05,
        0xC3
        };
```
