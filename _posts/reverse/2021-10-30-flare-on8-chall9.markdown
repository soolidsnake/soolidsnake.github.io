---
layout: post
title:  "Flare-on8 challenge 9"
date:   2021-10-30 23:05:00 +0100
tag: reverse
---
## Please read the [disclaimer]({{ site.baseurl }}{% link 9.disclamer.md %})

A quick static analysis of the binary main function shows invalid instructions between valid ones, we notice the use of instructions that will eventually generate an exception example :
```
xor eax, eax
div eax
```

An experienced malware analyst will recognize the obfuscation technique were the binary registers exception handler(s) (SEH or VEH) that patch the code at run time and restore the execution flow.

Using TinyTracer `https://github.com/hasherezade/tiny_tracer` by `@hasherezade`, I noticed the use of `addvectoredexceptionhandler` WINAPI, to make static analysis easier we can load the .tag file to IDA PRO.

![alt text](/assets/img/flare-on8/20211114203551.png)


### VEH handler analysis

![alt text](/assets/img/flare-on8/20211114203604.png)

Thanks to Tinytracer comments, we notice that the function `0x4054b0` fetch the address of `VirtualProtect`, it takes 2 parameters that look like hashes. a deeper analysis shows that this function is used to dynamically import functions were the second argument is the hash of the functon name.

We notice a second call to `0x4054b0` function with edx, and ecx as arguments, going back to the main function before the exception occurred we see the 2 hashes are loaded into ecx, and edx.

![alt text](/assets/img/flare-on8/20211114204629.png)


the return value (a function pointer) is written to `ContextRecord->eax`.
Next a call to `VirtualProtect` to set the memory writable followed by a patch at offset `EIP+3` with the opcode `call eax (0XD0FF)` then increments `ContextRecord->EIP` by 3 and finally calls `VirtualProtect` to remove the write attribute.

I wrote the following python script to fix the code and get a clean disassembly view for static analysis

```python
from idautils import *
from idaapi import *
from idc import *

#list of used instructions that generate exceptions 
#33 FF F7 F7
#33 C0 8B 00
#33 C0 f7 f0
#33 F6 F7 F6 xor     esi, esi ; div     esi

seg = get_segm_by_name(".text")
addr = seg.start_ea
end_seg = seg.end_ea

a = [0xf7f7ff33, 0x008bc033, 0xf0f7c033, 0xf6f7f633]


while addr < end_seg:
    if ida_bytes.get_dword(addr) in a:
        print(hex(addr))
        ida_bytes.patch_word(addr+5, 0xd0ff)
        ida_bytes.patch_byte(addr+4, 0x90)
    addr += 1
```

### Anti reverse engineering techniques
 We can notice the usage of different anti reverse engineer techniques, I will enumerate some of them:
 - **Check of hardware breakpoints**
 - **Patch DbgUiRemoteBreakin DbgBreakPoint**
 - **Check PEB BeingDebugged flag**

We can bypass the anti reverse engineer techniques by noping or overstepping ( I will not go in details due to time restriction).



### Network packet sniffing

![alt text](/assets/img/flare-on8/20211114203654.png)


The function **0x403a70** configure a network listener in promiscuous mode on the interface given as `ARGV[1]`.

After that a thread is created to execute the function **0x404310**. This function parses the incoming packets looking for UDP packets on port **4356** with specific flags set.
If the checks are successful, the **UDP** data is written to a structure that will be read by another thread executing the function **0x404310**.

### Analysing the function **0x404310**

The function has basically 3 blocks of instructions that will be executed according to the first Dword of the UDP data packet (0x0, 0x1, 0x2).

![alt text](/assets/img/flare-on8/20211114203704.png)

#### Command #0: 
This command decrypts a fake flag from memory, we can dismiss it.


#### Command #1: 
This command expects another Dword followed by a string, the Dword is the size of the string (including **\\x00**)
Then 4 interesting keywords are decrypted **g0d**, **L0ve**, **s3cret** and **5Ex**. a routine checks if the input is equal to one of the keywords, if yes, it will calculate the hash of the string and save it to a buffer.
In total we will have 4 buffers holding the hash of each keyword.

#### Command #2: 
And finally the last command also expects a Dword (size of string) and the string `MZ`.
It uses the buffers populated with the previous hashes to decrypt the flag.

Using netcat and python we can get the flag with the following commands
```
python -c 'print "\x02\x00\x00\x00" + "\x04\x00\x00\x00" + "g0d\x00"' | nc -u 172.16.45.128 4356
python -c 'print "\x02\x00\x00\x00" + "\x04\x00\x00\x00" + "5Ex\x00"' | nc -u 172.16.45.128 4356
python -c 'print "\x02\x00\x00\x00" + "\x07\x00\x00\x00" + "s3cret\x00"' | nc -u 172.16.45.128 4356
python -c 'print "\x02\x00\x00\x00" + "\x05\x00\x00\x00" + "L0ve\x00"' | nc -u 172.16.45.128 4356
# get flag
python -c 'print "\x03\x00\x00\x00" + "\x03\x00\x00\x00" + "MZ\x00"' | nc -u 172.16.45.128 4356
```