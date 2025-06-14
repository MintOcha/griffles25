# Writeup for "basic-overflow"

## 1. Initial recon

I basically just ignored the game logic (It's impossible to exploit that/too complicated) and focused solely on the overflow.

First, running pwn checksec [executable]

```
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

The biggest problem here is the arch: It's 32 bit, no wonder why i cant run it (I lack 32 bit binaries)

After doing a quick spray of ret by sending a cyclic, we realise the pattern "aaga" is where ret returns to

Conveinently, there is a win function provided already under game, as long as you jump to that line.

So i jumped to that line by padding with "A"s, but because of register mismatch, you no longer get the flag (it runs system but with the wrong arguments)

Easy fix! Just use a bit of ROP (rop gadgets find) to grab EBX (as i said, the most painful part of this is 32bit) and pop address of cat flag.txt + offset of 0x1fd0 into it (Before system)

```
 804920f:       8d 83 30 e0 ff ff       lea    eax,[ebx-0x1fd0]
 8049215:       50                      push   eax
 8049216:       e8 65 fe ff ff          call   8049080 <system@plt>
```
0x1fd0 is subtracted from ebx before it is used to call system (output from objdump -M intel -d executable)

Done!!