// gcc -o chall -fno-stack-protector chall.c

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>

void ignore_me_init_buffering() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void getname(void)
{
	char buf[010];
	printf("What's your name? ");
	scanf("%010s", buf); // RBP: ovrflowbyte1    byte2    0x00  [regular rbp bytes]
	//pwndbg> p $rbp (void *) 0x7fffff003938 (arb write to last 2 bytes, null into third)
	// rsp at 0x7fffffffdf88, way after new rbp value
}

void win(void)
{
	int fd = open("flag.txt", O_RDONLY);
	sendfile(1, fd, 0, 100);
}

char*ff;
typedef int(*g)(const char*);
int main(void)
{
	ignore_me_init_buffering();
	puts("Hello old chap spiffing pleased to meet you");

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
0x7fffffffdf90: 0x555551ea      0x00005555      0x00000000      0x00000000 <- Addr of getname to flow to
	*/
	(*(int(**)(void))(ff))(); // ff = f, calls getname. writes to a lower spot than before
	// leave (mov rsp, rbp; pop rbp) sets rsp = RBP_pivoted, then rbp = QWORD[RBP_pivoted].
	// Since we have arb control of rbp, we should be able to arb control rsp. inccreases (usually) rbp from stack
	// SOMEHOW rets to second scanf. As long as second scanf has correct addr should jump execution there.
}
