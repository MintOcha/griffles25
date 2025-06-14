#include <stdio.h>
#include <stdlib.h>

int main() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    char name[50];
    char choice[6];
    printf("what's your name? \n");
    gets(name); // overflow 1
    printf(name);
    gets(choice); // second overflow with leaked info from first overflow. override printf got table?
    printf(".\n");
    if (choice == "Purple") { // choice here is the pointer, not the value.
        printf("You are correct! Here is your flag: grifflesCTF{fake_flag}");
    } else {
        printf("You are wrong! Try again.");
        printf("Your choice is: ");
        printf(choice);
    }
    return 0;
}