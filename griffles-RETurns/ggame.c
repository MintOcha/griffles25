#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int answer = 0xABCDEF12;

void game(int a, int b) {
    if(a + b == answer){
        printf("Congrats here's your reward\n");
        system("cat flag.txt");
    }
    else{
        printf("What is bro doing here?\n");
    }
}

void register_name() {
    char name[10];
    printf("Hi I'm griffles! Let's play a game!\n");
    printf("I choose the number: %d\n", answer);
    printf("Before we start, What's your name?: \n");
    gets(name);
    printf("Uh oh, I have to go bye!\n");
}


int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    srand(time(NULL));
    answer = rand();
    answer = answer % 100;
    register_name();
    return 0;
}   

 // jump to 8049209