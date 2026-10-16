#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void clear_stdin(void)
{
    char c = 0;                     // ebp-0x9
    while (1) {
        c = getchar();
        if (c == '\n' || c == (char)0xff)   // 0x0a ou EOF
            return;
    }
}

unsigned int get_unum(void)
{
    unsigned int input = 0;         // ebp-0xc
    fflush(stdout);                 // 0x804a060 = stdout
    scanf("%u", &input);            // 0x8048ad0 = "%u"
    clear_stdin();
    return input;
}

void prog_timeout(void)
{
    exit(1);   // syscall exit(1) via int 0x80
}

int store_number(unsigned int  *buffer)       // buffer = argument à ebp+0x8
{
    unsigned int number = 0;        // ebp-0x10
    unsigned int index  = 0;        // ebp-0xc

    printf(" Number: ");
    number = get_unum();
    printf(" Index: ");
    index = get_unum();

    // index multiple de 3  OU  octet de poids fort de number == 0xb7 → refus
    if (index % 3 == 0 || (number >> 24) == 0xb7) {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        return 1;
    }

    buffer[index] = number;         // <-- écriture SANS borne sur index
    return 0;
}

void read_number(unsigned int  *buffer)       // ebp+0x8
{
    unsigned int index = 0;         // ebp-0xc
    printf(" Index: ");
    index = get_unum();
    printf(" Number at data[%u] is %u\n", index, buffer[index]);   // 0x8048b1b
}

int main(int argc, char **argv, char **envp)
{
    unsigned int  buffer[100];  // esp+0x24
    char input[20];             // esp+0x1b8
    int  result = 0;      // esp+0x1b4
    long canary;          // esp+0x1cc

    // efface argv et envp
    for (char **p = argv; *p; p++)
        memset(*p, 0, strlen(*p) - 1);
    for (char **p = envp; *p; p++)
        memset(*p, 0, strlen(*p) - 1);

    while (1) {
        puts("----------------------------------------------------\n\
              Welcome to wil's crappy number storage service!   \n\
            ----------------------------------------------------\n\
               Commands:                                          \n\
                   store - store a number into the data storage    \n\
                    read  - read a number from the data storage     \n\
                    quit  - exit the program                        \n\
            ----------------------------------------------------\n\
                wil has reserved some storage :>                 \n\
            ----------------------------------------------------\n");                 // 0x8048b38
        printf("Input command: ");               // 0x8048d4b
        result = 1;
        fgets(input, 20, stdin);     // 0x804a040 = stdin
        input[strlen(input) - 2] = 0;

        if (strncmp(input, "store", 5) == 0)        // 0x8048d5b
            result = store_number(buffer);
        else if (strncmp(input, "read", 4) == 0)   // 0x8048d61
            read_number(buffer);
        else if (strncmp(input, "quit", 4) == 0)   // 0x8048d66
            break;

        if (result != 0)
            printf(" Failed to do %s command\n", input);  // 0x8048d6b
        else
            printf(" Completed %s command successfully\n", input);  // 0x8048d88

        // remet input à zéro (20 octets)
        memset(input, 0, 20);
    }
    return 0;
}
