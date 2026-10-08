#include <stdio.h>
#include <stdlib.h>

int main() // 32 octets
{
    int pass; // esp + 0x1c
    puts("*************************************************");
    puts(""*         -Level00 -       *"");
    puts("*************************************************");
    printf("Password:");
    scanf("%d", &pass);
    if (pass == 5276)
    {
        puts("\nAuthenticated!");
        system("/bin/sh");
    }
    else
    {
        puts("Invalid Password!");
        return 1;
    }
    return 0;
}
