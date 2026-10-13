#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char buf[100];
    int  i;

    fgets(buf, 100, stdin);
    for (i = 0; i < strlen(buf); i++)
    {
        if (buf[i] > '@' && buf[i] <= 'Z')  // cmp 0x40 / cmp 0x5a → 'A'..'Z'
            buf[i] ^= 0x20;
    }
    printf(buf);
    exit(0);
}
