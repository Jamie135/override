#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("%p\n", getenv("SHELLCODE") + 150);
}
