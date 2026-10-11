#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void	decrypt(unsigned int key)
{
	char		buffer[] = "Q}|u`sfg~sf{}|a3";
	unsigned int	i;
	unsigned int	len;

	len = strlen(buffer);
	for (i = 0; i < len; i++)
		buffer[i] ^= key;

	if (strcmp(buffer, "Congratulations!") == 0)
		system("/bin/sh");
	else
		puts("\nInvalid Password");
}

void	test(unsigned int login, unsigned int password)
{
	unsigned int	index;

	index = password - login;
	switch (index)
	{
		case 1:  decrypt(index); break;
		case 2:  decrypt(index); break;
		case 3:  decrypt(index); break;
		case 4:  decrypt(index); break;
		case 5:  decrypt(index); break;
		case 6:  decrypt(index); break;
		case 7:  decrypt(index); break;
		case 8:  decrypt(index); break;
		case 9:  decrypt(index); break;
		case 16: decrypt(index); break;
		case 17: decrypt(index); break;
		case 18: decrypt(index); break;
		case 19: decrypt(index); break;
		case 20: decrypt(index); break;
		case 21: decrypt(index); break;
		default: decrypt(rand()); break;
	}
}

int	main(void)
{
	int	n;

	srand(time(NULL));
	puts("***********************************");
	puts("*\t\tlevel03\t\t**");
	puts("***********************************");
	printf("Password:");
	scanf("%d", &n);
	test(n, 322424845);
	return (0);
}
