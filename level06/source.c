#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

int	auth(char *login, unsigned int serial)
{
	unsigned int	len;
	unsigned int	hash;
	unsigned int	i;

	login[strcspn(login, "\n")] = '\0';		/* retire le '\n' de fgets */
	len = strnlen(login, 32);
	if (len <= 5)					/* login trop court */
		return (1);

	/* anti-debug : -1 si déjà tracé (gdb, ltrace, ...) */
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
	{
		puts("\x1b[32m.---------------------------.");
		puts("\x1b[31m| !! TAMPERING DETECTED !!  |");
		puts("\x1b[32m'---------------------------'");
		return (1);
	}

	/* graine initiale à partir du 4e caractère du login */
	hash = (login[3] ^ 0x1337) + 0x5eeded; /* = (login[3] ^ 4919) + 6221293 */
	for (i = 0; i < len; i++)
	{
		/* caractère non imprimable (<= 31 en ascii) → refus */
		if (login[i] <= 31)
			return (1);
		hash += (login[i] ^ hash) % 1337;
	}

	/* le hash du login est calculé */
	if (serial == hash)
		return (0);
	return (1);
}

int	main(int argc, char **argv)
{
	char		login[32];
	unsigned int	serial;

	(void)argc;
	(void)argv;

	puts("***********************************");
	puts("*\t\tlevel06\t\t  *");
	puts("***********************************");
	printf("-> Enter Login: ");
	fgets(login, 32, stdin);

	puts("***********************************");
	puts("***** NEW ACCOUNT DETECTED ********");
	puts("***********************************");
	printf("-> Enter Serial: ");
	scanf("%u", &serial);

	if (auth(login, serial) == 0)
	{
		puts("Authenticated!");
		system("/bin/sh");
		return (0);
	}
	return (1);
}
