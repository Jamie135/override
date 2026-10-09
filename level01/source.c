#include <stdio.h>
#include <string.h>

/* adresse fixe 0x804a040 */
char	a_user_name[100];

int	verify_user_name(void)
{
	puts("verifying username....\n");
	return (strncmp(a_user_name, "dat_wil", 7));
}

int	verify_user_pass(char *password)
{
	/* ne compare que les 5 premiers octets avec "admin" */
	return (strncmp(password, "admin", 5));
}

int	main(void)
{
	char	buf[64];
	int	result;

	result = 0;
	puts("********* ADMIN LOGIN PROMPT *********");
	printf("Enter Username: ");
	/* lit jusqu'à 256 octets dans a_user_name[100] */
	fgets(a_user_name, 0x100, stdin);

	result = verify_user_name();
	if (result != 0)
	{
		puts("nope, incorrect username...\n");
		return (1);
	}

	puts("Enter Password: ");
	/* lit jusqu'à 100 octets dans buf[64] -> débordement de 36 octets */
	fgets(buf, 0x64, stdin);

	result = verify_user_pass(buf);
	if (result == 0)
	{
		if (result != 0) /* succès : INATTEIGNABLE */
			return (0);
		puts("nope, incorrect password..");
	}
	return (1);
}
