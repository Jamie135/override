#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int	main(int argc, char **argv)
{
	char	username[100] = {0};		/* -0x70  */
	char	password[41]  = {0};		/* -0xa0: le secret */
	char	input[100]    = {0};		/* -0x110 */
	FILE	*fp  = NULL;			/* -0x8   */
	int	ret  = 0;			/* -0xc   */

	(void)argc;
	(void)argv;

	/* Ouverture du fichier de mot de passe de level03 (binaire SUID) */
	fp = fopen("/home/users/level03/.pass", "r");
	if (fp == NULL)
	{
		fprintf(stderr, "ERROR: failed to open password file\n");
		exit(1);
	}

	ret = fread(password, 1, 41, fp);
	password[strcspn(password, "\n")] = 0;

	if (ret != 41)
	{
		fprintf(stderr, "ERROR: failed to read password file\n");
		fprintf(stderr, "ERROR: failed to read password file\n");
		exit(1);
	}
	fclose(fp);

	puts("===== [ Secure Access System v1.0 ] =====");
	puts("/***************************************\\");
	puts("| You must login to access this system. |");
	puts("\\**************************************/");

	/* Saisie du username */
	printf("--[ Username: ");
	fgets(username, 0x64, stdin);
	username[strcspn(username, "\n")] = 0;

	/* Saisie du password */
	printf("--[ Password: ");
	fgets(input, 100, stdin);
	input[strcspn(input, "\n")] = 0;

	puts("*****************************************");

	if (strncmp(password, input, 41) == 0)
	{
		printf("Greetings, %s!\n", username);
		system("/bin/sh");
		return (0);
	}
	else
	{
		printf(username);		/* FAILLE */
		puts(" does not have access!");
		exit(1);
	}
}
