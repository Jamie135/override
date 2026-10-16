#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void	log_wrapper(FILE *stream, char *input, char *msg)
{
	char	buf[264];
	size_t	len;

	strcpy(buf, input);
	len = strlen(buf);
	snprintf(buf + len, 254 - len, msg);
	buf[strcspn(buf, "\n")] = 0;
	fprintf(stream, "%s\n", buf);
}

int	main(int argc, char **argv)
{
	FILE		*log;			/* -0x88 */
	FILE		*backup_src;		/* -0x80 */
	int		fd = -1;		/* -0x78 */
	unsigned char	c = 0xff;		/* -0x71 */
	char		path[100];		/* -0x70 : "./backups/" + argv[1] */

	if (argc != 2)
		printf("usage: %s filename\n", argv[0]);

    /* Create the backups directory if it doesn't exist */
	log = fopen("./backups/.log", "w");
	if (log == NULL)
	{
		printf("ERROR: Failed to open %s\n", "./backups/.log");
		exit(1);
	}

	log_wrapper(log, argv[1], "Starting back up: ");

	backup_src = fopen(argv[1], "r");
	if (backup_src == NULL)
	{
		printf("ERROR: Failed to open %s\n", argv[1]);
		exit(1);
	}

	/* Destination = "./backups/" + argv[1]*/
	strcpy(path, "./backups/");
	strncat(path, argv[1], 99 - strlen(path));

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0660);
	if (fd < 0)
	{
		printf("ERROR: Could not create backup of %s\n", argv[1]);
		exit(1);
	}

	while ((c = fgetc(backup_src)) != (unsigned char)0xff)
		write(fd, &c, 1);

	log_wrapper(log, argv[1], "Finished back up ");

	fclose(backup_src);
	close(fd);
	return (0);
}
