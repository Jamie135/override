#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>

int	main(void)
{
	char	buf[128] = {0};
	int	pid;
	int	status = 0;
	int	ret = 0;

	pid = fork();
	if (pid == 0)
	{
		/* --- enfant : la victime --- */
		prctl(PR_SET_PDEATHSIG, SIGHUP);	/* meurt si le parent meurt */
		ptrace(PTRACE_TRACEME, 0, 0, 0);	/* "mon parent peut me tracer" */
		puts("Give me some shellcode, k");
		gets(buf);
	}
	else
	{
		while (1)
		{
			wait(&status);
			if (WIFEXITED(status) || WIFSIGNALED(status))
			{
				puts("child is exiting...");
				break;
			}
			/* 0x2c = ORIG_EAX : le n° du syscall que l'enfant invoque */
			ret = ptrace(PTRACE_PEEKUSER, pid, 0x2c, 0);
			if (ret == 11)
			{
				puts("no exec() for you");
				kill(pid, 9);
				break;
			}
		}
	}
	return (0);
}
