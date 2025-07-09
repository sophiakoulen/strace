#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "strace: must have PROG [ARGS]\n");
		exit(1);
	}

	int pid = fork();
	if (pid < 0)
	{
		perror("strace: problem with fork");
		exit(2);
	}
	else if (pid == 0)
	{
		//in child process;
		printf("child\n");

		//need to execve
		if (execvp(argv[1], argv+1) < 0)
			perror("strace: problem with execvp");
	}
	else
	{
		//in parent process;
		printf("parent proc of pid %d\n", pid);
		if (ptrace(PTRACE_SEIZE, pid, (void*)0, (void*)0) < 0)
		{
			perror("problem with ptrace");
		}

		//inspect arguments of syscall
		ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0);

		//inspect return value of syscall
		ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0);

		wait(NULL);
	}

}
