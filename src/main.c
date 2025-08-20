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

		//wait for parent
		sleep(1);

		//need to execve
		if (execvp(argv[1], argv+1) < 0)
			perror("strace: problem with execvp");
	}
	else
	{
		//in parent process;
		printf("parent proc of pid %d\n", pid);

		if (ptrace(PTRACE_SEIZE, pid, (void*)0, (void*)0) < 0)
			perror("problem with ptrace");


		if (ptrace(PTRACE_INTERRUPT, pid, (void*)0, (void*)0) < 0)
			perror("problem with ptrace");

		int wstatus;

		waitpid(pid, &wstatus, 0);

		while (1)
		{
			//inspect arguments of syscall
			if (ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0) < 0)
			{
				perror("problem with ptrace A");
				break;
			}

			printf("bonjour\n");

			waitpid(pid, &wstatus, 0);

			//inspect return value of syscall
			if (ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0) < 0)
			{
				perror("problem with ptrace B");
				break;
			}

			printf("bonjour2\n");

			waitpid(pid, &wstatus, 0);
		}

		waitpid(pid, &wstatus, 0);
	}

}
