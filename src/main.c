#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

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
			//child will continue but stop when entering next syscall
			if (ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0) < 0)
			{
				perror("problem with ptrace A");
				break;
			}
			printf("ptrace parent syscall 1\n");

			//wait until process is stopped
			waitpid(pid, &wstatus, 0);

			struct iovec data;
			data.iov_base = malloc(1024);
			data.iov_len = 1024;

			//read registers
			if (ptrace(PTRACE_GETREGSET, pid, 1, &data) < 0)
			{
				perror("problem with ptrace C");
				break;
			}

			struct user_regs_struct *regs = data.iov_base;
			printf("rax = %llu\n", regs->rax);

			//child will continue but stop when leaving syscall
			if (ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0) < 0)
			{
				perror("problem with ptrace B\n");
				break;
			}
			printf("ptrace parent syscall 2\n");

			//wait until process is stopped
			waitpid(pid, &wstatus, 0);

			//read registers
			if (ptrace(PTRACE_GETREGSET, pid, 1, &data) < 0)
			{
				perror("problem with ptrace D\n");
				break;
			}

			regs = data.iov_base;
			printf("rax = %lld\n", regs->rax);
		}

		waitpid(pid, &wstatus, 0);
	}

}
