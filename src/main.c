#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

void stop_at_syscall(int pid)
{
	if (ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0) < 0)
	{
		perror("problem with ptrace SYSCALL");
		exit(4);
	}
	waitpid(pid, NULL, 0);
}

void print_registers(int pid)
{
	struct iovec data;
	data.iov_base = alloca(1024);
	data.iov_len = 1024;

	if (ptrace(PTRACE_GETREGSET, pid, 1, &data) < 0)
	{
		perror("Problem with ptrace GETREGSET");
		exit(3);
	}

	struct user_regs_struct *regs = data.iov_base;
	printf("rax = %llu\n", regs->rax);
}

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

		waitpid(pid, NULL, 0);

		while (1)
		{
			stop_at_syscall(pid);
			print_registers(pid);
			stop_at_syscall(pid);
			print_registers(pid);
		}

		waitpid(pid, NULL, 0);
	}
}
