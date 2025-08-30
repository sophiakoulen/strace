#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

void wait_and_print(int pid)
{
	int status;
	waitpid(pid, &status, 0);
	if (WIFEXITED(status))
	{
		printf("child exited with code %d\n", WEXITSTATUS(status));
		exit(0);
	}
	else if (WIFSIGNALED(status))
	{
		printf("child got signal no %d\n", WTERMSIG(status));
	   	exit(0);	
	}
	else if (WIFSTOPPED(status))
	{
		printf("child stopped with signal no %d\n", WSTOPSIG(status));
	}
	else
	{
		printf("something else happened.\n");
	}
	fflush(stdout);
}

void stop_at_syscall(int pid)
{
	if (ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0) < 0)
	{
		perror("problem with ptrace SYSCALL");
		exit(4);
	}
	wait_and_print(pid);
}

void print_sys_enter(int pid)
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
	printf("syscall number %lld with args: rdi = %llu, rsi = %llu, rdx = %llu, rcx = %llu\n",
			regs->orig_rax, regs->rdi, regs->rsi, regs->rdx, regs->rcx);
}

void print_sys_exit(int pid)
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
	printf("return value = %lld\n", regs->rax);
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
		printf("Hi i'm the child process\n");
		fflush(stdout);

		//send stop to itself
		kill(getpid(), SIGSTOP);

		if (execvp(argv[1], argv+1) < 0)
			perror("strace: problem with execvp");
	}
	else
	{
		//in parent process;
		printf("hello i'm the parent of pid %d\n", pid);
		fflush(stdout);

		if (ptrace(PTRACE_SEIZE, pid, (void*)0, (void*)0) < 0)
			perror("problem with ptrace A");

		//if (ptrace(PTRACE_INTERRUPT, pid, (void*)0, (void*)0) < 0)
		//	perror("problem with ptrace B");

		wait_and_print(pid);

		while (1)
		{
			stop_at_syscall(pid);
			print_sys_enter(pid);
			stop_at_syscall(pid);
			print_sys_exit(pid);
		}
	}
}
