#define _GNU_SOURCE
#include "ft_syscalls.h"
#include "ft_syscalls32.h"
#include "ft_strace.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>

struct i386_user_regs_struct {
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
};

#define IN_SYS 1
#define OUT_SYS 0
#define X86_64 0
#define X86_32 1

int current_status = OUT_SYS;
int current_mode = X86_64;

int wait_and_print(int pid)
{
	int status;
	waitpid(pid, &status, __WALL);
	if (WIFEXITED(status))
	{
		if (current_status == IN_SYS)
			printf("\n");

		printf("+++ exited with %d +++\n", WEXITSTATUS(status));
		fflush(stdout);
		exit(0);
	}
	else if (WIFSIGNALED(status))
	{
		if (current_status == IN_SYS)
			printf("\n");

		printf("+++ killed by %s +++\n", sigabbrev[WTERMSIG(status)]);
		fflush(stdout);
	   	exit(0);	
	}
	else if (WIFSTOPPED(status))
	{
		if (WSTOPSIG(status) == (SIGTRAP|0x80))
		{
			//entry or exit from syscall
			return 0;
		}
		else
		{
			if ((WSTOPSIG(status) == SIGSTOP
				|| WSTOPSIG(status) == SIGTSTP
				|| WSTOPSIG(status) == SIGTTIN
				|| WSTOPSIG(status) == SIGTTOU)
				&& status>>16  ==  PTRACE_EVENT_STOP)
			{
					if (current_status == IN_SYS)
						printf("\n");

					printf("-- stopped by %s ---\n", sigabbrev[WSTOPSIG(status)]);
					fflush(stdout);

					if (ptrace(PTRACE_LISTEN, pid, 0, WSTOPSIG(status)))
					{
						perror("problem with PTRACE_LISTEN");
						exit(1);
					}
					return wait_and_print(pid);
			}
			else
			{
				if (current_status == IN_SYS)
					printf("\n");

				//need to print additional siginfo
				printf("--- %s ---\n", sigabbrev[WSTOPSIG(status)]);
				fflush(stdout);

				if (ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status)))
				{
					perror("problem with PTRACE_SYSCALL");
					exit(1);
				}

				return wait_and_print(pid);
			}
		}
	}

	else
	{
		printf("HELP SOMETHING ELSE HAPPENED.\n");
		fflush(stdout);
		exit(1);
	}
	return 0;
}

void stop_at_syscall(int pid)
{
	if (ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0) < 0)
	{
		perror("problem with ptrace SYSCALL");
		exit(4);
	}
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

	if (data.iov_len == sizeof(struct user_regs_struct))
	{
		if (current_mode != X86_64)
		{
			current_mode = X86_64;
			printf("[ Process PID=%d runs in 64 bit mode. ]\n", pid);
		}
		struct user_regs_struct *regs = data.iov_base;
		printf("%s(%llu, %llu, %llu, %llu, %llu, %llu)",
			syscalls[regs->orig_rax], regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9);
	}
	else if (data.iov_len == sizeof(struct i386_user_regs_struct))
	{
		if (current_mode != X86_32)
		{
			current_mode = X86_32;
			printf("[ Process PID=%d runs in 32 bit mode. ]\n", pid);
		}
		struct i386_user_regs_struct *regs = data.iov_base;
		printf("%s(%d, %d, %d, %d, %d, %d)",
			syscalls32[regs->orig_eax], regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi, regs->ebp);

	}
	else
	{
		printf("PROBLEM\n");
		exit(3);
	}
	current_status = IN_SYS;
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

	if (data.iov_len == sizeof(struct user_regs_struct))
	{
		if (current_mode != X86_64)
		{
			current_mode = X86_64;
			printf("[ Process PID=%d runs in 64 bit mode. ]\n", pid);
		}
		struct user_regs_struct *regs = data.iov_base;
		if ((long long int)regs->rax >= -4095 && (long long int)regs->rax <= -1)
			printf("\t= %s\n", strerrorname_np(-1 * regs->rax));
		else
			printf("\t= %lld\n", regs->rax);
	}
	else
	{
		if (current_mode != X86_32)
		{
			current_mode = X86_32;
			printf("[ Process PID=%d runs in 32 bit mode. ]\n", pid);
		}
		struct i386_user_regs_struct *regs = data.iov_base;
		if ((int32_t)regs->eax >= -4095 && (int32_t)regs->eax <= -1)
			printf("\t= %s\n", strerrorname_np(-1 * regs->eax));
		else
			printf("\t= %d\n", regs->eax);
	}
	current_status = OUT_SYS;
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
		//send stop to itself
		kill(getpid(), SIGSTOP);

		if (execvp(argv[1], argv+1) < 0)
			perror("strace: problem with execvp");
	}
	else
	{
		//in parent process;
		if (ptrace(PTRACE_SEIZE, pid, (void*)0, (void*)0) < 0)
			perror("problem with ptrace SEIZE.\n");

		waitpid(pid, NULL, 0);

		if (ptrace(PTRACE_SETOPTIONS, pid, (void*)0, PTRACE_O_TRACESYSGOOD) < 0)
			perror("problem with ptrace SETOPTIONS.\n");

		while (1)
		{
			stop_at_syscall(pid);
			
			wait_and_print(pid);

			print_sys_enter(pid);
			
			stop_at_syscall(pid);
			
			wait_and_print(pid);

			print_sys_exit(pid);
		}
	}
}
