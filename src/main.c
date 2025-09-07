#define _GNU_SOURCE
#include "ft_strace.h"
#include "ft_syscalls.h"
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

void wait_for_syscall(int pid)
{
	int status;
	waitpid(pid, &status, __WALL);
	if (WIFEXITED(status))
	{
		if (current_status == IN_SYS)
			fprintf(stderr,"\n");
		fprintf(stderr,"+++ exited with %d +++\n", WEXITSTATUS(status));
		exit(0);
	}
	else if (WIFSIGNALED(status))
	{
		if (current_status == IN_SYS)
			fprintf(stderr,"\n");
		fprintf(stderr,"+++ killed by %s +++\n", sigabbrev[WTERMSIG(status)]);
		fflush(stdout);
	   	exit(0);	
	}
	else if (WIFSTOPPED(status))
	{
		if (WSTOPSIG(status) == (SIGTRAP|0x80))
			return;

		if ((WSTOPSIG(status) == SIGSTOP
			|| WSTOPSIG(status) == SIGTSTP
			|| WSTOPSIG(status) == SIGTTIN
			|| WSTOPSIG(status) == SIGTTOU)
			&& status>>16  ==  PTRACE_EVENT_STOP)
		{
				if (current_status == IN_SYS)
					fprintf(stderr,"\n");
				fprintf(stderr,"-- stopped by %s ---\n", sigabbrev[WSTOPSIG(status)]);
				fflush(stderr);

				if (ptrace(PTRACE_LISTEN, pid, 0, WSTOPSIG(status)))
				{
					perror("strace: ptrace");
					exit(1);
				}
				return wait_for_syscall(pid);
		}
		else
		{
			if (current_status == IN_SYS)
				fprintf(stderr,"\n");
			fprintf(stderr,"--- %s ---\n", sigabbrev[WSTOPSIG(status)]);
			fflush(stderr);

			if (ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status)))
			{
				perror("strace: ptrace");
				exit(1);
			}
			return wait_for_syscall(pid);
		}
	}
	else
	{
		fprintf(stderr, "strace: waitpid returned an unexpected status.\n");
		exit(1);
	}
}

void stop_at_syscall(int pid)
{
	if (ptrace(PTRACE_SYSCALL, pid, (void*)0, (void*)0) < 0)
	{
		perror("strace: ptrace");
		exit(1);
	}
}

#define GETMEM_BUFFERSIZE 1024
ssize_t getmem(int pid, char *buffer, void* addr)
{
	struct iovec  local[1];
	struct iovec  remote[1];

	local[0].iov_base = buffer;
	local[0].iov_len = GETMEM_BUFFERSIZE;
	remote[0].iov_base = addr;
	remote[0].iov_len = GETMEM_BUFFERSIZE;

	ssize_t ret = process_vm_readv(pid, local, 1, remote, 1, 0);
	buffer[GETMEM_BUFFERSIZE - 1] = '\0';
	return ret;
}

void print_arg32(int pid, uint32_t reg, enum arg_type_e type)
{
	 if (type == INT)
		 fprintf(stderr,"%d", reg);
	 else if (type == UINT)
		 fprintf(stderr,"%u", reg);
	 else if (type == STR)
	 {
		 char buffer[1024];
		 if (getmem(pid, buffer, (void*)reg) == -1)
		 	fprintf(stderr,"%p", (void*)reg);
		 else
			fprintf(stderr,"\"%s\"", buffer);
	 }
	 else
		 fprintf(stderr,"%p", (void*)reg);
}

void print_arg64(int pid, unsigned long long int reg, enum arg_type_e type)
{
	 if (type == INT)
		 fprintf(stderr,"%lld", reg);
	 else if (type == UINT)
		 fprintf(stderr,"%llu", reg);
	 else if (type == STR)
	 {
		 char buffer[1024];
		 if (getmem(pid, buffer, (void*)reg) == -1)
		 	fprintf(stderr,"%p", (void*)reg);
		 else
			fprintf(stderr,"\"%s\"", buffer);
	 }
	 else
		 fprintf(stderr,"%p", (void*)reg);
}

void print_sys_enter(int pid)
{
	struct iovec data;
	char buf[1024];
	data.iov_base = buf;
	data.iov_len = sizeof(buf);

	if (ptrace(PTRACE_GETREGSET, pid, 1, &data) < 0)
	{
		perror("strace: ptrace:");
		exit(1);
	}

	if (data.iov_len == sizeof(struct user_regs_struct))
	{
		if (current_mode != X86_64)
		{
			current_mode = X86_64;
			fprintf(stderr,"[ Process PID=%d runs in 64 bit mode. ]\n", pid);
		}

		struct user_regs_struct *regs = data.iov_base;
		fprintf(stderr,"%s(", syscalls64[regs->orig_rax].name);
		unsigned int l = syscalls64[regs->orig_rax].arg_count;
		unsigned long long int args[6] = {regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9};
		unsigned int i;
		for (i = 0; i < l; i++)
		{
			print_arg64(pid, args[i], (syscalls64[regs->orig_rax].args)[i]);
			if (i + 1 < l)
				fprintf(stderr,", ");
			else
				fprintf(stderr,")");
		}
		fflush(stderr);
	}
	else if (data.iov_len == sizeof(struct i386_user_regs_struct))
	{
		if (current_mode != X86_32)
		{
			current_mode = X86_32;
			fprintf(stderr,"[ Process PID=%d runs in 32 bit mode. ]\n", pid);
		}

		struct i386_user_regs_struct *regs = data.iov_base;
		fprintf(stderr,"%s(", syscalls32[regs->orig_eax].name);
		unsigned int l = syscalls32[regs->orig_eax].arg_count;
		unsigned long long int args[6] = {regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi, regs->ebp};
		unsigned int i;
		for (i = 0; i < l; i++)
		{
			print_arg32(pid, args[i], (syscalls32[regs->orig_eax].args)[i]);
			if (i + 1 < l)
				fprintf(stderr, ", ");
			else
				fprintf(stderr, ")");
		}
		fflush(stderr);
	}
	else
	{
		fprintf(stderr,"strace: ptrace returned an expected result.\n");
		exit(1);
	}
	current_status = IN_SYS;
}

void print_sys_exit(int pid)
{
	struct iovec data;
	char buffer[1024];
	data.iov_base = buffer;
	data.iov_len = sizeof(buffer);

	if (ptrace(PTRACE_GETREGSET, pid, 1, &data) < 0)
	{
		perror("strace: ptrace");
		exit(1);
	}

	if (data.iov_len == sizeof(struct user_regs_struct))
	{
		struct user_regs_struct *regs = data.iov_base;
		if ((long long int)regs->rax >= -4095 && (long long int)regs->rax <= -1)
			fprintf(stderr, "\t= %s\n", strerrorname_np(-1 * regs->rax));
		else
			fprintf(stderr, "\t= %lld\n", regs->rax);

		if (current_mode != X86_64)
		{
			current_mode = X86_64;
			fprintf(stderr, "[ Process PID=%d runs in 64 bit mode. ]\n", pid);
		}
	}
	else
	{
		struct i386_user_regs_struct *regs = data.iov_base;
		if ((int32_t)regs->eax >= -4095 && (int32_t)regs->eax <= -1)
			fprintf(stderr,"\t= %s\n", strerrorname_np(-1 * regs->eax));
		else
			fprintf(stderr,"\t= %d\n", regs->eax);

		if (current_mode != X86_32)
		{
			current_mode = X86_32;
			fprintf(stderr,"[ Process PID=%d runs in 32 bit mode. ]\n", pid);
		}
	}
	current_status = OUT_SYS;
}

void trace(int pid)
{
	if (ptrace(PTRACE_SEIZE, pid, (void*)0, (void*)0) < 0)
	{
		perror("strace: ptrace");
		exit(1);
	}

	if (waitpid(pid, NULL, __WALL) < 0)
	{
		perror("strace: waitpid");
		exit(1);
	}

	if (ptrace(PTRACE_SETOPTIONS, pid, (void*)0, PTRACE_O_TRACESYSGOOD) < 0)
	{
		perror("strace: ptrace");
		exit(1);
	}

	while (1)
	{
		stop_at_syscall(pid);
		wait_for_syscall(pid);
		print_sys_enter(pid);
		stop_at_syscall(pid);
		wait_for_syscall(pid);
		print_sys_exit(pid);
	}
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
		perror("strace: fork");
		exit(1);
	}
	else if (pid == 0)
	{
		kill(getpid(), SIGSTOP);

		if (execvp(argv[1], argv+1) < 0)
			perror("strace: execve");
		exit(1);
	}
	else
		trace(pid);
}
