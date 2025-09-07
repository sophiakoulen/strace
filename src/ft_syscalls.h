enum arg_type_e {STR, PTR, UINT, INT};
struct syscall_s { const char* name; unsigned int arg_count; enum arg_type_e args[6]; };
struct syscall_s syscalls[] = {
	{
		"read", 3,
			{
				UINT,
				PTR,
				INT,
			}
	},
	{
		"write", 3,
			{
				UINT,
				PTR,
				INT,
			}
	},
	{
		"open", 3,
			{
				STR,
				INT,
				INT,
			}
	},
	{
		"close", 1,
			{
				UINT,
			}
	},
	{
		"newstat", 2,
			{
				STR,
				PTR,
			}
	},
	{
		"newfstat", 2,
			{
				UINT,
				PTR,
			}
	},
	{
		"newlstat", 2,
			{
				STR,
				PTR,
			}
	},
	{
		"poll", 3,
			{
				PTR,
				UINT,
				INT,
			}
	},
	{
		"lseek", 3,
			{
				UINT,
				INT,
				UINT,
			}
	},
	{
		"mmap", 6,
			{
				UINT,
				UINT,
				UINT,
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"mprotect", 3,
			{
				UINT,
				INT,
				UINT,
			}
	},
	{
		"munmap", 2,
			{
				UINT,
				INT,
			}
	},
	{
		"brk", 1,
			{
				UINT,
			}
	},
	{
		"rt_sigaction", 4,
			{
				INT,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"rt_sigprocmask", 4,
			{
				INT,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"rt_sigreturn", 0,
			{
			}
	},
	{
		"ioctl", 3,
			{
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"pread64", 4,
			{
				UINT,
				PTR,
				INT,
				INT,
			}
	},
	{
		"pwrite64", 4,
			{
				UINT,
				PTR,
				INT,
				INT,
			}
	},
	{
		"readv", 3,
			{
				UINT,
				PTR,
				UINT,
			}
	},
	{
		"writev", 3,
			{
				UINT,
				PTR,
				UINT,
			}
	},
	{
		"access", 2,
			{
				STR,
				INT,
			}
	},
	{
		"pipe", 1,
			{
				PTR,
			}
	},
	{
		"select", 5,
			{
				INT,
				PTR,
				PTR,
				PTR,
				PTR,
			}
	},
	{
		"sched_yield", 0,
			{
			}
	},
	{
		"mremap", 5,
			{
				UINT,
				UINT,
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"msync", 3,
			{
				UINT,
				INT,
				INT,
			}
	},
	{
		"mincore", 3,
			{
				UINT,
				INT,
				PTR,
			}
	},
	{
		"madvise", 3,
			{
				UINT,
				INT,
				INT,
			}
	},
	{
		"shmget", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"shmat", 3,
			{
				INT,
				PTR,
				INT,
			}
	},
	{
		"shmctl", 3,
			{
				INT,
				INT,
				PTR,
			}
	},
	{
		"dup", 1,
			{
				UINT,
			}
	},
	{
		"dup2", 2,
			{
				UINT,
				UINT,
			}
	},
	{
		"pause", 0,
			{
			}
	},
	{
		"nanosleep", 2,
			{
				PTR,
				PTR,
			}
	},
	{
		"getitimer", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"alarm", 1,
			{
				UINT,
			}
	},
	{
		"setitimer", 3,
			{
				INT,
				PTR,
				PTR,
			}
	},
	{
		"getpid", 0,
			{
			}
	},
	{
		"sendfile64", 4,
			{
				INT,
				INT,
				PTR,
				INT,
			}
	},
	{
		"socket", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"connect", 3,
			{
				INT,
				PTR,
				INT,
			}
	},
	{
		"accept", 3,
			{
				INT,
				PTR,
				PTR,
			}
	},
	{
		"sendto", 6,
			{
				INT,
				PTR,
				INT,
				UINT,
				PTR,
				INT,
			}
	},
	{
		"recvfrom", 6,
			{
				INT,
				PTR,
				INT,
				UINT,
				PTR,
				PTR,
			}
	},
	{
		"sendmsg", 3,
			{
				INT,
				PTR,
				UINT,
			}
	},
	{
		"recvmsg", 3,
			{
				INT,
				PTR,
				UINT,
			}
	},
	{
		"shutdown", 2,
			{
				INT,
				INT,
			}
	},
	{
		"bind", 3,
			{
				INT,
				PTR,
				INT,
			}
	},
	{
		"listen", 2,
			{
				INT,
				INT,
			}
	},
	{
		"getsockname", 3,
			{
				INT,
				PTR,
				PTR,
			}
	},
	{
		"getpeername", 3,
			{
				INT,
				PTR,
				PTR,
			}
	},
	{
		"socketpair", 4,
			{
				INT,
				INT,
				INT,
				PTR,
			}
	},
	{
		"setsockopt", 5,
			{
				INT,
				INT,
				INT,
				PTR,
				INT,
			}
	},
	{
		"getsockopt", 5,
			{
				INT,
				INT,
				INT,
				PTR,
				PTR,
			}
	},
	{
		"clone", 5,
			{
				UINT,
				UINT,
				PTR,
				PTR,
				UINT,
			}
	},
	{
		"fork", 0,
			{
			}
	},
	{
		"vfork", 0,
			{
			}
	},
	{
		"execve", 3,
			{
				STR,
				PTR,
				PTR,
			}
	},
	{
		"exit", 1,
			{
				INT,
			}
	},
	{
		"wait4", 4,
			{
				INT,
				PTR,
				INT,
				PTR,
			}
	},
	{
		"kill", 2,
			{
				INT,
				INT,
			}
	},
	{
		"newuname", 1,
			{
				PTR,
			}
	},
	{
		"semget", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"semop", 3,
			{
				INT,
				PTR,
				UINT,
			}
	},
	{
		"semctl", 4,
			{
				INT,
				INT,
				INT,
				UINT,
			}
	},
	{
		"shmdt", 1,
			{
				PTR,
			}
	},
	{
		"msgget", 2,
			{
				INT,
				INT,
			}
	},
	{
		"msgsnd", 4,
			{
				INT,
				PTR,
				INT,
				INT,
			}
	},
	{
		"msgrcv", 5,
			{
				INT,
				PTR,
				INT,
				INT,
				INT,
			}
	},
	{
		"msgctl", 3,
			{
				INT,
				INT,
				PTR,
			}
	},
	{
		"fcntl", 3,
			{
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"flock", 2,
			{
				UINT,
				UINT,
			}
	},
	{
		"fsync", 1,
			{
				UINT,
			}
	},
	{
		"fdatasync", 1,
			{
				UINT,
			}
	},
	{
		"truncate", 2,
			{
				PTR,
				INT,
			}
	},
	{
		"ftruncate", 2,
			{
				UINT,
				UINT,
			}
	},
	{
		"getdents", 3,
			{
				UINT,
				PTR,
				UINT,
			}
	},
	{
		"getcwd", 2,
			{
				PTR,
				UINT,
			}
	},
	{
		"chdir", 1,
			{
				STR,
			}
	},
	{
		"fchdir", 1,
			{
				UINT,
			}
	},
	{
		"rename", 2,
			{
				STR,
				STR,
			}
	},
	{
		"mkdir", 2,
			{
				STR,
				INT,
			}
	},
	{
		"rmdir", 1,
			{
				STR,
			}
	},
	{
		"creat", 2,
			{
				STR,
				INT,
			}
	},
	{
		"link", 2,
			{
				STR,
				STR,
			}
	},
	{
		"unlink", 1,
			{
				STR,
			}
	},
	{
		"symlink", 2,
			{
				STR,
				STR,
			}
	},
	{
		"readlink", 3,
			{
				PTR,
				PTR,
				INT,
			}
	},
	{
		"chmod", 2,
			{
				STR,
				INT,
			}
	},
	{
		"fchmod", 2,
			{
				UINT,
				INT,
			}
	},
	{
		"chown", 3,
			{
				STR,
				INT,
				INT,
			}
	},
	{
		"fchown", 3,
			{
				UINT,
				INT,
				INT,
			}
	},
	{
		"lchown", 3,
			{
				STR,
				INT,
				INT,
			}
	},
	{
		"umask", 1,
			{
				INT,
			}
	},
	{
		"gettimeofday", 2,
			{
				PTR,
				PTR,
			}
	},
	{
		"getrlimit", 2,
			{
				UINT,
				PTR,
			}
	},
	{
		"getrusage", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"sysinfo", 1,
			{
				PTR,
			}
	},
	{
		"times", 1,
			{
				PTR,
			}
	},
	{
		"ptrace", 4,
			{
				INT,
				INT,
				UINT,
				UINT,
			}
	},
	{
		"getuid", 0,
			{
			}
	},
	{
		"syslog", 3,
			{
				INT,
				PTR,
				INT,
			}
	},
	{
		"getgid", 0,
			{
			}
	},
	{
		"setuid", 1,
			{
				INT,
			}
	},
	{
		"setgid", 1,
			{
				INT,
			}
	},
	{
		"geteuid", 0,
			{
			}
	},
	{
		"getegid", 0,
			{
			}
	},
	{
		"setpgid", 2,
			{
				INT,
				INT,
			}
	},
	{
		"getppid", 0,
			{
			}
	},
	{
		"getpgrp", 0,
			{
			}
	},
	{
		"setsid", 0,
			{
			}
	},
	{
		"setreuid", 2,
			{
				INT,
				INT,
			}
	},
	{
		"setregid", 2,
			{
				INT,
				INT,
			}
	},
	{
		"getgroups", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"setgroups", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"setresuid", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"getresuid", 3,
			{
				PTR,
				PTR,
				PTR,
			}
	},
	{
		"setresgid", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"getresgid", 3,
			{
				PTR,
				PTR,
				PTR,
			}
	},
	{
		"getpgid", 1,
			{
				INT,
			}
	},
	{
		"setfsuid", 1,
			{
				INT,
			}
	},
	{
		"setfsgid", 1,
			{
				INT,
			}
	},
	{
		"getsid", 1,
			{
				INT,
			}
	},
	{
		"capget", 2,
			{
				INT,
				INT,
			}
	},
	{
		"capset", 2,
			{
				INT,
				INT,
			}
	},
	{
		"rt_sigpending", 2,
			{
				PTR,
				INT,
			}
	},
	{
		"rt_sigtimedwait", 4,
			{
				PTR,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"rt_sigqueueinfo", 3,
			{
				INT,
				INT,
				PTR,
			}
	},
	{
		"rt_sigsuspend", 2,
			{
				PTR,
				INT,
			}
	},
	{
		"sigaltstack", 2,
			{
				PTR,
				PTR,
			}
	},
	{
		"utime", 2,
			{
				STR,
				PTR,
			}
	},
	{
		"mknod", 3,
			{
				STR,
				INT,
				UINT,
			}
	},
	{0, 0, {}},
	{
		"personality", 1,
			{
				UINT,
			}
	},
	{
		"ustat", 2,
			{
				UINT,
				PTR,
			}
	},
	{
		"statfs", 2,
			{
				STR,
				PTR,
			}
	},
	{
		"fstatfs", 2,
			{
				UINT,
				PTR,
			}
	},
	{
		"sysfs", 3,
			{
				INT,
				UINT,
				UINT,
			}
	},
	{
		"getpriority", 2,
			{
				INT,
				INT,
			}
	},
	{
		"setpriority", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"sched_setparam", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"sched_getparam", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"sched_setscheduler", 3,
			{
				INT,
				INT,
				PTR,
			}
	},
	{
		"sched_getscheduler", 1,
			{
				INT,
			}
	},
	{
		"sched_get_priority_max", 1,
			{
				INT,
			}
	},
	{
		"sched_get_priority_min", 1,
			{
				INT,
			}
	},
	{
		"sched_rr_get_interval", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"mlock", 2,
			{
				UINT,
				INT,
			}
	},
	{
		"munlock", 2,
			{
				UINT,
				INT,
			}
	},
	{
		"mlockall", 1,
			{
				INT,
			}
	},
	{
		"munlockall", 0,
			{
			}
	},
	{
		"vhangup", 0,
			{
			}
	},
	{
		"modify_ldt", 3,
			{
				INT,
				PTR,
				UINT,
			}
	},
	{
		"pivot_root", 2,
			{
				PTR,
				PTR,
			}
	},
	{0, 0, {}},
	{
		"prctl", 5,
			{
				INT,
				UINT,
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"arch_prctl", 2,
			{
				INT,
				UINT,
			}
	},
	{
		"adjtimex", 1,
			{
				PTR,
			}
	},
	{
		"setrlimit", 2,
			{
				UINT,
				PTR,
			}
	},
	{
		"chroot", 1,
			{
				STR,
			}
	},
	{
		"sync", 0,
			{
			}
	},
	{
		"acct", 1,
			{
				STR,
			}
	},
	{
		"settimeofday", 2,
			{
				PTR,
				PTR,
			}
	},
	{
		"mount", 5,
			{
				STR,
				STR,
				PTR,
				UINT,
				PTR,
			}
	},
	{
		"umount", 2,
			{
				STR,
				INT,
			}
	},
	{
		"swapon", 2,
			{
				PTR,
				INT,
			}
	},
	{
		"swapoff", 1,
			{
				PTR,
			}
	},
	{
		"reboot", 4,
			{
				INT,
				INT,
				UINT,
				PTR,
			}
	},
	{
		"sethostname", 2,
			{
				STR,
				INT,
			}
	},
	{
		"setdomainname", 2,
			{
				STR,
				INT,
			}
	},
	{
		"iopl", 1,
			{
				UINT,
			}
	},
	{
		"ioperm", 3,
			{
				UINT,
				UINT,
				INT,
			}
	},
	{0, 0, {}},
	{
		"init_module", 3,
			{
				PTR,
				UINT,
				PTR,
			}
	},
	{
		"delete_module", 2,
			{
				STR,
				UINT,
			}
	},
	{0, 0, {}},
	{0, 0, {}},
	{
		"quotactl", 4,
			{
				UINT,
				PTR,
				INT,
				PTR,
			}
	},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{
		"gettid", 0,
			{
			}
	},
	{
		"readahead", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"setxattr", 5,
			{
				STR,
				STR,
				PTR,
				INT,
				INT,
			}
	},
	{
		"lsetxattr", 5,
			{
				STR,
				STR,
				PTR,
				INT,
				INT,
			}
	},
	{
		"fsetxattr", 5,
			{
				INT,
				STR,
				PTR,
				INT,
				INT,
			}
	},
	{
		"getxattr", 4,
			{
				STR,
				STR,
				PTR,
				INT,
			}
	},
	{
		"lgetxattr", 4,
			{
				STR,
				STR,
				PTR,
				INT,
			}
	},
	{
		"fgetxattr", 4,
			{
				INT,
				STR,
				PTR,
				INT,
			}
	},
	{
		"listxattr", 3,
			{
				STR,
				PTR,
				INT,
			}
	},
	{
		"llistxattr", 3,
			{
				STR,
				PTR,
				INT,
			}
	},
	{
		"flistxattr", 3,
			{
				INT,
				PTR,
				INT,
			}
	},
	{
		"removexattr", 2,
			{
				STR,
				STR,
			}
	},
	{
		"lremovexattr", 2,
			{
				STR,
				STR,
			}
	},
	{
		"fremovexattr", 2,
			{
				INT,
				STR,
			}
	},
	{
		"tkill", 2,
			{
				INT,
				INT,
			}
	},
	{
		"time", 1,
			{
				PTR,
			}
	},
	{
		"futex", 6,
			{
				PTR,
				INT,
				INT,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"sched_setaffinity", 3,
			{
				INT,
				UINT,
				PTR,
			}
	},
	{
		"sched_getaffinity", 3,
			{
				INT,
				UINT,
				PTR,
			}
	},
	{0, 0, {}},
	{
		"io_setup", 2,
			{
				UINT,
				PTR,
			}
	},
	{
		"io_destroy", 1,
			{
				INT,
			}
	},
	{
		"io_getevents", 5,
			{
				INT,
				INT,
				INT,
				PTR,
				PTR,
			}
	},
	{
		"io_submit", 3,
			{
				INT,
				INT,
				PTR,
			}
	},
	{
		"io_cancel", 3,
			{
				INT,
				PTR,
				PTR,
			}
	},
	{0, 0, {}},
	{0, 0, {}},
	{
		"epoll_create", 1,
			{
				INT,
			}
	},
	{0, 0, {}},
	{0, 0, {}},
	{
		"remap_file_pages", 5,
			{
				UINT,
				UINT,
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"getdents64", 3,
			{
				UINT,
				PTR,
				UINT,
			}
	},
	{
		"set_tid_address", 1,
			{
				PTR,
			}
	},
	{
		"restart_syscall", 0,
			{
			}
	},
	{
		"semtimedop", 4,
			{
				INT,
				PTR,
				UINT,
				PTR,
			}
	},
	{
		"fadvise64", 4,
			{
				INT,
				INT,
				INT,
				INT,
			}
	},
	{
		"timer_create", 3,
			{
				INT,
				PTR,
				PTR,
			}
	},
	{
		"timer_settime", 4,
			{
				INT,
				INT,
				PTR,
				PTR,
			}
	},
	{
		"timer_gettime", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"timer_getoverrun", 1,
			{
				INT,
			}
	},
	{
		"timer_delete", 1,
			{
				INT,
			}
	},
	{
		"clock_settime", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"clock_gettime", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"clock_getres", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"clock_nanosleep", 4,
			{
				INT,
				INT,
				PTR,
				PTR,
			}
	},
	{
		"exit_group", 1,
			{
				INT,
			}
	},
	{
		"epoll_wait", 4,
			{
				INT,
				PTR,
				INT,
				INT,
			}
	},
	{
		"epoll_ctl", 4,
			{
				INT,
				INT,
				INT,
				PTR,
			}
	},
	{
		"tgkill", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"utimes", 2,
			{
				STR,
				PTR,
			}
	},
	{0, 0, {}},
	{
		"mbind", 6,
			{
				UINT,
				UINT,
				UINT,
				PTR,
				UINT,
				UINT,
			}
	},
	{
		"set_mempolicy", 3,
			{
				INT,
				PTR,
				UINT,
			}
	},
	{
		"get_mempolicy", 5,
			{
				PTR,
				PTR,
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"mq_open", 4,
			{
				STR,
				INT,
				INT,
				PTR,
			}
	},
	{
		"mq_unlink", 1,
			{
				STR,
			}
	},
	{
		"mq_timedsend", 5,
			{
				INT,
				PTR,
				INT,
				UINT,
				PTR,
			}
	},
	{
		"mq_timedreceive", 5,
			{
				INT,
				PTR,
				INT,
				PTR,
				PTR,
			}
	},
	{
		"mq_notify", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"mq_getsetattr", 3,
			{
				INT,
				PTR,
				PTR,
			}
	},
	{
		"kexec_load", 4,
			{
				UINT,
				UINT,
				PTR,
				UINT,
			}
	},
	{
		"waitid", 5,
			{
				INT,
				INT,
				PTR,
				INT,
				PTR,
			}
	},
	{
		"add_key", 5,
			{
				PTR,
				PTR,
				PTR,
				INT,
				INT,
			}
	},
	{
		"request_key", 4,
			{
				PTR,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"keyctl", 5,
			{
				INT,
				UINT,
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"ioprio_set", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"ioprio_get", 2,
			{
				INT,
				INT,
			}
	},
	{
		"inotify_init", 0,
			{
			}
	},
	{
		"inotify_add_watch", 3,
			{
				INT,
				STR,
				INT,
			}
	},
	{
		"inotify_rm_watch", 2,
			{
				INT,
				INT,
			}
	},
	{
		"migrate_pages", 4,
			{
				INT,
				UINT,
				PTR,
				PTR,
			}
	},
	{
		"openat", 4,
			{
				INT,
				STR,
				INT,
				INT,
			}
	},
	{
		"mkdirat", 3,
			{
				INT,
				STR,
				INT,
			}
	},
	{
		"mknodat", 4,
			{
				INT,
				STR,
				INT,
				UINT,
			}
	},
	{
		"fchownat", 5,
			{
				INT,
				STR,
				INT,
				INT,
				INT,
			}
	},
	{
		"futimesat", 3,
			{
				INT,
				STR,
				PTR,
			}
	},
	{
		"newfstatat", 4,
			{
				INT,
				STR,
				PTR,
				INT,
			}
	},
	{
		"unlinkat", 3,
			{
				INT,
				STR,
				INT,
			}
	},
	{
		"renameat", 4,
			{
				INT,
				STR,
				INT,
				STR,
			}
	},
	{
		"linkat", 5,
			{
				INT,
				STR,
				INT,
				STR,
				INT,
			}
	},
	{
		"symlinkat", 3,
			{
				STR,
				INT,
				STR,
			}
	},
	{
		"readlinkat", 4,
			{
				INT,
				STR,
				PTR,
				INT,
			}
	},
	{
		"fchmodat", 3,
			{
				INT,
				STR,
				INT,
			}
	},
	{
		"faccessat", 3,
			{
				INT,
				STR,
				INT,
			}
	},
	{
		"pselect6", 6,
			{
				INT,
				PTR,
				PTR,
				PTR,
				PTR,
				PTR,
			}
	},
	{
		"ppoll", 5,
			{
				PTR,
				UINT,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"unshare", 1,
			{
				UINT,
			}
	},
	{
		"set_robust_list", 2,
			{
				PTR,
				INT,
			}
	},
	{
		"get_robust_list", 3,
			{
				INT,
				PTR,
				PTR,
			}
	},
	{
		"splice", 6,
			{
				INT,
				PTR,
				INT,
				PTR,
				INT,
				UINT,
			}
	},
	{
		"tee", 4,
			{
				INT,
				INT,
				INT,
				UINT,
			}
	},
	{
		"sync_file_range", 4,
			{
				INT,
				INT,
				INT,
				UINT,
			}
	},
	{
		"vmsplice", 4,
			{
				INT,
				PTR,
				UINT,
				UINT,
			}
	},
	{
		"move_pages", 6,
			{
				INT,
				UINT,
				PTR,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"utimensat", 4,
			{
				INT,
				STR,
				PTR,
				INT,
			}
	},
	{
		"epoll_pwait", 6,
			{
				INT,
				PTR,
				INT,
				INT,
				PTR,
				INT,
			}
	},
	{
		"signalfd", 3,
			{
				INT,
				PTR,
				INT,
			}
	},
	{
		"timerfd_create", 2,
			{
				INT,
				INT,
			}
	},
	{
		"eventfd", 1,
			{
				UINT,
			}
	},
	{
		"fallocate", 4,
			{
				INT,
				INT,
				INT,
				INT,
			}
	},
	{
		"timerfd_settime", 4,
			{
				INT,
				INT,
				PTR,
				PTR,
			}
	},
	{
		"timerfd_gettime", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"accept4", 4,
			{
				INT,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"signalfd4", 4,
			{
				INT,
				PTR,
				INT,
				INT,
			}
	},
	{
		"eventfd2", 2,
			{
				UINT,
				INT,
			}
	},
	{
		"epoll_create1", 1,
			{
				INT,
			}
	},
	{
		"dup3", 3,
			{
				UINT,
				UINT,
				INT,
			}
	},
	{
		"pipe2", 2,
			{
				PTR,
				INT,
			}
	},
	{
		"inotify_init1", 1,
			{
				INT,
			}
	},
	{
		"preadv", 5,
			{
				UINT,
				PTR,
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"pwritev", 5,
			{
				UINT,
				PTR,
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"rt_tgsigqueueinfo", 4,
			{
				INT,
				INT,
				INT,
				PTR,
			}
	},
	{
		"perf_event_open", 5,
			{
				PTR,
				INT,
				INT,
				INT,
				UINT,
			}
	},
	{
		"recvmmsg", 5,
			{
				INT,
				PTR,
				UINT,
				UINT,
				PTR,
			}
	},
	{
		"fanotify_init", 2,
			{
				UINT,
				UINT,
			}
	},
	{
		"fanotify_mark", 5,
			{
				INT,
				UINT,
				INT,
				INT,
				STR,
			}
	},
	{
		"prlimit64", 4,
			{
				INT,
				UINT,
				PTR,
				PTR,
			}
	},
	{
		"name_to_handle_at", 5,
			{
				INT,
				STR,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"open_by_handle_at", 3,
			{
				INT,
				PTR,
				INT,
			}
	},
	{
		"clock_adjtime", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"syncfs", 1,
			{
				INT,
			}
	},
	{
		"sendmmsg", 4,
			{
				INT,
				PTR,
				UINT,
				UINT,
			}
	},
	{
		"setns", 2,
			{
				INT,
				INT,
			}
	},
	{
		"getcpu", 3,
			{
				PTR,
				PTR,
				PTR,
			}
	},
	{
		"process_vm_readv", 6,
			{
				INT,
				PTR,
				UINT,
				PTR,
				UINT,
				UINT,
			}
	},
	{
		"process_vm_writev", 6,
			{
				INT,
				PTR,
				UINT,
				PTR,
				UINT,
				UINT,
			}
	},
	{
		"kcmp", 5,
			{
				INT,
				INT,
				INT,
				UINT,
				UINT,
			}
	},
	{
		"finit_module", 3,
			{
				INT,
				PTR,
				INT,
			}
	},
	{
		"sched_setattr", 3,
			{
				INT,
				PTR,
				UINT,
			}
	},
	{
		"sched_getattr", 4,
			{
				INT,
				PTR,
				UINT,
				UINT,
			}
	},
	{
		"renameat2", 5,
			{
				INT,
				STR,
				INT,
				STR,
				UINT,
			}
	},
	{
		"seccomp", 3,
			{
				UINT,
				UINT,
				PTR,
			}
	},
	{
		"getrandom", 3,
			{
				PTR,
				INT,
				UINT,
			}
	},
	{
		"memfd_create", 2,
			{
				STR,
				UINT,
			}
	},
	{
		"kexec_file_load", 5,
			{
				INT,
				INT,
				UINT,
				PTR,
				UINT,
			}
	},
	{
		"bpf", 3,
			{
				INT,
				PTR,
				UINT,
			}
	},
	{
		"execveat", 5,
			{
				INT,
				STR,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"userfaultfd", 1,
			{
				INT,
			}
	},
	{
		"membarrier", 3,
			{
				INT,
				UINT,
				INT,
			}
	},
	{
		"mlock2", 3,
			{
				UINT,
				INT,
				INT,
			}
	},
	{
		"copy_file_range", 6,
			{
				INT,
				PTR,
				INT,
				PTR,
				INT,
				UINT,
			}
	},
	{
		"preadv2", 6,
			{
				UINT,
				PTR,
				UINT,
				UINT,
				UINT,
				INT,
			}
	},
	{
		"pwritev2", 6,
			{
				UINT,
				PTR,
				UINT,
				UINT,
				UINT,
				INT,
			}
	},
	{
		"pkey_mprotect", 4,
			{
				UINT,
				INT,
				UINT,
				INT,
			}
	},
	{
		"pkey_alloc", 2,
			{
				UINT,
				UINT,
			}
	},
	{
		"pkey_free", 1,
			{
				INT,
			}
	},
	{
		"statx", 5,
			{
				INT,
				STR,
				UINT,
				UINT,
				PTR,
			}
	},
	{
		"io_pgetevents", 6,
			{
				INT,
				INT,
				INT,
				PTR,
				PTR,
				PTR,
			}
	},
	{
		"rseq", 4,
			{
				PTR,
				INT,
				INT,
				INT,
			}
	},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{0, 0, {}},
	{
		"pidfd_send_signal", 4,
			{
				INT,
				INT,
				PTR,
				UINT,
			}
	},
	{
		"io_uring_setup", 2,
			{
				INT,
				PTR,
			}
	},
	{
		"io_uring_enter", 6,
			{
				UINT,
				INT,
				INT,
				INT,
				PTR,
				INT,
			}
	},
	{
		"io_uring_register", 4,
			{
				UINT,
				UINT,
				PTR,
				UINT,
			}
	},
	{
		"open_tree", 3,
			{
				INT,
				STR,
				UINT,
			}
	},
	{
		"move_mount", 5,
			{
				INT,
				STR,
				INT,
				STR,
				UINT,
			}
	},
	{
		"fsopen", 2,
			{
				STR,
				UINT,
			}
	},
	{
		"fsconfig", 5,
			{
				INT,
				UINT,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"fsmount", 3,
			{
				INT,
				UINT,
				UINT,
			}
	},
	{
		"fspick", 3,
			{
				INT,
				PTR,
				UINT,
			}
	},
	{
		"pidfd_open", 2,
			{
				INT,
				UINT,
			}
	},
	{
		"clone3", 2,
			{
				PTR,
				INT,
			}
	},
	{
		"close_range", 3,
			{
				UINT,
				UINT,
				UINT,
			}
	},
	{
		"openat2", 4,
			{
				INT,
				STR,
				PTR,
				INT,
			}
	},
	{
		"pidfd_getfd", 3,
			{
				INT,
				INT,
				UINT,
			}
	},
	{
		"faccessat2", 4,
			{
				INT,
				STR,
				INT,
				INT,
			}
	},
	{
		"process_madvise", 5,
			{
				INT,
				PTR,
				INT,
				INT,
				UINT,
			}
	},
	{
		"epoll_pwait2", 6,
			{
				INT,
				PTR,
				INT,
				PTR,
				PTR,
				INT,
			}
	},
	{
		"mount_setattr", 5,
			{
				INT,
				PTR,
				UINT,
				PTR,
				INT,
			}
	},
	{
		"quotactl_fd", 4,
			{
				UINT,
				UINT,
				INT,
				PTR,
			}
	},
	{
		"landlock_create_ruleset", 3,
			{
				INT,
				INT,
				INT,
			}
	},
	{
		"landlock_add_rule", 4,
			{
				INT,
				INT,
				INT,
				INT,
			}
	},
	{
		"landlock_restrict_self", 2,
			{
				INT,
				INT,
			}
	},
	{
		"memfd_secret", 1,
			{
				UINT,
			}
	},
	{
		"process_mrelease", 2,
			{
				INT,
				UINT,
			}
	},
	{
		"futex_waitv", 5,
			{
				PTR,
				UINT,
				UINT,
				PTR,
				INT,
			}
	},
	{
		"set_mempolicy_home_node", 4,
			{
				UINT,
				UINT,
				UINT,
				UINT,
			}
	},
};
