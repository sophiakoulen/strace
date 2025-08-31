#include <signal.h>
int main()
{
	printf("pid: %d\n", getpid());
	kill(getpid(), SIGSTOP);
}
