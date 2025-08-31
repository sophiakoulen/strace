#include <signal.h>
int main()
{
	kill(getpid(), SIGSTOP);
}
