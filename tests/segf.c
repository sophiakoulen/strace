#include <fcntl.h>
int main()
{
	int a = 42;
	int fd = open((char*)a, 0);
}
