#include <unistd.h>
int main()
{
	char buffer[1024];
	int a = read(0, &buffer, 1024);
}
