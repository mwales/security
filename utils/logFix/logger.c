#include<stdio.h>
#include<unistd.h>

int main()
{
	FILE* f = fopen("log.txt", "w+");
	int counter = 0;
	while(1)
	{
      fprintf(f, "Ogre did like %d dumb things today\n", counter++);
		fflush(f);
		sleep(2);
	}

	return 0;
}

