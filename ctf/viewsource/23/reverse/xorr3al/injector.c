#include <stdio.h>

char* strstr(const char* haystack, const char* needle)
{
	printf("haystack=%s and needle=%s\n", haystack, needle);
	return 0;
}

void dumpBigFrozenStack(int* stackAddr)
{
	printf("Stack Pointer near %p\n", stackAddr);

	for(int i = 0; i < 0x30; i+= 4)
	{
		printf("0x%04x %08x %08x %08x %08x\n", i, stackAddr[i], stackAddr[i+1], stackAddr[i+2], stackAddr[i+3]);
	}
}

void dumpFrozenStack(int* stackAddr)
{
	printf("Num flag bytes correct = %d\n", stackAddr[11]);
}

int close(int fd)
{
	static int closeCallTracker = 0;
	closeCallTracker++;
	printf("close called %d times on fd = %d\n", closeCallTracker, fd);

	int dumbVar = 0;
	if (closeCallTracker == 2)
	{
		dumpFrozenStack(&dumbVar);
	}

	return 0;
}

