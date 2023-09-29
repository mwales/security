#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char** argv)
{
	char buf[0x50];
	memset(buf, 0, 0x50);

	uint64_t* ptr = (uint64_t*) buf;


	*ptr = 0x71267032217f2271;
	ptr++;
	*ptr = 0x6b327c217a653279;
	ptr++;
	*ptr = 0x357c216073326722;
	ptr++;
	*ptr = 0x2666322323733266;
	ptr++;

	uint16_t* ptr2 = (uint16_t*) ptr;
	*ptr2 = 0x797e;
	ptr2++;

	uint8_t* ptr3 = (uint8_t*) ptr2;
	*ptr3 = 0x33;
	//for (int32_t var_3c = 0; var_3c <= 0x22; var_3c = (var_3c + 1))
	//{
	//    putchar(((int32_t)(*(int8_t*)(&var_38 + ((int64_t)var_3c)) ^ 0x12)));
	//}
	//putchar(0xa);
//	int64_t rax_8 = (rax ^ *(int64_t*)((char*)fsbase + 0x28));

	for(int i = 0; i < strlen(buf); i++)
	{
		buf[i] ^= 0x12;
	}

	printf("Buf %s\n", buf);

	return 0;
}
