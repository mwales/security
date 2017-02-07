#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>

/* This program calculates the password the for catalyst challenge.  The writeup will tell you how
   the username was found.  The username is then used as the seed for the PRNG.  The constants used
   with it were found by reversing the binary.
*/

int main()
{
	char username[] = "catalyst_ceo";

	uint32_t* seedStuff = (uint32_t*) &username[0];

	srand(seedStuff[0] + seedStuff[1] + seedStuff[2]);

	char password[200];
	bzero(password, 200);

	uint32_t* passwordNum = (uint32_t*) &password[0];

	passwordNum[0] = rand() + 0x55eb052a;
	passwordNum[1] = rand() + 0xef76c39;
	passwordNum[2] = rand() + 0xcc1e2d64;
	passwordNum[3] = rand() + 0xc7b6c6f5;
	passwordNum[4] = rand() + 0x26941bfa;
	passwordNum[5] = rand() + 0x260cf0f3;
	passwordNum[6] = rand() + 0x10d4caef;
	passwordNum[7] = rand() + 0xc666e824;
	passwordNum[8] = rand() + 0xfc89459c;
	passwordNum[9] = rand() + 0x2413073a;

	printf("Password: %s\n", password);

	return 0;
}
