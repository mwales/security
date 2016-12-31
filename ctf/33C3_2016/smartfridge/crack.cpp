#include <iostream>
#include <istream>
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>

//// To compile: g++ crack.cpp -lcrypto -o crack
//// To run: ./crack

//// Tool to crack pin for the smartfridge2 crypto challenge for 33C3 CTF 2016

//// Description: Given the same interface as smartfridge1, you are given a PCAP
//// of a client connecting to the fridge and retrieving info from shelf 2.  Get
//// the flag stored in shelf 2

int main(int argc, char *argv[])
{
    // These values were extracted from PCAP of client connecting to the smartfridge

#define CTF_VERSION
#ifdef CTF_VERSION
    unsigned char MRand[] = {
        0x31, 0x19, 0xf4, 0x5f, 0x74, 0x99, 0xcd, 0xa0,
        0x07, 0x67, 0x0b, 0x2f, 0x51, 0xfd, 0x41, 0x27 };

    unsigned char MConfirm[] = {
        0xe6, 0x6d, 0x09, 0xaa, 0xad, 0x15, 0xd1, 0x91,
        0xb6, 0xfa, 0x3a, 0x47, 0x4e, 0x98, 0xa4, 0x6c };

    unsigned char shelfNum = 0x2;
#else
    unsigned char MConfirm[] = {
        0x6e, 0x58, 0x9a, 0x93, 0x5d, 0x14, 0xd8, 0xbc,
        0xb4, 0x72, 0xb9, 0xdf, 0x6f, 0xa2, 0x0e, 0xfb
    };

    const unsigned char MRand[] = {
          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
          };

    unsigned char shelfNum = 0x1;
#endif


    //*********************************************************************************************
    // Creating and sending MConfirm
    //*********************************************************************************************
    bool crackSuccess = false;
    long long int pinCodeHalfBlock = 0;
    int progressCounter = 0;
    while (!crackSuccess)
    {

        // Pin code only fills up half of the block
        unsigned char pinBlock[0x10];
        bzero(pinBlock, 0x10);
        memcpy(pinBlock, &pinCodeHalfBlock, 0x8);

        //printf("Pin Block:\n");
        //hexDump( (unsigned char*) &pinBlock, 0x10);

        unsigned char MConfirmTest[0x10];
        AES_KEY encryptKey;
        AES_set_encrypt_key( (unsigned char*) &pinBlock, 128, &encryptKey);
        AES_encrypt( MRand, MConfirmTest, &encryptKey);

        if (!memcmp(MConfirmTest, MConfirm, 0x10))
        {
            printf("Found the pin: %lld\n", pinCodeHalfBlock);
            crackSuccess = true;
        }

        pinCodeHalfBlock++;
        progressCounter++;

        if (progressCounter == 1000000)
        {
            printf("Shelf Num = %d\nPin Code = %lld\n", shelfNum, pinCodeHalfBlock);
            progressCounter = 0;
        }

    }

    return 0;
}
