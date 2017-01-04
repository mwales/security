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

// To compile: g++ main.cpp -lcrypto -o fc
// To run: ./fc 127.0.0.1 12345 1 123456 (for the binary they give you)

// Tool to retrieve flag for the smartfridge1 reversing challenge for 33C3 CTF 2016

// Description: We've developed a new smart refrigerator with networking functionality. We have
// adopted the proven Bluetooth LE 4.0 crypto protocol to secure your food from your flatmates.
// There are two lockable shelves. Shelf number 1 belongs to you. Find the fridge at (ip removed).
// The pincode for your shelf is 768305. In it you will find the first flag.
// Note: this challenge is rate limited

// Also was given a binary of the application that we could run ourselves and analyze

void hexDump(unsigned char const * const buffer, unsigned int bufferLen, FILE* fd = stdout)
{
  unsigned int i;
  for(i = 0; i < bufferLen; i++)
  {
    fprintf(fd, "%02x", buffer[i]);
    if (i % 16 == 15)
    {
      fprintf(fd, "\n");
    }
    else if (i % 16 == 7)
    {
      fprintf(fd, "  ");
    }
    else
    {
      fprintf(fd, " ");
    }
  }

  if (i % 16 != 0)
  {
    fprintf(fd, "\n");
  }
}

bool cbcCryptMessage(std::string message, unsigned char* aes128Key, unsigned char* cipherText, uint32_t* cipherTextLength)
{
    int messageLength = message.length() + 1; // Add a byte for null terminator
    int numberOfBlocksReqd = messageLength / 16 + 1;
    int paddingBytes = 16 - messageLength % 16;

    printf("\nEncrypting message of length %d, blocks required = %d, padding byte = %d\n",
           messageLength, numberOfBlocksReqd, paddingBytes);

    unsigned char* buffer = (unsigned char*) malloc(numberOfBlocksReqd * 0x10);

    int currentByte = 0;
    for(unsigned int i = 0; i < message.length(); i++)
    {
        buffer[currentByte] = message[i];
        currentByte++;
    }

    // Null terminate the message
    buffer[currentByte++] = 0;

    while (currentByte < numberOfBlocksReqd * 0x10)
    {
        buffer[currentByte++] = paddingBytes;
    }

    unsigned char iv[0x10];
    bzero(iv, 0x10);

    AES_KEY key;
    AES_set_encrypt_key(aes128Key, 128, &key);
    AES_cbc_encrypt(buffer, cipherText, numberOfBlocksReqd * 0x10, &key, iv, AES_ENCRYPT);

//    printf("Plaintext:\n");
//    hexDump(buffer, numberOfBlocksReqd * 0x10);
//    printf("Ciphertext:\n");
//    hexDump(cipherText, numberOfBlocksReqd * 0x10);

    *cipherTextLength = numberOfBlocksReqd * 0x10;

    free(buffer);
    return true;
}

bool cbcDecryptMessage(unsigned char* aes128Key, unsigned char* cipherText, uint32_t cipherTextLength)
{
    if (cipherTextLength % 16 != 0)
    {
        printf("Incoming cipher text length of %d is invalid block size\n", cipherTextLength);
        return false;
    }

    unsigned char* plaintext = (unsigned char*) malloc(cipherTextLength);

    unsigned char iv[0x10];
    bzero(iv, 0x10);

    AES_KEY key;
    AES_set_decrypt_key(aes128Key, 128, &key);
    AES_cbc_encrypt(cipherText, plaintext, cipherTextLength, &key, iv, AES_DECRYPT);

    printf("\nDecrypting Ciphertext:\n");
    hexDump(cipherText, cipherTextLength);

    printf("Plaintext:\n");
    hexDump(plaintext, cipherTextLength);

    // Truncate off the padding
    int rxPaddingByte = plaintext[cipherTextLength - 1];
    if (rxPaddingByte <= 0x10)
    {
        // Seems like probable valid padding
        plaintext[cipherTextLength - rxPaddingByte] = 0; // Add null terminator
        printf("Plaintext in ASCII:\n%s\n", plaintext);
    }
    else
    {
        printf("Received message had invalid padding\n");
    }

    free(plaintext);
    return true;
}

bool doesStringStartWith(std::string needle, std::string haystack)
{
    if (haystack.length() < needle.length())
    {
        return false;
    }

    for(unsigned int i = 0; i < needle.length(); i++)
    {
        if (needle[i] != haystack[i])
        {
            return false;
        }
    }

    return true;
}


int main(int argc, char *argv[])
{
    if (argc != 5)
    {
        std::cerr << "Usage: " << argv[0] << " ipAddress portNumber shelfNumber pinCode" << std::endl;
        return 1;
    }

    int socketFd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in tcpSocketAddr;
    tcpSocketAddr.sin_family = AF_INET;
    tcpSocketAddr.sin_port = htons(atoi(argv[2]));
    inet_aton(argv[1], &(tcpSocketAddr.sin_addr));


    int status = connect(socketFd, (struct sockaddr *) &tcpSocketAddr, sizeof(struct sockaddr_in));
    if (status != 0)
    {
        std::cerr << "Error connecting to the server" << std::endl;
        return 1;
    }

    // Online documentation at https://community.nxp.com/thread/332191 was really helpful about the
    // Bluetooth 4.0 LE authentication scheme, which boils down to basically:
    // 1. Client sends MConfirm (AES encrypt random number MRand using Pin as key)
    // 2. Server responds with SConfirm (AES encrypt random number MRand using Pin as key)
    // 3. Client sends random number MRand
    // 4. Server validates that MRand matches the one encrypted with Pin Code
    // 5. Server responds with SRand
    // 6. Both sides create Session Key derived from MRand and SRand
    // 7. All messages afterwords encrypted with AES using Session Key

    //*********************************************************************************************
    // Creating and sending MConfirm
    //*********************************************************************************************

    char* pinCode = argv[4]; // "123456";
    int shelfNum = atoi(argv[3]);
    std::cerr << "Shelf Num = " << shelfNum << std::endl;
    std::cerr << "Pin Code = " << pinCode << std::endl;;

    // Pin code only fills up half of the block
    long long int pinCodeHalfBlock = strtoll(pinCode, NULL, 10);
    unsigned char pinBlock[0x10];
    bzero(pinBlock, 0x10);
    memcpy(pinBlock, &pinCodeHalfBlock, 0x8);

    std::cerr << "Pin Block:" << std::endl;
    hexDump( (unsigned char*) &pinBlock, 0x10);

    // Clients "random" number
    const unsigned char MRand[] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
      };

    unsigned char MConfirm[0x10];
    AES_KEY encryptKey;
    AES_set_encrypt_key( (unsigned char*) &pinBlock, 128, &encryptKey);
    AES_encrypt( MRand, MConfirm, &encryptKey);

    std::cout << "MRand:" << std::endl;
    hexDump(MRand, 16);

    std::cout << "MConfirm:" << std::endl;
    hexDump(MConfirm, 16, stderr);

    // Each message is always preceded by a uint32_t message length (including the size field itself)
    // Even the encrypted messages once pairing is complete.

    unsigned char MConfirmMsg[0x15];
    uint32_t messageLen = 0x15;
    memcpy(&MConfirmMsg[0], &messageLen, 4);
    MConfirmMsg[4] = shelfNum; // I think this is a shelf number
    memcpy(&MConfirmMsg[5], MConfirm, 0x10);

    std::cerr << "About to send the MConfirmMsg" << std::endl;
    hexDump(MConfirmMsg, 0x15);
    write(socketFd, MConfirmMsg, 0x15);

    //*********************************************************************************************
    // Receiving SConfirm
    //*********************************************************************************************

    uint32_t SConfigMsgSize;
    read(socketFd, &SConfigMsgSize, 4);

    std::cerr << "SConfigSize = " << SConfigMsgSize << std::endl;

    unsigned char SConirmData[16];
    read(socketFd, SConirmData, 16);

    hexDump(SConirmData, 0x10, stderr);

    //*********************************************************************************************
    // Sending MRand
    //*********************************************************************************************

    unsigned char MRandMsg[0x14];
    messageLen = 0x14;
    memcpy(&MRandMsg[0], &messageLen, 4);
    memcpy(&MRandMsg[4], MRand, 0x10);
    //bzero(&MRand[0x14], 4);

    std::cout << "About to send the MRand" << std::endl;
    hexDump(MRandMsg, 0x14);

    write(socketFd, MRandMsg, 0x14);

    //*********************************************************************************************
    // Receiving SRand (if received, this means "pairing" successful
    //*********************************************************************************************

    uint32_t SRandMsgSize;
    read(socketFd, &SRandMsgSize, sizeof(uint32_t));

    unsigned char SRand[0x10];
    int bytesRead = read(socketFd, SRand, 0x10);

    if (bytesRead != 0x10)
    {
        std::cerr << "Failed to complete handshake.  Only received " << bytesRead
                  << " of required 10 bytes of SRand" << std::endl;
        close(socketFd);
        return 1;
    }

    std::cerr << "SRand Received.  Msg Size = " << SRandMsgSize << std::endl;
    hexDump(SRand, 0x10);

    //*********************************************************************************************
    // Create AES Session Key
    //*********************************************************************************************

    // AES key is created by encrypting upper 8 bytes of SRand and MRand using pin block
    unsigned char aesSessionKey[0x10];
    unsigned char mergedRands[0x10];
    memcpy(&mergedRands[0], &SRand[8], 0x8);
    memcpy(&mergedRands[0x8], &MRand[8], 0x8);

    AES_encrypt( mergedRands, aesSessionKey, &encryptKey);

    std::cout << std::endl << "Derived AES session key:" << std::endl;
    hexDump(aesSessionKey, 0x10);

    //*********************************************************************************************
    // Interactive command and control interface
    // To get flag:
    // OPEN 1
    // LIST
    // SHOW 0
    //*********************************************************************************************

    std::string inputCommand;
    unsigned char hugeBuffer[1024];
    unsigned char responseBuffer[65536];
    while(inputCommand != "exit")
    {
        std::cout << "Enter a command (or exit to close client)" << std::endl;
        std::cout << "Valid commands from reversing:" << std::endl;
        std::cout << "  OPEN ShelfNumber              (use 1 or 2, needs to match the shelf number used at program startup)" << std::endl;
        std::cout << "  LIST                          (lists contents of shelf, use OPEN first)" << std::endl;
        std::cout << "  SHOW ItemNumber               (displays the item description)" << std::endl;
        std::cout << "  PUT ItemNumber Name Desc      (adds an item to the shelf)" << std::endl;
        std::cout << "  TAKE ItemNumber               (shows item, then removes from shelf)" << std::endl;
        std::cout << "  CLOSE" << std::endl;
        std::getline(std::cin, inputCommand);

        cbcCryptMessage(inputCommand, aesSessionKey, &hugeBuffer[4], &messageLen);

        messageLen += 4;
        memcpy(hugeBuffer, &messageLen, 4);

        write(socketFd, hugeBuffer, messageLen);

        // Not all commands will get a response
        if (doesStringStartWith("OPEN", inputCommand) ||
            doesStringStartWith("PUT", inputCommand) ||
            doesStringStartWith("CLOSE", inputCommand) )
        {
            std::cerr << "No response expected for command: " << inputCommand << std::endl;
            continue;
        }

        uint32_t responseLength;
        read(socketFd, &responseLength, 4);

        if (responseLength <= 4)
        {
            std::cerr << "Empty response received! Size = " << responseLength << std::endl;
            continue;
        }

        std::cout << "Response rx length = " << responseLength << std::endl;
        responseLength -= 4;

        if (responseLength > sizeof(responseBuffer) / sizeof(unsigned char))
        {
            std::cerr << "Response message way too large!!!! " << responseLength << " bytes" << std::endl;
            close(socketFd);
            return 1;
        }

        read(socketFd, &responseBuffer, responseLength);
        hexDump(responseBuffer, responseLength);

        cbcDecryptMessage(aesSessionKey, responseBuffer, responseLength);

    }

    close(socketFd);
    return 0;


}
