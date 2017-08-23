#include <iostream>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// AES Overview

// 128 = 10 rounds
// 192 = 12 rounds
// 256 = 14 rounds

// Each round
// * addRoundKey
// * subBytes
// * shiftRows
// * mixColumns (omitted in last round)

const int BLOCK_SIZE = 16;

void aesCrypt(uint8_t* data, uint8_t* key, int keyLen);

uint8_t fwdSBox(uint8_t val);
uint8_t revSBox(uint8_t val);

uint8_t gmul(uint8_t a, uint8_t b);

uint8_t rcon(uint8_t val);

void mixColumns(uint8_t* colOf4Nums);
void mixColumnsBlock(uint8_t* dataBlock);

void xorBlock(uint8_t* blockToModify, uint8_t* blockToXorWith);

void expandKey(uint8_t* originalKey, int keyLen, uint8_t** expandedKey);

void rotateLeftWord(uint8_t* data);

void shiftRowsBlock(uint8_t* dataBlock);

void executeTestFunctions();

void sboxTest();

void dumpBytes(uint8_t* data, int dataLen);


int main(int argc, char *argv[])
{
    if ( (argc == 2) && (strcmp(argv[1], "-t") == 0) )
    {
        std::cout << "Test mode entered!" << std::endl;
        executeTestFunctions();
        return 0;
    }

    if (argc != 6)
    {
        std::cerr << "Usage: " << argv[0] << "enc key.bin keyLen plaintext.bin ciphertext.bin" << std::endl;
        std::cerr << "     : " << argv[0] << "dec key.bin keyLen ciphertext.bin plaintext.bin" << std::endl;
        std::cerr << "Key Len = 128, 192, or 256 bits" << std::endl;
        return 0;
    }

    bool encryptMode = (strcmp(argv[1], "enc") == 0);
    std::cout << "Mode = " << (encryptMode ? "Encrypt" : "Decrypt") << std::endl;

    int keyLen = atoi(argv[3]);
    if ( (keyLen != 128) && (keyLen != 192) && (keyLen != 256))
    {
        std::cerr << "Invalid Key Length" << keyLen << "!  Must be 128, 192, or 256!" << std::endl;
        return 2;
    }
    int keyBytes = keyLen / 8;
    std::cout << "Key Len = " << keyLen << " bits, " << keyBytes << " bytes\n" << std::endl;

    std::cout << "Key File = " << argv[2] << std::endl;
    std::cout << "In File  = " << argv[4] << std::endl;
    std::cout << "Out File = " << argv[5] << std::endl;

    int keyFd = open(argv[2], O_RDONLY);
    int inFd  = open(argv[4], O_RDONLY);
    int outFd = open(argv[5], O_WRONLY | O_CREAT, 0644);

    if ( (keyFd <= 0) || (inFd <= 0) || (outFd <= 0) )
    {
        std::cerr << "Error opening one of the files!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        return 1;
    }

    uint8_t keyBuf[16];
    if (keyBytes != read(keyFd, keyBuf, keyBytes))
    {
        std::cerr << "Error reading the key data" << std::endl;
        return 1;
    }

    close(keyFd);

    uint8_t buf[BLOCK_SIZE];
    int bytesRead = read(inFd, buf, BLOCK_SIZE);

    if (bytesRead != BLOCK_SIZE)
    {
        std::cerr << "Couldn't read a block of data from the input file" << std::endl;
        return 1;
    }

    aesCrypt(buf, keyBuf, keyBytes);

    if (BLOCK_SIZE != write(outFd, buf, BLOCK_SIZE))
    {
        std::cerr << "Error writing the cipher text" << std::endl;
        return 1;
    }

    close(inFd);
    close(outFd);


    return 0;
}

void aesCrypt(uint8_t* data, uint8_t* key, int keyLen)
{
    int numRounds;

    if (keyLen == 128)
    {
        numRounds = 10;
        std::cout << "AES-128 Crypt, 10 rounds" << std::endl;
    }
    else if (keyLen == 192)
    {
        numRounds = 12;
        std::cout << "AES-192 Crypt, 12 rounds" << std::endl;
    }
    else
    {
        numRounds = 14;
        std::cout << "AES-256 Crypt, 14 rounds" << std::endl;
    }


    uint8_t* expandedKey;
    expandKey(key, keyLen, &expandedKey);

    // Initial round
    xorBlock(data, expandedKey + 0);

    for(int roundNum = 1; roundNum <= numRounds; roundNum++)
    {
        // Sub bytes
        for(int i = 0; i < 16; i++)
        {
            data[i] = fwdSBox(data[i]);
        }

        // Shift rows
        shiftRowsBlock(data);

        // Mix Columns (don't do this in the last round)
        if (roundNum != numRounds)
        {
            mixColumnsBlock(data);
        }

        // Add Round Key
        xorBlock(data, expandedKey + 16 * roundNum);
    }

}

uint8_t fwdSBox(uint8_t val)
{
    static uint8_t s[] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
     };

    return s[val];
}

uint8_t revSBox(uint8_t val)
{
    static uint8_t inv_s[] =
     {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
     };

    return inv_s[val];
}

uint8_t rcon(uint8_t val)
{
    uint8_t rconLookupTable[256] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    };

    return rconLookupTable[val];
}

void sboxTest()
{
    for(uint16_t i = 0; i < 256; i++)
    {
        std::string data;
        data = "i=";
        data += std::to_string(i);
        data += ", s[i]=";

        uint16_t sVal = fwdSBox(i);

        data += std::to_string(sVal);
        data += ", invS[s[i]]=";

        uint16_t invSVal = revSBox(sVal);

        data += std::to_string(invSVal);

        std::cout << data << std::endl;
    }
}

// Copied directly from Wikipedia
uint8_t gmul(uint8_t a, uint8_t b)
{
    if (a == 1)
        return b;

    uint8_t p = 0; /* the product of the multiplication */
    while (b) {
            if (b & 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
                p ^= a; /* since we're in GF(2^m), addition is an XOR */

            if (a & 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
                a = (a << 1) ^ 0x11b; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) – you can change it but it must be irreducible */
            else
                a <<= 1; /* equivalent to a*2 */
            b >>= 1; /* equivalent to b // 2 */
    }
    return p;
}

void mixColumns(uint8_t* colOf4Nums)
{
    uint8_t results[4];

    results[0] = gmul(2, colOf4Nums[0]) ^ gmul(3, colOf4Nums[1]) ^ gmul(1, colOf4Nums[2]) ^ gmul(1, colOf4Nums[3]);
    results[1] = gmul(1, colOf4Nums[0]) ^ gmul(2, colOf4Nums[1]) ^ gmul(3, colOf4Nums[2]) ^ gmul(1, colOf4Nums[3]);
    results[2] = gmul(1, colOf4Nums[0]) ^ gmul(1, colOf4Nums[1]) ^ gmul(2, colOf4Nums[2]) ^ gmul(3, colOf4Nums[3]);
    results[3] = gmul(3, colOf4Nums[0]) ^ gmul(1, colOf4Nums[1]) ^ gmul(1, colOf4Nums[2]) ^ gmul(2, colOf4Nums[3]);

    for(int i = 0; i < 4; i++)
    {
        colOf4Nums[i] = results[i];
    }
}

void mixColumnsBlock(uint8_t* dataBlock)
{
    for(int i = 0; i < 16; i+= 4)
    {
        mixColumns(dataBlock + i);
    }
}

void executeTestFunctions()
{
    sboxTest();

    uint8_t tv1[4] = {0xdb, 0x13, 0x53, 0x45};
    mixColumns(tv1);
    printf("MixCol(tv1) = 0x%02x 0x%02x 0x%02x 0x%02x\n", (int) tv1[0], (int) tv1[1], (int) tv1[2], (int) tv1[3]);

    uint8_t tv2[4] = {0xf2, 0x0a, 0x22, 0x5c};
    mixColumns(tv2);
    printf("MixCol(tv2) = 0x%02x 0x%02x 0x%02x 0x%02x\n", (int) tv2[0], (int) tv2[1], (int) tv2[2], (int) tv2[3]);

    uint8_t tv3[4] = {0x01, 0x01, 0x01, 0x01};
    mixColumns(tv3);
    printf("MixCol(tv3) = 0x%02x 0x%02x 0x%02x 0x%02x\n", (int) tv3[0], (int) tv3[1], (int) tv3[2], (int) tv3[3]);
    dumpBytes(tv3, 4);

    uint8_t key1[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t* expKey1;
    expandKey( key1, 128, &expKey1);
    dumpBytes(expKey1, 176);

    uint8_t key2[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t* expKey2;
    expandKey( key2, 128, &expKey2);
    dumpBytes(expKey2, 176);

    uint8_t d1[]   = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    std::cout << "\n\n\n";
    std::cout << "KEY:" << std::endl;
    dumpBytes(key1, 16);

    std::cout << "\nDATA:" << std::endl;
    dumpBytes(d1, 16);

    aesCrypt(d1, key1, 128);
    std::cout << "\nCT:" << std::endl;
    dumpBytes(d1, 16);
}

/// Need to free expandedKey after encrypting complete
/// Only works so far for AES-128
void expandKey(uint8_t* originalKey, int keyLen, uint8_t** expandedKey)
{
    // 128bit key (16 bytes) = 10 aes rounds = 160 for rounds + 16 in initial round = 176 bytes expanded key
    // 192bit key (24 bytes) = 12 aes rounds = 192 for rounds + 16 in initial round = 208 bytes expanded key
    // 256bit key (32 bytes) = 14 aes rounds = 224 for rounds + 16 in initial round = 240 bytes expanded key

    uint8_t* expKey = NULL;
    int curByte = 0;
    int numBytesNeeded = 0;
    int numBlocksNeeded = 0;
    if(keyLen == 128)
    {
        numBytesNeeded = 176;
        numBlocksNeeded = 11;
    }

    expKey = (uint8_t*) malloc(numBytesNeeded);

    int rconI = 1;

    int curWord;
    for(curWord = 0; curWord < numBytesNeeded / 4; curWord++)
    {

        if (curWord < 4)
        {
            // These words just get copied over
            for(int i = 0; i < 4; i++)
            {
                expKey[curByte] = originalKey[curByte];
                curByte++;
            }

            // Next word!
            continue;
        }

        // We get previous 4 bytes (rotated)
        // CB-4 CB-3 CB-2 CB-1   CB+0 CB+1 CB+2 CB+3
        // CB-4 CB-3 CB-2 CB-1   CB-4 CB-3 CB-2 CB-1   after copying
        // CB-4 CB-3 CB-2 CB-1   CB-3 CB-2 CB-1 CB-4   after rotation
        expKey[curByte  ] = expKey[curByte-4];
        expKey[curByte+1] = expKey[curByte-3];
        expKey[curByte+2] = expKey[curByte-2];
        expKey[curByte+3] = expKey[curByte-1];

        if ((curWord % 4) == 0)
        {
            // Rotate
            rotateLeftWord(&(expKey[curByte]));

            // S-box each of the 4 bytes
            expKey[curByte  ] = fwdSBox(expKey[curByte  ]);
            expKey[curByte+1] = fwdSBox(expKey[curByte+1]);
            expKey[curByte+2] = fwdSBox(expKey[curByte+2]);
            expKey[curByte+3] = fwdSBox(expKey[curByte+3]);

            // Rcon the 1st byte
            expKey[curByte] = expKey[curByte] ^ rcon(rconI);
            rconI++;
        }

        // X-or with the bytes from the previous block
        expKey[curByte  ] = expKey[curByte  ] ^ expKey [curByte - 16];
        expKey[curByte+1] = expKey[curByte+1] ^ expKey [curByte - 15];
        expKey[curByte+2] = expKey[curByte+2] ^ expKey [curByte - 14];
        expKey[curByte+3] = expKey[curByte+3] ^ expKey [curByte - 13];

        curByte += 4;
    }

    *expandedKey = expKey;
}

void dumpBytes(uint8_t* data, int dataLen)
{
    char dumpBuffer[10];
    for(int i = 0; i < dataLen; i++)
    {
        if ( (i % 16 == 0) && (i != 0))
            std::cout << std::endl;

        if (i != 0)
            std::cout << ", ";

        sprintf(dumpBuffer, "0x%02x", data[i]);
        std::cout << dumpBuffer;
    }

    std::cout << std::endl;
}

void rotateLeftWord(uint8_t* data)
{
    uint8_t extra = data[0];
    data[0] = data[1];
    data[1] = data[2];
    data[2] = data[3];
    data[3] = extra;
}

void xorBlock(uint8_t* blockToModify, uint8_t* blockToXorWith)
{
    for(int i = 0; i < 16; i++)
    {
        blockToModify[i] = blockToModify[i] ^ blockToXorWith[i];
    }
}

void shiftRowsBlock(uint8_t* dataBlock)
{
    // 0  4  8  12               0  4  8  12
    // 1  5  9  13    becomes    5  9  13 1
    // 2  6  10 14               10 14 2  6
    // 3  7  11 15               15 3  7  11

    // Shift 2nd row left 1 byte
    uint8_t tempByte;
    tempByte = dataBlock[1];
    dataBlock[1] = dataBlock[5];
    dataBlock[5] = dataBlock[9];
    dataBlock[9] = dataBlock[13];
    dataBlock[13] = tempByte;

    // Shift 3rd row 2 bytes
    uint8_t anotherTempByte;
    tempByte = dataBlock[2];
    anotherTempByte = dataBlock[6];
    dataBlock[2] = dataBlock[10];
    dataBlock[6] = dataBlock[14];
    dataBlock[10] = tempByte;
    dataBlock[14] = anotherTempByte;

    // Shift 4th row 3 bytes left (1 byte right)
    tempByte = dataBlock[3];
    dataBlock[3] = dataBlock[15];
    dataBlock[15] = dataBlock[11];
    dataBlock[11] = dataBlock[7];
    dataBlock[7] = tempByte;

}
