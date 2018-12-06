#ifndef CRCTOOL_H
#define CRCTOOL_H

#include <stdint.h>
#include <vector>

class CrcTool
{
public:
   CrcTool();

   static uint8_t calcCrc8(uint8_t const * buffer, int length, uint8_t seed);

   static uint16_t calcCrc16(uint8_t const * buffer, int length, uint16_t seed);

   static std::vector<uint8_t> calculateCrc8Seed(uint8_t const * buffer, int length, uint8_t crc8);

   static std::vector<uint16_t> calculateCrc16Seed(uint8_t const * buffer, int length, uint16_t crc16);

protected:

   static const uint8_t theCrc8Table[256];

   static const uint16_t theCrc16Table[256];


};

#endif // CRCTOOL_H
