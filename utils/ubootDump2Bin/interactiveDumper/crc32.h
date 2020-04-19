#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>
#include <stddef.h>

uint32_t updateCRC32(unsigned char ch, uint32_t crc);

uint32_t crc32buf(char *buf, size_t len);

#endif
