#include "simple_patcher.h"

#include <stdio.h>
#include <map>
#include <vector>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>

std::map<uint32_t, std::string> getSectionNames(FILE* f,
                                         struct Elf32_Ehdr const & elfHeader)
{
   struct Elf32_SectionHeader stringSectionHdr;

   uint32_t stringSectionLocation = elfHeader.e_shoff + elfHeader.e_shstrndx * elfHeader.e_shentsize;
   // printf("String section @ 0x%08x\n", stringSectionLocation);

   if (!readFile(f, stringSectionLocation, sizeof(struct Elf32_SectionHeader), (uint8_t*) &stringSectionHdr))
   {
      // printf("Failed to read the header names section of the ELF\n");
      return std::map<uint32_t, std::string>();
   }

   int numSections = elfHeader.e_shnum;

   uint32_t nameDataLocation = stringSectionHdr.sh_offset;
   uint32_t nameDataSize     = stringSectionHdr.sh_size;

   char* nameData = new char[stringSectionHdr.sh_size];
   uint32_t strIndexOffset = 0;
   readFile(f, nameDataLocation, nameDataSize, (uint8_t*) nameData);

   // printf("Going to read section strings at 0x%08x\n", nameDataLocation);

   std::map<uint32_t, std::string> sectionNames;
   for(int i = 0; i < numSections; i++)
   {
      std::string secName(nameData + strIndexOffset);
      sectionNames[strIndexOffset]=secName;
      strIndexOffset += secName.length() + 1;

      //printf("Just added section name %s to the list of sections\n", secName.c_str());
   }

   delete[] nameData;
   return sectionNames;
}

void printSectionInfo(FILE* f,
                       struct Elf32_Ehdr const & elfHeader,
                       int i,
                       std::map<uint32_t, std::string> const & sectionNames)
{
   if (i > elfHeader.e_shnum)
   {
      printf("Section number %d is invalid for this ELF\n", i);
      return;
   }

   if (sizeof(struct Elf32_SectionHeader) != elfHeader.e_shentsize)
   {
      if (sizeof(struct Elf32_SectionHeader) < elfHeader.e_shentsize)
      {
         printf("Error: Size of section header (%d bytes) is smaller than the struct we need to load it into (%zu bytes)!",
                elfHeader.e_shentsize, sizeof(struct Elf32_SectionHeader));
         return;
      }

      printf("Size of section header (%d bytes) is different than the struct we need to load it into (%zu bytes)!",
             elfHeader.e_shentsize, sizeof(struct Elf32_SectionHeader));
   }

   struct Elf32_SectionHeader sectionData;

   if (!readFile(f,
                 elfHeader.e_shoff + i * elfHeader.e_shentsize,
                 sizeof(struct Elf32_SectionHeader),
                 (uint8_t*) &sectionData))
   {
      printf("Error reading section %d header\n", i);
   }

   std::string secName;
   if (sectionNames.find(sectionData.sh_name) != sectionNames.end())
   {
      secName = sectionNames.at(sectionData.sh_name);
   }


   // Section, Name, VMA, Size, Offset
   printf("%2d %20s  0x%08x  0x%08x  0x%08x\n",
          i,
          secName.c_str(),
          sectionData.sh_addr,
          sectionData.sh_size,
          sectionData.sh_offset);

}

void printElfInfo(FILE* f)
{
   struct Elf32_Ehdr elfHeader;

   if (!readElfHeader(f, &elfHeader))
   {
      printf("Not an ELF\n");
      return;
   }

   std::map<int, char const *> elfTypeMap;
   elfTypeMap[0] = "None";
   elfTypeMap[1] = "Relocatable File";
   elfTypeMap[2] = "Executable File";
   elfTypeMap[3] = "Shared Object File";
   elfTypeMap[4] = "Core File";
   if (elfTypeMap.find(elfHeader.e_type) != elfTypeMap.end())
   {
      printf("ELF Type = %s\n", elfTypeMap[elfHeader.e_type]);
   }
   else
   {
      printf("ELF Type = Unknown\n");
   }

   std::map<int, char const *> machineMap;
   machineMap[3]   = "Intel 386";
   machineMap[20]  = "PowerPC";
   machineMap[21]  = "PowerPC 64";
   machineMap[40]  = "ARM";
   machineMap[42]  = "Hitachi SH";
   machineMap[50]  = "Intel IA-64";
   machineMap[62]  = "AMD x86-64";
   machineMap[83]  = "Atmel AVR";
   machineMap[105] = "TI MSP 430";
   machineMap[183] = "ARM AArch64";
   machineMap[190] = "NVidia CUDA";

   if (machineMap.find(elfHeader.e_machine) == machineMap.end())
   {
      printf("Unknown Machine Type (%d)\n", elfHeader.e_machine);
   }
   else
   {
      printf("Machine Type = %s\n", machineMap[elfHeader.e_machine]);
   }

   if (elfHeader.e_shnum <= 0)
   {
      printf("There are no sections in this elf file\n");
      return;
   }

   //printf("Section Strings = 0x%08x\n", elfHeader.e_shstrndx);

   std::map<uint32_t, std::string> secNames = getSectionNames(f, elfHeader);

   // Section, Name, VMA, Size, Offset
   printf("Sec# %18s    VirtAddr        Size  FileOffset\n",
          "Section Name");
   for(int i = 0; i < elfHeader.e_shnum; i++)
   {
      printSectionInfo(f, elfHeader, i, secNames);
   }
}

bool readElfHeader(FILE* f, struct Elf32_Ehdr* header)
{
   struct Elf32_Ehdr elfHeader;

   if (!readFile(f, 0, sizeof(struct Elf32_Ehdr), (uint8_t*) header))
   {
      printf("Failed to read ELF header.  File to small?\n");
      return false;
   }

   // Verify the ELF
   if ( header->e_ident[0] == 0x7f &&
        header->e_ident[1] == 'E' &&
        header->e_ident[2] == 'L' &&
        header->e_ident[3] == 'F')
   {
      return true;
   }
   else
   {
      printf("ELF Header magic string invalid\n");
      return false;
   }
}

bool findFileOffset(uint32_t vma,
                    FILE* f,
                    uint32_t* fileOffset)
{
   struct Elf32_Ehdr elfHeader;

   if (!readElfHeader(f, &elfHeader))
   {
      printf("Aborting, not an ELF\n");
      return 1;
   }

   uint32_t sectionHeaderOffset = elfHeader.e_shoff;
   for(int i = 0; i < elfHeader.e_shnum; i++)
   {
      struct Elf32_SectionHeader sec;
      if(!readFile(f, sectionHeaderOffset, sizeof(struct Elf32_SectionHeader), (uint8_t*) &sec))
      {
         printf("Failed attempting to read section header %d\n", i);
         return false;
      }

      uint32_t endVmaOfSection = sec.sh_addr + sec.sh_size;
      if ((vma >= sec.sh_addr) && (vma <= endVmaOfSection))
      {
         // This is the section the virtual memory address points to
         uint32_t sectionOffset = vma - sec.sh_addr;
         *fileOffset = sec.sh_offset + sectionOffset;
         return true;
      }

      sectionHeaderOffset += elfHeader.e_shentsize;
   }

   printf("No sections contain the VMA 0x%08x\n", vma);
   return false;
}

int main(int argc, char** argv)
{
   if (argc != 5)
   {
      printf("Usage: %s elf_file VMA_Start NumBytes PatchBytesHex\n", argv[0]);
      printf(" All bytes after the patch will be NOPed until NumBytes reached\n");
      return 1;
   }

   char const * filenameArg   = argv[1];
   char const * vmaAddressArg = argv[2];
   char const * numBytesArg   = argv[3];
   char const * patchBytesArg = argv[4];

   FILE* fileToPatch = fopen(filenameArg, "r+");

   if (fileToPatch == NULL)
   {
      printf("Couldn't open file %s to patch it\n", argv[1]);
      return 1;
   }

   struct Elf32_Ehdr elfHeader;

   if (!readElfHeader(fileToPatch, &elfHeader))
   {
      printf("Aborting, not an ELF\n");
      return 1;
   }

   printElfInfo(fileToPatch);

   /* // ELF Header Debug
   printf("Type                             = 0x%08x\n", elfHeader.e_type);
   printf("Machine                          = 0x%08x\n", elfHeader.e_machine);
   printf("Version                          = 0x%08x\n", elfHeader.e_version);
   printf("Entry                            = 0x%08x\n", elfHeader.e_entry);
   printf("Program Header Offset            = 0x%08x\n", elfHeader.e_phoff);
   printf("Section Header Offset            = 0x%08x\n", elfHeader.e_shoff);
   printf("Flags                            = 0x%08x\n", elfHeader.e_flags);
   printf("ELF Header Size                  = 0x%08x\n", elfHeader.e_ehsize);
   printf("Program Header Table Entry Size  = 0x%08x\n", elfHeader.e_phentsize);
   printf("Number of ProgHdr Table Entries  = 0x%08x\n", elfHeader.e_phnum);
   printf("Section Header Size              = 0x%08x\n", elfHeader.e_shentsize);
   printf("Number of Section Header Entries = 0x%08x\n", elfHeader.e_shnum);
   printf("String Index                     = 0x%08x\n", elfHeader.e_shstrndx);
   */

   uint32_t startAddress;
   if (vmaAddressArg[0] == '0' && vmaAddressArg[1] == 'x')
   {
      // Address is in hexadecimal
      startAddress = strtoul(vmaAddressArg, NULL, 16);
   }
   else
   {
      startAddress = strtoul(vmaAddressArg, NULL, 10);
   }

   uint32_t patchFileOffset = 0;
   if (!findFileOffset(startAddress, fileToPatch, &patchFileOffset))
   {
      printf("Couldn't find valid section / file offset for VMA 0x%08x\n", startAddress);
      return 1;
   }

   printf("Virtual Address 0x%08x is at file offset 0x%08x\n", startAddress, patchFileOffset);

   uint32_t numBytes;
   if (numBytesArg[0] == '0' && numBytesArg[1] == 'x')
   {
      // Number of bytes is in hexadecimal
      numBytes = strtoul(numBytesArg, NULL, 16);
   }
   else
   {
      numBytes = strtoul(numBytesArg, NULL, 10);
   }

   if (strlen(patchBytesArg) % 2 != 0)
   {
      printf("Patch bytes must be an even number of hexadecimal characters\n");
      return 1;
   }

   uint8_t* patchData = new uint8_t[numBytes];
   for(int i = 0; i < numBytes; i++)
   {
      // NOP the entire buffer
      patchData[i] = 0x90;
   }

   for(int i = 0; i < strlen(patchBytesArg) - 1; i += 2)
   {
      char hexCode[3];
      hexCode[0] = patchBytesArg[i];
      hexCode[1] = patchBytesArg[i+1];
      hexCode[2] = 0;

      patchData[i/2] = strtoul(hexCode, 0, 16);
   }

   printf("Patching!\n");
   if (!writeFile(fileToPatch , patchFileOffset, numBytes, patchData))
   {
      printf("Error while writing the patch data into the file\n");
      return 1;
   }

   printf("Patch Success\n");
   fclose(fileToPatch);

   return 0;
}

bool readFile(FILE* f,
              uint32_t offset,
              uint32_t length,
              uint8_t* buffer)
{
   if (0 != fseek(f, offset, SEEK_SET))
   {
      printf("Error seeking in the file to offset 0x%08x\n", offset);
      return false;
   }

   if ( 1 != fread(buffer, length, 1, f))
   {
      printf("Error reading data into file.  Offset=0x%08x, Length=%d\n", offset, length);
      return false;
   }

   return true;
}

bool writeFile(FILE* f,
               uint32_t offset,
               uint32_t length,
               uint8_t* buffer)
{
   if (fseek(f, offset, SEEK_SET))
   {
      printf("Seek failure!\n");
      return false;
   }

   if (1 != fwrite(buffer, length, 1, f))
   {
      printf("Error calling fwrite! (%s)\n", strerror(errno));
      return false;
   }

   return true;
}

std::string readSectionName(FILE* f,
                            struct Elf32_Ehdr const & elfHeader,
                            int i)
{
   if (0 != fseek(f, elfHeader.e_shstrndx + i, SEEK_SET))
   {
      printf("Error seeking in the file to offset 0x%08x (string index)\n", elfHeader.e_shstrndx);
      return "";
   }

   std::string retVal;
   char data = ' ';
   while(data != 0)
   {
      if (1 != fread(&data, 1, 1, f))
      {
         printf("Error reading section name for section index %d\n", i);
         return retVal;
      }

      if (data != 0)
         retVal += (char) data;
   }

   return retVal;
}


