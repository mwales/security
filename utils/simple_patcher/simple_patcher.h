#ifndef SIMPLE_PATCHER_H
#define SIMPLE_PATCHER_H


#include <stdint.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>



#define EI_NIDENT 16

struct Elf32_Ehdr
{
   uint8_t   e_ident[EI_NIDENT];
   uint16_t  e_type;
   uint16_t  e_machine;
   uint32_t  e_version;
   uint32_t  e_entry;
   uint32_t  e_phoff;
   uint32_t  e_shoff;
   uint32_t  e_flags;
   uint16_t  e_ehsize;
   uint16_t  e_phentsize ;
   uint16_t  e_phnum;
   uint16_t  e_shentsize;
   uint16_t  e_shnum ;
   uint16_t  e_shstrndx;
};

struct Elf32_SectionHeader
{
   uint32_t sh_name;
   uint32_t sh_type;
   uint32_t sh_flags;
   uint32_t sh_addr;
   uint32_t sh_offset;
   uint32_t sh_size;
   uint32_t sh_link;
   uint32_t sh_info;
   uint32_t sh_addralign;
   uint32_t sh_entsize;
};


void printElfInfo(FILE* f);

void printSectionInfo(FILE* file,
                       struct Elf32_Ehdr const & elfHeader,
                       int i);

bool readFile(FILE* f,
              uint32_t offset,
              uint32_t length,
              uint8_t* buffer);

bool writeFile(FILE* f,
               uint32_t offset,
               uint32_t length,
               uint8_t* buffer);

std::string readSectionName(FILE* f,
                            struct Elf32_Ehdr const & elfHeader,
                            int i);

bool readElfHeader(FILE* f, struct Elf32_Ehdr* header);

bool findFileOffset(uint32_t vma,
                    FILE* f,
                    uint32_t* fileOffset);

/**
 * Returns a map of the section names.  The key to the map is the index that the other headers
 * use in their section headers (offset into the string index)
 *
 * @param f Elf file
 * @param elfHeader Elf header structure (already populated)
 * @return Map of section names
 */
std::map<uint32_t, std::string> getSectionNames(FILE* f,
                                         struct Elf32_Ehdr const & elfHeader);



#endif
