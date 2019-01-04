/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Adopted from ARM emulation sample code */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <unicorn/unicorn.h>
#include <string.h>


// code to be emulated
#define ARM_CODE "\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3
#define THUMB_CODE "\x83\xb0" // sub    sp, #0xc

// memory address where emulation starts
#define ADDRESS 0x10000

bool gInstructionTrace = false;

void dumpCpuRegisters(uc_engine* uc);






void hexDump(unsigned char const * const buffer, unsigned int bufferLen, bool asciiToo)
{
   char asciiDump[0x11];
   char const * const ASCII_BLANK = "                ";
   strcpy(asciiDump, ASCII_BLANK);

   unsigned int i;
   for(i = 0; i < bufferLen; i++)
   {
      if ( (i % 16) == 0)
      {
         printf("%04x ", i);
      }

      if ( (buffer[i] >= ' ') && (buffer[i] <= '~') )
      {
         // Printable in ASCII
         asciiDump[i % 16] = buffer[i];
      }
      else
      {
         // Not printable ASCII
         asciiDump[i % 16] = '.';
      }

      printf("%02x", buffer[i]);
      if (i % 16 == 15)
      {
         if (asciiToo)
         {
            printf("  |%s|\n", asciiDump);
            strcpy(asciiDump, ASCII_BLANK);
         }
         else
         {
            printf("\n");
         }
      }
      else if (i % 16 == 7)
      {
         printf("  ");
      }
      else
      {
         printf(" ");
      }
   }

   if (i % 16 != 0)
   {
      if (asciiToo)
      {
         // Need to print out padding before ascii
         for (int paddingByte = ( i % 16); paddingByte < 16; paddingByte++)
         {
            printf("   ");
         }

         if ((i % 16) < 8)
         {
            // There is an extra space between byte 8 and 9 that must be accounted for
            printf(" ");
         }

         printf(" |%s|\n", asciiDump);
         strcpy(asciiDump, ASCII_BLANK);
      }
      else
      {
         printf("\n");
      }
   }
}

typedef struct mapped_file_data
{
   off_t fileSize;
   uint64_t loadAddress;
   uint64_t mapFileOffset;
   uint64_t mapStartAddress;
   uint64_t mapSize;
   char* mapData;
} mapped_file_data;

void print_map_file_data(mapped_file_data mfd)
{
   printf("Mapped File Data:\n");

   printf("  file size = 0x%08lx = %ld\n", mfd.fileSize, mfd.fileSize);
   printf("  load addr = 0x%016llx\n", mfd.loadAddress);
   printf("  start off = 0x%016llx\n", mfd.mapFileOffset);
   printf("  map start = 0x%016llx\n", mfd.mapStartAddress);
   printf("  map size  = 0x%016llx\n", mfd.mapSize);

   //hexDump(mfd.mapData, mfd.mapSize, false);
}

mapped_file_data readFileIntoMallocBuffer(char* filename, uint64_t loadAddress)
{
   mapped_file_data retData;
   retData.loadAddress = loadAddress;

   int fd;
   fd = open(filename, 0);

   retData.fileSize = lseek(fd, 0, SEEK_END);
   lseek(fd, 0, SEEK_SET);

   const uint64_t MAP_START_MASK  = 0xfffffffffffff000;
   const uint64_t MAP_OFFSET_MASK = 0x0000000000000fff;

   retData.mapFileOffset = loadAddress & MAP_OFFSET_MASK;
   retData.mapStartAddress = loadAddress & MAP_START_MASK;

   retData.mapSize = retData.mapFileOffset + retData.fileSize;
   retData.mapSize |= MAP_OFFSET_MASK;
   retData.mapSize += 1;

   printf("Creating a buffer of size %lld bytes to hold contents of code file\n", retData.mapSize);
   retData.mapData = (char*) malloc(retData.mapSize);
   memset(retData.mapData, 0, retData.mapSize);

   int bytesRead = 0;
   while(bytesRead < retData.fileSize)
   {
      int nbr = read(fd, retData.mapData + bytesRead + retData.mapFileOffset,
                     retData.fileSize - bytesRead);

      if (nbr <= 0)
      {
         printf("Error reading bytes from the file\n");
         free(retData.mapData);
         retData.mapData = NULL;
         return retData;
      }

      bytesRead += nbr;
   }

   print_map_file_data(retData);

   return retData;
}

typedef void (*native_function_call)(uc_engine* uc, uint64_t address);

typedef struct function_patch_entry
{
   uint64_t functionAddr;
   native_function_call functionPtr;
} function_patch_entry;

#define MAX_PATCHES 255
function_patch_entry patchList[MAX_PATCHES];
int num_patches = 0;
const uint16_t NOP_THUMB_MODE = 0x46c0;

void patch_address_with_native_function(uc_engine* uc, uint64_t address,
                                        native_function_call f, int bytesToNop)
{
   if (num_patches == 0)
   {
      // Zero the patch list
      memset(&patchList, 0, sizeof(function_patch_entry) * MAX_PATCHES);
   }

   if (num_patches == MAX_PATCHES)
   {
      printf("Too many patches, try compiling with higher MAX_PATCHES\n");
      return;
   }

   if ( (bytesToNop % 2) == 1)
   {
      printf("bytesToNop must be even number for ARM THUMB NOP 0x46c0\n");
      return;
   }

   for(int i = 0; i < bytesToNop; i+=2)
   {
      uint16_t memoryToPatch;
      uc_err err = uc_mem_read(uc, address + i, &memoryToPatch, 2);
      if (err != UC_ERR_OK)
      {
         printf("Error reading address 0x%016llx during patch\n", address + i);
         return;
      }

      printf("Patching address 0x%016llx:  0x%04x -> 0x%04x\n", address + i,
             memoryToPatch, NOP_THUMB_MODE);
      memoryToPatch = NOP_THUMB_MODE;

      err = uc_mem_write(uc, address + i, &memoryToPatch, 2);
      if (err != UC_ERR_OK)
      {
         printf("Error writing NOP to address 0x%016llx during patching\n", address + i);
         return;
      }

   }

   // Add entry to our patch list
   patchList[num_patches].functionAddr = address;
   patchList[num_patches].functionPtr = f;
   num_patches++;
}

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    if (size == 2)
    {
       // Add hex dump code
       uint16_t val16;
       uc_mem_read(uc, address, &val16, sizeof(uint16_t));

       printf(">>>> 0x%04x\n", val16);

       // Check for patches
       if (val16 == NOP_THUMB_MODE)
       {
          // This is a NOP instruction, might be a patch!
          for(int i = 0; i < num_patches; i++)
          {
             if (address == patchList[i].functionAddr)
             {
                printf("Calling a native patch function\n");
                (patchList[i].functionPtr)(uc, address);
             }
          }
       }
    }

    if (size == 4)
    {
       // Add hex dump code
       uint32_t val32;
       uc_mem_read(uc, address, &val32, sizeof(uint32_t));

       printf(">>>> 0x%08x\n", val32);
    }

    if (gInstructionTrace)
    {
       dumpCpuRegisters(uc);
    }

//    char* fart = (char*) malloc(0x1000);
//    uc_mem_read(uc, 0x1000, fart, 0x1000);
//    hexDump(fart, 0x1000, false);
//    free(fart);
}

void unmapped_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
   printf("Unmapped hook.  address = 0x%016llx, size = 0x%x\n", address, size);
}

char* uc_mem_type_to_string(uc_mem_type x)
{
   switch(x)
   {
      case UC_MEM_READ:
         return "UC_MEM_READ";
      case UC_MEM_WRITE:
         return "UC_MEM_WRITE";
      case UC_MEM_FETCH:
         return "UC_MEM_FETCH";
      case UC_MEM_READ_UNMAPPED:
         return "UC_MEM_READ_UNMAPPED";
      case UC_MEM_WRITE_UNMAPPED:
         return "UC_MEM_UNMAPPED";
      case UC_MEM_FETCH_UNMAPPED:
         return "UC_MEM_FETCH_UNMAPPED";
      case UC_MEM_WRITE_PROT:
         return "UC_MEM_WRITE_PROT";
      case UC_MEM_READ_PROT:
         return "UC_MEM_READ_PROT";
      case UC_MEM_FETCH_PROT:
         return "UC_MEM_FETCH_PROT";
      case UC_MEM_READ_AFTER:
         return "UC_MEM_READ_AFTER";
      default:
         return "UC_MEM_TYPE_UNKNONW";
   }
}

void memory_access_debugging(uc_engine *uc, uc_mem_type type,
                        uint64_t address, int size, int64_t value, void *user_data)
{
   printf("Memory access: Addr=0x%016llx, Size=%d, Value=%lld, Type=%s\n",
          address, size, value, uc_mem_type_to_string(type));
}

void dumpCpuRegisters(uc_engine* uc)
{
   int r0, r1, r2, r3, r4, r5, r6, r7, r8, r12, r13, r14, r15;
   uc_reg_read(uc, UC_ARM_REG_R0, &r0);
   uc_reg_read(uc, UC_ARM_REG_R1, &r1);
   uc_reg_read(uc, UC_ARM_REG_R2, &r2);
   uc_reg_read(uc, UC_ARM_REG_R3, &r3);
   uc_reg_read(uc, UC_ARM_REG_R4, &r4);
   uc_reg_read(uc, UC_ARM_REG_R5, &r5);
   uc_reg_read(uc, UC_ARM_REG_R6, &r6);
   uc_reg_read(uc, UC_ARM_REG_R7, &r7);
   uc_reg_read(uc, UC_ARM_REG_R8, &r8);

   uc_reg_read(uc, UC_ARM_REG_R12, &r12);
   uc_reg_read(uc, UC_ARM_REG_R13, &r13);
   uc_reg_read(uc, UC_ARM_REG_R14, &r14);
   uc_reg_read(uc, UC_ARM_REG_R15, &r15);

   printf(" R0 = 0x%08x = %8d", r0, r0);
   printf(" R1 = 0x%08x = %8d\n", r1, r1);
   printf(" R2 = 0x%08x = %8d", r2, r2);
   printf(" R3 = 0x%08x = %8d\n", r3, r3);
   printf(" R4 = 0x%08x = %8d", r4, r4);
   printf(" R5 = 0x%08x = %8d\n", r5, r5);
   printf(" R6 = 0x%08x = %8d", r6, r6);
   printf(" R7 = 0x%08x = %8d\n", r7, r7);
   printf(" R8 = 0x%08x = %8d\n", r8, r8);
   printf(" R12 = 0x%08x = %8d", r12, r12);
   printf(" R13 = 0x%08x = %8d\n", r13, r13);
   printf(" R14 = 0x%08x = %8d", r14, r14);
   printf(" R15 = 0x%08x = %8d\n", r15, r15);

}






void native_strcat(uc_engine* uc, uint64_t address)
{
   printf("Call native strcat here!\n");
}

void native_realpath(uc_engine* uc, uint64_t address)
{
   printf("Call native realpath here!\n");

   gInstructionTrace = true;

   dumpCpuRegisters(uc);

   // char *realpath(const char *path, char *resolved_path);

   // Need the path passed in via r0
   uint32_t r0stringAddress;

   uc_reg_read(uc, UC_ARM_REG_R0, &r0stringAddress);
   printf("  r0 = 0x%08x\n", r0stringAddress);

   char smallBuffer[1024];
   uc_mem_read(uc, r0stringAddress, smallBuffer, 1024);

   printf("  r0 str before = %s\n", smallBuffer);

   uint32_t r1resolvePath;
   uc_reg_read(uc, UC_ARM_REG_R1, &r1resolvePath);

   if (r1resolvePath == 0)
   {
      printf("Emulation doens't support the NULL parameter!  WTF\n");
      return;
   }

   char resolvePath[4096];
   char* retVal = realpath(smallBuffer, resolvePath);

   if (retVal == NULL)
   {
      printf("realpath returned NULL\n");
      r0stringAddress = 0;
      uc_reg_write(uc, UC_ARM_REG_R0, &r0stringAddress);
   }
   else
   {
      printf("realpath returned: %s\n", resolvePath);
      int resolvePathLen = strlen(resolvePath);
      uc_mem_write(uc, r1resolvePath, resolvePath, resolvePathLen + 1);

      // Would return resolve path normall (copies r1 to r0)
      uc_reg_write(uc, UC_ARM_REG_R0, &r1resolvePath);
   }

   dumpCpuRegisters(uc);
}



void native_strstr(uc_engine* uc, uint64_t address)
{
   printf("Call native strstr here! 0x%016llx\n", address);

   dumpCpuRegisters(uc);

   uint32_t r0haystack, r1needle;
   char r0haystackString[1024];
   char r1needleString[1024];

   uc_err err;
   err = uc_reg_read(uc, UC_ARM_REG_R0, &r0haystack);
   if (err != UC_ERR_OK)
   {
      printf("  Error reading r0\n");
      return;
   }

   err = uc_reg_read(uc, UC_ARM_REG_R1, &r1needle);
   if (err != UC_ERR_OK)
   {
      printf("  Error reading r1\n");
      return;
   }

   err = uc_mem_read(uc, r0haystack, r0haystackString, 128);
   if (err != UC_ERR_OK)
   {
      printf("Failure to read haystack string (%s)\n", uc_strerror(err));
      return;
   }

   err = uc_mem_read(uc, r1needle, r1needleString, 128);
   if (err != UC_ERR_OK)
   {
      printf("Failure to read needle string (%s)\n", uc_strerror(err));
      return;
   }

   printf("  r0 haystack = %s\n", r0haystackString);
   printf("  r1 needle = %s\n", r1needleString);

   char* result = strstr(r0haystackString, r1needleString);

   if (result == NULL)
   {
      printf("  strstr returned NULL\n");
      r0haystack = 0;
   }
   else
   {
      printf("  strstr returned %s\n", result);
      r0haystack += (result - r0haystackString);
   }

   uc_reg_write(uc, UC_ARM_REG_R0, &r0haystack);

   dumpCpuRegisters(uc);
}

void native_strcpy(uc_engine* uc, uint64_t address)
{
   printf("Call native strcpy here! 0x%016llx\n", address);

   dumpCpuRegisters(uc);

   uint32_t r0dest, r1src;
   char r0destString[1024];
   char r1srcString[1024];

   uc_err err;
   err = uc_reg_read(uc, UC_ARM_REG_R0, &r0dest);
   if (err != UC_ERR_OK)
   {
      printf("  Error reading r0\n");
      return;
   }

   err = uc_reg_read(uc, UC_ARM_REG_R1, &r1src);
   if (err != UC_ERR_OK)
   {
      printf("  Error reading r1\n");
      return;
   }

   err = uc_mem_read(uc, r0dest, r0destString, 128);
   if (err != UC_ERR_OK)
   {
      printf("Failure to read dest string (%s)\n", uc_strerror(err));
      return;
   }

   err = uc_mem_read(uc, r1src, r1srcString, 128);
   if (err != UC_ERR_OK)
   {
      printf("Failure to read src string (%s)\n", uc_strerror(err));
      return;
   }

   printf("  r0 dest = %s\n", r0destString);
   printf("  r1 src = %s\n", r1srcString);

   int srcLength = strlen(r1srcString);

   err = uc_mem_write(uc, r0dest, r1srcString, srcLength+1);
   if (err != UC_ERR_OK)
   {
      printf("Error copying bytes for the strcpy implementation\n");
   }
}

void stop_emulator_pop(uc_engine* uc, uint64_t address)
{
   printf("\n\n\n\nWe hit the pop instruction\n");

   uint32_t r0;
   char buf[256];

   uc_reg_read(uc, UC_ARM_REG_R0, &r0);
   uc_mem_read(uc, r0, buf, 256);

   printf("r0 = %s\n", buf);


   uc_emu_stop(uc);
}


#define CHECK_FOR_UC_ERRORS(err, subsystem) if (err == UC_ERR_OK) \
   printf("%s was successful\n", subsystem); \
   else { \
   printf("%s was unsuccessful (%s)\n", subsystem, uc_strerror(err)); \
   return; }

static void test_arm(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2, hook1, hook2;

    int r0 = 0x00010000;     // R0 register / same as stack addr

    printf("Emulate ARM code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    CHECK_FOR_UC_ERRORS(err, "Unicorn Open");

    mapped_file_data mfd = readFileIntoMallocBuffer("sub_1C78_0x1c78L_0x1d06L", 0x1c78);

    // map memory for this emulation
    const uint32_t CODE_START_ADDRESS = 0x1c78;
    err = uc_mem_map_ptr(uc, mfd.mapStartAddress, mfd.mapSize, UC_PROT_NONE, mfd.mapData);
    CHECK_FOR_UC_ERRORS(err, "Code Memory Mapping");

    mapped_file_data dataSection = readFileIntoMallocBuffer("data_0x7ec4_0x8000", 0x7ec4);
    err = uc_mem_map_ptr(uc, dataSection.mapStartAddress, dataSection.mapSize, UC_PROT_NONE,
                         dataSection.mapData);
    CHECK_FOR_UC_ERRORS(err, "Data Section Mapping");

    mapped_file_data externSection = readFileIntoMallocBuffer("extern_0xc2fc_0xc424", 0xc2fc);
    err = uc_mem_map_ptr(uc, externSection.mapStartAddress, externSection.mapSize, UC_PROT_NONE,
                         externSection.mapData);
    CHECK_FOR_UC_ERRORS(err, "Extern Section Mapping");

    mapped_file_data roDataSection = readFileIntoMallocBuffer("rodata_0x5400_0x5f0c", 0x5400);
    err = uc_mem_map_ptr(uc, roDataSection.mapStartAddress, roDataSection.mapSize, UC_PROT_NONE,
                         roDataSection.mapData);
    CHECK_FOR_UC_ERRORS(err, "RO Data Section Mapping");

    // Create some stack memory
    const uint64_t STACK_ADDR = 0x00010000;
    int r13Sp = STACK_ADDR + 512 * 1024;     // sp register

    const int STACK_SIZE = 1024 * 1024;
    err = uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_NONE);
    CHECK_FOR_UC_ERRORS(err, "Stack Memory Mapping");


    // Patch in native calls
    patch_address_with_native_function(uc, 0x1cb6, native_strcat, 4);
    patch_address_with_native_function(uc, 0x1cc4, native_realpath, 4);
    patch_address_with_native_function(uc, 0x1ccc, native_strstr, 4);
    patch_address_with_native_function(uc, 0x1cf2, native_strcpy, 4);

    patch_address_with_native_function(uc, 0x1d04, stop_emulator_pop, 2);




    // Put some data ont the stack
    char* stackData = "/data/dji/log/fart/../poop/../../secret";
    err = uc_mem_write(uc, STACK_ADDR, stackData, strlen(stackData) + 1);
    CHECK_FOR_UC_ERRORS(err, "Writing Stack Memory");

    // initialize machine registers
    err = uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    CHECK_FOR_UC_ERRORS(err, "Setting r0");

    err = uc_reg_write(uc, UC_ARM_REG_R13, &r13Sp);
    CHECK_FOR_UC_ERRORS(err, "Setting r13 / stack pointer");

    // tracing all basic blocks with customized callback
    err = uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
    CHECK_FOR_UC_ERRORS(err, "Hook Block Setup");


    // tracing one instruction at ADDRESS with customized callback
    err = uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);
    CHECK_FOR_UC_ERRORS(err, "Hook Code Setup");

    err = uc_hook_add(uc, &hook1, UC_HOOK_MEM_UNMAPPED, unmapped_hook, NULL, 1, 0);
    CHECK_FOR_UC_ERRORS(err, "Mem Unmapped Hook Setup");


    err = uc_hook_add(uc, &hook2, UC_HOOK_MEM_VALID + UC_HOOK_MEM_INVALID,
                      memory_access_debugging, NULL, 1, 0);
    CHECK_FOR_UC_ERRORS(err, "Memory Access Hook Setup");


    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.  Add 1 to the start address to emulate in THUMB mode
    err = uc_emu_start(uc, CODE_START_ADDRESS | 1, CODE_START_ADDRESS + mfd.fileSize -1, 0, 0);
    //CHECK_FOR_UC_ERRORS(err, "Emulation Start");


    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    dumpCpuRegisters(uc);

    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    //uc_reg_read(uc, UC_ARM_REG_R1, &r1);
    printf(">>> R0 = 0x%x\n", r0);
    //printf(">>> R1 = 0x%x\n", r1);

    CHECK_FOR_UC_ERRORS(err, "Emulation Start");

    uc_close(uc);
}



int main(int argc, char **argv, char **envp)
{
    // dynamically load shared library
#ifdef DYNLOAD
    if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading shared library.\n");
        printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
        printf("any other dependent dll/so files.\n");
        printf("The easiest way is to place them in the same directory as this app.\n");
        return 1;
    }
#endif
    
    test_arm();
    //printf("==========================\n");
    //test_thumb();

    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
