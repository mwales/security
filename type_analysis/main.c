#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char** argv)
{
   struct stat s;

   printf("Size of struct stat = %d\n", sizeof(struct stat));

   int baseAddr = (int) &s;
   int offset_st_ino = (int) &s.st_ino - baseAddr;
   printf("  Offset fo st_ino = %d\n", offset_st_ino);

   int offset_st_mode = (int) &s.st_mode - baseAddr;
   printf("  Offset of st_mode = %d\n", offset_st_mode);

   int offset_st_uid = (int) &s.st_uid - baseAddr;
   printf("  Offset of st_uid = %d\n", offset_st_uid);

   int offset_st_gid = (int) &s.st_gid - baseAddr;
   printf("  Offset of st_gid = %d\n", offset_st_gid);

   int offset_st_size = (int) &s.st_size - baseAddr;
   printf("  Offset of st_size = %d\n", offset_st_size);

   //int offset_st_attr = (int) &s.st_attr - baseAddr;
   //printf("  Offset of st_attr = %d\n", offset_st_attr);

   return 0;
}
