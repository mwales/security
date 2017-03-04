#include<iostream>
#include<stdio.h>
#include<fcntl.h>
#include<sys/stat.h>
#include<stdint.h>
#include<sys/types.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>

int main(int argc, char** argv)
{
   if (argc != 4)
   {
      std::cerr << "Xors 2 files into a 3rd file" << std::endl;
      std::cerr << "Usage: " << argv[0] << "ct1 ct2 ptsXored" << std::endl;
      return 1;
   }

   int fd1 = open(argv[1], O_RDONLY);
   int fd2 = open(argv[2], O_RDONLY);

   if ( (fd1 <= 0) || (fd2 <= 0) )
   {
      std::cerr << "Error opening one of the 2 source files" << std::endl;
      return 2;
   }

   int fd3 = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0664);
   if (fd3 <= 0)
   {
      std::cerr << "Error opening file for writing" << std::endl;
      return 3;
   }

   // Seek to the end of of the files and determine how long they are
   int len1 = lseek(fd1, 0, SEEK_END);
   int len2 = lseek(fd2, 0, SEEK_END);

   if (len1 != len2)
   {
      std::cerr << "The two files need to be the same length" << std::endl;
      return 4;
   }

   lseek(fd1, 0, SEEK_SET);
   lseek(fd2, 0, SEEK_SET);

   uint8_t* buf1 = new uint8_t[len1];
   uint8_t* buf2 = new uint8_t[len1];

   int bytesRead = 0;
   while(bytesRead < len1)
   {
      bytesRead += read(fd1, &buf1[bytesRead], len1 - bytesRead);
      std::cout << "Bytes read so far from buf1 " << bytesRead << std::endl;
   }

   bytesRead = 0;
   while(bytesRead < len1)
   {
      bytesRead += read(fd2, &buf2[bytesRead], len1 - bytesRead);
      std::cout << "Bytes read so far from buf2 " << bytesRead << std::endl;
   }

   for(int i = 0x0; i < len1; i++)
   {
      buf1[i] = buf1[i] ^ buf2[i];
   }

   int bytesWritten = 0;
   while( (bytesWritten < len1) && (bytesWritten >= 0) )
   {
      bytesWritten += write(fd3, &buf1[bytesWritten], len1 - bytesWritten);
      std::cout << "Bytes written so far from buf1 " << bytesWritten << std::endl;
   }

   if (bytesWritten != len1)
   {
      std::cerr << "Error: " << strerror(errno) << std::endl;
   }

   return 0;
}



