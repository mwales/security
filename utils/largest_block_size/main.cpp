#include<iostream>
#include<stdio.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<vector>
#include<map>
#include<stdint.h>

int main(int argc, char** argv)
{
   if (!argc)
   {
      std::cout << "Usage: " << argv[0] << " file1 file2 file3 ..." << std::endl;
      return 1;
   }

   std::vector<uint64_t> filesizes;
   for(int i = 1; i < argc; i++)
   {
      struct stat fileInfo;
      if (stat(argv[i], &fileInfo))
      {
         std::cerr << "Couldn't open file: " << argv[i] << std::endl;
         continue;
      }

      std::cout << "Analyzing " << argv[i] << " size " << fileInfo.st_size << " byte(s)" << std::endl;
      filesizes.push_back(fileInfo.st_size);
   }

   int gcd = 1;
   for(int i = 2; i < 4096; i++)
   {
      bool success = true;
      for(uint64_t singleSize: filesizes)
      {
         if ( (singleSize % i) != 0)
         {
            success = false;
            break;
         }
      }

      if (success)
      {
         std::cout << i << " is a common divisor" << std::endl;
         gcd = i;
      }

   }

   std::cout << "Greatest common divisor: " << gcd << std::endl;
}
