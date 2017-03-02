#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <iostream>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

std::string processLine;

void processSingleLine(char* singleLine, int outputFd)
{
   processLine += singleLine;

   std::cout << "In > " << singleLine << std::endl;

   while(processLine.find("Ogre") != std::string::npos)
   {
      processLine = processLine.replace(processLine.find("Ogre"), strlen("Ogre"), "BJ");
   }

   std::cout << "Out> " << processLine << std::endl;

   write(outputFd, processLine.data(), processLine.length());
   write(outputFd, "\n", 1);
   sync();

   processLine = "";
}


void parseFileData(char* buffer, int bytesRead, int outputFd)
{
   char* curLine = &buffer[0];
   for(int i = 0; i < bytesRead; i++)
   {
      if (buffer[i] == '\n')
      {
         buffer[i] = 0; // add null terminator
         processSingleLine(curLine, outputFd);

         curLine = &buffer[i+1];
      }
   }

   // Process trailing bytes
   if (curLine != &buffer[bytesRead])
   {
      processLine += curLine;
   }
}

int main(int argc, char** argv)
{
   if (argc != 2)
   {
      std::cerr << "This program fixes a log being written by another program" << std::endl;
      std::cerr << "Usage: " << argv[0] << " logfile.txt" << std::endl;
      return 1;
   }

   // Open the original log file
   int oldFd = open(argv[1], O_RDONLY);
   if (oldFd == -1)
   {
      std::cerr << "An error occurred opening the old file" << std::endl;
      return 2;
   }

   // Stat the old file to get the permissions
   struct stat oldFileInfo;
   if (-1 == fstat(oldFd, &oldFileInfo))
   {
      std::cerr << "Error getting the old file permission information from stat" << std::endl;
      close(oldFd);
      return 3;
   }

   // Unlink the original log file
   if (-1 == unlink(argv[1]))
   {
      std::cerr << "Error deleting the log file!" << std::endl;
      close(oldFd);
      return 4;
   }

   // Open the new log file
   int newFd = creat(argv[1], oldFileInfo.st_mode & 0777);
   if (newFd == -1)
   {
      std::cerr << "Error opening new file to replace it" << std::endl;
      close(oldFd);
      return 5;
   }

   const int BUF_SIZE=1024;
   char incomingBuf[BUF_SIZE];
   while(true)
   {
      int bytesRead = read(oldFd, incomingBuf, BUF_SIZE);

      if (bytesRead == 0)
      {
         std::cout << "Nothing more in the file" << std::endl;
         sleep(1);
      }
      else
      {
         parseFileData(incomingBuf, bytesRead, newFd);
      }

   }

   return 0;
}
