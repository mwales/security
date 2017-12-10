#include<stdio.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<errno.h>

// This application reads a file into RAM, and then writes muck_0, muck_1, etc copies of it where
// each file has a single bit flipped.

// This was orginally written to solve a SECCON 2017 CTF Challenge.  A JPG image had a 1 bit change,
// if you fix the 1 bit change, you will see the flag.  I flipped the first 4000 bits or so, and
// didn't seem like I found any Jpegs that loaded into my viewer.  So failed at the CTF, but will
// keep this around as a really shitty fuzzer

void muckBit(uint8_t* buffer, int bit)
{
   const uint8_t muckBits[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

   uint8_t byteToMuck = bit / 8;
   buffer[byteToMuck] = buffer[byteToMuck] ^ muckBits[bit % 8];
}

bool writeFile(char* filename, char* buffer, int fileSize)
{

   printf("writeFile(%s) called\n", filename);

   int fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

   if (fd <= 0)
   {
      printf("Error writing file %s\n", filename);
      return false;
   }

   int numBytesWritten = 0;
   int bytesWrote = 0;
   while(numBytesWritten < fileSize)
   {
      bytesWrote = write(fd, buffer + numBytesWritten, fileSize - numBytesWritten);
      if (bytesWrote <= 0)
      {
         printf("Error writing the contents of the file %s at %d\n", filename, bytesWrote);
	 printf("  errno = %s\n", strerror(errno));
	 close(fd);
	 return false;
      }

      numBytesWritten += bytesWrote;
   }

   printf("Writing %s complete!\n", filename);
   return true;
}

int main(int argc, char** argv)
{
   if ( (argc != 3) && (argc != 4) )
   {
      printf("This application takes the input file and creates many copies of it with 1 bit flipped\n\n");
      printf("Usage: %s filename numBitsToChange [offset]\n", argv[0]);
      return 1;
   }

   int muckOffset = 0;
   if (argc == 4)
   {
      muckOffset = atoi(argv[3]);
      printf("Offset for mucking = %d\n", muckOffset);
   }

   int numBitsToChange = atoi(argv[2]);
   printf("Number bits to change = %d\n", numBitsToChange);

   int fd = open(argv[1], O_RDONLY);
   if (fd <= 0)
   {
      printf("Error opening file for reading\n");
      return 1;
   }

   int fileSize = lseek(fd, 0, SEEK_END);
   lseek(fd, 0, SEEK_SET);

   printf("Filesize = %d bytes\n", fileSize);

   char* fileContents = (char*) malloc(fileSize);

   if (fileContents == 0)
   {
      printf("Malloc failed\n");
      close(fd);
      return 1;
   }

   int numBytesRead = 0;
   int bytesRead = 0;
   while (numBytesRead < fileSize)
   {
      bytesRead = read(fd, fileContents + numBytesRead, fileSize - numBytesRead);

      if (bytesRead == 0)
      {
         printf("Error reading the contents of the file!\n");
	 close(fd);
	 return 1; 
      }

      numBytesRead += bytesRead;
   }

   close(fd);

   char const * fileExtension = strstr(argv[1], ".");
   if (fileExtension == NULL)
   {
      fileExtension = "";
   }
   printf("File extension: %s\n", fileExtension);

   for(int i = muckOffset; i < (numBitsToChange + muckOffset); i++)
   {
      muckBit((uint8_t*) fileContents, i);

      char nameBuffer[256];
      snprintf(nameBuffer, 256, "mucked_%d%s", i, fileExtension);

      bool success = writeFile(nameBuffer, fileContents, fileSize);
      if (!success)
      {
         printf("Error writing bit %d in file %s\n", i, nameBuffer);
	 break;
      }

      muckBit((uint8_t*) fileContents, i);
   }
     
   printf("Done\n");

   return 0;
}



