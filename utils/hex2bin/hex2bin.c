#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <stdlib.h>

int isValidChar(char x)
{
   if ( (x >= '0') && (x <= '9'))
      return 1;


   if ( (x >= 'a') && (x <= 'z'))
      return 1;

   if ( (x >= 'A') && (x <= 'Z') )
      return 1;

   return 0;
}

void bin2hex(int inputFd)
{
   fprintf(stderr, "bin2hex mode, woot\n");

   int bytesRead = 1;
   char buf;
   int value = 0;
   int curOnesPos = 8;
   while(bytesRead)
   {
      bytesRead = read(inputFd, &buf, 1);
      if (bytesRead == 1)
      {

         fprintf(stderr, "Read a byte: %c\n", buf);

         if ( (buf == '1') || (buf == '0') )
         {

            if (buf == '1')
            {
                value |= curOnesPos;
            }

            curOnesPos >>= 1;

            fprintf(stderr, "Value = %d and curOnesPos = %d\n", value, curOnesPos);
         }

         if (curOnesPos == 0)
         {
            curOnesPos = 8;

            if (value <= 9)
            {
               printf("%d", value);
            }
            else
            {
               printf("%c", value - 10 + 'a');
            }

            value = 0;

         }
      }
   }

   printf("\n");
}

int main(int argc, char** argv)
{
   if (argc != 2)
   {
      // Print usage
      fprintf(stderr, "Usage: %s file_of_numbers.txt\n", argv[0]);
      fprintf(stderr, "Usage: %s -       # Reads numbers from stdin\n", argv[0]);
      return 0;
   }

   // stdin is 0
   int inputFd;

   if (strcmp(argv[1], "-") == 0)
   {
      // Read from stdin (fd 0)
      inputFd = 0;
   }
   else
   {
      inputFd = open(argv[1], 0);
      if (inputFd == -1)
      {
         fprintf(stderr, "Error opening file %s\n", argv[1]);
         return 1;
      }

      fprintf(stderr, "File opened successfully\n");
   }
   

   if (strstr(argv[0], "bin2hex"))
   {
      bin2hex(inputFd);
      return 0;
   }

   int bytesRead;
   int i = 0;
   char buf[3];
   buf[2] = 0;
   do
   {
      bytesRead = read(inputFd, buf + i, 1);
      if (bytesRead != 1)
         continue; // end of file

      //fprintf(stderr, "Read a char (%c), i = %d, buf = %s\n", *(buf+i), i, buf);

      if (isValidChar( *(buf + i)) )
      {
         i++;

         if (i == 2)
         {
            // We now have 2 characters, convert from hex to an ASCII character
            long int val = strtol(buf, 0, 16);
            //printf("Val = %ld\n", val);

            char val2 = val;

            //fprintf(stderr, "Outputting 1 byte\n");

            printf("%c", val2);

            i = 0;
         }
      }

   } while (bytesRead == 1);

   if (inputFd != 0)
   {
      // Must have been an actual file that was opened
      close(inputFd);
   }

   return 0;
}
