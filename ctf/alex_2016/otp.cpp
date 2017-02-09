#include<iostream>
#include<vector>
#include<stdint.h>
#include<stdlib.h>


std::vector<uint8_t> hex2Ascii(std::string hexString)
{
   std::vector<uint8_t> retVal;

   for(int i = 0; i < hexString.length() - 1 ; i+=2)
   {
      char shortBuf[3];
      shortBuf[0] = hexString[i];
      shortBuf[1] = hexString[i+1];
      shortBuf[2] = 0;

      unsigned long val = strtoul(shortBuf, NULL, 16);

      //std::cout << "Val of " << shortBuf << " = " << val << std::endl;
      retVal.push_back(val);

   }

   //std::cout << __FUNCTION__ << " - exit" << std::endl;
   return retVal;
}

std::string ascii2Hex(std::vector<uint8_t> msgData)
{
   std::string retVal;
   char smallBuf[3];
   for(auto curByte : msgData)
   {
      snprintf(smallBuf, 3, "%02x", curByte);
      retVal += smallBuf;
      retVal += " ";
   }

   return retVal;
}

std::string toAscii(std::vector<uint8_t> msg)
{
   std::string retVal;
   for(auto curChar : msg)
   {
      if ( (curChar >= ' ') && (curChar <= '~') )
      {
         retVal += curChar;
      }
      else
      {
         retVal += ".";
      }
   }

   return retVal;
}

bool isValidKeyByte(uint8_t keyByte, int position, std::vector<uint8_t> ciphertext)
{
   const uint8_t PRINTABLE_ASCII_BEGIN = 0x20; // space character
   const uint8_t PRINTABLE_ASCII_END   = 0x7e; // tilde

   if (position >= ciphertext.size())
   {
      //std::cerr << "Checking for keyByte=" << keyByte << " at pos=" << position
      //          << " exceeds the lenth of CT " << ciphertext.size() << std::endl;
      return true;
   }

   uint8_t ctByte = ciphertext[position];
   uint8_t decodedByte = ctByte ^ keyByte;

   if ( (decodedByte < PRINTABLE_ASCII_BEGIN) || (decodedByte > PRINTABLE_ASCII_END) )
   {
      return false;
   }
   else
   {
      if (decodedByte == 0x20)
      {
         std::cout << "KeyByte=" << (int) keyByte << "creates a space in position " << position << std::endl;
      }
      return true;
   }
}

bool isValidKeyByteAllStrings(uint8_t keyByte, int position, std::vector<std::vector<uint8_t> > msgs)
{
   for(auto curMsg : msgs)
   {
      if (!isValidKeyByte(keyByte, position, curMsg))
      {
         return false;
      }
   }

   return true;
}

int minMsgLength(std::vector<uint8_t> const & msgA, std::vector<uint8_t> const & msgB)
{
   if (msgA.size() > msgB.size())
   {
      return msgB.size();
   }
   else
   {
      return msgA.size();
   }
}

bool areAllStringsPlainAscii(std::vector<std::vector<uint8_t> > msgs)
{
   // Since ASCII plaintext is 0-127, no high bits should be set for two XOR-ed ciphter texts
   for(auto curMsg : msgs)
   {
      // Now XOR it against every other CT
      for(auto otherMsg : msgs)
      {
         int lengthOfShortest = minMsgLength(curMsg, otherMsg);

         for(int i = 0; i < lengthOfShortest; i++)
         {
            uint8_t ctXor = curMsg[i] ^ otherMsg[i];

            if (ctXor & 0x80)
            {
               std::cout << "These aren't 2 ASCII messages!" << std::endl;
               return false;
            }
         }
      }
   }

   std::cout << "Verified all CTs are ASCII plaintext data" << std::endl;
   return true;
}

std::vector<uint8_t> xorTwoMsgs(std::vector<uint8_t> msgA, std::vector<uint8_t> msgB)
{
   int length = minMsgLength(msgA, msgB);

   std::vector<uint8_t> retVal;
   retVal.reserve(length);
   for(int i = 0; i < length; i++)
   {
      retVal.push_back(msgA[i] ^ msgB[i]);
   }

   return retVal;
}


int main()
{
   std::string keyLine;
   std::cin >> keyLine;

   std::vector<uint8_t> keyData = hex2Ascii(keyLine);

   std::vector<std::string> linesInHex;
   std::vector< std::vector<uint8_t> > rawMsgs;
   int maxMessageLen = 0;
   while(true)
   {
      std::string nextLine;
      std::cin >> nextLine;

      if (std::cin.eof())
      {
         break;
      }

      linesInHex.push_back(nextLine);

      rawMsgs.push_back(hex2Ascii(nextLine));


      std::cout << "Read in " << nextLine << std::endl;

      // OTP will have to be as long as the longest message
      if (nextLine.length() / 2 > maxMessageLen)
      {
         maxMessageLen = nextLine.length() / 2;
      }
   }

   if (!areAllStringsPlainAscii(rawMsgs))
   {
      return 1;
   }

   std::cout << "Max message len = " << maxMessageLen << std::endl;

   std::cout << "Key (len = " << keyData.size() << ") = " << ascii2Hex(keyData)
             << "    " << toAscii(keyData) << std::endl;

   for(int msgIndex = 0; msgIndex < rawMsgs.size(); msgIndex++)
   {
      for(int otherIndex = 0; otherIndex < rawMsgs.size(); otherIndex++)
      {
         if (otherIndex == msgIndex)
         {
            // don't xor the same msg with itself, that would be dumb
            continue;
         }

         // XOR 2 messages, print them out, then XOR that sequence with all spaces, and then print that out
         std::vector<uint8_t> plaintextsXored = xorTwoMsgs(rawMsgs[msgIndex], rawMsgs[otherIndex]);
         std::cout << msgIndex << "^" << otherIndex << "=     " << ascii2Hex(plaintextsXored)
                   << "   " << toAscii(plaintextsXored) << std::endl;

         // All space msg
         std::vector<uint8_t> allSpaces(minMsgLength(rawMsgs[msgIndex], rawMsgs[otherIndex]), 0x20);
         std::vector<uint8_t> ptsXorSpaces = xorTwoMsgs(allSpaces, plaintextsXored);
         std::cout << msgIndex << "^" << otherIndex << "^' ' =" << ascii2Hex(ptsXorSpaces)
                   << "   " << toAscii(ptsXorSpaces) << std::endl;
      }

      // Print out this CT xor-ed with the current prospective key
      std::vector<uint8_t> proposedPt = xorTwoMsgs(rawMsgs[msgIndex], keyData);
      std::cout << msgIndex << " PT " << ascii2Hex(proposedPt)
                << "    " << toAscii(proposedPt) << std::endl;

   }

   std::cout << "************************************************************" << std::endl;
   std::cout << "************************************************************" << std::endl << std::endl;

   std::vector<uint8_t> derivedKey;
   for(int msgIndex = 0; msgIndex < rawMsgs.size(); msgIndex++)
   {


      // Print out this CT xor-ed with the current prospective key
      std::vector<uint8_t> proposedPt = xorTwoMsgs(rawMsgs[msgIndex], keyData);
      std::cout << msgIndex << " PT " << ascii2Hex(proposedPt)
                << "    " << toAscii(proposedPt) << std::endl;

   }

   // Try to determine the key
   for(int i = 0; i < maxMessageLen; i++)
   {
      std::vector<int> candidatesForEachMsg;
      for(int msgA = 0; msgA < rawMsgs.size(); msgA++)
      {
         int candidateQty = 0;
         for(int msgB = 0; msgB < rawMsgs.size(); msgB++)
         {
            uint8_t val = rawMsgs[msgA][i] ^ rawMsgs[msgB][i];
            if ( (val >= 'A') && (val <= 'z') )
            {
               candidateQty++;
            }
         }

         candidatesForEachMsg.push_back(candidateQty);
      }

      // Now, if any msg has more than 1/2 the number of msgs as candidates, lets consider it a space!
      for(int msgCand = 0; msgCand < rawMsgs.size(); msgCand++)
      {
         if (candidatesForEachMsg[msgCand] > (rawMsgs.size() / 2) )
         {
            std::cout << "We think for pos " << i << " msg " << msgCand << " is a space!" << std::endl;
            derivedKey.push_back(rawMsgs[msgCand][i] ^ 0x20);
            msgCand = rawMsgs.size(); // terminate this loop
         }
      }

      // None may match at all, if then, add 00 into key
      if (derivedKey.size() == i)
      {
         std::cout << "We think for pos " << i << " there are no msgs with a space" << std::endl;
         derivedKey.push_back(0);
      }
   }

   std::cout << "Derived Key: " << ascii2Hex(derivedKey) << std::endl;

   return 0;
}
