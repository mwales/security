#include<iostream>
#include<vector>
#include<map>
#include<stdint.h>
#include<stdlib.h>


/**

# To build and run the OTP solution:

```
g++ --std=c++11 otp.cpp -o otp
cat otp_key.txt otp_msg.txt | ./otp
```

# Input Data

This program processes hexadecimal text data, not raw binary (that is what the data format for the
CTF was.

The first line of data to provide to the program is a key (can be 0's at first)
All the lines following are considered ciphertext

# What does the program do?

It first uses the provided key to try to decrypt the ciphertext, and it prints out the ASCII
plaintext for the user

It then tries to derive what it thinks the key is.  It determines what the each byte of the key is
based on XOR-ing two cipher text messages together.  If there are spaces at that position, it can
use that to determine what the key byte is for the data.  Non alphabetic characters sort of mess
this process up

It then tries to decrypte the ciphertext completely using the key it derived

# How do you really use this?

Create a dummy key

```
echo "0000" > dumb_key.txt
cat dumb_key.txt otp_msg.txt | ./otp
```

The program will then generate a derived key.  But it may have positions in the key that are
incorrectly deduced.  Copy this dereived key to key.txt.  Use your brain to fix the key by
recognizing the correct text and updating the key as necessary.

```
cat key.txt otp_msg.txt | ./otp
```

*/

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

void decryptData(std::vector<std::vector<uint8_t> > msgs, std::vector<uint8_t> key)
{
   for(auto singleMsg : msgs)
   {
      // Print out this CT xor-ed with the current prospective key
      std::vector<uint8_t> proposedPt = xorTwoMsgs(singleMsg, key);
      std::cout << ascii2Hex(proposedPt) << "    " << toAscii(proposedPt) << std::endl;
   }
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


      std::cout << "Ciphertext = " << nextLine << std::endl;

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

   std::cout << "********************************************************************************" << std::endl;
   std::cout << "* Decrypting with key provided                                                 *" << std::endl;
   std::cout << "********************************************************************************" << std::endl;

   std::cout << "Key (len = " << keyData.size() << ") = " << ascii2Hex(keyData)
             << "    " << toAscii(keyData) << std::endl << std::endl;

   decryptData(rawMsgs, keyData);

   std::cout << std::endl;
   std::cout << "********************************************************************************" << std::endl;
   std::cout << "* Decrypting with derived key                                                  *" << std::endl;
   std::cout << "********************************************************************************" << std::endl;


   // Try to determine the key
   std::vector<uint8_t> derivedKey;
   for(int i = 0; i < maxMessageLen; i++)
   {
      std::map<uint8_t, int> candidatesForEachMsg;
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

         uint8_t suggestedKeyValue = rawMsgs[msgA][i] ^ 0x20;

         if (candidatesForEachMsg.find(suggestedKeyValue) == candidatesForEachMsg.end())
         {
            // This is a new entry in the map
            candidatesForEachMsg[suggestedKeyValue] = candidateQty;
         }
         else
         {
            // This is already a suggested value, add to the existing entry
            candidatesForEachMsg[suggestedKeyValue] += candidateQty;
         }
      }

      // Now, lets find the best candidate, and any candidate to be considered must have 1/2 msgs or more
      uint8_t bestCandidate = 0;
      int bestCandidateQty = 0;
      for(auto prospect : candidatesForEachMsg)
      {
         if (prospect.second > bestCandidateQty)
         {
            bestCandidateQty = prospect.second;
            bestCandidate = prospect.first;
         }
      }

      if (bestCandidateQty > (rawMsgs.size() / 2) )
      {
         std::cout << "We think for pos " << i << " ct " << (int) bestCandidate << " is a space! ("
                   << bestCandidateQty << " matches)" << std::endl;
         derivedKey.push_back(bestCandidate);
      }
      else
      {
         // None may match at all, if then, add 00 into key
         std::cout << "We think for pos " << i << " there are no msgs with a space.  Best candidate = "
                   << bestCandidateQty << " matches" << std::endl;
         derivedKey.push_back(0);
      }
   }

   std::cout << std::endl << "Derived Key: " << ascii2Hex(derivedKey) << std::endl << std::endl;

   decryptData(rawMsgs, derivedKey);

   return 0;
}
