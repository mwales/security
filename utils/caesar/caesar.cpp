#include <iostream>
#include <fstream>
#include <vector>
#include <map>

/**
 * This tool I wrote to help me break caesar ciphers.  It does have a slight limitation in that it
 * will only work on a single case cipher, not upper and lower case translations.
 *
 * Call the program with no parameters to see usage
 *
 * g++ --std=c++11 -o caesar caesar.cpp
 */

std::vector<std::string> tokenizeCipherText(std::string const & ct)
{
   std::vector<std::string> tokenizedRetVal;
   std::string curString;
   for(auto const & singleChar : ct)
   {
      if ((singleChar >= 'a') && (singleChar <= 'z'))
      {
         curString += singleChar;
      }
      else
      {
         if (!curString.empty())
         {
            tokenizedRetVal.push_back(curString);
            curString = "";
         }
      }
   }

   if (!curString.empty())
   {
      tokenizedRetVal.push_back(curString);
      curString = "";
   }

   return tokenizedRetVal;

}

std::string decrypt(std::string const & ct, std::string const & key)
{
   std::string retVal;
   for(auto const & singleCt : ct)
   {
      if ( (singleCt >= 'a') && (singleCt <= 'z'))
      {
         retVal += key[singleCt - 'a' ];
      }
      else
      {
         retVal += singleCt;
      }
   }

   return retVal;
}

std::map<int, char> invertMap(std::vector<int> const & data)
{
   std::map<int, char> tableByFreq;
   char currentCharacter = 'a';
   for(auto const & curFreq : data)
   {
      tableByFreq[curFreq] = currentCharacter++;
   }

   return tableByFreq;
}

std::string createStarterKey(std::vector<int> const & dictFreqs,
                             std::vector<int> const & ctFreqs)
{
   std::map<int, char> inverseDict = invertMap(dictFreqs);
   std::map<int, char> inverseCt   = invertMap(ctFreqs);

   std::string dictByFreq;
   for(auto inverseDictIt = inverseDict.rbegin(); inverseDictIt != inverseDict.rend(); inverseDictIt++)
   {
      dictByFreq += inverseDictIt->second;
   }

   std::string ctByFreq;
   for(auto inverseCtIt = inverseCt.rbegin(); inverseCtIt != inverseCt.rend(); inverseCtIt++)
   {
      ctByFreq += inverseCtIt->second;
   }

   dictByFreq.insert(dictByFreq.end(), 26 - dictByFreq.length(), ' ');
   ctByFreq.insert(ctByFreq.end(), 26 - ctByFreq.length(), ' ');

   std::cout << "Dict: [" << dictByFreq << "]" << std::endl;
   std::cout << "  Ct: [" << ctByFreq   << "]" << std::endl;

   std::map<char, char> keyMap;
   for(int i = 0; i < 26; i++)
   {
      if (ctByFreq[i] != ' ')
      {
         keyMap[ctByFreq[i]] = dictByFreq[i];
      }
   }

   std::string retVal;
   for(char singleCtChar = 'a'; singleCtChar <= 'z'; singleCtChar++)
   {
      if (keyMap.find(singleCtChar) != keyMap.end())
      {
         retVal += keyMap[singleCtChar];
      }
      else
      {
         retVal += ' ';
      }
   }

   return retVal;

}

void updateLetterFrequency(std::string text, std::vector<int>& freqsByRef)
{
   if (freqsByRef.size() != 26)
   {
      std::cerr << "freqArray size of " << freqsByRef.size() << " is invalid" << std::endl;
      return;
   }

   for(auto singleChar : text)
   {
      if ( (singleChar >= 'a') && (singleChar <= 'z') )
      {
         // Valid letter
         int letterIndex = singleChar - 'a';
         freqsByRef[letterIndex] += 1;
      }
   }
}

std::string toLower(std::string orig)
{
   std::string retVal;
   for(auto singleChar : orig)
   {
      if ((singleChar >= 'A') && (singleChar <= 'Z'))
      {
         retVal += singleChar -'A' + 'a';
      }
      else
      {
         retVal += singleChar;
      }
   }

   return retVal;
}

std::string readCipherText(char* ctFilename)
{
   std::ifstream ctFile;
   ctFile.open(ctFilename);

   std::string completeCipherText;
   while(!ctFile.eof())
   {
      std::string lineOfText;
      std::getline(ctFile, lineOfText);

      std::cout << ">> " << lineOfText << std::endl;

      // Make the whole thing toLower
      completeCipherText += toLower(lineOfText);
      completeCipherText += "\n";
   }

   std::cout << "CT:" << std::endl << completeCipherText;

   ctFile.close();

   return completeCipherText;
}

std::string readKey(char* keyFile)
{
   std::ifstream fileHandle;
   fileHandle.open(keyFile);

   std::string key;
   std::getline(fileHandle, key);

   if (fileHandle.fail())
   {
      std::cerr << "Error reading data from the key file" << std::endl;
      return std::string(' ', 26);
   }

   fileHandle.close();

   if (key.size() != 26)
   {
      std::cerr << "Key: " << key << std::endl;
      std::cerr << "Key length of " << key.size() << " is invalid!" << std::endl;
      return std::string(' ', 26);
   }

   // Verify key sane
   std::vector<int> freqs(26, 0);
   updateLetterFrequency(key, freqs);

   for(auto singleFreq : freqs)
   {
      if ( (singleFreq != 0) && (singleFreq != 1))
      {
         std::cerr << "Multiples of character in key, key invalid" << std::endl;
         return std::string(' ', 26);
      }
   }

   std::cout << "Key: " << key << std::endl;
   return key;
}

void readDictionary(char* dictFile, std::vector<std::string> & dictionaryByRef)
{
   std::ifstream fileHandle;
   fileHandle.open(dictFile);

   while(!fileHandle.eof())
   {
      std::string lineOfText;
      std::getline(fileHandle, lineOfText);

      //std::cout << "Dict: " << lineOfText << std::endl;

      dictionaryByRef.push_back(lineOfText);
   }
}

void printFreqs(std::vector<int> const & freqs)
{
   for(int i = 0; i < 26; i++)
   {
      std::cout << (char)('a' + i) << "=" << freqs[i] << "\t";
      if (i % 5 == 4)
      {
         std::cout << std::endl;
      }
   }

   std::cout << std::endl;
}

void printInvFreqs(std::vector<int> const & freqs)
{
   int i = 0;
   std::map<int, char> invFreq = invertMap(freqs);
   std::cout << "Got here" << std::endl;

   for(auto curFreq = invFreq.rbegin(); curFreq != invFreq.rend(); curFreq++)
   {
      std::cout << curFreq->second << "\t" << curFreq->first << "\t";

      if (++i % 3 == 0)
      {
         std::cout << std::endl;
      }
   }

   std::cout << std::endl;
}

bool possibleMatch(std::string dictWord, std::string unknownWord)
{
   if (dictWord.length() != unknownWord.length())
      return false;

   for(int i = 0; i < dictWord.length(); i++)
   {
      if (unknownWord[i] == '_')
         continue;

      if (unknownWord[i] != dictWord[i])
         return false;
   }

   return true;
}

std::string getSuggestions(std::string singleToken, std::vector<std::string> const & dictionary)
{
   int unknown = 0;
   for(auto eachChar : singleToken)
   {
      if (eachChar == '_')
         unknown++;
   }

   if (unknown - 1 > singleToken.length() - unknown)
   {
      return "[no suggestions yet]";
   }

   bool first = true;
   std::string suggestions;
   for(auto const & dictWord : dictionary)
   {
      if (possibleMatch(dictWord, singleToken))
      {
         if (first)
         {
            first = false;
         }
         else
         {
            suggestions += ", ";
         }

         suggestions += dictWord;
      }
   }

   return suggestions;
}

int main(int argc, char** argv)
{
   if (argc != 4)
   {
      std::cout << "Usage: " << argv[0] << " ciphertext keyfile dictionary" << std::endl;
      std::cout << "  ciphertext = file of caesar ciphertext" << std::endl;
      std::cout << "  keyfile = file with 26 lowercase characters or spaces of the known values" << std::endl;
      std::cout << "  dictionary = file with word list for guessing" << std::endl;
      return 1;
   }

   std::string completeCipherText = readCipherText(argv[1]);
   std::string key = readKey(argv[2]);

   std::vector<std::string> dictionary;
   readDictionary(argv[3], dictionary);

   std::cout << "Dictionary size = " << dictionary.size() << std::endl;

   std::vector<int> stdFreqs(26, 0);
   for(auto singleDictWord : dictionary)
   {
      updateLetterFrequency(singleDictWord, stdFreqs);
   }

   //printFreqs(stdFreqs);
   //printInvFreqs(stdFreqs);

   std::vector<std::string> ctTokens = tokenizeCipherText(completeCipherText);
   std::vector<int> ctFreqs(26,0);
   for(auto const & singleToken : ctTokens)
   {
      updateLetterFrequency(singleToken, ctFreqs);
   }

   //printInvFreqs(ctFreqs);


   std::string startKey = createStarterKey(stdFreqs, ctFreqs);
   std::cout << "StartKey = [" << startKey << "]" << std::endl;

   std::cout << "PT:" << std::endl << decrypt(completeCipherText, key) << std::endl;

   for(auto singleToken : ctTokens)
   {
      std::cout << "Suggestions for " << decrypt(singleToken, key) << std::endl
                << getSuggestions(decrypt(singleToken, key), dictionary) << std::endl << std::endl;
   }

   return 0;
}
