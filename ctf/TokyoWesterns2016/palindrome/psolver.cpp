#include<iostream>
#include<vector>

bool isPalindrome(std::string testWordWithSpaces)
{
   std::string testWord;
   for(auto singleChar : testWordWithSpaces)
   {
       if (singleChar != ' ')
         testWord += singleChar;
   }

   int i = 0;
   int j = testWord.length() - 1;

   while (i <= j)
   {
      if (testWord[i] != testWord[j])
      {
         //std::cerr << testWord << " not a palindrome" << std::endl;
         return false;
      }

      i++;
      j--;
   }

   return true;
}


// Recursively tries to find palindrome
std::string findPalindrome(std::string wordSoFar, std::vector<std::string> argsLeft)
{
   //std::cerr << "Finding palindrome for " << wordSoFar << " plus ";
   for(auto singleWord : argsLeft)
   {
      //std::cerr << singleWord << ", ";
   }

   //std::cerr << std::endl;

   if (argsLeft.size() == 0)
   {
      // end of recursion, return palindrome or empty string
      if (isPalindrome(wordSoFar))
      {
         return wordSoFar;
      }
      else
      {
         return "";
      }
   }


   for(int i = 0; i < argsLeft.size(); i++)
   {
      std::string newWordSoFar = wordSoFar;
      std::vector<std::string> newArgsSoFar;

      for(int assembleIndex = 0; assembleIndex < argsLeft.size(); assembleIndex++)
      {
         if (i == assembleIndex)
         {
            if (newWordSoFar.size() != 0)
               newWordSoFar += " ";
            newWordSoFar += argsLeft[assembleIndex];
         }
         else
         {
            newArgsSoFar.push_back(argsLeft[assembleIndex]);
         }
      }

      std::string solution = findPalindrome(newWordSoFar, newArgsSoFar);
      if (solution != "")
      {
         return solution;
      }
   }

   return "";
}

int main(int argc, char** argv)
{
   if (argc == 1)
   {
      std::cerr << "Palindrome finder" << std::endl;
      std::cerr << "  Usage: " << argv[0] << " fragment1 fragment2 ..." << std::endl;
      std::cerr << "  Examp: " << argv[0] << " ra car ce" << std::endl;
   }

   std::vector<std::string> arguments;
   for(int i = 1; i < argc; i++)
   {
      arguments.push_back(std::string(argv[i]));
   }

   std::cout << findPalindrome("", arguments) << "\n";

   return 0;
}
