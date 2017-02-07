#include<iostream>

int main()
{
	std::string value;
   int place = 0;
   int word = 0;
	while(true)
	{
		std::cin >> value;

		if (value != "ZERO" && value != "ONE")
      {
         std::cerr << "Invalid value: " << value << std::endl;
			break;
      }

      if (std::cin.eof())
      {
         //std::cout << "End of input" << std::endl;
         break;
      }

      int bitVal = (value == "ZERO" ? 0 : 1);
      word <<= 1;
      word |= bitVal;
      place++;

      if (place == 8)
      {
         std::cout << (char) word;
         place = 0;
         word = 0;
      }


	}

   std::cout << std::endl;

   //std::cout << "Done." << std::endl;

	return 0;
}
