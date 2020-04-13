#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

//#define DUMP_DEBUG
#ifdef DUMP_DEBUG
#define DBGOUT std::cerr << "DBG: "
#else
#define DBGOUT if(0) std::cerr
#endif

std::string toHexString(uint32_t val)
{
	std::ostringstream oss;
	oss << std::setw(8) << std::setfill('0') << std::hex << val << std::dec;
	return oss.str();
}

int isHexChar(char x)
{
	if ( (x >= '0') && (x <= '9'))
		return 1;	
	
	if ( (x >= 'a') && (x <= 'f'))
		return 1;
	
	if ( (x >= 'A') && (x <= 'F') )
		return 1;
	
	return 0;
}

std::vector<std::string> tokenize(std::string const & text, std::string const & delims)
{
	std::vector<std::string> retVal;
	std::string curToken;
	
	for(auto curChar: text)
	{
		if (delims.find(curChar) == std::string::npos)
		{
			curToken += curChar;
		}
		else
		{
			if (!curToken.empty())
			{
				retVal.push_back(curToken);
				curToken.clear();
			}
		}
	}
	
	if (!curToken.empty())
	{
		retVal.push_back(curToken);
	}
	
	return retVal;
}

bool isHexString(std::string const & s)
{
	for(auto letter : s)
	{
		if (!isHexChar(letter))
		{
			return false;
		}
	}
	return true;
}


/**
 * Reads the next line from file into std::string, if the string is empty,
 * we are at the end of the file
 */
std::string readLine(int fd)
{
	std::string retVal;
	
	char nextChar;
	while(read(fd, &nextChar, 1))
	{
		retVal += nextChar;
		
		if (nextChar == '\n')
		{
			break;
		}
	}
	
	return retVal;
}


/**
 * Reads a line of text from the dump file.  If the line of text is not in the
 * correct format, or the correct address, the method return 0, ignore the
 * text in buffer.
 *
 * ########: xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx    xxxxxxxxxxxxxxxx
 */
bool processDumpText(uint64_t currentAddress, uint8_t* buffer, std::string data)
{
	DBGOUT << __PRETTY_FUNCTION__ << " called with: " << data;
	
	std::vector<std::string> tokens = tokenize(data, ": ");
	
	// There needs to be 18 tokens: address, 16 bytes, ascii
	if (tokens.size() < 18)
	{
		DBGOUT << "  process failed, not enough tokens" << std::endl;
		return false;
	}
	
	// Make sure the first 17 tokens are the correct length:  address and 16 bytes
	if (tokens[0].size() != 8)
	{
		DBGOUT << "  addresss token the wrong size" << std::endl;
		return false;
	}
	
	for(int i = 1; i <= 16; i++)
	{
		if (tokens[i].size() != 2)
		{
			DBGOUT << "  process failed, data token " << i << " wrong size" << std::endl;
			return false;
		}
	}
	
	// All the first 17 tokens must be hex
	for(int i = 0; i < 17; i++)
	{
		if (!isHexString(tokens[i]))
		{
			DBGOUT << "  process failed, data token text not hex" << std::endl;
			return false;
		}
	}
	
	unsigned long temp[17];
	for(int i = 0; i < 17; i++)
	{
		temp[i] = strtol(tokens[i].c_str(), NULL, 16);
	}
	
	uint64_t addressOfText = 0xffffffff & temp[0];
	
	if ( (addressOfText != currentAddress) &&
	     ( (addressOfText - currentAddress < 0x80)) )
	{
		std::cerr << "Looking for address " << toHexString(currentAddress) 
		          << " but we found address " << toHexString(addressOfText) 
		          << " instead" << std::endl;
	}
	
	if (addressOfText != currentAddress)
	{
		DBGOUT << "  process failed, wrong address: " << toHexString(addressOfText) 
		       << "!=" << toHexString(currentAddress) << std::endl;
		return false;
	}
	
	unsigned long byteVal;
	for(int i = 1; i <= 16; i++)
	{
		buffer[i-1] = temp[i] & 0xff;
	}
	
	return true;
}

bool writeDataToFile(int fd, uint8_t* data, int len)
{
	int numBytesWritten = 0;
	while(numBytesWritten < len)
	{
		int bw = write(fd, data + numBytesWritten, len - numBytesWritten);
		if (bw == 0)
		{
			return false;
		}
		
		numBytesWritten += bw;
	}
	
	return true;
}

std::string removeCharFromString(std::string original, char removeMe)
{
	std::string retVal;
	for(auto curChar: original)
	{
		if (curChar == removeMe)
		{
			continue;
		}
		
		retVal += curChar;
	}
	
	return retVal;
}

int main(int argc, char** argv)
{
	if (argc != 4)
	{
		// Print usage
		std::cerr << "Usage: " << argv[0] << " startAddr inputfile.hex outputfile.bin" << std::endl;
		std::cerr << "Usage: " << argv[0] << " startAddr - outputfile.bin  # Reads hex from stdin (-)" << std::endl;
		return 0;
	}
	
	// stdin is 0
	int inputFd;
	if (strcmp(argv[2], "-") == 0)
	{
		// Read from stdin (fd 0)
		inputFd = 0;
	}
	else
	{
		inputFd = open(argv[2], O_RDONLY);
		if (inputFd == -1)
		{
			std::cerr << "Error opening input file " << argv[2] << std::endl;
			return 1;
		}
		
		std::cerr << "Input file opened successfully" << std::endl;
	}
	
	// stdout is 1
	int outputFd;
	if (strcmp(argv[3], "-") == 0)
	{
		// write to stdout (fd 1)
		outputFd = 1;
	}
	else
	{
		outputFd = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0664);
		if (outputFd == -1)
		{
			std::cerr << "Error opening output file " << argv[2] << std::endl;
			return 1;
		}
		
		std::cerr << "Output file opened successfully" << std::endl;
	}
	
	unsigned long currentAddr = strtol(argv[1], NULL, 0) & 0xffffffff;
	
	std::string nextLine = " ";
	uint8_t buffer[16];
	do
	{
		nextLine = readLine(inputFd);
		nextLine = removeCharFromString(nextLine, '\r');
		
		if( processDumpText(currentAddr, buffer, nextLine) )
		{
			// Text processsed successfully, write the binary to output
			writeDataToFile(outputFd, buffer, 0x10);
			currentAddr += 0x10;
		}
		
	} while(!nextLine.empty());
	
	if (inputFd != 0)
	{
		// Must have been an actual file that was opened
		close(inputFd);
	}
	
	if (outputFd != 0)
	{
		// Must have been an actual file that was opened
		close(outputFd);
	}
	
	return 0;
}
