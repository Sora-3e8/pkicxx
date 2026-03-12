#include <iomanip>
#include <sstream>
#include "pkicxx.hpp"

namespace pkicxx
{
  std::string hexStr(const std::vector<unsigned char> &DER)
  {
    int counter = 0;
    std::stringstream hex_str;
    for(unsigned char val : DER)
    {
     hex_str << std::hex << std::setw(2) << std::setfill('0') << (int) val << (((counter+1)%16==0) ? '\n' : ' ' );
     counter++;
    }

    return hex_str.str();
  }

}
