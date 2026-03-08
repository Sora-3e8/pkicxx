#ifndef PKICXX_HPP
#define PKICXX_HPP

#include "pkicxx-pkic.hpp"

namespace pkicxx
{
  std::string DERhexStr(const std::vector<unsigned char> &DER);
  class pkic;
 // class pki; future encryption/decryption handler, uncomment once implemented
}
#endif
