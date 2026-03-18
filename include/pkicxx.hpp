#ifndef PKICXX_HPP
#define PKICXX_HPP

#include "pkicxx-pkic.hpp"
#include "pkicxx-pki.hpp"
#include "pkicxx-hash.hpp"

namespace pkicxx
{ 
  std::string hexStr(const std::vector<unsigned char> &DER);
  class pkic;
  class pki;
 // class pki; future encryption/decryption handler, uncomment once implemented
}
#endif
