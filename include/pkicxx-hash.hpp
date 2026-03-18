#ifndef PKICXX_HASH_HPP
#define PKICXX_HASH_HPP
#include "pkicxx-hashtypes.hpp"
#include <vector>

namespace pkicxx
{
  std::vector<unsigned char> hash(std::vector<unsigned char> &buffer, hashAlg alg);
}

#endif
