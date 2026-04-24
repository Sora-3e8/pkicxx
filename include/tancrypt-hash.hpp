#ifndef TANCRYPT_HASH_HPP
#define TANCRYPT_HASH_HPP

#include "tancrypt-hashtypes.hpp"
#include <vector>
#include "dutils.hpp"

namespace tancrypt
{
  dutils::dbuffer hash(const dutils::dbuffer &buffer, hashAlg alg);
}

#endif
