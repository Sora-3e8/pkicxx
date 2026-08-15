#ifndef TANCRYPT_HASH_HPP
#define TANCRYPT_HASH_HPP

#include "dutils.hpp"
#include "hashtypes.hpp"

namespace tancrypt
{
  dutils::dbuffer hash(const dutils::dbuffer& buffer, hashAlg alg);
}

#endif
