#ifndef TANCRYPT_HPP
#define TANCRYPT_HPP

#include "tancrypt-aes.hpp"
#include "tancrypt-rsa.hpp"
#include "tancrypt-hash.hpp"

namespace tancrypt
{ 
  std::string hexStr(const std::vector<unsigned char> &data);
  namespace AES{};
  namespace RSA{};
}
#endif
