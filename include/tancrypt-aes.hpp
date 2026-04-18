#ifndef TANCRYPT_AES
#define TANCRYPT_AES

#include "tancrypt-aes-keyc.hpp"
#include <vector>

namespace tancrypt
{
  namespace AES
  {
    std::vector<unsigned char> encrypt(AES::keyc &key_container,const std::vector<unsigned char> &buffer);
    std::vector<unsigned char> decrypt(AES::keyc &key_container, const std::vector<unsigned char> &buffer);
    std::vector<unsigned char> getNonce(const std::vector<unsigned char> &buffer,AES::Type type);
    class keyc; 
  }
}

#endif
