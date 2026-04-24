#ifndef TANCRYPT_AES_HPP
#define TANCRYPT_AES_HPP

#include "tancrypt-aes-keyc.hpp"
#include <vector>
#include "dutils.hpp"


namespace tancrypt
{
  namespace AES
  {
    dutils::dbuffer encrypt(AES::keyc &key_container,const dutils::dbuffer &buffer);
    dutils::dbuffer decrypt(AES::keyc &key_container, const dutils::dbuffer &buffer);
    dutils::dbuffer getNonce(const dutils::dbuffer &buffer,AES::Type type);
    class keyc; 
  }
}

#endif
