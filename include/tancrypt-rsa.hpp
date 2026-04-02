#include "tancrypt-pkic.hpp"
#include "tancrypt-hashtypes.hpp"

extern "C" struct evp_pkey_st;

namespace tancrypt
{
  namespace RSA
  {
    class pkic;
    std::vector<unsigned char> encrypt(pkic& key,std::vector<unsigned char>& payload);
    std::vector<unsigned char> decrypt(pkic& key,std::vector<unsigned char>& payload);
    std::vector<unsigned char> sign(pkic& key, std::vector<unsigned char> &buffer, hashAlg alg);
    bool verify(pkic& key, std::vector<unsigned char>& sig,std::vector<unsigned char>& buffer, hashAlg alg);

  }  
}
