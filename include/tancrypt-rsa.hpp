#include "tancrypt-pkic.hpp"
#include "tancrypt-hashtypes.hpp"
#include "dutils.hpp"

extern "C" struct evp_pkey_st;

namespace tancrypt
{
  namespace RSA
  {
    class pkic;
    dutils::dbuffer encrypt(pkic& key,dutils::dbuffer &payload);
    dutils::dbuffer decrypt(pkic& key,dutils::dbuffer &payload);
    dutils::dbuffer sign(pkic& key, dutils::dbuffer &buffer, hashAlg alg);
    bool verify(pkic& key, dutils::dbuffer &sig, dutils::dbuffer &buffer, hashAlg alg);

  }  
}
