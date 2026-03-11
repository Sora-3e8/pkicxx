#ifndef PKICXX_PKI_HPP
#define PKICXX_PKI_HPP

#include <vector>

extern "C" struct evp_pkey_st;

namespace pkicxx
{
  class pkic;
  class pki
  {
    public:
      static std::vector<unsigned char> encrypt(pkic& key,std::vector<unsigned char>& payload);
      static void decrypt();
      static void sign();

    private:
      pki(){}
  };
}
#endif
