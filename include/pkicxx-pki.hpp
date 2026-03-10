#include <string>
#include <vector>

extern "C" struct evp_pkey_st;

namespace pkicxx
{
  class pki
  {
    public:
      pki();
      ~pki();
      void encrypt();
      void decrypt();
      void sign();
  };
} 
