#ifndef TANCRYPT_HASHTYPES_HPP
#define TANCRYPT_HASHTYPES_HPP
#include <map>

namespace tancrypt
{
  enum class hashAlg : int
  {
     MDC2 = 0,
     MD4 = 1,
     MD5 = 2,
     SHA1 = 3,
     RSA_SHA1 = 4,
     SHA224 = 5,
     SHA256 = 6,
     SHA384 = 7,
     SHA512 = 8,
     SHA512_224 = 9,
     SHA512_256 = 10,
     SM3 = 11,
     BLAKE2B512 = 12,
     BLAKE2S256 = 13,
  };
  static const std::map<int, const char*>& _hashTypeMap()
  {
    static const std::map<int,const char*> m =
    {
      {0,"MDC2"},
      {1,"MD4"},
      {2,"MD5"},
      {3,"SHA1"},
      {4,"RSASHA1"},
      {5,"SHA224"},
      {6,"SHA256"},
      {7,"SHA384"},
      {8,"SHA512"},
      {9,"SHA512224"},
      {10,"SHA512256"},
      {11,"SM3"},
      {12,"BLAKE2B512"}
    };
    
    return m;
  }

}
#endif
