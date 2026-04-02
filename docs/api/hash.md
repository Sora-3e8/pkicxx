# Hash

## Overview

!!! note "Algorithm support"
    The supported OpenSSL algorithms are limited to those mapped in enum class hashAlg.  
    This prevents errors from requesting unsupported or non-existent algorithms.

This component provides the hashing functionality required for `#!cpp RSA::sign` and `#!cpp RSA::verify`, but it can also be used as a standalone hasher.
Supported algorithms are directly provided by OpenSSL.


Extends the `#!cpp namespace pkicxx` without a sub-namespace.

</br></br>

## `#!cpp enum class tancrypt::hashAlg : int`

This enum class is used as hashAlg type, it allows better type safety and decreases amount of errors caused by typos

### Available algorithms
- `hashAlg::MDC2`
- `hashAlg::MD4`
- `hashAlg::MD5`
- `hashAlg::SHA1`
- `hashAlg::RSA_SHA1`
- `hashAlg::SHA224`
- `hashAlg::SHA256`
- `hashAlg::SHA384`
- `hashAlg::SHA512`
- `hashAlg::SHA512_224`
- `hashAlg::SHA512_256`
- `hashAlg::SM3`
- `hashAlg::BLAKE2B512`
- `hashAlg::BLAKE2S256`


</br></br>

## `#!cpp tancrypt::hash`
Provides hashing functionality required for sign and verify functions,  
but can be also used independently.

### `#!cpp tancrypt::hash(std::vector<unsigned char>& data,hashAlg alg)`
* **Parameters:**
    * `#!cpp std::vector<unsigned char>& data` - Data buffer to hash
    * `#!cpp tancrypt::hashAlg alg` - Algorithm to use for the digest.
* **Returns:**
    * `std::vector<unsigned char> data` - Hashed data buffer

</br></br>

## `#!cpp _hashTypeMap`
Internal function that returns internal **`#!cpp std::map`**, which maps enums to the OpenSSL algorithm names

### `#!cpp static const std::map<int,const char>& _hashTypeMap()`
* **Parameters:**
* **Returns:**
    * `#!cpp static const std::map<int,const char*>&` - Map of `#!cpp enum : int` values to `#!cpp char*` names of the algorithms

</br></br>
