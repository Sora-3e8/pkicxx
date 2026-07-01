# Hash

## Overview
Provides the hashing functionality required for `#!cpp RSA::sign` and `#!cpp RSA::verify`, but it can also be used as a standalone hasher.
Supported algorithms are directly provided by OpenSSL.

## Hash
Provides hashing functionality required for sign and verify functions,  
but can be also used independently.

<h3><code>tancrypt::hash(dutils::dbuffer& data,hashAlg alg)</code></h3>

* **Parameters:**
    * `#!cpp dutils::dbuffer& data` - Data buffer to hash
    * `#!cpp tancrypt::hashAlg alg` - Algorithm to use for the digest.
* **Returns:**
    * `dutils::dbuffer data` - Hashed data buffer

???+ example
    ```cpp
    #include <iostream>
    #include "tancrypt/hash.hpp"

    int main()
    {
      // Data setup
      dutils::dbuffer payload("Hewwo, I am secret ^.^");

      // Data gets hashed here  
      dutils::dbuffer hashed_payload = tancrypt::hash(payload,tancrypt::hashAlg::SHA256);

      // You can check the results via helper function dutils::hexStr
      std::cout << "Original:" << payload.toStr() << std::endl;
      std::cout << "Original(hex):" << dutils::hexStr(payload) << std::endl;
      std::cout << "Hashed:" << hashed_payload.toStr() << std::endl;
      std::cout << "Hashed(hex):" << dutils::hexStr(hashed_payload) << std::endl;

      return 0;
    }
    ```

## hashAlg
Enum class used as hash type.

<h3><code class="language-cpp highlight">enum class tancrypt::hashAlg : int</code></h3>

</br>

<h4> Available algorithms:</h4>

| Enum Constant | Hashing algorithm | Digest Size |   |
| :--- | :---: | :---: | :---: |
`hashAlg::MDC2` | MDC-2 | 128-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::MDC2" data-md-type="copy"></span> |
`hashAlg::MD4` | MD4 | 128-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::MD4" data-md-type="copy"></span> |
`hashAlg::MD5` | MD5 | 128-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::MD5" data-md-type="copy"></span> |
`hashAlg::SHA1` | SHA-1 | 160-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::SHA1" data-md-type="copy"></span> |
`hashAlg::RSA_SHA1` | RSA-SHA1 | 160-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::RSA_SHA1" data-md-type="copy"></span> |
`hashAlg::SHA224` | SHA-224 | 224-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::SHA224" data-md-type="copy"></span> |
`hashAlg::SHA256` | SHA-256 | 256-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::SHA256" data-md-type="copy"></span> |
`hashAlg::SHA384` | SHA-384 | 384-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::SHA384" data-md-type="copy"></span> |
`hashAlg::SHA512` | SHA-512 | 512-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::SHA512" data-md-type="copy"></span> |
`hashAlg::SHA512_224` | SHA-512-224 | 1024-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::SHA512_224" data-md-type="copy"></span> |
`hashAlg::SHA512_256` | SHA-512-256 | 1024-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::SHA512_256" data-md-type="copy"></span> |
`hashAlg::SM3` | ShangMi 3 | 512-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::SM3" data-md-type="copy"></span> |
`hashAlg::BLAKE2B512` | BLAKE2B-512 | 1024-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::BLAKE2B512" data-md-type="copy"></span> |
`hashAlg::BLAKE2S256` | BLAKE2S-256 | 1024-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="hashAlg::BLAKE2S256" data-md-type="copy"></span> |

</br>
</br>
