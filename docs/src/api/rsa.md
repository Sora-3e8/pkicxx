# RSA

## Overview
Sub-namespace `#!cpp tancrypt::RSA` provides basic cryptographic functions and pulls in `#!cpp tancrypt::RSA::pkic` as required dependency.

All provided functions are provided as static stateless functions, this simplifies their usage.

</br>
</br>
</br>
</br>

## `#!cpp RSA::encrypt`
### `#!cpp RSA::encrypt(pkic& key,std::vector<unsigned char>& payload)`
* **Parameters:**
    * `#!cpp tancrypt::RSA::pkic key` - Key container (priv/pubkey must be loaded)
    * `#!cpp std::vector<unsigned char>& payload` - Data buffer to encrypt
* **Returns:**
    * `#!cpp std::vector<unsigned char>` - Encrypted data buffer

### Encrypt example
```cpp linenums="1"
#include "tancrypt.hpp"

int main()
{
  // Data buffer setup
  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data());

  // Keypair with key size of 2048 gets generated and our buffer gets encrypted
  tancrypt::RSA::pkic key_store;
  key_store.generate_keypair(2048);
  std::vector<unsigned char> res = tancrypt::RSA::pki::encrypt(key_store,payload);

  // Check results compared original, hex x  encrypted
  std::cout << "Original:" << std::endl;
  std::cout << my_message << std::endl;
  std::cout << "Hex:" << std::endl;
  std::cout << tancrypt::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << tancrypt::hexStr(res) << std::endl;

  return 0;
}
```
</br>
</br>
</br>
</br>

## `#!cpp RSA::decrypt`
### `#!cpp RSA::decrypt(pkic& key,std::vector<unsigned char>& payload)`
* **Parameters:**
    * `#!cpp tancrypt::RSA::pkic& key` - Key container (Must contain private key)
    * `#!cpp std::vector<unsigned char>& payload` - Encrypted data buffer
* **Returns:**
    * `#!cpp std::vector<unsigned char>` - Decrypted data buffer
    

### Decrypt example
```cpp linenums="1"
#include "tancrypt.hpp"

int main()
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);

  // Preparing encrypted data 
  std::string my_message = "Hewwo I am secret ^.^";
  std::vector<unsigned char> payload(my_message.size());
  std::copy(my_message.data(),my_message.data()+my_message.size(),payload.data()); 
  std::vector<unsigned char> res = tancrypt::RSA::pki::encrypt(key,payload);
  std::cout << "Original:" << std::endl;
  std::cout << my_message << std::endl;
  std::cout << "Hex:" << std::endl;
  std::cout << tancrypt::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << tancrypt::hexStr(res) << std::endl;

  // Decrypting the data again
  std::vector<unsigned char> res_decrypted = tancrypt::pki::decrypt(key,res);
  
  // Debug print to check that the data indeed match
  std::cout << "Res decrypted hex:"<< std::endl;
  std::cout << tancrypt::hexStr(res_decrypted) << std::endl;
  std::cout << "Res decrypted:" << std::endl;
  std::cout << res_decrypted.data() << std::endl;

  return 0;
}
```
</br>
</br>
</br>
</br>

## `#!cpp RSA::sign`

### `#!cpp RSA::sign(pkic& key,std::vector<unsigned char> &buffer, hashAlg alg)`
* **Parameters:**
    * `#!cpp tancrypt::RSA::pkic key` - key container (must contain private key)
    * `#!cpp std::vector<unsigned char> &buffer` - The data to be signed
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm to use for the digest
* **Returns:**
    * `#!cpp std::vector<unsigned char>` - Data signature

### Signature example
```cpp linenums="1"
#include "tancrypt.hpp"

int main()
{
  tancrypt::RSA::pkic key_store;
  key_store.generate_keypair(2048);

  std::string message = "I confirm this transaction.";
  std::vector<unsigned char> data(message.begin(), message.end());

  // Signing the data using SHA256
  std::vector<unsigned char> signature = tancrypt::RSA::pki::sign(key_store, data, tancrypt::hashAlg::SHA256);

  std::cout << "Signature (Hex):" << std::endl;
  std::cout << tancrypt::hexStr(signature) << std::endl;

  return 0;
}
```
</br>
</br>
</br>
</br>

## `RSA::verify`
!!! note
    Algorithm choice must match the algorithm which was used to sign the data, otherwise the operation will fail.
### `RSA::verify(pkic& key, std::vector<unsigned char>&sig, std::vector<unsigned char> &buffer, hashAlg alg)`
* **Parameters:**
    * `#!cpp tancrypt::RSA::pkic& key` - key container (must contain public key)
    * `#!cpp std::vector<unsigned char> &sig` - Singature data buffer
    * `#!cpp std::vector<unsigned char> &buffer` - The data to verify
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm to use for the digest
* **Returns:**
    * `#!cpp bool` - Signature matches data (returns `#!cpp true` if valid)

### Verify signature example
```cpp linenums="1"
#include "tancrypt.hpp"

int main()
{
  // Assuming 'key_store' contains public key, 'signature' and 'data' contain valid data
  bool is_valid = tancrypt::RSA::pki::verify(key_store, signature, data, tancrypt::hashAlg::SHA256);

  if (is_valid) {
      std::cout << "Signature is authentic!" << std::endl;
  } else {
      std::cout << "Signature verification failed." << std::endl;
  }

  return 0;
}
```
</br>
</br>
</br>
</br>


