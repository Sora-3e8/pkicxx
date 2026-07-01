# Tancrypt

## Introduction

This C++ library provides simple cryptographic API with focus on RSA and AES.</br>
Built on OpenSSL, but isn't a direct wrapper to make the usage as simple as possible.

This library is MIT licensed, so you can use it however you want in your projects!

### Features
- RSA encryption, decryption, sign and verify
- AES encryption, decryption
- Hashing

### Requirements
- C++ Standard : C++11 or later
- Dependencies : OpenSSL3.0+

</br>

???+ example
    === "RSA encryption"
    ```cpp
    #include <iostream>
    #include "tancrypt/rsa.hpp"

    int main()
    {
      // Makes life easier 
      using namespace tancrypt;
    
      // Keypair generation
      RSA::pkic key;
      key.generate_keypair(2048);

      // Preparing example buffer from string
      dutils::dbuffer data_in("Hewwo, I am secret ^.^");

      // Encrypting data
      dutils::dbuffer encrypted_buffer = RSA::encrypt(key,data_in);

      // You can check the results via helper function dutils::hexStr
      std::cout << "Original:" << data_in.toStr()<< std::endl;
      std::cout << "Original(hex):" << dutils::hexStr(data_in) << std::endl;
      std::cout << "Encrypted:" << encrypted_buffer.toStr() << std::endl;
      std::cout << "Encrypted(hex):" << dutils::hexStr(encrypted_buffer) << std::endl;

      return 0;
    }
    ```

</br>
</br>
