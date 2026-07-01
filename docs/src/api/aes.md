# AES

## Overview
Provides basic AES cryptographic operations, depends on AES Key Container.  
For proper use, also check the documentation of [AES Key container](keyc.md).


## Encrypt
Is a static stateless function, uses AES Key Container as AES parameters.  
Takes the buffer by reference and returns a new encrypted copy of the data.

<h3><code>AES::encrypt(AES::keyc &key_container, dutils::dbuffer &buffer)</code></h3>

* **Parameters:**
    * `#!cpp tancrypt::AES::keyc &key_container - AES key with preloaded credentials`
    * `#!cpp dutils::dbuffer &buffer - Data to encrypt`
* **Returns:**
    * `#!cpp dutils::dbuffer AES_DATA` - Encrypted buffer

In case of a failure throws an exception.

</br>

???+ example

    === "Hashed Key"
        ```cpp
        #include <iostream>
        #include "tancrypt/aes.hpp"

        int main()
        {
          // Makes life easier 
          using namespace tancrypt;

          // Data and key setup
          dutils::dbuffer payload("Hewwo, I am secret >.<");
          dutils::dbuffer my_keydata("Hewwo, I am key ^.^");

          // Setting up AES Key Container
          AES::keyc my_key(my_keydata, AES::Type::CBC256, hashAlg::SHA256);

          // Encrypting the data
          dutils::dbuffer encrypted_payload = AES::encrypt(my_key, payload);

          // You can check the results via helper function dutils::hexStr
          std::cout << "Original: " << payload.toStr() << std::endl; 
          std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl; 
          std::cout << "Encrypted: " << encrypted_payload.toStr() << std::endl;
          std::cout << "Encrypted(hex): " << dutils::hexStr(encrypted_payload) << std::endl;
        
          return 0;
        }
        ```

    === "Raw Key"
        ```cpp
        #include <iostream>
        #include "tancrypt/aes.hpp"
        #include "tancrypt/hash.hpp"
        
        int main()
        {
          // Makes life easier 
          using namespace tancrypt;

          dutils::dbuffer payload("Hewwo, I am secret >.<");
          
          // Raw key
          dutils::dbuffer raw_key("Oh no, I am nor padded nor hashed!");

          // Hashing the key - this method allows us to pre-hash the key just once and use it multiple times!
          dutils::dbuffer hashed_key = tancrypt::hash(raw_key,tancrypt::hashAlg::SHA256);

          // Setting up the AES Key Container
          AES::keyc my_key(hashed_key, AES::Type::CBC256);

          // Encrypting the data
          dutils::dbuffer encrypted_payload = AES::encrypt(my_key, payload);

          // You can check the results via helper function dutils::hexStr
          std::cout << "Original: " << payload.toStr() << std::endl; 
          std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl; 
          std::cout << "Encrypted: " << encrypted_payload.toStr() << std::endl;
          std::cout << "Encrypted(hex): " << dutils::hexStr(encrypted_payload) << std::endl;
        
          return 0;
        }
        ```

</br>
</br>


## Decrypt
Is a static stateless function, uses AES Key Container as AES parameters.  
Takes the buffer by reference and returns a new decrypted copy of the data.

<h3><code>AES::decrypt(AES::keyc &key_container, dutils::dbuffer &buffer)</code></h3>

* **Parameters:**
    * `#!cpp tancrypt::AES::keyc &key_container - AES key with preloaded credentials`
    * `#!cpp dutils::dbuffer &buffer - Data to decrypt`
* **Returns:**
    * `#!cpp dutils::dbuffer AES_DATA` - Decrypted buffer

In case of a failure throws an exception.

</br>

???+ example

    === "Hashed Key"
        ```cpp
        #include <iostream>
        #include "tancrypt/aes.hpp"
        
        int main()
        {
          // Makes life easier 
          using namespace tancrypt;

          // Data and key setup 
          dutils::dbuffer payload;
          // Assuming whatever encrypted data was loaded into the dbuffer here
          //...
          dutils::dbuffer my_keydata("Hewwo, I am key ^.^");

          // Setting up AES Key Container
          AES::keyc my_key(my_keydata, AES::Type::CBC256, hashAlg::SHA256);

          // Decrypting the data
          dutils::dbuffer encrypted_payload = AES::encrypt(my_key, payload);


          // You can check the results via helper function dutils::hexStr
          std::cout << "Original: " << payload.toStr() << std::endl; 
          std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl; 
          std::cout << "Decrypted(hex): " << dutils::hexStr(decrypted_buffer) << std::endl;
          std::cout << "Decrypted: " << decrypted_buffer.data() << std::endl;

          return 0;
        }
        ```

    === "Raw Key"
        ```cpp
        #include <iostream>
        #include "tancrypt/aes.hpp"
        #include "tancrypt/hash.hpp"

        int main()
        {
          // Makes life easier 
          using namespace tancrypt;

          // Data and key setup 
          dutils::dbuffer payload;
          // Assuming whatever encrypted data was loaded into the dbuffer here
          //...
          // Raw key
          dutils::dbuffer raw_key("Oh no, I am nor padded nor hashed!");
          
          // Hashing the key - this method allows us to pre-hash the key just once and use it multiple times!
          dutils::dbuffer hashed_key = tancrypt::hash(raw_key,tancrypt::hashAlg::SHA256);

          // Setting up the AES Key Container
          AES::keyc my_key(hashed_key, AES::Type::CBC256);

          // You can check the results via helper function dutils::hexStr
          std::cout << "Original: " << payload.toStr() << std::endl; 
          std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl; 
          std::cout << "Decrypted(hex): " << dutils::hexStr(decrypted_buffer) << std::endl;
          std::cout << "Decrypted: " << decrypted_buffer.data() << std::endl;
        
          return 0;
        }
        ```

</br>

## getNonce
!!! Warning
    Please note that this should be only used for ciphers where it's applicable, otherwise logic error exception  
    "Not applicable" is thrown.
Allows you to retrieve, Nonce from dutils::dbuffer, in order for this operation to succeed the AES::Type is needed to correctly determine length of the Nonce.  
Do note however, that this relies on the Nonce to be stored at the start of the buffer.

<h3><code>AES::getNonce(dutils::dbuffer buffer,AES::Type type)</code></h3>

* **Parameters:**
    * `#!cpp dutils::dbuffer` - AES encrypted buffer
    * `#!cpp AES::Type type` - Type of the AES cipher, needed to determine nonce/IV length
* **Returns:**
    * `#!cpp dutils::dbuffer nonce_buffer` - Nonce/IV buffer

</br>

## RefKeylen
Is a static steless function, takes AES::Type and returns length of key for the given AES::type

<h3><code>AES::RefKeylen(AES::Type type)</code></h3>

* **Parameters:**
    * `#!cpp AES::Type type` - Type of the AES cipher, needed to determine nonce/IV length
* **Returns:**
    * `#!cpp int keylen` - Required length of the key for given AES::Type

</br>
</br>
