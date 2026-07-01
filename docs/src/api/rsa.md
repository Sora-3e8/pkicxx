# RSA

## Overview
Provides basic RSA cryptographic operations, depends on [PKIC](pkic.md).

## Encrypt
Is a static stateless function, which uses a PKIC as Public Key.  
Takes the buffer by reference and returns a new encrypted copy of the data.

<h3><code>RSA::encrypt(pkic& key,dutils::dbuffer& payload)</code></h3>

* **Parameters:**
    * `#!cpp tancrypt::RSA::pkic key` - Key container (priv/pubkey must be loaded)
    * `#!cpp dutils::dbuffer& payload` - Data buffer to encrypt
* **Returns:**
    * `#!cpp dutils::dbuffer` - Encrypted data buffer

In case of a failure throws an exception.

</br>

???+ example
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

## Decrypt
Is a static stateless function, which uses a PKIC as Private Key.  
Takes the buffer by reference and returns a new decrypted copy of the data.

<h3><code>RSA::decrypt(pkic& key,dutils::dbuffer& payload)</code></h3>

* **Parameters:**
    * `#!cpp tancrypt::RSA::pkic& key` - Key container (Must contain private key)
    * `#!cpp dutils::dbuffer& payload` - Encrypted data buffer
* **Returns:**
    * `#!cpp dutils::dbuffer` - Decrypted data buffer

In case of a failure throws an exception.

</br>

???+ example
    ```cpp linenums="1"
    #include <iostream>
    #include "tancrypt/rsa.hpp"

    int main()
    {
      // Makes life easier 
      using namespace tancrypt;
    
      RSA::pkic key;
      // Loading the key from PEM file here
      key.importPEM("my_path/key.pem");
    
      dutils::dbuffer data_in;
      // Assuming whatever encrypted data was loaded into the dbuffer here
      //...

      // Decrypting the data
      dutils::dbuffer decrypted_buffer = RSA::decrypt(key,data_in);

      // You can check the results via helper function dutils::hexStr
      std::cout << "Decrypted(hex):" << dutils::hexStr(decrypted_buffer) << std::endl;
      std::cout << "Decrypted:" << decrypted.toStr() << std::endl

      return 0;
    }
    ```
</br>

## Sign
Is a static stateless function, takes PKIC and hashing algorithm of your choice.  
Takes the buffer by reference and returns a new cryptographic signature.

<h3><code>RSA::sign(pkic& key,dutils::dbuffer &buffer, hashAlg alg)</code></h3>

* **Parameters:**
    * `#!cpp tancrypt::RSA::pkic key` - key container (must contain private key)
    * `#!cpp dutils::dbuffer &buffer` - The data to be signed
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm to use for the digest
* **Returns:**
    * `#!cpp dutils::dbuffer` - Data signature


???+ example
    ```cpp linenums="1"
    #include <iostream>
    #include "tancrypt/rsa.hpp"

    int main()
    {

      // Makes life easier 
      using namespace tancrypt;
    
      RSA::pkic key;
      key.generate_keypair(2048);

      std::string message = "I confirm this transaction.";
      dutils::dbuffer data_in(message);

      // Signing the data using SHA256
      dutils::dbuffer signature = RSA::sign(key, data_in, hashAlg::SHA256);

      // You can check the results via helper function dutils::hexStr
      std::cout << "Signature (Hex):" << dutils::hexStr(signature) << std::endl;

      return 0;
    }
    ```
</br>

## Verify
Is a static stateless function, which takes PKIC, data, hashing algorithm and original data.  
This function verifies the signature against  original data.

!!! note
    Algorithm choice must match the algorithm which was used to sign the data, otherwise the operation will fail.
    
<h3><code>RSA::verify(pkic& key, dutils::dbuffer&sig, dutils::dbuffer &buffer, hashAlg alg)</code></h3>

* **Parameters:**
    * `#!cpp tancrypt::RSA::pkic& key` - key container (must contain public key)
    * `#!cpp dutils::dbuffer &sig` - Singature data buffer
    * `#!cpp dutils::dbuffer &buffer` - The data to verify
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm to use for the digest
* **Returns:**
    * `#!cpp bool` - Signature matches data (returns `#!cpp true` if valid)

???+ example
    ```cpp linenums="1"
    #include <iostream>
    #include "tancrypt.hpp"

    int main()
    {
      // Makes life easier 
      using namespace tancrypt;

      RSA::pkic key;
      // Loading the key from PEM file here
      key.importPEM("my_path/key.pem");

      dutils::dbuffer data_in;
      // Assuming whatever data was loaded into the dbuffer here
      //...

      dutils::dbuffer signature;
      // Assuming whatever signature data was loaded into the dbuffer here
      //...

      bool is_valid = RSA::verify(key, signature, data_in, hashAlg::SHA256);

      // Tenary shows us the result
      std::cout << ( (is_valid) ? "Signature is authentic!" : "Signature verification failed") << std::endl;

      return 0;
    }
    ```

</br>
</br>


