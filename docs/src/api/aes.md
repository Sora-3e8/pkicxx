# AES

## Overview
This namespace provides basic AES cryptographic operations, depends AES::keyc.
For proper use, also check documentation of AES::keyc.
</br>
</br>
</br>
</br>

## `#!cpp AES::encrypt`
### `#!cpp AES::encrypt(AES::keyc &key_container, std::vector<unsigned char> &buffer)`
* **Parameters:**
  * `#!cpp tancrypt::AES::keyc &key_container - AES key with preloaded credentials`
  * `#!cpp std::vector<unsigned char> &buffer - Data to encrypt`
* **Returns:**
    * `#!cpp std::vector<unsigned char> AES_DATA` - Encrypted buffer
</br>
</br>
</br>
</br>

## `#!cpp AES::decrypt`
### `#!cpp AES::decrypt(AES::keyc &key_container, std::vector<unsigned char> &buffer)`
* **Parameters:**
  * `#!cpp tancrypt::AES::keyc &key_container - AES key with preloaded credentials`
  * `#!cpp std::vector<unsigned char> &buffer - Data to decrypt`
* **Returns:**
    * `#!cpp std::vector<unsigned char> AES_DATA` - Decrypted buffer
</br>
</br>
</br>
</br>

## `#!cpp AES::getNonce`
!!! Warning
    Please note that this should be only used for ciphers where it's applicable, otherwise logic error exception  
    "Not applicable" is thrown.
### `#!cpp AES::getNonce(std::vector<unsigned char> buffer,AES::Type type)`
* **Parameters:**
  * `#!cpp tancrypt::AES::keyc &key_container` - AES key with preloaded credentials
  * `#!cpp AES::Type type` - Type of the AES cipher, needed to determine nonce/IV length
* **Returns:**
    * `#!cpp std::vector<unsigned char> nonce_buffer` - Nonce/IV buffer

</br>
</br>
</br>
</br>
