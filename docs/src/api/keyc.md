# KEYC

## Overview

!!! Warning
    Please note that when constructing without a Hashing enabled on the keyc,
    you're expected to provide a properly padded key of correct length.
    If you do not want to handle your key enable hashing by constructing with `hashAlg`.

AES::keyc fulfills function of key container.
Similar to how `RSA::pkic`, the `AES::keyc` stores a key and AES type.

## Constructor

## tancrypt::AES::keyc()
* **Parameters:**

Constructs blank keyc, you then need to manually setup the key container.  
If you're using hashing using the container, do not forget to also enable the hashing not just setting the hashAlg.

## tancrypt::AES::keyc(const dutils::dbuffer& key,AES::Type type)
* **Parameters:**
    * 
## tancrypt::AES::keyc(const dutils::dbuffer& key,AES::Type type,hashAlg alg);
