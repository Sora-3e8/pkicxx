# PKIC

## Overview
Public Key Infrastructure Container (PKIC) is a container for both private and public key.  
Various methods of loading, generating and exporting the Keys are available.  
PKIC keys are a raw cryptographic keys and do not hold any additional information like, subject etc...

</br>

## Constructor
Constructs a blank un-initialized instance of PKIC, which holds no keys.

<h3><code>RSA::pkic()</code></h3>

* **Parameters:**

## Binary loaders
Load the RSA keys from DER binary format data buffer into PKIC.

<h3><code>RSA::pkic::loadPrivDER(dutils::dbuffer& DER)</code></h3>

* **Parameters:**
    * `#!cpp dutils::dbuffer& DER` - Private key data buffer in with DER format

<h3><code>RSA::pkic::loadPubDER(dutils::dbuffer& DER)</code></h3>

* **Parameters:**
    * `#!cpp dutils::dbuffer& DER` - Public key data buffer in with DER format

</br>
</br>

## PEM loaders
Load the RSA keys from PEM format string into PKIC.

<h3><code>RSA::pkic::loadPEMStr()</code></h3>

* **Parameters:** `#!cpp const char* PEM` - PEM string to load

<h3><code>RSA::pkic::importPEM()</code></h3>

* **Parameters:** `#!cpp const char* file` - Path to file to load PEM string from

</br>
</br>

## DER getters
Return the RSA keys in DER binary format.

<h3><code>RSA::pkic::getPrivDER()</code></h3>

* **Parameters:**
* **Returns:**
    * `dutils::dbuffer& DER` - Private key DER data buffer


<h3><code>RSA::pkic::getPubDER()</code></h3>

* **Parameters:**
* **Returns:**
    * `dutils::dbuffer& DER` - Public key DER data buffer

</br>
</br>
    
## PEM string getters
Return the RSA keys in PEM string format.

<h3><code>RSA::pkic::getPrivPEM()</code></h3>

* **Parameters:**
* **Returns:**
    * `#!cpp std::string` private key in form of PEM string

<h3><code>RSA::pkic::getPubPEM()</code></h3>

* **Parameters:**
* **Returns:**
    * `#!cpp std::string` public key in form of PEM string
    
<h3><code>RSA::pkic::getBundlePEM()</code></h3>

* **Parameters:**
* **Returns:**
    * `#!cpp std::string` fullkey key in form of PEM string

</br>
</br>

## Get key bitsize
Returns the bitsize of the key.

<h3><code>RSA::pkic::getBits()</code></h3>

* **Parameters:**
* **Returns:**
    * `size_t bitsize` - Bitsize of key (eg. 2048, 3072, 4096, ...)

