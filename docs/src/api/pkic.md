# PKIC

## Overview
!!! Note
    Please note that newly created instance of `#!cpp RSA::pkic` is blank  
    and needs to be initialized properly before it can be used.

PKIC serves as a container, which stores and manages the RSA keys.</br>
The PKIC by itself does not provide any cryptographic operations, it only provides the keys.
`#!cpp class pkic` extends the `#!cpp namespace RSA` and is automatically included in the RSA header.

If you wish to merely generate keypairs or load keypairs and manage them, you can include `tancrypt-pkic.hpp`
as a standalone header.
</br>
</br>
</br>
</br>

## Constructor
### tancrypt::RSA::pkic()
* **Parameters:**
</br>
</br>
</br>
</br>

#### Initialization methods
* Keypair generation
* Load from DER
* Load from PEM string
* Load from PEM file
</br>
</br>
</br>
</br>

## DER loaders
DER loaders, class methods that load RSA keys from DER data buffers

### `#!cpp loadPrivDER(std::vector<unsigned char>& DER)`
Loads private key from DER data buffer into the key container

* **Parameters:**
    * `#!cpp std::vector<unsigned char>& DER` - Private key data buffer in with DER format
* **Returns:**

### `#!cpp loadPubDER(std::vector<unsigned char>& DER)`
Loads public key from DER data buffer into the key container

* **Parameters:**
    * `#!cpp std::vector<unsigned char>& DER` - Public key data buffer in with DER format
* **Returns:**
</br>
</br>
</br>
</br>

## PEM loaders

### `#!cpp loadPEMStr()`
* **Parameters:** `#!cpp const char* PEM` - PEM string to load
* **Returns:**

### `#!cpp importPEM()`
* **Parameters:** `#!cpp const char* file` - Path to file to load PEM string from
* **Returns:**
</br>
</br>
</br>
</br>

## DER getters

### `#!cpp getPrivDER()`
* **Parameters:**
* **Returns:**
    * `std::vector<unsigned char>& DER` - Private key DER data buffer

### `#!cpp getPubDER()`
* **Parameters:**
* **Returns:**
    * `std::vector<unsigned char>& DER` - Public key DER data buffer
</br>
</br>
</br>
</br>
    
## PEM string getters

### `#!cpp getPrivPEM()`
* **Parameters:**
* **Returns:**
    * `#!cpp std::string` private key in form of PEM string
    
### `#!cpp getPublicPEM()`
* **Parameters:**
* **Returns:**
    * `#!cpp std::string` public key in form of PEM string
    
### `#!cpp getBundlePEM()`
* **Parameters:**
* **Returns:**
    * `#!cpp std::string` fullkey key in form of PEM string
</br>
</br>
</br>
</br>
