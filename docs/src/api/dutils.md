# Dutils

## Overview
Helpful utilities, provides custom data buffer and data utility functions.  

## Dbuffer
Useful class for storing data.  
Has an easy conversion method from string and back.  
Various methods of initialization are available.

### Constructors

</br>

#### Initializer list
Equivalent to `#!cpp std::vector<unsigned char> buffer = {1,2,3...};`

<h4><code>dutils::dbuffer(std::initializer_list<unsinged int> list)</code></h4>

* **Parameters:**
    * `#!cpp std::initializer_list<unsigned int> list` - Input data

</br>

#### Char
Initializes buffer and copies the char data into it.

!!! Note 
    In case you wish to assign the data without copying you can use the _data, but you have to update _size as well. 

<h4><code>dutils::dbuffer(const char* src, size_t size)</code></h4> 

* **Parameters:**
    * `#!cpp const char* src` - Data to copy

<h4><code>dutils::dbuffer(const unsigned char* src, size_t size)</code></h4> 

* **Parameters:**
    * `#!cpp const unsigned char* src` - Data to copy

</br>
</br>

#### Vector
Copies data from `#!cpp std::vector<unsigned char>` to newly created blank dbuffer,
this is primarily for compatibility purposes, but direct construction of `#!cpp dutils::dbuffer` is more efficient.

<h4><code>dutils::dbuffer(std::vector<unsigned char> data)</code></h4>

* **Parameters:**
    * `#!cpp std::vector<unsinged char> data` - Buffer to copy

</br>

#### String
Initializes buffer and copies the string into it.

<h4><code>dutils::dbuffer(std::string s_data)</code></h4>
 
* **Parameters:**
    * `#!cpp std::string s_data` - String to copy

</br>
</br>

### Methods

#### toStr
!!! Warning
    Please note that the dbuffer contents are not checked for string safety,
    thus when converting you must handle possible nullterminators yourself.

Returns content of the buffer in form of string

<h4><code>dutils::dbuffer::toStr()</code></h4>

* **Parametrs:**
* **Returns:**
    * `#!cpp std::string buffer_stringified`

</br>
</br>

## hexStr
This function provides an easy way to convert data into string interpretation of hex values.  
Useful when you want to print out or compare buffers with non-string data.  

<h3><code>dutils::hexStr(const dutils::dbuffer &data)</code></h3>

* **Parameters:**
    * `#!cpp const dutils::dbuffer &data` - The input data buffer.
* **Returns:**
    * `#!cpp std::string` - A formatted hex string

</br>
</br>
