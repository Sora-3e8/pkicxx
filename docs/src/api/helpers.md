# Helper functions

Helpful utility functions, good for debugging and other processes.  
These functions live in `#!cpp namespace tancrypt`.

## `#!cpp tancrypt::hexStr`
This function provides an easy way to convert data into string interpretation of hex values.  
Useful when you want to print out or compare buffers with non-string data.  

### `#!cpp tancrypt::hexStr(const dutils::dbuffer &data)`
* **Parameters:**
    * `#!cpp const dutils::dbuffer &data` - The input data buffer.
* **Returns:**
    * `#!cpp std::string` - A formatted hex string (16 blocks per row).

