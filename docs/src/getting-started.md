# Getting started
Tancrypt supports few ways you can integrate the lib into your project.  
So you can choose which suits you the best!

## From source

### Adding as subdirectory
Adding as subdirectory into ``lib/``.

???+ example

    === "Shell"
        ```bash
        mkdir lib
        cd lib/
        git clone https://github.com/Sora3e8/tancrypt
        ```

    === "CMakeLists.txt"
        ```CMake
        cmake_minimum_required(VERSION 3.19)
        project(MyProject VERSION 1.0 LANGUAGES CXX)
        add_subdirectory(lib/tancrypt)
        ...
        target_link_libraries(my_binary PRIVATE tancrypt)
        ```

### Installing as system lib

Install the library to the system.

???+ example

    === "Shell"
        ```bash
        git clone https://github.com/Sora3e8/tancrypt && cd tancrypt/build
        cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
        sudo cmake --build . --target install 
        ```

    === "CMakeLists.txt"
        ```CMake
        cmake_minimum_required(VERSION 3.19)
        project(MyProject VERSION 1.0 LANGUAGES CXX)
        ...
        find_package(tancrypt REQUIRED)
        # Available components are aes,rsa and hash
        target_link_libraries(my_binary PRIVATE tancrypt::rsa)
        ```
        
