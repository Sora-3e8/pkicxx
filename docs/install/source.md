# From source

## Adding library as dependency

You can simply add it as your dependency into ``lib/``.
```bash
cd lib/
git clone https://github.com/Sora-3e8/tancrypt  
```
Now either add it as subdirectory into your cmake or build manually using:
```bash
cd lib/
git clone https://github.com/Sora-3e8/tancrypt && cd pkicxx/build
cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
```

## Installing as system lib

You can install the library to your system and keep it as shared lib.</br>
To install use following commands:

```bash
git clone https://github.com/Sora-3e8/tancrypt && cd pkicxx/build
cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
sudo cmake --install .
```
Now you can link against it as if it was normal system library.</br>
The library should be findable by cmake.


