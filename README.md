# NODEPP-ARGON-2
Argon2 for NodePP

## Dependencies
```bash
# Argon2
    🪟: pacman -S mingw-w64-ucrt-x86_64-argon2
    🐧: sudo apt install libargon2-dev
```

## Usage 
```cpp
#include <nodepp/nodepp.h>
#include <nodepp/encoder.h>
#include <argon/argon2.h>

using namespace nodepp;

void onMain() {

    ptr_t<uchar> hash ( 32, '\0' );
    argon2_t argon; 

    argon.hash( hash, "password" );
    console::log( encoder::hex::get( hash ) );

}
```

## Build & Run
- 🐧: `g++ -o main main.cpp -I ./include -largon2 ; ./main`
- 🪟: `g++ -o main main.cpp -I ./include -largon2 ; ./main`

## License

**Nodepp** is distributed under the MIT License. See the LICENSE file for more details.
