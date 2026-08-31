# Crypt 
## About
Crypt is a set of structures and algorithms used in **Cryptography** written in ```C++```. ```Supports Key exchange```, ```Hashing```, ```Encrypting and Decrypting Data```, ```Data Validation```.



## Table of Contents
- [About](#about)
- [Table of Contents](#table-of-contents)
- [Installation](#installation)
  - [Via GitHub Repo](#via-github-repo)
  - [Via vcpkg](#via-vcpkg)
- [Usage](#usage)
- [Configurations Flags](#configurations-flags)
- [Testing](#testing)
- [Supported Structures and Algorithms](#supported-structures-and-algorithms)
- [TODO:](#todo)



## Installation
### Via GitHub Repo
#### 1.1 Clone Repo
```bash
  git clone https://github.com/Daynlight/Crypt
```
#### 1.2 Download from tag
[Latest releases](https://github.com/Daynlight/Crypt/releases)
#### 2. Add it and link in cmake
```cmake
cmake_minimum_required(VERSION 3.15)


project(A LANGUAGES CXX)

add_subdirectory(<Path_to_crypt>)

set(src 
  main.cpp
)

add_executable(A ${src})
target_link_libraries(A PRIVATE Crypt::Crypt)
```


### Via vcpkg
#### 1. Create ```vcpkg-configuration.json```
```json
{
  "overlay-ports": [
    "./.ports"
  ]
}
```
#### 2. Copy ports
Copy [```crypt```](vcpkg-port-tmplate/crypt/) folder to your ports.
Should be something like ```.ports/crypt/vcpkg.json``` and ```.ports/crypt/portfile.cmake```.
#### 3. Add ```crypt to your root ```vcpkg.json```
```json
{
  "name": "test",
  "version": "1.0.0",
  "dependencies": [
    "crypt"
  ]
}
```
#### 4. Update ```portfile.cmake```
- REF to commit hash you want to use
- SHA512 generated after first run
#### 5. Link it in cmake
```cmake
cmake_minimum_required(VERSION 3.15)


project(A LANGUAGES CXX)

find_package(Crypt CONFIG REQUIRED)

set(src 
  main.cpp
)

add_executable(A ${src})
target_link_libraries(A PRIVATE Crypt::Crypt)
```



## Usage



## Configurations Flags



## Testing



## Supported Structures and Algorithms
- [Elliptic Curves](docs/Elliptic.md)
- [Des](docs/Des.md)
- [Aes](docs/Aes.md)
- [Sha](docs/Sha.md)
- [Rsa](docs/Rsa.md)
- [ElGamal](docs/ElGamal.md)



## TODO:
- [x] RSA
- [x] SHA256
- [x] ELGamal
- [ ] EC-ELGamal
- [ ] Deffie-Hellman
- [ ] BigInt
- [ ] BigIntModulo