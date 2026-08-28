// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include <string>

#include "Elliptic.h"


struct CryptStruct{
  void* data = nullptr;
  size_t data_size = 0; 
  void* key = nullptr;
  size_t key_size = 0;
};



int main(){
  // std::string test = "Hello World";
  // std::string key = "heh";
  
  // CryptStruct data;
  // data.data = static_cast<void*>(&test);
  // data.key = static_cast<void*>(&key);
  // data.data_size = test.size();
  // data.key_size = key.size();
  {
    Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic = elliptic + elliptic;  
    printf("%s\n", elliptic.c_str());
  }

  {
    Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic = elliptic.mult(2); 
    printf("%s\n", elliptic.c_str());
  }
  
  {
    Elliptic elliptic(17, 2, 2, 5, 1);
    elliptic *= 2; 
    printf("%s\n", elliptic.c_str());
  }

  {
    Elliptic elliptic1(17, 2, 2, 5, 1);
    elliptic1 *= 2; 
    printf("%s\n", elliptic1.c_str());

    Elliptic elliptic2(17, 2, 2, 5, 1);
    elliptic2 *= 3; 
    printf("%s\n", elliptic2.c_str());

    elliptic1 *= 3; 
    printf("%s\n", elliptic1.c_str());

    elliptic2 *= 2; 
    printf("%s\n", elliptic2.c_str());

    printf("Are EQ: %s\n", elliptic1 == elliptic2 ? "YES" : "NO");
  }

  return 0;
};