// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "fmt/base.h"
#include "fmt/color.h"

#include <string>

#include <Crypt/Rsa/Rsa.h>



void RsaSettersGetters(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Rsa Getters and Setters");
  fmt::println("");

  Crypt::Rsa rsa;
  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);
  std::string message = "Hello World";
  std::string cipher = "Cipher Set Test";
  rsa.setMessage(message.data(), message.size());
  rsa.setCipher(cipher.data(), cipher.size());

  if(rsa.pIsPrime())
    fmt::println(fg(fmt::color::green), "P = {} and is Prime", rsa.getP());
  else 
    fmt::println(fg(fmt::color::red), "P = {} and is not Prime", rsa.getP());

  if(rsa.qIsPrime())
    fmt::println(fg(fmt::color::green), "Q = {} and is Prime", rsa.getQ());
  else 
    fmt::println(fg(fmt::color::red), "Q = {} and is not Prime", rsa.getQ());
  
  if(rsa.eIsValid())
    fmt::println(fg(fmt::color::green), "E = {} and is Valid", rsa.getE());
  else 
    fmt::println(fg(fmt::color::red), "E = {} and is not Valid", rsa.getE());
  
  std::pair<const void*, size_t> get_message = rsa.getMessage();
  std::string recreate_message(static_cast<const char*>(get_message.first), get_message.second);

  std::pair<const void*, size_t> get_cipher = rsa.getCipher();
  std::string recreate_cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

  if(message == recreate_message)
    fmt::println(fg(fmt::color::green), "Message: {} == {}", message, recreate_message);
  else 
    fmt::println(fg(fmt::color::red), "Message: {} != {}", message, recreate_message);

  if(cipher == recreate_cipher)
    fmt::println(fg(fmt::color::green), "Cipher: {} == {}", cipher, recreate_cipher);
  else 
    fmt::println(fg(fmt::color::red), "Cipher: {} != {}", cipher, recreate_cipher);

  fmt::println(fg(fmt::color::yellow), "{}", rsa.c_str());
};



void RsaCryptEncrypt(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Rsa Crypt and Encrypt");
  fmt::println("");

  Crypt::Rsa rsa;
  rsa.setP(21191);
  rsa.setQ(48337);
  rsa.setE(65537);
  std::string message = "Hello World";
  rsa.setMessage(message.data(), message.size());
  
  fmt::println(fg(fmt::color::aqua), "Crypt");
  rsa.crypt();
  std::pair<const void*, size_t> get_cipher = rsa.getCipher();
  std::string cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

  if(message != cipher){
    fmt::print(fg(fmt::color::green), "Cipher: ");
    for(unsigned char byte : cipher) fmt::print(fg(fmt::color::green), "{:02x}", byte);
    fmt::print(fg(fmt::color::green), " != Message: ");
    for(unsigned char byte : message) fmt::print(fg(fmt::color::green), "{:02x}", byte);
    fmt::print("\n");
  }
  else {
    fmt::print(fg(fmt::color::red), "Cipher: ");
    for(unsigned char byte : cipher) fmt::print(fg(fmt::color::red), "{:02x}", byte);
    fmt::print(fg(fmt::color::red), " == Message: ");
    for(unsigned char byte : message) fmt::print(fg(fmt::color::red), "{:02x}", byte);
    fmt::print("\n");
  };


  fmt::println(fg(fmt::color::aqua), "Encrypt");
  Crypt::Rsa rsa2;
  rsa2.setP(21191);
  rsa2.setQ(48337);
  rsa2.setE(65537);
  rsa2.setCipher(get_cipher.first, get_cipher.second);

  rsa2.encrypt();
  std::pair<const void*, size_t> get_message = rsa2.getMessage();
  std::string recreated_message(static_cast<const char*>(get_message.first), get_message.second);

  if(message == recreated_message)
    fmt::println(fg(fmt::color::green), "Message: '{}' == Recreated Message: '{}'", message, recreated_message);
  else 
    fmt::println(fg(fmt::color::red), "Message: '{}' == Recreated Message: '{}'", message, recreated_message);

};



void RsaExample(){
  fmt::println("");
  fmt::println("");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "================");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "= Rsa Examples =");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "================");
  fmt::println("");

  RsaSettersGetters();
  RsaCryptEncrypt();
};