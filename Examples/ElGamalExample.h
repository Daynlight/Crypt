// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "fmt/base.h"
#include "fmt/color.h"
#include <string>
#include <Crypt/ElGamal/ElGamal.h>



void ELGamalSettersGetters(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "ELGamal Getters and Setters");
  fmt::println("");

  Crypt::ELGamal elgamal;
  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);

  std::string message = "Hello World";
  std::string cipher = "Cipher Set Test";

  elgamal.setMessage(message.data(), message.size());
  elgamal.setCipher(cipher.data(), cipher.size());

  if(elgamal.pIsPrime())
    fmt::println(fg(fmt::color::green), "P = {} and is Prime", elgamal.getP());
  else
    fmt::println(fg(fmt::color::red), "P = {} and is not Prime", elgamal.getP());

  if(elgamal.gIsValid())
    fmt::println(fg(fmt::color::green), "G = {} and is Valid", elgamal.getG());
  else
    fmt::println(fg(fmt::color::red), "G = {} and is not Valid", elgamal.getG());

  if(elgamal.xIsValid())
    fmt::println(fg(fmt::color::green), "X = {} and is Valid", elgamal.getX());

  else
    fmt::println(fg(fmt::color::red), "X = {} and is not Valid", elgamal.getX());

  fmt::println(fg(fmt::color::green), "Y = {}", elgamal.getY());

  std::pair<const void*, size_t> get_message = elgamal.getMessage();
  std::string recreate_message(static_cast<const char*>(get_message.first), get_message.second);

  std::pair<const void*, size_t> get_cipher = elgamal.getCipher();
  std::string recreate_cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

  if(message == recreate_message)
    fmt::println(fg(fmt::color::green), "Message: {} == {}", message, recreate_message);
  else
    fmt::println(fg(fmt::color::red), "Message: {} != {}", message, recreate_message);

  if(cipher == recreate_cipher)
    fmt::println(fg(fmt::color::green), "Cipher: {} == {}", cipher, recreate_cipher);
  else
    fmt::println(fg(fmt::color::red), "Cipher: {} != {}", cipher, recreate_cipher);

  fmt::println(fg(fmt::color::yellow), "{}", elgamal.c_str());
};



void ELGamalCryptEncrypt(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "ELGamal Crypt and Encrypt");
  fmt::println("");

  Crypt::ELGamal elgamal;
  elgamal.setP(467);
  elgamal.setG(2);
  elgamal.setX(127);
  std::string message = "Hello World";
  elgamal.setMessage(message.data(), message.size());

  fmt::println(fg(fmt::color::aqua), "Crypt");
  elgamal.crypt();
  std::pair<const void*, size_t> get_cipher = elgamal.getCipher();
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
  Crypt::ELGamal elgamal2;
  elgamal2.setP(467);
  elgamal2.setG(2);
  elgamal2.setX(127);
  elgamal2.setCipher(get_cipher.first, get_cipher.second);
  elgamal2.encrypt();

  std::pair<const void*, size_t> get_message = elgamal2.getMessage();
  std::string recreated_message(static_cast<const char*>(get_message.first), get_message.second);

  if(message == recreated_message)
    fmt::println(fg(fmt::color::green), "Message: '{}' == Recreated Message: '{}'", message, recreated_message);
  else
    fmt::println(fg(fmt::color::red), "Message: '{}' != Recreated Message: '{}'", message, recreated_message);

};



void ELGamalExample(){
  fmt::println("");
  fmt::println("");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "====================");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "= ELGamal Examples =");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "====================");
  fmt::println("");

  ELGamalSettersGetters();
  ELGamalCryptEncrypt();
};