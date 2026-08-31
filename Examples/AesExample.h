// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "fmt/base.h"
#include "fmt/color.h"

#include <string>

#include <Crypt/Aes/Aes.h>



void AesGettersSetters(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Aes Setters/Getters");
  fmt::println("");
  
  fmt::println(fg(fmt::color::aqua), "Message");
  {
    Crypt::Aes aes;
    std::string message = "Hello World Message";
    aes.setMessage(message.data(), message.size());
    
    fmt::println(fg(fmt::color::yellow), "Original Text: {}", message);
    
    std::pair<const void*, size_t> get_message = aes.getMessage();
    std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

    if(recovered_message == message)
      fmt::println(fg(fmt::color::green), "Recovered Text: {}", recovered_message);
    else
      fmt::println(fg(fmt::color::red), "Recovered Text: {}", recovered_message);
  }

  fmt::println(fg(fmt::color::aqua), "Cipher");
  {
    Crypt::Aes aes;
    std::string cipher = "Hello World Cipher";
    aes.setCipher(cipher.data(), cipher.size());
    
    fmt::println(fg(fmt::color::yellow), "Original Text: {}", cipher);
    
    std::pair<const void*, size_t> get_cipher = aes.getCipher();
    std::string recovered_cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

    if(recovered_cipher == cipher)
      fmt::println(fg(fmt::color::green), "Recovered Text: {}", recovered_cipher);
    else
      fmt::println(fg(fmt::color::red), "Recovered Text: {}", recovered_cipher);
  }

  fmt::println(fg(fmt::color::aqua), "Key");
  {
    Crypt::Aes aes;
    std::string key = "Hello World key";
    aes.setKey(key.data(), key.size());
    
    fmt::println(fg(fmt::color::yellow), "Original Text: {}", key);
    
    std::pair<const void*, size_t> get_key = aes.getKey();
    std::string recovered_key(static_cast<const char*>(get_key.first), get_key.second);

    if(recovered_key == key)
      fmt::println(fg(fmt::color::green), "Recovered Text: {}", recovered_key);
    else
      fmt::println(fg(fmt::color::red), "Recovered Text: {}", recovered_key);
  }
};



void AesCryptEncrypt(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Aes Crypt/Encrypt");
  fmt::println("");
  
  {
    std::string message = "Hello World Message";
    std::string key = "VeryLongAndHiddenPassword";
    
    
    Crypt::Aes aes;
    aes.setMessage(message.data(), message.size());
    aes.setKey(key.data(), key.size());
        
    aes.crypt();
    std::pair<const void*, size_t> get_cipher = aes.getCipher();
    std::string cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);
    

    Crypt::Aes aes2;
    aes2.setCipher(cipher.data(), cipher.size());
    aes2.setKey(key.data(), key.size());
    
    aes2.encrypt();
    std::pair<const void*, size_t> get_message = aes2.getMessage();
    std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);
    

    fmt::println(fg(fmt::color::yellow), "Key: {}", key);
    fmt::println(fg(fmt::color::yellow), "Original Message: {}", message);
    fmt::print(fg(fmt::color::yellow), "Original Message: ");
    for(unsigned char byte : message) fmt::print(fg(fmt::color::yellow), "{:02x}", byte);
    fmt::print("\n");

    if(cipher != message){
      fmt::print(fg(fmt::color::green), "Cipher: ");
      for(unsigned char byte : cipher) fmt::print(fg(fmt::color::green), "{:02x}", byte);
      fmt::print("\n");
    }
    else{
      fmt::print(fg(fmt::color::red), "Cipher: ");
      for(unsigned char byte : cipher) fmt::print(fg(fmt::color::red), "{:02x}", byte);
      fmt::print("\n");
    };
    
    
    if(recovered_message == message)
      fmt::println(fg(fmt::color::green), "Recovered Message: {}", recovered_message);
    else
      fmt::println(fg(fmt::color::red), "Recovered Message: {}", recovered_message);
  }
};



void AesExample(){
  fmt::println("");
  fmt::println("");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "================");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "= Aes Examples =");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "================");
  fmt::println("");

  AesGettersSetters();
  AesCryptEncrypt();
};