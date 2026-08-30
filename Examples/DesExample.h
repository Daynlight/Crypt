// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "fmt/base.h"
#include "fmt/color.h"

#include <string>

#include <Crypt/Des/Des.h>



void DesGettersSetters(){
  fmt::println(fg(fmt::color::aqua), "Des Setters/Getters");
  fmt::println("");
  
  fmt::println(fg(fmt::color::aqua), "Message");
  {
    Crypt::Des des;
    std::string message = "Hello World Message";
    des.setMessage(message.data(), message.size());
    
    fmt::println(fg(fmt::color::yellow), "Original Text: {}", message);
    
    std::pair<const void*, size_t> get_message = des.getMessage();
    std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);

    if(recovered_message == message)
      fmt::println(fg(fmt::color::green), "Recovered Text: {}", recovered_message);
    else
      fmt::println(fg(fmt::color::red), "Recovered Text: {}", recovered_message);
  }

  fmt::println(fg(fmt::color::aqua), "Cipher");
  {
    Crypt::Des des;
    std::string cipher = "Hello World Cipher";
    des.setCipher(cipher.data(), cipher.size());
    
    fmt::println(fg(fmt::color::yellow), "Original Text: {}", cipher);
    
    std::pair<const void*, size_t> get_cipher = des.getCipher();
    std::string recovered_cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);

    if(recovered_cipher == cipher)
      fmt::println(fg(fmt::color::green), "Recovered Text: {}", recovered_cipher);
    else
      fmt::println(fg(fmt::color::red), "Recovered Text: {}", recovered_cipher);
  }

  fmt::println(fg(fmt::color::aqua), "Key");
  {
    Crypt::Des des;
    std::string key = "Hello World key";
    des.setKey(key.data(), key.size());
    
    fmt::println(fg(fmt::color::yellow), "Original Text: {}", key);
    
    std::pair<const void*, size_t> get_key = des.getKey();
    std::string recovered_key(static_cast<const char*>(get_key.first), get_key.second);

    if(recovered_key == key)
      fmt::println(fg(fmt::color::green), "Recovered Text: {}", recovered_key);
    else
      fmt::println(fg(fmt::color::red), "Recovered Text: {}", recovered_key);
  }
};



void DesCryptEncrypt(){
  fmt::println(fg(fmt::color::aqua), "Des Crypt/Encrypt");
  fmt::println("");
  
  {
    std::string message = "Hello World Message";
    std::string key = "VeryLongAndHiddenPassword";
    
    
    Crypt::Des des;
    des.setMessage(message.data(), message.size());
    des.setKey(key.data(), key.size());
        
    des.crypt();
    std::pair<const void*, size_t> get_cipher = des.getCipher();
    std::string cipher(static_cast<const char*>(get_cipher.first), get_cipher.second);
    

    Crypt::Des des2;
    des2.setCipher(cipher.data(), cipher.size());
    des2.setKey(key.data(), key.size());
    
    des2.encrypt();
    std::pair<const void*, size_t> get_message = des2.getMessage();
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



void DesExample(){
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "Des Examples");
  fmt::println("");

  DesGettersSetters();
  DesCryptEncrypt();
};