// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "fmt/base.h"
#include "fmt/color.h"
#include <Crypt/Elliptic/Elliptic.h>
#include <Crypt/Aes/Aes.h>



class User{
private:
  Crypt::Elliptic shared_key;
  Crypt::Aes aes;
  size_t private_key = 0;
  std::string message = "";

public:
  Crypt::Elliptic public_key;

public:
  User(size_t modulo, size_t a, size_t b, size_t x, size_t y)
    : shared_key(modulo, a, b, x, y),
      public_key(modulo, a, b, x, y) {};

  void setPrivateKey(size_t key){
    private_key = key;
    public_key *= private_key;
  };

  void getSecondPublicKey(Crypt::Elliptic second_public_key){
    shared_key = second_public_key * private_key;
  };

  void setCipher(std::pair<const void*, size_t> cipher){
    aes.setCipher(cipher.first, cipher.second);
  };

  std::pair<const void*, size_t> getCipher(){
    std::array<size_t, 2> point = shared_key.getPoint();
    std::string key = std::to_string(point[0]) + std::to_string(point[1]);
    aes.setKey(key.data(), key.size());

    aes.crypt();

    return aes.getCipher();
  };

  void setMessage(std::string message){
    aes.setMessage(message.data(), message.size());
  };

  std::string getMessage(){
    std::array<size_t, 2> point = shared_key.getPoint();
    std::string key = std::to_string(point[0]) + std::to_string(point[1]);
    aes.setKey(key.data(), key.size());

    aes.encrypt();

    std::pair<const void*, size_t> get_message = aes.getMessage();
    std::string recovered_message(static_cast<const char*>(get_message.first), get_message.second);
    message = recovered_message;
    return message;
  };
};



void DataTransferTwoUsers(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Data Transfer Two Users");
  fmt::println("");


  size_t modulo = 14143;
  std::array<size_t, 2> elliptic_params = {2, 2};
  std::array<size_t, 2> base_point = {55, 839};
  fmt::println(fg(fmt::color::yellow), "Public Params: Modulo {}, a: {}, b: {}, x: {}, y: {}", modulo, elliptic_params[0], elliptic_params[1], base_point[0], base_point[1]);
  
  
  fmt::println(fg(fmt::color::aqua), "Public Params");
  fmt::println(fg(fmt::color::yellow), "Set Public Parameters");
  User user1(modulo, elliptic_params[0], elliptic_params[1], base_point[0], base_point[1]);
  User user2(modulo, elliptic_params[0], elliptic_params[1], base_point[0], base_point[1]);
  

  fmt::println(fg(fmt::color::aqua), "Private Keys");
  {
    size_t private_key = 24;
    fmt::println(fg(fmt::color::pink), "User1 - Set Private Key: {}", private_key);
    user1.setPrivateKey(private_key);
  }
  {
    size_t private_key = 77;
    fmt::println(fg(fmt::color::purple), "User2 - Set Private Key {}", private_key);
    user2.setPrivateKey(private_key);
  }


  fmt::println(fg(fmt::color::aqua), "Key Exchange");
  {
    fmt::println(fg(fmt::color::pink), "User1 - Set Public Key: {}", user2.public_key.c_str());
    user1.getSecondPublicKey(user2.public_key);
  }
  {
    fmt::println(fg(fmt::color::purple), "User2 - Set Public Key: {}", user1.public_key.c_str());
    user2.getSecondPublicKey(user1.public_key);
  }
  

  fmt::println(fg(fmt::color::aqua), "Creating Chipper");
  std::pair<const void*, size_t> cipher;
  {
    fmt::println(fg(fmt::color::pink), "User1 - Create Message And Cipher");
    
    std::string hidden_message = "Hello User2";
    user1.setMessage(hidden_message);
    
    fmt::print(fg(fmt::color::pink), "Hidden Message: ");
    for(unsigned char byte : hidden_message) fmt::print(fg(fmt::color::pink), "{:02x}", byte);
    fmt::print("\n");

    cipher = user1.getCipher();
  }    

  fmt::println(fg(fmt::color::aqua), "Encrypting Chipper");
  {
    fmt::println(fg(fmt::color::purple), "User2 - Encrypt Cipher");
    
    user2.setCipher(cipher);
    std::string received_message = "";
    received_message = user2.getMessage();

    fmt::print(fg(fmt::color::purple), "Received Message: ");
    for(unsigned char byte : received_message) fmt::print(fg(fmt::color::purple), "{:02x}", byte);
    fmt::print("\n");
    fmt::println(fg(fmt::color::purple), "Received Message: {}", received_message);
  }


  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Public Available Data");
  fmt::println("");
  
  fmt::println(fg(fmt::color::yellow), "Modulo: {}", modulo);
  fmt::println(fg(fmt::color::yellow), "Elliptic Params: {}, {}", elliptic_params[0], elliptic_params[1]);
  fmt::println(fg(fmt::color::yellow), "Base Point: {}, {}", base_point[0], base_point[1]);
  
  std::string cipher_str(static_cast<const char*>(cipher.first), cipher.second);
  fmt::print(fg(fmt::color::yellow), "Public Cipher: ");
  for(unsigned char byte : cipher_str) fmt::print(fg(fmt::color::yellow), "{:02x}", byte);
  fmt::print("\n");

  fmt::println(fg(fmt::color::yellow), "User1 public_key: {}", user1.public_key.c_str());
  fmt::println(fg(fmt::color::yellow), "User2 public_key: {}", user2.public_key.c_str());
};



void DataTransferExample(){
  fmt::println("");
  fmt::println("");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "=================");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "= Data Transfer =");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "=================");
  fmt::println("");

  DataTransferTwoUsers();
};