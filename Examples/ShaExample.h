// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "fmt/base.h"
#include "fmt/color.h"

#include <string>

#include <Crypt/Sha/Sha.h>



void ShaExampleHashData(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Hash Data with SHA256");
  fmt::println("");
  
  std::string data = "Data To hash";
  Crypt::Sha sha;
  sha.setData(data.data(), data.size());
  std::array<uint8_t, 32> hash = sha.getHash();

  fmt::print(fg(fmt::color::yellow), "Data: ");
  for(unsigned char byte : data) fmt::print(fg(fmt::color::yellow), "{:02x}", byte);
  fmt::print("\n");

  fmt::print(fg(fmt::color::yellow), "Hash: ");
  for(unsigned char byte : hash) fmt::print(fg(fmt::color::yellow), "{:02x}", byte);
  fmt::print("\n");
};



void ShaExampleHashBigData(){
  fmt::println("");
  fmt::println(fg(fmt::color::aqua), "Hash Data Big Data");
  fmt::println("");
  
  std::string data = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since 1966, when designers at Letraset and James Mosley, the librarian at St Bride Printing Library in London, took a 1914 Cicero translation and scrambled it to make dummy text for Letraset's Body Type sheets. It has survived not only many decades, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised thanks to these sheets and more recently with desktop publishing software like Aldus PageMaker and Microsoft Word including versions of Lorem Ipsum.";
  Crypt::Sha sha;
  sha.setData(data.data(), data.size());
  std::array<uint8_t, 32> hash = sha.getHash();

  fmt::print(fg(fmt::color::yellow), "Data: ");
  for(unsigned char byte : data) fmt::print(fg(fmt::color::yellow), "{:02x}", byte);
  fmt::print("\n");

  fmt::print(fg(fmt::color::yellow), "Hash: ");
  for(unsigned char byte : hash) fmt::print(fg(fmt::color::yellow), "{:02x}", byte);
  fmt::print("\n");
};



void ShaExample(){
  fmt::println("");
  fmt::println("");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "================");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "= Sha Examples =");
  fmt::println(fg(fmt::color::blue) | fmt::emphasis::bold, "================");
  fmt::println("");

  ShaExampleHashData();
  ShaExampleHashBigData();
};