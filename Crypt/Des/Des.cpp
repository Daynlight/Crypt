// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "Des.h"



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
// core
Crypt::Des::Des() noexcept {};



Crypt::Des::~Des() noexcept {
  delete[] static_cast<unsigned char*>(cipher);
  delete[] static_cast<unsigned char*>(message);
  delete[] static_cast<unsigned char*>(key);
};



// copy
Crypt::Des::Des(const Des& second) noexcept {
  setMessage(second.message, second.message_size);
  setKey(second.key, second.key_size);
  setCipher(second.cipher, second.cipher_size);
};



Crypt::Des& Crypt::Des::operator=(const Des& second) noexcept {
  if(this == &second) return *this;

  setMessage(second.message, second.message_size);
  setKey(second.key, second.key_size);
  setCipher(second.cipher, second.cipher_size);

  return *this;
};



// move
Crypt::Des::Des(Des&& second) noexcept
  : key(std::move(second.key)),
    message(std::move(second.message)),
    cipher(std::move(second.cipher)),
    key_size(std::move(second.key_size)),
    message_size(std::move(second.message_size)),
    cipher_size(std::move(second.cipher_size)) {
  
  second.key = nullptr;
  second.message = nullptr;
  second.cipher = nullptr;
  second.key_size = 0;
  second.message_size = 0;
  second.cipher_size = 0;
};



Crypt::Des& Crypt::Des::operator=(Des&& second) noexcept {
  if(this == &second) return *this;

  delete[] static_cast<unsigned char*>(key);
  delete[] static_cast<unsigned char*>(message);
  delete[] static_cast<unsigned char*>(cipher);
  
  key = std::move(second.key);
  message = std::move(second.message);
  cipher = std::move(second.cipher);
  key_size = std::move(second.key_size);
  message_size = std::move(second.message_size);
  cipher_size = std::move(second.cipher_size);

  second.key = nullptr;
  second.message = nullptr;
  second.cipher = nullptr;
  second.key_size = 0;
  second.message_size = 0;
  second.cipher_size = 0;

  return *this;
};



//// ============================= ////
//// ====== Getters/Setters ====== ////
//// ============================= ////
std::pair<const void*, size_t> Crypt::Des::getMessage() const noexcept {
  return {message, message_size};
};



void Crypt::Des::setMessage(const void *message, size_t size) noexcept {
  if(message == nullptr || size == 0) {
    delete[] static_cast<unsigned char*>(this->message);
    this->message = nullptr;
    this->message_size = 0;
    return;
  };

  auto* copy = new unsigned char[size];
  std::memcpy(copy, message, size);

  delete[] static_cast<unsigned char*>(this->message);

  this->message = copy;
  this->message_size = size;
};



std::pair<const void*, size_t> Crypt::Des::getCipher() const noexcept {
  return {cipher, cipher_size};
};



void Crypt::Des::setCipher(const void *cipher, size_t size) noexcept {
  if(cipher == nullptr || size == 0) {
    delete[] static_cast<unsigned char*>(this->cipher);
    this->cipher = nullptr;
    this->cipher_size = 0;
    return;
  };

  auto* copy = new unsigned char[size];
  std::memcpy(copy, cipher, size);

  delete[] static_cast<unsigned char*>(this->cipher);

  this->cipher = copy;
  this->cipher_size = size;
};



std::pair<const void*, size_t> Crypt::Des::getKey() const noexcept {
  return {key, key_size};
};



void Crypt::Des::setKey(const void *key, size_t size) noexcept {
  if(key == nullptr || size == 0) {
    delete[] static_cast<unsigned char*>(this->key);
    this->key = nullptr;
    this->key_size = 0;
    return;
  };

  auto* copy = new unsigned char[size];
  std::memcpy(copy, key, size);

  delete[] static_cast<unsigned char*>(this->key);

  this->key = copy;
  this->key_size = size;
};



//// =================== ////
//// ====== Crypt ====== ////
//// =================== ////
void Crypt::Des::crypt() noexcept {
  if(message == nullptr || message_size == 0 || key == nullptr || key_size == 0) {
    cipher_size = 0;
    delete[] static_cast<unsigned char*>(cipher);
    cipher = nullptr;
    return;
  };

  const size_t padding = 8 - (message_size % 8);
  const size_t padded_size = message_size + padding;
  cipher_size = padded_size;

  delete[] static_cast<unsigned char*>(cipher);
  cipher = new unsigned char[padded_size];

  std::memcpy(cipher, message, message_size);
  auto* bytes = static_cast<unsigned char*>(cipher);

  for(size_t i = message_size; i < padded_size; ++i) 
    bytes[i] = static_cast<unsigned char>(padding);

  generateRoundKeys();

  for(size_t offset = 0; offset < cipher_size; offset += 8) {
    uint64_t block = 0;

    for(size_t i = 0; i < 8; ++i) {
      block <<= 8;
      block |= bytes[offset + i];
    };

    block = permute(block, IP, 64, 64);
    uint32_t left = static_cast<uint32_t>(block >> 32);
    uint32_t right = static_cast<uint32_t>(block & 0xFFFFFFFF);

    for(size_t round = 0; round < 16; ++round) {
      uint32_t old_right = right;

      right = left ^ feistel(right, round_keys[round]);
      left = old_right;
    };

    uint64_t combined = (static_cast<uint64_t>(right) << 32) | left;
    uint64_t encrypted = permute(combined, FP, 64, 64);

    for(int i = 7; i >= 0; --i) {
      bytes[offset + i] = static_cast<unsigned char>(encrypted & 0xFF);
      encrypted >>= 8;
    };
  };
};



void Crypt::Des::encrypt() noexcept {
  if(cipher == nullptr || cipher_size == 0 || cipher_size % 8 != 0) {
    message_size = 0;
    delete[] static_cast<unsigned char*>(message);
    message = nullptr;
    return;
  };

  if(key == nullptr || key_size == 0) {
    message_size = 0;
    delete[] static_cast<unsigned char*>(message);
    message = nullptr;
    return;
  };

  generateRoundKeys();

  const auto* cipher_bytes = static_cast<const unsigned char*>(cipher);

  auto* decrypted = new unsigned char[cipher_size];

  for(size_t offset = 0; offset < cipher_size; offset += 8) {
    uint64_t block = 0;

    for(size_t i = 0; i < 8; ++i) {
      block <<= 8;
      block |= static_cast<uint64_t>(cipher_bytes[offset + i]);
    };

    block = permute(block, IP, 64, 64);
    uint32_t left = static_cast<uint32_t>(block >> 32);
    uint32_t right = static_cast<uint32_t>(block & 0xFFFFFFFFULL);

    for(size_t round = 0; round < 16; ++round) {
      const uint32_t old_right = right;
      right = left ^ feistel(right, round_keys[15 - round]);
      left = old_right;
    };

    uint64_t combined = (static_cast<uint64_t>(right) << 32) | static_cast<uint64_t>(left);
    uint64_t decrypted_block = permute(combined, FP, 64, 64);

    for(int i = 7; i >= 0; --i) {
      decrypted[offset + i] = static_cast<unsigned char>(decrypted_block & 0xFF);
      decrypted_block >>= 8;
    };
  };

  const unsigned char padding = decrypted[cipher_size - 1];

  if(padding == 0 || padding > 8) {
    delete[] decrypted;
    delete[] static_cast<unsigned char*>(message);
    message = nullptr;
    message_size = 0;
    return;
  };

  for(size_t i = 0; i < padding; ++i) {
    if(decrypted[cipher_size - 1 - i] != padding) {
      delete[] decrypted;
      delete[] static_cast<unsigned char*>(message);
      message = nullptr;
      message_size = 0;
      return;
    };
  };

  message_size = cipher_size - padding;
  auto* result = new unsigned char[message_size];
  
  std::memcpy(result, decrypted, message_size);
  delete[] decrypted;
  
  delete[] static_cast<unsigned char*>(message);
  message = result;
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
void Crypt::Des::generateRoundKeys() noexcept {
  if(key == nullptr || key_size == 0) return;

  const auto* key_bytes = static_cast<const unsigned char*>(key);

  uint64_t raw_key = 14695981039346656037ULL;

  for(size_t i = 0; i < key_size; ++i) {
    raw_key ^= static_cast<uint64_t>(key_bytes[i]);
    raw_key *= 1099511628211ULL;
  };

  uint64_t permuted = permute(raw_key, PC1, 56, 64);
  uint32_t C = static_cast<uint32_t>((permuted >> 28) & 0x0FFFFFFF);
  uint32_t D = static_cast<uint32_t>(permuted & 0x0FFFFFFF);

  for(size_t round = 0; round < 16; ++round) {
    const int shift = SHIFTS[round];

    C = ((C << shift) | (C >> (28 - shift))) & 0x0FFFFFFF;
    D = ((D << shift) | (D >> (28 - shift))) & 0x0FFFFFFF;

    uint64_t combined = (static_cast<uint64_t>(C) << 28) | D;
    round_keys[round] = permute(combined, PC2, 48, 56);
  };
};



uint64_t Crypt::Des::permute(uint64_t value, const int* table, size_t output_size, size_t input_size) noexcept {
  uint64_t result = 0;

  for(size_t i = 0; i < output_size; ++i) {
    result <<= 1;
    size_t source_bit = input_size - table[i];
    result |= (value >> source_bit) & 1ULL;
  };

  return result;
};



uint32_t Crypt::Des::feistel(uint32_t right, uint64_t round_key) noexcept {
    uint64_t expanded = permute(right, E, 48, 32);
    uint64_t mixed = expanded ^ round_key;
    uint32_t substituted = 0;

    for(size_t i = 0; i < 8; ++i) {
      const int shift = 42 - static_cast<int>(i) * 6;

      uint8_t chunk = static_cast<uint8_t>((mixed >> shift) & 0x3F);
      uint8_t row = static_cast<uint8_t>(((chunk & 0x20) >> 4) | (chunk & 0x01));
      uint8_t column = static_cast<uint8_t>((chunk >> 1) & 0x0F);

      substituted <<= 4;
      substituted |= SBOX[i][row][column];
    };

  return static_cast<uint32_t>(permute(substituted, P, 32, 32));
};
