// Crypt
// Copyright 2026 Daynlight
// Licensed under the GNU General, Version 3.0.
// See LICENSE file for details.



#include "Aes.h"



//// ========================== ////
//// ====== Constructors ====== ////
//// ========================== ////
// core
Crypt::Aes::Aes() noexcept {};



Crypt::Aes::~Aes() noexcept {
  delete[] static_cast<unsigned char*>(cipher);
  delete[] static_cast<unsigned char*>(message);
  delete[] static_cast<unsigned char*>(key);
};



// copy
Crypt::Aes::Aes(const Aes& second) noexcept {
  setMessage(second.message, second.message_size);
  setKey(second.key, second.key_size);
  setCipher(second.cipher, second.cipher_size);
};



Crypt::Aes& Crypt::Aes::operator=(const Aes& second) noexcept {
  if(this == &second) return *this;

  setMessage(second.message, second.message_size);
  setKey(second.key, second.key_size);
  setCipher(second.cipher, second.cipher_size);

  return *this;
};



// move
Crypt::Aes::Aes(Aes&& second) noexcept
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



Crypt::Aes& Crypt::Aes::operator=(Aes&& second) noexcept {
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
std::pair<const void*, size_t> Crypt::Aes::getMessage() const noexcept {
  return {message, message_size};
};



void Crypt::Aes::setMessage(const void *message, size_t size) noexcept {
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



std::pair<const void*, size_t> Crypt::Aes::getCipher() const noexcept {
  return {cipher, cipher_size};
};



void Crypt::Aes::setCipher(const void *cipher, size_t size) noexcept {
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



std::pair<const void*, size_t> Crypt::Aes::getKey() const noexcept {
  return {key, key_size};
};



void Crypt::Aes::setKey(const void *key, size_t size) noexcept {
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
void Crypt::Aes::crypt() noexcept {
  if(message == nullptr || message_size == 0) return;
  if(key == nullptr || key_size == 0) return;

  delete[] static_cast<unsigned char*>(cipher);
  cipher = nullptr;
  cipher_size = 0;

  const size_t padding = 16 - (message_size % 16);
  const size_t padded_size = message_size + padding;

  auto* data = new unsigned char[padded_size];

  std::memcpy(data, message, message_size);
  std::memset(data + message_size, static_cast<unsigned char>(padding), padding);

  auto* output = new unsigned char[padded_size];

  keyExpansion();

  for(size_t offset = 0; offset < padded_size; offset += 16) {
    uint8_t state[4][4];

    loadBlock(data + offset, state);

    addRoundKey(state, 0);

    for(size_t round = 1; round < 10; ++round) {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state, round);
    };

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, 10);

    storeBlock(state, output + offset);
  };

  delete[] data;

  cipher = output;
  cipher_size = padded_size;
};



void Crypt::Aes::encrypt() noexcept {
  if(cipher == nullptr || cipher_size == 0 || cipher_size % 16 != 0) {
    delete[] static_cast<unsigned char*>(message);
    message = nullptr;
    message_size = 0;
    return;
  };

  if(key == nullptr || key_size == 0) {
    delete[] static_cast<unsigned char*>(message);
    message = nullptr;
    message_size = 0;
    return;
  };

  keyExpansion();

  auto* output = new unsigned char[cipher_size];

  for(size_t offset = 0; offset < cipher_size; offset += 16) {
    uint8_t state[4][4];

    loadBlock(static_cast<const unsigned char*>(cipher) + offset, state);

    addRoundKey(state, 10);

    for(size_t round = 9; round > 0; --round) {
      invShiftRows(state);
      invSubBytes(state);
      addRoundKey(state, round);
      invMixColumns(state);
    };

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, 0);

    storeBlock(state, output + offset);
  };

  const uint8_t padding = output[cipher_size - 1];

  if(padding == 0 || padding > 16) {
    delete[] output;

    delete[] static_cast<unsigned char*>(message);
    message = nullptr;
    message_size = 0;
    return;
  };

  for(size_t i = 0; i < padding; ++i) {
    if(output[cipher_size - 1 - i] != padding) {
      delete[] output;

      delete[] static_cast<unsigned char*>(message);
      message = nullptr;
      message_size = 0;
      return;
    };
  };

  const size_t decrypted_size = cipher_size - padding;

  auto* result = new unsigned char[decrypted_size];

  if(decrypted_size > 0)
    std::memcpy(result, output, decrypted_size);

  delete[] output;

  delete[] static_cast<unsigned char*>(message);

  message = result;
  message_size = decrypted_size;
};



//// ===================== ////
//// ====== Helpers ====== ////
//// ===================== ////
void Crypt::Aes::keyExpansion() noexcept {
  if(key == nullptr || key_size == 0) return;

  uint8_t derived_key[16];
  deriveKey(key, key_size, derived_key);

  for(size_t i = 0; i < 4; ++i) {
    round_keys[i] =
      (static_cast<uint32_t>(derived_key[i * 4]) << 24) |
      (static_cast<uint32_t>(derived_key[i * 4 + 1]) << 16) |
      (static_cast<uint32_t>(derived_key[i * 4 + 2]) << 8) |
      static_cast<uint32_t>(derived_key[i * 4 + 3]);
  };

  for(size_t i = 4; i < 44; ++i) {
    uint32_t temp = round_keys[i - 1];

    if(i % 4 == 0) {
      temp = rotWord(temp);
      temp = subWord(temp);
      temp ^= static_cast<uint32_t>(RCON[i / 4]) << 24;
    };

    round_keys[i] = round_keys[i - 4] ^ temp;
  };
};



void Crypt::Aes::subBytes(uint8_t state[4][4]) noexcept {
  for(size_t row = 0; row < 4; ++row)
    for(size_t col = 0; col < 4; ++col)
      state[row][col] = SBOX[state[row][col]];
};



void Crypt::Aes::invSubBytes(uint8_t state[4][4]) noexcept {
  for(size_t row = 0; row < 4; ++row)
    for(size_t col = 0; col < 4; ++col)
      state[row][col] = INV_SBOX[state[row][col]];
};



void Crypt::Aes::shiftRows(uint8_t state[4][4]) noexcept {
  uint8_t temp;

  temp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = temp;

  std::swap(state[2][0], state[2][2]);
  std::swap(state[2][1], state[2][3]);

  temp = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = state[3][0];
  state[3][0] = temp;
};



void Crypt::Aes::invShiftRows(uint8_t state[4][4]) noexcept {
  uint8_t temp;

  temp = state[1][3];
  state[1][3] = state[1][2];
  state[1][2] = state[1][1];
  state[1][1] = state[1][0];
  state[1][0] = temp;

  std::swap(state[2][0], state[2][2]);
  std::swap(state[2][1], state[2][3]);

  temp = state[3][0];
  state[3][0] = state[3][1];
  state[3][1] = state[3][2];
  state[3][2] = state[3][3];
  state[3][3] = temp;
};



void Crypt::Aes::mixColumns(uint8_t state[4][4]) noexcept {
  for(size_t col = 0; col < 4; ++col) {
    const uint8_t a = state[0][col];
    const uint8_t b = state[1][col];
    const uint8_t c = state[2][col];
    const uint8_t d = state[3][col];

    state[0][col] = gmul(a, 0x02) ^ gmul(b, 0x03) ^ c ^ d;
    state[1][col] = a ^ gmul(b, 0x02) ^ gmul(c, 0x03) ^ d;
    state[2][col] = a ^ b ^ gmul(c, 0x02) ^ gmul(d, 0x03);
    state[3][col] = gmul(a, 0x03) ^ b ^ c ^ gmul(d, 0x02);
  };
};



void Crypt::Aes::invMixColumns(uint8_t state[4][4]) noexcept {
  for(size_t col = 0; col < 4; ++col) {
    const uint8_t a = state[0][col];
    const uint8_t b = state[1][col];
    const uint8_t c = state[2][col];
    const uint8_t d = state[3][col];

    state[0][col] = gmul(a, 0x0E) ^ gmul(b, 0x0B) ^ gmul(c, 0x0D) ^ gmul(d, 0x09);
    state[1][col] = gmul(a, 0x09) ^ gmul(b, 0x0E) ^ gmul(c, 0x0B) ^ gmul(d, 0x0D);
    state[2][col] = gmul(a, 0x0D) ^ gmul(b, 0x09) ^ gmul(c, 0x0E) ^ gmul(d, 0x0B);
    state[3][col] = gmul(a, 0x0B) ^ gmul(b, 0x0D) ^ gmul(c, 0x09) ^ gmul(d, 0x0E);
  };
};



void Crypt::Aes::addRoundKey(uint8_t state[4][4], size_t round) noexcept {
  for(size_t col = 0; col < 4; ++col) {
    const uint32_t word = round_keys[round * 4 + col];

    state[0][col] ^= static_cast<uint8_t>((word >> 24) & 0xFF);
    state[1][col] ^= static_cast<uint8_t>((word >> 16) & 0xFF);
    state[2][col] ^= static_cast<uint8_t>((word >> 8) & 0xFF);
    state[3][col] ^= static_cast<uint8_t>(word & 0xFF);
  };
};



uint8_t Crypt::Aes::gmul(uint8_t a, uint8_t b) noexcept {
  uint8_t result = 0;

  while(b) {
    if(b & 1)
      result ^= a;

    const bool high_bit = a & 0x80;
    a <<= 1;

    if(high_bit)
      a ^= 0x1B;

    b >>= 1;
  };

  return result;
};



void Crypt::Aes::loadBlock(const unsigned char* input, uint8_t state[4][4]) noexcept {
  for(size_t col = 0; col < 4; ++col)
    for(size_t row = 0; row < 4; ++row)
      state[row][col] = input[col * 4 + row];
};



void Crypt::Aes::storeBlock(const uint8_t state[4][4], unsigned char* output) noexcept {
  for(size_t col = 0; col < 4; ++col)
    for(size_t row = 0; row < 4; ++row)
      output[col * 4 + row] = state[row][col];
};



uint32_t Crypt::Aes::rotWord(uint32_t word) noexcept {
  return (word << 8) | (word >> 24);
};



uint32_t Crypt::Aes::subWord(uint32_t word) noexcept {
  return
    (static_cast<uint32_t>(SBOX[(word >> 24) & 0xFF]) << 24) |
    (static_cast<uint32_t>(SBOX[(word >> 16) & 0xFF]) << 16) |
    (static_cast<uint32_t>(SBOX[(word >> 8) & 0xFF]) << 8) |
    static_cast<uint32_t>(SBOX[word & 0xFF]);
};



void Crypt::Aes::deriveKey(const void* key, size_t key_size, uint8_t output[16]) noexcept {
  const auto* bytes = static_cast<const uint8_t*>(key);

  uint64_t hash1 = 14695981039346656037ULL;
  uint64_t hash2 = 1099511628211ULL;

  for(size_t i = 0; i < key_size; ++i) {
    hash1 ^= static_cast<uint64_t>(bytes[i]);
    hash1 *= 1099511628211ULL;

    hash2 ^= static_cast<uint64_t>(bytes[i] + i);
    hash2 *= 14695981039346656037ULL;
  };

  for(size_t i = 0; i < 8; ++i) {
    output[i] = static_cast<uint8_t>((hash1 >> (i * 8)) & 0xFF);
    output[i + 8] = static_cast<uint8_t>((hash2 >> (i * 8)) & 0xFF);
  };
};